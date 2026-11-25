//! The store of revisions as the commands and the follower see it: one small trait, with
//! plain data in and out. [`crate::SqlStore`] keeps the revisions in SQLite or
//! PostgreSQL, [`crate::MemoryStore`] in memory.

use std::time::Duration;

use crate::document;
use crate::error::Error;

/// The longest note of a revision, in bytes.
pub const MAX_NOTE: usize = 200;
/// The longest author and the longest source name, in bytes.
pub const MAX_NAME: usize = 128;
/// The largest source, in bytes. It is the limit of an edge file.
pub const MAX_SOURCE: usize = document::LIMITS.max_input_bytes;
/// The most revisions that [`Store::history`] returns.
pub const MAX_HISTORY: usize = 1000;
/// The most nodes that [`Store::nodes`] returns.
pub const MAX_NODES: usize = 256;
/// The longest detail of a report, in bytes.
pub const MAX_DETAIL: usize = 300;

/// The newest revision. `revision` is 0 and `digest` is empty when nothing is published.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Head {
    /// The number of the newest revision.
    pub revision: u64,
    /// The digest of its document.
    pub digest: String,
}

/// How a revision came about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// A source was applied.
    Apply,
    /// The document of this earlier revision was restored.
    Rollback(u64),
}

/// A revision on its way into the store. It borrows everything for the commit.
#[derive(Clone, Copy, Debug)]
pub struct Draft<'a> {
    /// The canonical text of the published sections.
    pub document: &'a str,
    /// The source as the operator gave it.
    pub source: &'a [u8],
    /// The file name of the source, which tells its language.
    pub source_name: &'a str,
    /// How the revision comes about.
    pub origin: Origin,
    /// Who commits.
    pub author: &'a str,
    /// Why, in one line.
    pub note: &'a str,
    /// The time of the commit in Unix seconds.
    pub now: u64,
}

impl Draft<'_> {
    /// Fails with [`Error::Rejected`] when a part exceeds its bound or a line holds a
    /// control character.
    pub fn check(&self) -> Result<(), Error> {
        let line = |text: &str| !text.chars().any(char::is_control);
        let fault = match () {
            () if self.document.len() > document::LIMITS.max_input_bytes => "the document",
            () if self.source.len() > MAX_SOURCE => "the source",
            () if self.source_name.len() > MAX_NAME || !line(self.source_name) => {
                "the name of the source"
            }
            () if self.author.len() > MAX_NAME || !line(self.author) => "the author",
            () if self.note.len() > MAX_NOTE || !line(self.note) => "the note",
            () => return Ok(()),
        };
        Err(Error::Rejected(format!(
            "{fault} is too long or holds a control character. A document and a source \
             hold at most {MAX_SOURCE} bytes, a name {MAX_NAME} and a note {MAX_NOTE}"
        )))
    }
}

/// A committed revision without its document and its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The number of the revision, from 1.
    pub number: u64,
    /// How it came about.
    pub origin: Origin,
    /// The digest of its document.
    pub digest: String,
    /// The file name of its source.
    pub source_name: String,
    /// The digest of its source.
    pub source_digest: String,
    /// Who committed it.
    pub author: String,
    /// Why.
    pub note: String,
    /// When, in Unix seconds.
    pub committed_at: u64,
}

/// A committed revision, whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    /// What [`Store::history`] lists.
    pub entry: Entry,
    /// The canonical text of the published sections. Its digest is `entry.digest`.
    pub document: String,
    /// The source as the operator gave it.
    pub source: Vec<u8>,
}

impl Revision {
    /// The revision that committing `draft` as number `number` gives.
    pub fn from_draft(number: u64, draft: &Draft<'_>) -> Revision {
        Revision {
            entry: Entry {
                number,
                origin: draft.origin,
                digest: document::digest(draft.document.as_bytes()),
                source_name: draft.source_name.to_owned(),
                source_digest: document::digest(draft.source),
                author: draft.author.to_owned(),
                note: draft.note.to_owned(),
                committed_at: draft.now,
            },
            document: draft.document.to_owned(),
            source: draft.source.to_vec(),
        }
    }

    /// Fails with [`Error::Damaged`] when the document does not have the digest that
    /// the row states, or the row has another number than `number`.
    pub fn verify(&self, number: u64) -> Result<(), Error> {
        if self.entry.number != number {
            return Err(Error::Damaged(format!(
                "revision {number} was asked for and revision {} was read",
                self.entry.number
            )));
        }
        if document::digest(self.document.as_bytes()) != self.entry.digest {
            return Err(Error::Damaged(format!(
                "the document of revision {number} does not have the digest of its row"
            )));
        }
        Ok(())
    }
}

/// What a node says about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeReport {
    /// The name of the node.
    pub node: String,
    /// The revision that it serves, 0 for none.
    pub applied: u64,
    /// The digest of that revision.
    pub digest: String,
    /// The revision that it refused, 0 for none.
    pub refused: u64,
    /// Why it refused, at most [`MAX_DETAIL`] bytes.
    pub detail: String,
    /// When it reported, in Unix seconds.
    pub seen_at: u64,
}

/// Why [`Store::wait`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woken {
    /// The store announced a commit, or somebody woke the waiter.
    Notified,
    /// The time passed.
    TimedOut,
}

/// At most `max` bytes of `text` on one line, cut at a character.
pub fn clip(text: &str, max: usize) -> String {
    let mut line: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if line.len() > max {
        let mut end = max;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
    }
    line
}

/// The store of revisions (SID 0028). Revisions are numbered 1, 2, 3 and so on. A
/// committed revision never changes.
///
/// Every operation fails with [`Error::Unavailable`] when the store cannot be asked.
pub trait Store {
    /// The newest revision, or revision 0 when nothing is published.
    fn head(&mut self) -> Result<Head, Error>;

    /// Revision `number`, whole and verified against its digest. Fails with
    /// [`Error::Unknown`] when there is none and [`Error::Damaged`] when the stored
    /// document does not match its digest.
    fn revision(&mut self, number: u64) -> Result<Revision, Error>;

    /// Commits `draft` as revision `expected + 1` when the head is `expected`, in one
    /// transaction, and returns the new number. Fails with [`Error::Conflict`] and
    /// changes nothing when the head is another, and with [`Error::Rejected`] when a
    /// part of the draft exceeds its bound.
    fn commit(&mut self, expected: u64, draft: &Draft<'_>) -> Result<u64, Error>;

    /// The newest revisions without their bodies, newest first, at most `limit` and at
    /// most [`MAX_HISTORY`].
    fn history(&mut self, limit: usize) -> Result<Vec<Entry>, Error>;

    /// Records what a node says about itself, in the place of its earlier report.
    fn report(&mut self, report: &NodeReport) -> Result<(), Error>;

    /// The reports of the nodes in the order of their names, at most [`MAX_NODES`].
    fn nodes(&mut self) -> Result<Vec<NodeReport>, Error>;

    /// Blocks until the store announces a commit or `timeout` passes. A store that
    /// cannot announce returns after `timeout`. The caller looks at the head either way.
    fn wait(&mut self, timeout: Duration) -> Woken;
}

/// Commits `draft` on `store` and settles a commit whose outcome the database left
/// unknown: when the connection fails during the commit, the head tells whether the
/// revision is in. Returns the new number, or the failure of the commit.
pub fn commit_settled(
    store: &mut impl Store,
    expected: u64,
    draft: &Draft<'_>,
) -> Result<u64, Error> {
    let failure = match store.commit(expected, draft) {
        Err(failure) if failure.is_unavailable() => failure,
        outcome => return outcome,
    };
    let digest = document::digest(draft.document.as_bytes());
    match store.head() {
        Ok(head) if head.revision == expected + 1 && head.digest == digest => Ok(head.revision),
        _ => Err(failure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft<'a>(note: &'a str) -> Draft<'a> {
        Draft {
            document: "{}",
            source: b"{}",
            source_name: "edge.json",
            origin: Origin::Apply,
            author: "op@host",
            note,
            now: 7,
        }
    }

    #[test]
    fn a_draft_is_bounded() {
        assert!(draft("fix the weight").check().is_ok());
        assert_eq!(draft(&"x".repeat(MAX_NOTE + 1)).check().unwrap_err().code(), "DBA001");
        assert!(draft("two\nlines").check().is_err());
        let long = "x".repeat(MAX_SOURCE + 1);
        assert!(Draft { source: long.as_bytes(), ..draft("") }.check().is_err());
        assert!(Draft { document: &long, ..draft("") }.check().is_err());
        assert!(Draft { author: &long, ..draft("") }.check().is_err());
    }

    #[test]
    fn a_revision_is_verified_against_its_digest_and_number() {
        let mut revision = Revision::from_draft(3, &draft("n"));
        assert!(revision.verify(3).is_ok());
        assert_eq!(revision.verify(4).unwrap_err().code(), "DBA008");
        revision.document.push(' ');
        assert_eq!(revision.verify(3).unwrap_err().code(), "DBA008");
    }

    #[test]
    fn a_detail_is_one_short_line() {
        assert_eq!(clip("a\nb", 10), "a b");
        assert_eq!(clip("abcdef", 4), "abcd");
        assert_eq!(clip("a\u{e9}\u{e9}", 2), "a");
    }
}
