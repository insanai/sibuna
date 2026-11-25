//! What a node knows while it follows the store (SID 0028). Plain state and its
//! transitions, with no I/O: the daemon reads the store, checks documents and tells the
//! outcome here.
//!
//! ```text
//!   saw_head(head) ----> read this revision?        lost_database(why): keep everything
//!   read(revision) ----> the candidate
//!   refuse(n, why) ----> remembered, serving stays  (check failed, or the worker refused)
//!   applied(revision) -> serving = revision         (the worker serves it)
//! ```
//!
//! The transitions are those of the Lean model: an unavailable database and a refused
//! revision leave `serving` as it was, and `serving` only ever holds a revision that
//! the node applied.

use std::sync::Arc;

use crate::store::{Head, MAX_DETAIL, NodeReport, clip};

/// A revision as a node holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// The number of the revision.
    pub revision: u64,
    /// The digest of its document.
    pub digest: String,
    /// The canonical text of its published sections.
    pub document: String,
}

/// Whether the store answered the last look.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reach {
    /// The node has not looked yet.
    Unknown,
    /// The store answered.
    Up,
    /// The store did not answer, since this Unix second, for this reason.
    Down {
        /// When the store stopped answering.
        since: u64,
        /// What the last attempt said.
        reason: String,
    },
}

/// The state of a follower. Create one with [`Following::new`].
#[derive(Clone, Debug)]
pub struct Following {
    node: String,
    serving: Option<Arc<Published>>,
    candidate: Option<Arc<Published>>,
    refused: Option<(u64, String)>,
    /// The head that was read or refused. The node does not read it again at each poll.
    handled: u64,
    head: u64,
    reach: Reach,
    checked_at: u64,
}

impl Following {
    /// A follower that serves nothing yet and reports as `node`.
    pub fn new(node: &str) -> Following {
        Following {
            node: node.to_owned(),
            serving: None,
            candidate: None,
            refused: None,
            handled: 0,
            head: 0,
            reach: Reach::Unknown,
            checked_at: 0,
        }
    }

    /// Records that the store answered with `head` at the Unix second `now`. Returns
    /// the revision to read, if the head is one that the node has not handled.
    pub fn saw_head(&mut self, head: &Head, now: u64) -> Option<u64> {
        self.reach = Reach::Up;
        self.head = head.revision;
        self.checked_at = now;
        // A database that was restored may hold another document under a known number.
        let replaced = self.candidate.as_ref().is_some_and(|candidate| {
            candidate.revision == head.revision && candidate.digest != head.digest
        });
        let unhandled = head.revision != self.handled || replaced;
        (head.revision != 0 && unhandled).then_some(head.revision)
    }

    /// Records that the store did not answer at the Unix second `now`. Returns true
    /// when it answered before, so the caller logs the outage once. Nothing else
    /// changes: the node keeps what it serves.
    pub fn lost_database(&mut self, reason: &str, now: u64) -> bool {
        let first = !matches!(self.reach, Reach::Down { .. });
        let since = match &self.reach {
            Reach::Down { since, .. } => *since,
            _ => now,
        };
        self.reach = Reach::Down { since, reason: clip(reason, MAX_DETAIL) };
        first
    }

    /// Whether the store did not answer the last look.
    pub fn is_down(&self) -> bool {
        matches!(self.reach, Reach::Down { .. })
    }

    /// Why the store did not answer the last look, or `None` when it answered.
    pub fn down_reason(&self) -> Option<&str> {
        match &self.reach {
            Reach::Down { reason, .. } => Some(reason),
            _ => None,
        }
    }

    /// Takes a revision that was read from the store as the candidate and returns it.
    pub fn read(&mut self, published: Published) -> Arc<Published> {
        self.handled = published.revision;
        self.head = self.head.max(published.revision);
        let candidate = Arc::new(published);
        self.candidate = Some(Arc::clone(&candidate));
        candidate
    }

    /// Records that the node refused revision `revision`, by its check or by its
    /// worker. What it serves stays.
    pub fn refuse(&mut self, revision: u64, reason: &str) {
        self.handled = self.handled.max(revision);
        self.refused = Some((revision, clip(reason, MAX_DETAIL)));
    }

    /// Makes the next look read the head again, also when it was refused before.
    pub fn retry(&mut self) {
        self.handled = 0;
    }

    /// Records that the worker serves `published`. Returns true when that is another
    /// revision than before.
    pub fn applied(&mut self, published: &Arc<Published>) -> bool {
        if self.refused.as_ref().is_some_and(|(revision, _)| *revision <= published.revision) {
            self.refused = None;
        }
        let changed = self.serving.as_ref().is_none_or(|serving| {
            serving.revision != published.revision || serving.digest != published.digest
        });
        self.serving = Some(Arc::clone(published));
        self.head = self.head.max(published.revision);
        changed
    }

    /// The revisions to compose a file with, best first: the candidate, then the
    /// revision that the node serves.
    pub fn choices(&self) -> Vec<Arc<Published>> {
        let mut choices: Vec<Arc<Published>> = Vec::with_capacity(2);
        for choice in [&self.candidate, &self.serving].into_iter().flatten() {
            if !choices.iter().any(|known| known.revision == choice.revision) {
                choices.push(Arc::clone(choice));
            }
        }
        choices
    }

    /// The revision that the node serves.
    pub fn serving(&self) -> Option<&Arc<Published>> {
        self.serving.as_ref()
    }

    /// The newest head that the node saw.
    pub fn head(&self) -> u64 {
        self.head
    }

    /// The revision that the node refused, with the reason.
    pub fn refused(&self) -> Option<(u64, &str)> {
        self.refused.as_ref().map(|(revision, reason)| (*revision, reason.as_str()))
    }

    /// What the node tells the store about itself at the Unix second `now`.
    pub fn report(&self, now: u64) -> NodeReport {
        let (refused, detail) = self.refused().unwrap_or((0, ""));
        NodeReport {
            node: self.node.clone(),
            applied: self.serving.as_ref().map_or(0, |serving| serving.revision),
            digest: self.serving.as_ref().map_or(String::new(), |s| s.digest.clone()),
            refused,
            detail: detail.to_owned(),
            seen_at: now,
        }
    }

    /// The state in words: `current`, `behind`, `refused N: WHY` or `starting`, and
    /// after it `database unavailable for Ns: WHY` when the store does not answer.
    pub fn state(&self, now: u64) -> String {
        let applied = self.serving.as_ref().map_or(0, |serving| serving.revision);
        let mut state = match self.refused() {
            Some((revision, why)) if revision > applied => format!("refused {revision}: {why}"),
            _ if applied == 0 => "starting".to_owned(),
            _ if applied >= self.head => "current".to_owned(),
            _ => "behind".to_owned(),
        };
        if let Reach::Down { since, reason } = &self.reach {
            let seconds = now.saturating_sub(*since);
            state.push_str(&format!("; database unavailable for {seconds}s: {reason}"));
        }
        state
    }

    /// The lines of `show authority` after the store and the name: `applied`, `head`,
    /// `state` and `checked`, one `key: value` on each line.
    pub fn describe(&self, now: u64) -> String {
        let applied = match &self.serving {
            Some(serving) => format!("{} {}", serving.revision, short(&serving.digest)),
            None => "none".to_owned(),
        };
        let checked = match self.checked_at {
            0 => "never".to_owned(),
            at => format!("{}s ago", now.saturating_sub(at)),
        };
        format!(
            "applied: {applied}\nhead: {}\nstate: {}\nchecked: {checked}\n",
            self.head,
            self.state(now)
        )
    }
}

/// The first twelve digits of a digest, as the tables show it.
pub fn short(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published(revision: u64) -> Published {
        Published { revision, digest: format!("{revision:064}"), document: "{}".to_owned() }
    }

    fn head(revision: u64) -> Head {
        Head { revision, digest: format!("{revision:064}") }
    }

    #[test]
    fn a_replaced_document_under_a_known_number_is_read_again() {
        let mut node = Following::new("n");
        let head = |digest: &str| Head { revision: 2, digest: digest.to_owned() };
        assert_eq!(node.saw_head(&head("aa"), 1), Some(2));
        node.read(Published { revision: 2, digest: "aa".into(), document: "{}".into() });
        assert_eq!(node.saw_head(&head("aa"), 2), None);
        assert_eq!(node.saw_head(&head("bb"), 3), Some(2));
        assert_eq!(node.down_reason(), None);
    }

    #[test]
    fn a_new_head_is_read_once_and_served_after_the_worker_applied_it() {
        let mut node = Following::new("a");
        assert_eq!(node.saw_head(&head(0), 10), None, "nothing is published");
        assert_eq!(node.state(10), "starting");
        assert_eq!(node.saw_head(&head(1), 11), Some(1));
        let first = node.read(published(1));
        assert_eq!(node.saw_head(&head(1), 12), None, "the head is read once");
        assert_eq!(node.report(12).applied, 0, "read is not applied");
        assert!(node.applied(&first));
        assert!(!node.applied(&first), "the same revision again changes nothing");
        assert_eq!(node.state(12), "current");
        assert_eq!(
            node.report(13),
            NodeReport {
                node: "a".into(),
                applied: 1,
                digest: first.digest.clone(),
                refused: 0,
                detail: String::new(),
                seen_at: 13,
            }
        );
        assert_eq!(node.saw_head(&head(2), 14), Some(2));
        assert_eq!(node.state(14), "behind");
    }

    /// The lemmas `step_invalid` and `step_unavailable`: the snapshot stays.
    #[test]
    fn a_refusal_and_an_outage_keep_what_the_node_serves() {
        let mut node = Following::new("a");
        node.saw_head(&head(1), 1);
        let first = node.read(published(1));
        node.applied(&first);
        assert_eq!(node.saw_head(&head(2), 2), Some(2));
        node.read(published(2));
        node.refuse(2, "frontends.web: no\nbinds");
        assert_eq!(node.serving().unwrap().revision, 1);
        assert_eq!(node.state(3), "refused 2: frontends.web: no binds");
        assert_eq!(node.saw_head(&head(2), 3), None, "a refused head is not read at each poll");
        assert_eq!((node.report(3).applied, node.report(3).refused), (1, 2));
        // A reload composes the file with the candidate first, then with what is served.
        let choices: Vec<u64> = node.choices().iter().map(|choice| choice.revision).collect();
        assert_eq!(choices, [2, 1]);
        node.retry();
        assert_eq!(node.saw_head(&head(2), 4), Some(2), "a reload reads the head again");
        assert!(node.lost_database("connection refused", 5));
        assert!(!node.lost_database("connection refused", 9), "the outage is logged once");
        assert!(node.is_down());
        assert_eq!(node.serving().unwrap().revision, 1);
        assert!(node.state(9).ends_with("database unavailable for 4s: connection refused"));
        assert_eq!(node.saw_head(&head(3), 10), Some(3));
        assert!(!node.is_down());
        let third = node.read(published(3));
        assert!(node.applied(&third));
        assert_eq!(node.refused(), None, "a newer revision that applies clears the refusal");
        assert_eq!(node.state(10), "current");
    }

    #[test]
    fn the_description_has_one_key_on_each_line() {
        let mut node = Following::new("a");
        assert_eq!(node.describe(5), "applied: none\nhead: 0\nstate: starting\nchecked: never\n");
        node.saw_head(&head(1), 5);
        let first = node.read(published(1));
        node.applied(&first);
        let text = node.describe(8);
        assert!(text.starts_with("applied: 1 000000000000\nhead: 1\nstate: current\n"), "{text}");
        assert!(text.ends_with("checked: 3s ago\n"), "{text}");
    }
}
