//! Policy workflows: rule ordering, replay of retained events, reputation prefixes,
//! country blocks and atomic set import. Every mutation names an expected revision.

use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::Text;
use crate::users;

/// The longest address prefix.
pub const MAX_PREFIX: usize = 48;
/// The longest reputation note.
pub const MAX_NOTE: usize = 128;
/// The longest reputation source.
pub const MAX_SOURCE: usize = 32;
/// Reputation rows per page.
pub const PAGE_ROWS: usize = 8;
/// Prefixes per country chunk.
pub const CHUNK_PREFIXES: u8 = 32;
/// The most prefixes a country replacement holds.
pub const MAX_COUNTRY_PREFIXES: u16 = 1024;
/// Rows a replay summary shows.
pub const REPLAY_ROWS: usize = 8;
/// Retained events one replay scan reads.
pub const REPLAY_SCAN: usize = 64;
/// The longest replay window, in hours.
pub const MAX_REPLAY_HOURS: u16 = 24 * 7;
/// How long a staged workflow lives, in seconds.
pub const STAGE_SECONDS: u64 = 600;
/// The most chunks an import holds.
pub const MAX_IMPORT_CHUNKS: u16 = 128;

/// A move in the rule order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Earlier.
    #[default]
    Up,
    /// Later.
    Down,
}

/// Moves one rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Order {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The revision the operator saw.
    pub expected_revision: u64,
    /// The rule id.
    pub id: Text<128>,
    /// Where it moves.
    pub direction: Direction,
}

/// Replays retained events against the committed policy or a draft.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replay {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The committed revision the draft replaces; present exactly with `draft`.
    pub committed: Option<u64>,
    /// A draft document.
    pub draft: Option<Text<4096>>,
    /// The rule name to look for; empty means any non-allow decision.
    pub rule: Text<128>,
    /// Hours of events, 1 to [`MAX_REPLAY_HOURS`].
    pub hours: u16,
}

impl Default for Replay {
    fn default() -> Replay {
        Replay {
            auth: users::Auth::default(),
            committed: None,
            draft: None,
            rule: Text::default(),
            hours: 24,
        }
    }
}

/// One replayed event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayRow {
    /// The incident id.
    pub id: u64,
    /// The client address.
    pub ip: Text<MAX_PREFIX>,
    /// The request path.
    pub path: Text<128>,
    /// The replayed action.
    pub action: Text<16>,
    /// The matching rule.
    pub rule: Text<64>,
    /// The retained evidence sufficed to decide.
    pub conclusive: bool,
    /// The rule matched.
    pub matched: bool,
}

/// A replay's result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplaySummary {
    /// Events replayed.
    pub total: u32,
    /// Events the rule matched.
    pub matched: u32,
    /// Events without enough evidence.
    pub inconclusive: u32,
    /// The applied revision.
    pub applied: u64,
    /// The committed revision.
    pub committed: u64,
    /// A draft was replayed.
    pub preview: bool,
    /// At most [`REPLAY_ROWS`] rows.
    pub rows: Vec<ReplayRow>,
}

/// What a reputation entry does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ReputationAction {
    /// Deny the prefix.
    #[default]
    Deny,
    /// Allow the prefix.
    Allow,
}

/// A page of reputation entries after a prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReputationQuery {
    /// The reader's credential.
    pub auth: users::Auth,
    /// The last prefix of the previous page.
    pub after: Text<MAX_PREFIX>,
}

/// One reputation entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReputationRow {
    /// The address prefix.
    pub prefix: Text<MAX_PREFIX>,
    /// The score.
    pub score: i32,
    /// The ban's end, in Unix seconds.
    pub banned_until: Option<u64>,
    /// What raised the entry.
    pub trigger: Text<64>,
    /// Where it came from.
    pub source: Text<MAX_SOURCE>,
    /// The operator's note.
    pub note: Text<MAX_NOTE>,
    /// Requests that matched it.
    pub hits: u64,
    /// The last match, in Unix seconds.
    pub last_seen: u64,
}

/// A page of reputation entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReputationPage {
    /// At most [`PAGE_ROWS`] rows.
    pub rows: Vec<ReputationRow>,
    /// The prefix to continue after.
    pub next: Option<Text<MAX_PREFIX>>,
    /// The committed revision.
    pub committed: u64,
    /// Nodes that applied it.
    pub nodes: u16,
}

/// Adds or changes a reputation entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReputationEdit {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The revision the operator saw.
    pub expected_revision: u64,
    /// The address prefix.
    pub prefix: Text<MAX_PREFIX>,
    /// What it does.
    pub action: ReputationAction,
    /// When it ends, in Unix seconds.
    pub until: Option<u64>,
    /// The operator's note.
    pub note: Text<MAX_NOTE>,
}

/// Removes a reputation entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReputationRemove {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The revision the operator saw.
    pub expected_revision: u64,
    /// The address prefix.
    pub prefix: Text<MAX_PREFIX>,
}

/// One chunk of a staged country prefix set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CountryChunk {
    /// SHA-256 of the whole set.
    pub digest: [u8; 32],
    /// The chunk number.
    pub ordinal: u16,
    /// 1 to [`CHUNK_PREFIXES`] prefixes.
    pub prefixes: Vec<Text<MAX_PREFIX>>,
}

/// Previews a country replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountryPreflight {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The revision the operator saw.
    pub expected_revision: u64,
    /// SHA-256 of the staged set.
    pub digest: [u8; 32],
    /// Prefixes in the set.
    pub count: u16,
    /// The country code.
    pub country: [u8; 2],
    /// What the entries do.
    pub action: ReputationAction,
    /// The first change to list.
    pub diff_offset: u16,
}

/// Applies a country replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountryApply {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The revision the operator saw.
    pub expected_revision: u64,
    /// SHA-256 of the staged set.
    pub digest: [u8; 32],
    /// Prefixes in the set.
    pub count: u16,
    /// The country code.
    pub country: [u8; 2],
    /// What the entries do.
    pub action: ReputationAction,
    /// When the entries end, in Unix seconds.
    pub until: Option<u64>,
    /// The GeoIP generation the operator reviewed.
    pub geo_generation: Text<64>,
}

/// How a prefix changes in a country replacement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ChangeKind {
    /// New.
    #[default]
    Added,
    /// Kept.
    Retained,
    /// Dropped.
    Removed,
}

/// One listed change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Change {
    /// The prefix.
    pub prefix: Text<MAX_PREFIX>,
    /// How it changes.
    pub kind: ChangeKind,
}

/// A country replacement's preview or result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CountrySummary {
    /// Prefixes in the new set.
    pub prefixes: u16,
    /// Trie nodes before.
    pub nodes_before: u16,
    /// Trie nodes after.
    pub nodes_after: u16,
    /// Prefixes another owner already holds.
    pub overlaps: u16,
    /// Prefixes in the previous set.
    pub previous: u16,
    /// Prefixes added.
    pub added: u16,
    /// Prefixes removed.
    pub removed: u16,
    /// Prefixes kept.
    pub retained: u16,
    /// The previous set's GeoIP generation.
    pub previous_generation: Text<64>,
    /// At most eight removed prefixes.
    pub removed_sample: Vec<Text<MAX_PREFIX>>,
    /// At most eight listed changes.
    pub changes: Vec<Change>,
    /// The offset of the next changes, if more exist.
    pub next_offset: Option<u16>,
    /// At most eight prefixes of the new set.
    pub sample: Vec<Text<MAX_PREFIX>>,
}

/// One chunk of a staged policy import.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportChunk {
    /// SHA-256 of the whole import.
    pub digest: [u8; 32],
    /// The chunk number, below [`MAX_IMPORT_CHUNKS`].
    pub ordinal: u16,
    /// A non-empty document part.
    pub document: Text<4096>,
}

/// Commits a staged import atomically.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportCommit {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The revision the operator saw.
    pub expected_revision: u64,
    /// SHA-256 of the whole import.
    pub digest: [u8; 32],
    /// Chunks, 1 to [`MAX_IMPORT_CHUNKS`].
    pub count: u16,
}

/// Checks a rule move.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an oversized revision or an empty id.
pub fn validate_order(input: &Order) -> Result<(), ValidationError> {
    limit(input.expected_revision >= MAX_I64 || input.id.is_empty())
}

/// Checks a replay.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a draft without a committed revision (or the
/// reverse), an oversized revision, a window outside 1 to [`MAX_REPLAY_HOURS`] hours, or
/// an empty draft.
pub fn validate_replay(input: &Replay) -> Result<(), ValidationError> {
    limit(input.draft.is_some() != input.committed.is_some())?;
    limit(input.committed.unwrap_or(0) > MAX_I64)?;
    limit(input.hours == 0 || input.hours > MAX_REPLAY_HOURS)?;
    limit(input.draft.as_ref().is_some_and(Text::is_empty))
}

/// Checks a reputation edit.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an oversized revision or end, or an empty prefix.
pub fn validate_reputation_edit(input: &ReputationEdit) -> Result<(), ValidationError> {
    limit(input.expected_revision >= MAX_I64 || input.prefix.is_empty())?;
    limit(input.until.unwrap_or(0) > MAX_I64)
}

/// Checks a reputation removal.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an empty prefix or an oversized revision.
pub fn validate_reputation_remove(input: &ReputationRemove) -> Result<(), ValidationError> {
    limit(input.prefix.is_empty() || input.expected_revision >= MAX_I64)
}

/// Checks a country chunk.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for no prefixes or more than [`CHUNK_PREFIXES`].
pub fn validate_country_chunk(input: &CountryChunk) -> Result<(), ValidationError> {
    limit(input.prefixes.is_empty() || input.prefixes.len() > usize::from(CHUNK_PREFIXES))
}

/// Checks a country set's size and the expected revision.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for more than [`MAX_COUNTRY_PREFIXES`] prefixes or an
/// oversized revision.
pub fn validate_country(count: u16, revision: u64) -> Result<(), ValidationError> {
    limit(count > MAX_COUNTRY_PREFIXES || revision >= MAX_I64)
}

/// Checks an import chunk.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an empty document or an ordinal of
/// [`MAX_IMPORT_CHUNKS`] or more.
pub fn validate_import_chunk(input: &ImportChunk) -> Result<(), ValidationError> {
    limit(input.document.is_empty() || input.ordinal >= MAX_IMPORT_CHUNKS)
}

/// Checks an import commit.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for no chunks or more than [`MAX_IMPORT_CHUNKS`], or
/// an oversized revision.
pub fn validate_import_commit(input: &ImportCommit) -> Result<(), ValidationError> {
    limit(
        input.count == 0 || input.count > MAX_IMPORT_CHUNKS || input.expected_revision >= MAX_I64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflows_are_fenced_and_bounded() {
        assert!(validate_order(&Order::default()).is_err());
        assert_eq!(validate_replay(&Replay::default()), Ok(()));
        assert!(validate_replay(&Replay { hours: 169, ..Replay::default() }).is_err());
        assert!(validate_replay(&Replay { committed: Some(1), ..Replay::default() }).is_err());
        assert_eq!(validate_country(1024, 0), Ok(()));
        assert!(validate_country(1025, 0).is_err());
        assert!(
            validate_import_commit(&ImportCommit { count: 129, ..ImportCommit::default() })
                .is_err()
        );
        assert!(
            validate_import_chunk(&ImportChunk { ordinal: 1, ..ImportChunk::default() }).is_err()
        );
        let chunk =
            CountryChunk { prefixes: vec![Text::default(); 33], ..CountryChunk::default() };
        assert!(validate_country_chunk(&chunk).is_err());
        let edit = ReputationEdit {
            prefix: Text::new("10.0.0.0/8").unwrap(),
            until: Some(u64::MAX),
            ..ReputationEdit::default()
        };
        assert!(validate_reputation_edit(&edit).is_err());
    }
}
