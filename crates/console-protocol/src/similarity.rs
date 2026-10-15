//! Incremental cosine search. Cursors bound one scan to 64 historical rows; each part's
//! best ten suffice to merge the global best ten without retaining all inputs.

use crate::error::{MAX_I64, ValidationError, limit};
use crate::events;

/// How many matches a search keeps.
pub const BEST_ROWS: usize = 10;

/// A similarity search for one source incident.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The source incident id.
    pub source: u64,
    /// The earliest time, in Unix seconds.
    pub from: u64,
    /// The latest time, in Unix seconds.
    pub until: u64,
    /// Continue before this position.
    pub before: Option<events::Cursor>,
}

/// One candidate and its cosine distance (0 is identical, 2 is opposite).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Match {
    /// The incident id.
    pub id: u64,
    /// The recording node.
    pub node: u32,
    /// The incident time, in Unix seconds.
    pub time: u64,
    /// The cosine distance, 0 to 2.
    pub distance: f64,
}

/// The ten nearest matches, nearest first, ties broken by the smaller id.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Best {
    rows: Vec<Match>,
}

impl Best {
    /// Returns the matches, nearest first.
    pub fn rows(&self) -> &[Match] {
        &self.rows
    }

    /// Offers a candidate. A repeated id, a candidate behind ten nearer ones, and a distance
    /// that is not a finite number from 0 to 2 are ignored.
    pub fn add(&mut self, candidate: Match) {
        if !(0.0..=2.0).contains(&candidate.distance)
            || self.rows.iter().any(|row| row.id == candidate.id)
        {
            return;
        }
        let position = self
            .rows
            .iter()
            .position(|row| {
                candidate.distance < row.distance
                    || (candidate.distance == row.distance && candidate.id < row.id)
            })
            .unwrap_or(self.rows.len());
        if position == BEST_ROWS {
            return;
        }
        self.rows.truncate(BEST_ROWS - 1);
        self.rows.insert(position, candidate);
    }
}

/// One bounded scan's result.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Part {
    /// The source incident has an embedding.
    pub source_available: bool,
    /// Rows scanned.
    pub scanned: u16,
    /// Rows without a usable embedding.
    pub invalid: u16,
    /// Where the next scan continues, if the window is not exhausted.
    pub next: Option<events::Cursor>,
    /// The best matches of this scan.
    pub best: Best,
}

/// Checks a similarity query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a zero or oversized source, an inverted or
/// oversized range, or a cursor outside it.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    limit(query.source == 0 || query.source > MAX_I64 || query.from > query.until)?;
    limit(query.until > MAX_I64)?;
    limit(query.before.is_some_and(|cursor| cursor.time > query.until || cursor.id > MAX_I64))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of similarity.zig "merging partition top tens matches whole-scan ordering with
    // deterministic ties".
    #[test]
    fn merging_partition_top_tens_matches_whole_scan_ordering_with_deterministic_ties() {
        let mut all = Best::default();
        let mut merged = Best::default();
        for part in 0..8u64 {
            let mut subset = Best::default();
            for index in 0..64u64 {
                let id = part * 64 + index + 1;
                let candidate =
                    Match { id, distance: (id % 23) as f64 / 23.0, ..Match::default() };
                all.add(candidate);
                subset.add(candidate);
            }
            for row in subset.rows() {
                merged.add(*row);
            }
        }
        assert_eq!(all, merged);
        let previous = merged.clone();
        merged.add(merged.rows()[0]);
        assert_eq!(previous, merged);
        assert_eq!(merged.rows().len(), BEST_ROWS);
        merged.add(Match { id: 9999, distance: f64::NAN, ..Match::default() });
        assert_eq!(previous, merged);
    }

    #[test]
    fn queries_are_bounded() {
        let query = Query { source: 1, until: 10, ..Default::default() };
        assert_eq!(validate(&query), Ok(()));
        let before = Some(events::Cursor { time: 11, id: 1 });
        assert!(validate(&Query { before, ..query.clone() }).is_err());
        assert!(validate(&Query { source: 0, ..query }).is_err());
    }
}
