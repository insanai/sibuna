//! Campaign assignment over an in-memory window of recent embeddings (SID 0011).
//!
//! The window keeps the most recent [`WINDOW`] embeddings of every node, normalised to unit
//! length so that cosine similarity is a dot product. An incident joins the campaign of its
//! nearest neighbour when the cosine distance is at most [`CAMPAIGN_DISTANCE`]; otherwise it
//! starts a campaign named by its own incident id. The search is a linear scan over
//! contiguous `[f32; 64]` rows, which the compiler vectorises.
//!
//! The window is refreshed incrementally from the durable receipts: every node's row of
//! `incident_receipts` advances in the same transaction as that node's incidents, so all of
//! a node's rows below its receipt are committed once the receipt is visible. The refresh
//! reads the receipts, and for each node that advanced fetches exactly the new id range.

use std::collections::HashMap;

use crate::database::{Columns, Database, Dialect, Param, Row, Sql};
use crate::error::StorageError;
use crate::incidents::IncidentReceipt;

/// The number of dimensions of an incident embedding (SID 0006).
pub const DIMENSIONS: usize = 64;
/// The number of recent embeddings the window keeps: 4 MiB of `f32`.
pub const WINDOW: usize = 16_384;
/// The largest cosine distance at which an incident joins its neighbour's campaign.
pub const CAMPAIGN_DISTANCE: f32 = 0.35;

/// One embedding, as the caller's embedding function returns it.
pub type Embedding = [f32; DIMENSIONS];

/// The bit position of the node id inside an incident id.
pub(crate) const NODE_SHIFT: u32 = 40;
/// One past the largest sequence number of a node.
pub(crate) const SEQUENCE_LIMIT: u64 = 1 << NODE_SHIFT;

/// Returns `embedding` scaled to unit length, or all zeros when it has no length or holds a
/// value that is not finite (such a vector is never anyone's neighbour).
pub fn normalize(embedding: &Embedding) -> Embedding {
    let norm = dot(embedding, embedding).sqrt();
    if !norm.is_finite() || norm == 0.0 {
        return [0.0; DIMENSIONS];
    }
    embedding.map(|value| value / norm)
}

/// Returns the dot product of two embeddings. Eight independent partial sums let the
/// compiler use vector registers; a single running sum would serialise every addition.
#[inline]
pub fn dot(a: &Embedding, b: &Embedding) -> f32 {
    let mut lanes = [0.0f32; 8];
    // 64 is a multiple of 8, so the remainders of `as_chunks` are empty.
    for (left, right) in a.as_chunks::<8>().0.iter().zip(b.as_chunks::<8>().0) {
        for ((lane, x), y) in lanes.iter_mut().zip(left).zip(right) {
            *lane += x * y;
        }
    }
    lanes.iter().sum()
}

/// Returns the 256 little-endian bytes stored in `security_incidents.embedding`.
pub fn embedding_bytes(embedding: &Embedding) -> [u8; DIMENSIONS * 4] {
    let mut bytes = [0u8; DIMENSIONS * 4];
    for (chunk, value) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(embedding) {
        *chunk = value.to_le_bytes();
    }
    bytes
}

/// Returns the embedding stored as `bytes`, or `None` when it is not 256 bytes long.
pub fn embedding_from_bytes(bytes: &[u8]) -> Option<Embedding> {
    if bytes.len() != DIMENSIONS * 4 {
        return None;
    }
    let mut embedding = [0.0f32; DIMENSIONS];
    for (value, chunk) in embedding.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *value = f32::from_le_bytes(*chunk);
    }
    Some(embedding)
}

/// The nearest neighbour of a query: its campaign and its cosine similarity.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Neighbour {
    /// The neighbour's campaign.
    pub campaign: i64,
    /// The cosine similarity, 1 for identical directions.
    pub similarity: f32,
}

impl Neighbour {
    /// Returns true when the neighbour is close enough to share its campaign.
    pub fn is_close(&self) -> bool {
        1.0 - self.similarity <= CAMPAIGN_DISTANCE
    }
}

/// A ring of the most recent normalised embeddings and their campaigns.
#[derive(Debug)]
pub struct CampaignWindow {
    vectors: Vec<Embedding>,
    campaigns: Vec<i64>,
    /// The ring position the next push overwrites once the window is full.
    next: usize,
    /// For each node, the sequence number below which its rows are in the window or were
    /// skipped as older than the window.
    cursors: HashMap<u32, u64>,
}

impl Default for CampaignWindow {
    fn default() -> Self {
        CampaignWindow::new()
    }
}

impl CampaignWindow {
    /// Returns an empty window; its storage grows to [`WINDOW`] rows as it fills.
    pub fn new() -> CampaignWindow {
        CampaignWindow {
            vectors: Vec::new(),
            campaigns: Vec::new(),
            next: 0,
            cursors: HashMap::new(),
        }
    }

    /// Returns the number of embeddings held.
    pub fn len(&self) -> usize {
        self.vectors.len()
    }

    /// Returns true when the window holds nothing.
    pub fn is_empty(&self) -> bool {
        self.vectors.is_empty()
    }

    /// Adds a normalised embedding with its campaign, replacing the oldest when full.
    pub fn push(&mut self, unit: Embedding, campaign: i64) {
        if self.vectors.len() < WINDOW {
            self.vectors.push(unit);
            self.campaigns.push(campaign);
            return;
        }
        // `next` stays below WINDOW, which equals both lengths once the window is full.
        if let (Some(vector), Some(slot)) =
            (self.vectors.get_mut(self.next), self.campaigns.get_mut(self.next))
        {
            *vector = unit;
            *slot = campaign;
        }
        self.next = (self.next + 1) % WINDOW;
    }

    /// Returns the most similar embedding to the normalised `unit`, or `None` when the
    /// window is empty.
    pub fn nearest(&self, unit: &Embedding) -> Option<Neighbour> {
        let mut best: Option<(usize, f32)> = None;
        for (index, vector) in self.vectors.iter().enumerate() {
            let similarity = dot(unit, vector);
            if best.is_none_or(|(_, top)| similarity > top) {
                best = Some((index, similarity));
            }
        }
        let (index, similarity) = best?;
        let campaign = *self.campaigns.get(index)?;
        Some(Neighbour { campaign, similarity })
    }

    /// Returns the sequence number below which `node`'s rows are known.
    pub(crate) fn cursor(&self, node: u32) -> u64 {
        self.cursors.get(&node).copied().unwrap_or(0)
    }

    /// Records that `node`'s rows below `sequence` are known.
    pub(crate) fn advance(&mut self, node: u32, sequence: u64) {
        let cursor = self.cursors.entry(node).or_insert(0);
        *cursor = (*cursor).max(sequence);
    }

    /// Fills an empty window with the most recent rows of every node, read in one snapshot
    /// together with the receipts, so the later incremental refresh neither misses nor
    /// repeats a row.
    pub(crate) async fn load(&mut self, db: &Database) -> Result<(), StorageError> {
        let mut tx = db.begin().await?;
        if tx.dialect() == Dialect::Postgres {
            tx.execute(REPEATABLE_READ, &[]).await?;
        }
        let receipts = tx.fetch_all(RECEIPTS, &[]).await?;
        let limit = i64::try_from(WINDOW).unwrap_or(i64::MAX);
        let rows = tx.fetch_all(RECENT, &[limit.into()]).await?;
        tx.commit().await?;
        let receipts = decode_receipts(receipts)?;
        let mut recent =
            rows.into_iter().map(StoredEmbedding::decode).collect::<Result<Vec<_>, _>>()?;
        recent.reverse();
        for stored in recent {
            self.push(normalize(&stored.embedding), stored.campaign_id);
        }
        for receipt in receipts {
            self.advance(receipt.node_id, receipt.next_sequence);
        }
        Ok(())
    }

    /// Fetches the rows every node committed since the last refresh, at most [`WINDOW`]
    /// per node.
    pub(crate) async fn refresh(&mut self, db: &Database) -> Result<(), StorageError> {
        let receipts = decode_receipts(db.fetch_all(RECEIPTS, &[]).await?)?;
        for IncidentReceipt { node_id: node, next_sequence: cursor } in receipts {
            let known = self.cursor(node);
            if cursor <= known {
                continue;
            }
            let window = u64::try_from(WINDOW).unwrap_or(u64::MAX);
            let first = known.max(cursor.saturating_sub(window));
            let base = u64::from(node) << NODE_SHIFT;
            // Both cursors are at most 2^40, so the bounds stay inside this node's range,
            // the exclusive upper bound reaching at most the next node's first id.
            let low = i64::try_from(base + first).unwrap_or(i64::MAX);
            let high = i64::try_from(base + cursor).unwrap_or(i64::MAX);
            let range: [Param<'_>; 2] = [low.into(), high.into()];
            for row in db.fetch_all(RANGE, &range).await? {
                let stored = StoredEmbedding::decode(row)?;
                self.push(normalize(&stored.embedding), stored.campaign_id);
            }
            self.advance(node, cursor);
        }
        Ok(())
    }
}

/// The `(campaign_id, embedding)` columns of one `security_incidents` row.
struct StoredEmbedding {
    campaign_id: i64,
    embedding: Embedding,
}

impl StoredEmbedding {
    /// Decodes one row of [`RECENT`] or [`RANGE`]. Fails with [`StorageError::InvalidRow`]
    /// when the embedding is not 256 bytes, which the schema's `CHECK` already refuses.
    fn decode(row: Row) -> Result<StoredEmbedding, StorageError> {
        let mut columns = Columns::new(row, "security_incidents");
        let campaign_id = columns.integer("campaign_id")?;
        let bytes = columns.bytes("embedding")?;
        let embedding =
            embedding_from_bytes(&bytes).ok_or_else(|| columns.invalid("embedding"))?;
        Ok(StoredEmbedding { campaign_id, embedding })
    }
}

/// Decodes the rows of [`RECEIPTS`], clamping each receipt to 2^40 (the schema's bound).
fn decode_receipts(rows: Vec<Row>) -> Result<Vec<IncidentReceipt>, StorageError> {
    rows.into_iter()
        .map(|row| {
            let receipt = IncidentReceipt::decode(row)?;
            Ok(IncidentReceipt {
                next_sequence: receipt.next_sequence.min(SEQUENCE_LIMIT),
                ..receipt
            })
        })
        .collect()
}

const REPEATABLE_READ: Sql = Sql::both("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");

const RECEIPTS: Sql = Sql::both("SELECT node_id, next_sequence FROM incident_receipts");

pub(crate) const RECENT: Sql = Sql::both(
    "SELECT campaign_id, embedding FROM security_incidents \
     ORDER BY recorded_at DESC, id DESC LIMIT $1",
);

pub(crate) const RANGE: Sql = Sql::both(
    "SELECT campaign_id, embedding FROM security_incidents WHERE id >= $1 AND id < $2 \
     ORDER BY id",
);

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(index: usize) -> Embedding {
        let mut vector = [0.0; DIMENSIONS];
        vector[index % DIMENSIONS] = 1.0;
        vector
    }

    #[test]
    fn nearest_finds_the_most_similar_embedding_and_applies_the_threshold() {
        let mut window = CampaignWindow::new();
        assert!(window.nearest(&unit(0)).is_none());
        window.push(unit(1), 10);
        window.push(unit(2), 20);
        let found = window.nearest(&unit(2)).unwrap();
        assert_eq!(found.campaign, 20);
        assert!(found.is_close());
        let mut between = [0.0; DIMENSIONS];
        between[1] = 0.6;
        between[3] = 0.8;
        let found = window.nearest(&normalize(&between)).unwrap();
        assert_eq!(found.campaign, 10);
        // Distance 0.4 is beyond the 0.35 threshold.
        assert!(!found.is_close());
    }

    #[test]
    fn the_window_keeps_only_the_most_recent_embeddings() {
        let mut window = CampaignWindow::new();
        for index in 0..WINDOW + 5 {
            window.push(unit(index), i64::try_from(index).unwrap());
        }
        assert_eq!(window.len(), WINDOW);
        // The first five pushes were replaced by the last five.
        let campaigns: Vec<i64> = window.campaigns.iter().take(5).copied().collect();
        let expected: Vec<i64> = (0..5).map(|i| i64::try_from(WINDOW + i).unwrap()).collect();
        assert_eq!(campaigns, expected);
    }

    #[test]
    fn zero_and_non_finite_embeddings_are_never_close() {
        assert_eq!(normalize(&[0.0; DIMENSIONS]), [0.0; DIMENSIONS]);
        let mut broken = unit(3);
        broken[5] = f32::NAN;
        assert_eq!(normalize(&broken), [0.0; DIMENSIONS]);
        let mut window = CampaignWindow::new();
        window.push(normalize(&[0.0; DIMENSIONS]), 1);
        assert!(!window.nearest(&normalize(&[0.0; DIMENSIONS])).unwrap().is_close());
    }

    #[test]
    fn embeddings_round_trip_through_their_stored_bytes() {
        let mut vector = [0.0f32; DIMENSIONS];
        for (index, value) in vector.iter_mut().enumerate() {
            *value = index as f32 * -0.25;
        }
        let bytes = embedding_bytes(&vector);
        assert_eq!(bytes.len(), 256);
        assert_eq!(&bytes[4..8], &(-0.25f32).to_le_bytes());
        assert_eq!(embedding_from_bytes(&bytes), Some(vector));
        assert_eq!(embedding_from_bytes(&bytes[1..]), None);
    }

    #[test]
    fn dot_agrees_with_a_naive_sum() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 40) as f32 / (1u64 << 24) as f32 - 0.5
        };
        for _ in 0..1000 {
            let a: Embedding = std::array::from_fn(|_| next());
            let b: Embedding = std::array::from_fn(|_| next());
            let naive: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
            assert!((dot(&a, &b) - naive).abs() < 1e-4);
        }
    }

    /// Times the campaign search over a full window. Run with
    /// `cargo test --release -p sibuna-storage -- --ignored --nocapture campaign_search`.
    #[test]
    #[ignore]
    fn campaign_search_cost_over_a_full_window() {
        let mut window = CampaignWindow::new();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 40) as f32 / (1u64 << 24) as f32 - 0.5
        };
        for index in 0..WINDOW {
            let vector: Embedding = std::array::from_fn(|_| next());
            window.push(normalize(&vector), i64::try_from(index).unwrap());
        }
        let queries: Vec<Embedding> =
            (0..64).map(|_| normalize(&std::array::from_fn(|_| next()))).collect();
        let rounds = 400;
        let start = std::time::Instant::now();
        let mut checksum = 0i64;
        for round in 0..rounds {
            let found = window.nearest(&queries[round % queries.len()]).unwrap();
            checksum = checksum.wrapping_add(found.campaign);
        }
        let per_search = start.elapsed() / u32::try_from(rounds).unwrap();
        println!("campaign search over {WINDOW} embeddings: {per_search:?} (checksum {checksum})");
    }
}
