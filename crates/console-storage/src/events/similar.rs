//! The bounded similarity scan of the Events page (`events/similar`): one call compares the
//! source incident's embedding with at most [`SCAN_ROWS`] incidents of the window, newest
//! first, and returns the best matches with a cursor to continue. The console merges the
//! parts; no call scans without a bound.
//!
//! Embeddings are the 256-byte little-endian `security_incidents.embedding` column (Zig
//! kept them in sqlite-vec's `incidents_vec`). A stored vector that is not finite or has no
//! length is counted as invalid and skipped.

use sibuna_console_protocol::events::Cursor;
use sibuna_console_protocol::similarity::{self, Match, Part, Query};
use sibuna_storage::{Param, Sql, Transaction};

use super::EVENTS_NEED;
use crate::access::{self, Credential};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// The most incidents one call compares.
pub const SCAN_ROWS: usize = 64;
/// The dimensions of an embedding (SID 0006).
const DIMENSIONS: usize = 64;

const SOURCE: Sql = Sql::both("SELECT embedding FROM security_incidents WHERE id = $1");

const SCAN: Sql = Sql::both(
    "SELECT id, recorded_at, node_id, embedding FROM security_incidents \
     WHERE recorded_at BETWEEN $1 AND $2 \
     AND (recorded_at < $3 OR (recorded_at = $3 AND id < $4)) \
     ORDER BY recorded_at DESC, id DESC LIMIT 64",
);

/// Returns the unit vector stored as `bytes`, or `None` when it is not 64 finite floats
/// with a positive length. The length is computed in `f64`, as Zig computed it.
fn decode(bytes: &[u8]) -> Option<[f32; DIMENSIONS]> {
    let (chunks, rest) = bytes.as_chunks::<4>();
    if chunks.len() != DIMENSIONS || !rest.is_empty() {
        return None;
    }
    let mut vector = [0.0f32; DIMENSIONS];
    let mut norm = 0.0f64;
    for (value, chunk) in vector.iter_mut().zip(chunks) {
        *value = f32::from_le_bytes(*chunk);
        if !value.is_finite() {
            return None;
        }
        norm += f64::from(*value) * f64::from(*value);
    }
    if !norm.is_finite() || norm <= 0.0 {
        return None;
    }
    let scale = 1.0 / norm.sqrt();
    // The scaled values are finite and at most 1 in magnitude, so they fit in `f32`.
    vector.iter_mut().for_each(|value| *value = (f64::from(*value) * scale) as f32);
    Some(vector)
}

/// The cosine of two unit vectors, summed in order in `f32` as Zig's `embedding.cosine`.
fn cosine(a: &[f32; DIMENSIONS], b: &[f32; DIMENSIONS]) -> f32 {
    a.iter().zip(b).fold(0.0, |sum, (x, y)| sum + x * y)
}

/// Compares the embedding of incident `input.source` with the next [`SCAN_ROWS`] incidents
/// of the window `input.from` to `input.until`, before `input.before`, and returns the ten
/// best matches by cosine distance. `next` is the position to continue before, or `None`
/// when the window is exhausted; `source_available` is false when the source has no stored
/// embedding. The credential is `credential`; `input.session_digest` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] with [`EVENTS_NEED`], and with the driver's error.
pub async fn similar(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Query,
    now: u64,
) -> Result<Part, ConsoleStorageError> {
    similarity::validate(input).map_err(|_| ConsoleStorageError::InvalidInput("similarity"))?;
    access::authorize_in(tx, credential, EVENTS_NEED, now).await?;
    let mut part = Part::default();
    let source = row::first(tx.fetch_all(SOURCE, &[row::int(input.source)?.into()]).await?);
    let Some(source) = source else { return Ok(part) };
    let bytes = Fields::new(source, "security_incidents").bytes("embedding")?;
    let Some(vector) = decode(&bytes) else { return Ok(part) };
    part.source_available = true;
    let before = input.before.unwrap_or(Cursor { time: input.until, id: row::MAX_INTEGER });
    let params: [Param<'_>; 4] = [
        row::int(input.from)?.into(),
        row::int(input.until)?.into(),
        row::int(before.time)?.into(),
        row::int(before.id)?.into(),
    ];
    let rows = tx.fetch_all(SCAN, &params).await?;
    let full = rows.len() >= SCAN_ROWS;
    for cells in rows {
        let mut fields = Fields::new(cells, "security_incidents");
        let id: u64 = fields.integer("id")?;
        let time: u64 = fields.integer("recorded_at")?;
        let node: u32 = fields.integer("node_id")?;
        let embedding = fields.bytes("embedding")?;
        part.scanned = part.scanned.saturating_add(1);
        part.next = Some(Cursor { time, id });
        if id == input.source {
            continue;
        }
        let Some(candidate) = decode(&embedding) else {
            part.invalid = part.invalid.saturating_add(1);
            continue;
        };
        let distance = (1.0 - cosine(&vector, &candidate)).clamp(0.0, 2.0);
        part.best.add(Match { id, node, time, distance: f64::from(distance) });
    }
    if !full {
        part.next = None;
    }
    Ok(part)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(values: &[f32]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_le_bytes()).collect()
    }

    // Port of console_similarity.zig "stored vectors reject empty, zero and non-finite
    // evidence".
    #[test]
    fn stored_vectors_reject_empty_zero_and_non_finite_evidence() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[0; 256]).is_none());
        let mut values = [0.5f32; DIMENSIONS];
        assert!(decode(&bytes(&values)).is_some());
        values[3] = f32::NAN;
        assert!(decode(&bytes(&values)).is_none());
        let unit = decode(&bytes(&[3.0; DIMENSIONS])).expect("a vector");
        assert!((cosine(&unit, &unit) - 1.0).abs() < 1e-4);
        assert!(decode(&bytes(&[1.0; DIMENSIONS - 1])).is_none());
    }
}
