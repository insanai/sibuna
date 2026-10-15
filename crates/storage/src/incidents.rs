//! Incident records: the fixed-size copy a request thread queues, the prepared batch the
//! storage thread writes, the durable receipt, retention's deletion, and forensic search.
//!
//! The user agent, path and payload are stored as the raw bytes the request carried, because
//! an investigator needs an attack's exact bytes (SID 0011). Full-text search indexes the
//! canonical tokens of the path and the payload ([`crate::search::tokens`], SID 0013): as
//! text in `incidents_fts` on SQLite, and as the `tsvector` column `search` on PostgreSQL.
//!
//! An incident id is `(node << 40) | sequence`. Each node keeps its receipt, a row of
//! `incident_receipts`: the sequence after its last committed batch.
//! The receipt advances in the same transaction as the batch, and every insert of the batch
//! is guarded by "the receipt is still below this batch's end". Replaying a batch whose
//! commit was not acknowledged therefore writes nothing twice, exactly as in the Zig daemon.
//! The console's sidecars (evidence, heads, country) are written by the incident hook in the
//! same transaction ([`crate::Hooks::on_incidents`]).

use sibuna_core::incident_heads::{REQUEST_BYTES, RESPONSE_BYTES, ResponseState};
use sibuna_core::{Evidence, Incident};

use crate::campaigns::{
    CampaignWindow, Embedding, NODE_SHIFT, SEQUENCE_LIMIT, dot, embedding_bytes, normalize,
};
use crate::database::{Columns, Database, Dialect, Param, Row, Sql, Transaction};
use crate::error::StorageError;
use crate::policy::sql_time;
use crate::search::{self, Query};
use crate::storage::IncidentHook;

/// The most incidents one transaction writes.
pub const INCIDENT_BATCH: usize = 32;
/// The number of slots of the incident ring.
pub const INCIDENT_QUEUE: usize = 512;
/// The longest search query accepted, in bytes (the search language's bound).
pub const MAX_SEARCH_QUERY: usize = search::MAX_QUERY_BYTES;
/// The most rows one search returns.
pub const MAX_SEARCH_RESULTS: u32 = 1000;

/// A fixed-capacity byte field of an [`IncidentRecord`]; longer input is cut.
#[derive(Clone, Copy)]
struct Field<const N: usize> {
    bytes: [u8; N],
    len: u16,
}

impl<const N: usize> Field<N> {
    fn copy_from(source: &[u8]) -> Self {
        let mut bytes = [0u8; N];
        let len = source.len().min(N);
        // `len` is at most both lengths, so both ranges are in bounds.
        bytes[..len].copy_from_slice(&source[..len]);
        // N is at most 512 for every field, so the length fits.
        Field { bytes, len: u16::try_from(len).unwrap_or(0) }
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }
}

/// The copy of an [`Incident`] that crosses the ring: fixed size, owning its bytes, so a
/// request thread hands it over without allocating. The capacities are the Zig record's,
/// including the console's evidence and redacted heads.
#[derive(Clone, Copy)]
pub(crate) struct IncidentRecord {
    client_ip: Field<48>,
    user_agent: Field<200>,
    method: Field<8>,
    path: Field<512>,
    category: Field<32>,
    payload: Field<512>,
    now: u64,
    evidence: Evidence,
    request_head: Field<REQUEST_BYTES>,
    response_head: Field<RESPONSE_BYTES>,
    request_truncated: bool,
    response_truncated: bool,
    response_state: ResponseState,
}

impl IncidentRecord {
    /// Copies `incident`, cutting each field at its capacity. As in Zig, the evidence's
    /// `truncated` bits gain one bit per field the copy cut (IP, User-Agent, method, path,
    /// category, payload, lowest first) and bit 6 for a body shorter than declared.
    pub(crate) fn from_incident(incident: &Incident<'_>) -> IncidentRecord {
        let record = IncidentRecord {
            client_ip: Field::copy_from(incident.client_ip.as_bytes()),
            user_agent: Field::copy_from(incident.user_agent),
            method: Field::copy_from(incident.method.as_bytes()),
            path: Field::copy_from(incident.path),
            category: Field::copy_from(incident.category.as_bytes()),
            payload: Field::copy_from(incident.payload),
            now: incident.now,
            evidence: incident.evidence,
            request_head: Field::copy_from(incident.request_head),
            response_head: Field::copy_from(incident.response_head),
            request_truncated: incident.request_truncated,
            response_truncated: incident.response_truncated,
            response_state: incident.response_state,
        };
        let cut = [
            incident.client_ip.len() > 48,
            incident.user_agent.len() > 200,
            incident.method.len() > 8,
            incident.path.len() > 512,
            incident.category.len() > 32,
            incident.payload.len() > 512,
            incident.evidence.body_bytes < incident.evidence.declared_body_bytes,
        ];
        let mut evidence = record.evidence;
        for (bit, cut) in (0u16..).zip(cut) {
            if cut {
                evidence.truncated |= 1 << bit;
            }
        }
        IncidentRecord { evidence, ..record }
    }
}

/// Database text from captured bytes: invalid UTF-8 becomes U+FFFD and NUL bytes are
/// dropped, because PostgreSQL text cannot hold them. Used for the text columns (client
/// address, method, category).
fn render(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().filter(|&c| c != '\0').collect()
}

/// One incident ready to write; everything derived (id, embedding, campaign) is fixed here
/// so a replay writes exactly the same rows.
#[derive(Clone, Debug)]
pub(crate) struct PreparedIncident {
    pub(crate) id: i64,
    client_ip: String,
    user_agent: Vec<u8>,
    method: String,
    path: Vec<u8>,
    category: String,
    payload: Vec<u8>,
    /// The canonical tokens of `path` that full-text search indexes.
    path_tokens: Vec<String>,
    /// The canonical tokens of `payload` that full-text search indexes.
    payload_tokens: Vec<String>,
    embedding: [u8; 256],
    pub(crate) unit: Embedding,
    pub(crate) campaign: i64,
    recorded_at: i64,
    /// For honeypot hits, the time the ban ends.
    ban_until: Option<i64>,
    /// What the console captured, for the incident hook.
    capture: Capture,
}

/// The console's capture of one incident, kept for the incident hook.
#[derive(Clone, Debug)]
struct Capture {
    evidence: Evidence,
    request_head: Vec<u8>,
    response_head: Vec<u8>,
    request_truncated: bool,
    response_truncated: bool,
    response_state: ResponseState,
}

/// One incident of a written batch, as the incident hook sees it (SID 0013, "Changes to the
/// core storage", item 2). It borrows the prepared batch.
#[derive(Clone, Copy, Debug)]
pub struct BatchIncident<'a> {
    /// The incident id, `(node << 40) | sequence`.
    pub id: i64,
    /// The client address as stored.
    pub client_ip: &'a str,
    /// The time of the incident in Unix seconds.
    pub recorded_at: u64,
    /// The evidence metadata; version 0 means nothing was recorded.
    pub evidence: Evidence,
    /// The redacted request head; empty when capture is off.
    pub request_head: &'a [u8],
    /// The redacted origin response head; empty when there was none.
    pub response_head: &'a [u8],
    /// True when the request head was cut at its capacity.
    pub request_truncated: bool,
    /// True when the response head was cut at its capacity.
    pub response_truncated: bool,
    /// How the response side was observed.
    pub response_state: ResponseState,
}

/// A batch of incidents with consecutive sequence numbers ending before `end`.
#[derive(Clone, Debug)]
pub(crate) struct PreparedBatch {
    pub(crate) end: u64,
    pub(crate) incidents: Vec<PreparedIncident>,
}

/// What [`prepare`] needs besides the records.
pub(crate) struct BatchContext<'a> {
    pub(crate) node: u32,
    pub(crate) first_sequence: u64,
    pub(crate) ban_seconds: u64,
    pub(crate) embed: &'a (dyn Fn(&[u8]) -> Embedding + Send),
    pub(crate) window: &'a CampaignWindow,
}

/// Assigns ids, embeddings and campaigns to `records`. An incident's nearest neighbour is
/// searched in the window and among the earlier incidents of the same batch.
///
/// Fails with [`StorageError::IncidentIdExhausted`] when the batch would pass sequence 2^40.
pub(crate) fn prepare(
    records: &[IncidentRecord],
    context: &BatchContext<'_>,
) -> Result<PreparedBatch, StorageError> {
    let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
    let end = context.first_sequence.saturating_add(count);
    if end > SEQUENCE_LIMIT {
        return Err(StorageError::IncidentIdExhausted);
    }
    let base = u64::from(context.node) << NODE_SHIFT;
    let mut incidents: Vec<PreparedIncident> = Vec::with_capacity(records.len());
    for (sequence, record) in (context.first_sequence..).zip(records) {
        // The node is below 2^23 and the sequence below 2^40, so the id is positive.
        let id = i64::try_from(base | sequence).unwrap_or(i64::MAX);
        let embedding = (context.embed)(record.payload.as_bytes());
        let unit = normalize(&embedding);
        let mut nearest = context.window.nearest(&unit);
        for earlier in &incidents {
            let similarity = dot(&unit, &earlier.unit);
            if nearest.is_none_or(|best| similarity > best.similarity) {
                nearest =
                    Some(crate::campaigns::Neighbour { campaign: earlier.campaign, similarity });
            }
        }
        let campaign = nearest.filter(|found| found.is_close()).map_or(id, |found| found.campaign);
        let category = render(record.category.as_bytes());
        let ban_until = (category == "honeypot")
            .then(|| sql_time(record.now.saturating_add(context.ban_seconds)));
        incidents.push(PreparedIncident {
            id,
            client_ip: render(record.client_ip.as_bytes()),
            user_agent: record.user_agent.as_bytes().to_vec(),
            method: render(record.method.as_bytes()),
            path: record.path.as_bytes().to_vec(),
            category,
            payload: record.payload.as_bytes().to_vec(),
            path_tokens: search::index_tokens(record.path.as_bytes()),
            payload_tokens: search::index_tokens(record.payload.as_bytes()),
            embedding: embedding_bytes(&embedding),
            unit,
            campaign,
            recorded_at: sql_time(record.now),
            ban_until,
            capture: Capture {
                evidence: record.evidence,
                request_head: record.request_head.as_bytes().to_vec(),
                response_head: record.response_head.as_bytes().to_vec(),
                request_truncated: record.request_truncated,
                response_truncated: record.response_truncated,
                response_state: record.response_state,
            },
        });
    }
    Ok(PreparedBatch { end, incidents })
}

// Every insert of a batch carries the receipt guard: "the node's receipt is still below this
// batch's end", `COALESCE((SELECT next_sequence FROM incident_receipts WHERE node_id = $n),
// 0) < $end`. A replayed batch whose first commit succeeded therefore inserts nothing.

/// SQLite binds the first 12 parameters of [`write_incident`]'s row; PostgreSQL also binds
/// the `tsvector` literal of the canonical tokens.
const INSERT_INCIDENT: Sql = Sql {
    sqlite: "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11 \
             WHERE COALESCE((SELECT next_sequence FROM incident_receipts \
             WHERE node_id = $2), 0) < $12",
    postgres: "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, \
               path, violation_category, offending_payload, campaign_id, recorded_at, \
               embedding, search) \
               SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CAST($13 AS tsvector) \
               WHERE COALESCE((SELECT next_sequence FROM incident_receipts \
               WHERE node_id = $2), 0) < $12",
};

/// The number of parameters [`INSERT_INCIDENT`] reads on SQLite.
const SQLITE_INSERT_PARAMS: usize = 12;

const INSERT_FTS: Sql = Sql::both(
    "INSERT INTO incidents_fts (rowid, path, offending_payload) SELECT $1, $2, $3 \
     WHERE COALESCE((SELECT next_sequence FROM incident_receipts WHERE node_id = $4), 0) < $5",
);

/// Zig's honeypot upsert: score -100, the later of the two ban ends, one more hit.
const HONEYPOT: Sql = Sql {
    sqlite: "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, \
             trigger_rule, hits, last_seen) SELECT $1, -100, $2, 'honeypot', 1, $3 \
             WHERE COALESCE((SELECT next_sequence FROM incident_receipts \
             WHERE node_id = $4), 0) < $5 \
             ON CONFLICT (ip_or_cidr) DO UPDATE SET hits = ip_reputation.hits + 1, \
             reputation_score = -100, \
             banned_until = MAX(COALESCE(ip_reputation.banned_until, 0), excluded.banned_until), \
             trigger_rule = 'honeypot', \
             last_seen = MAX(ip_reputation.last_seen, excluded.last_seen)",
    postgres: "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, \
               trigger_rule, hits, last_seen) SELECT $1, -100, $2, 'honeypot', 1, $3 \
               WHERE COALESCE((SELECT next_sequence FROM incident_receipts \
               WHERE node_id = $4), 0) < $5 \
               ON CONFLICT (ip_or_cidr) DO UPDATE SET hits = ip_reputation.hits + 1, \
               reputation_score = -100, \
               banned_until = GREATEST(COALESCE(ip_reputation.banned_until, 0), \
               excluded.banned_until), trigger_rule = 'honeypot', \
               last_seen = GREATEST(ip_reputation.last_seen, excluded.last_seen)",
};

/// Advances the node's receipt; it never moves backwards.
const ADVANCE_RECEIPT: Sql = Sql {
    sqlite: "INSERT INTO incident_receipts (node_id, next_sequence) VALUES ($1, $2) \
             ON CONFLICT (node_id) DO UPDATE SET \
             next_sequence = MAX(incident_receipts.next_sequence, excluded.next_sequence)",
    postgres: "INSERT INTO incident_receipts (node_id, next_sequence) VALUES ($1, $2) \
               ON CONFLICT (node_id) DO UPDATE SET \
               next_sequence = GREATEST(incident_receipts.next_sequence, \
               excluded.next_sequence)",
};

/// Taken first by a PostgreSQL batch that bans: the revision triggers lock this row, and
/// taking it before any reputation row keeps concurrent nodes from deadlocking.
const LOCK_REVISION: Sql =
    Sql::both("SELECT revision FROM policy_revision WHERE id = 1 FOR UPDATE");

pub(crate) const NEXT_SEQUENCE: Sql = Sql::both(
    "SELECT CAST(COALESCE(MAX(id), 0) AS BIGINT), \
     COALESCE((SELECT next_sequence FROM incident_receipts WHERE node_id = $1), 1) \
     FROM security_incidents WHERE id >= $2 AND id < $3",
);

pub(crate) const SEARCH: Sql = Sql {
    sqlite: "SELECT s.id, s.client_ip, s.method, s.user_agent, s.path, s.violation_category, \
             s.offending_payload, s.campaign_id \
             FROM incidents_fts f JOIN security_incidents s ON s.id = f.rowid \
             WHERE incidents_fts MATCH $1 ORDER BY f.rank, s.id LIMIT $2",
    postgres: "SELECT id, client_ip, method, user_agent, path, violation_category, \
               offending_payload, campaign_id \
               FROM security_incidents, CAST($1 AS tsquery) AS query \
               WHERE search @@ query ORDER BY ts_rank(search, query) DESC, id LIMIT $2",
};

/// One row of `incident_receipts`: a node's durable receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncidentReceipt {
    /// The node, 1 to [`crate::MAX_NODE_ID`].
    pub node_id: u32,
    /// The sequence number after the node's last committed batch, 1 to 2^40.
    pub next_sequence: u64,
}

impl IncidentReceipt {
    /// Decodes a `(node_id, next_sequence)` row. Fails with [`StorageError::InvalidRow`] for
    /// a cell that does not have its column's type or range.
    pub(crate) fn decode(row: Row) -> Result<IncidentReceipt, StorageError> {
        let mut columns = Columns::new(row, "incident_receipts");
        Ok(IncidentReceipt {
            node_id: columns.integer("node_id")?,
            next_sequence: columns.integer("next_sequence")?,
        })
    }
}

/// Writes `batch` for `node`, runs the incident hook over it, and advances the receipt, all
/// in one transaction. A hook failure rolls the whole batch back, so the batch and its
/// sidecars commit together.
pub(crate) async fn write_batch(
    db: &Database,
    node: u32,
    batch: &PreparedBatch,
    hook: Option<&mut IncidentHook>,
) -> Result<(), StorageError> {
    let node = i64::from(node);
    let end = i64::try_from(batch.end).unwrap_or(i64::MAX);
    let mut tx = db.begin().await?;
    let bans = batch.incidents.iter().any(|incident| incident.ban_until.is_some());
    if bans && tx.dialect() == Dialect::Postgres {
        tx.execute(LOCK_REVISION, &[]).await?;
    }
    for incident in &batch.incidents {
        write_incident(&mut tx, incident, node, end).await?;
    }
    if let Some(hook) = hook {
        let incidents: Vec<BatchIncident<'_>> = batch.incidents.iter().map(view).collect();
        hook(&mut tx, &incidents).await?;
    }
    tx.execute(ADVANCE_RECEIPT, &[node.into(), end.into()]).await?;
    tx.commit().await
}

fn view(incident: &PreparedIncident) -> BatchIncident<'_> {
    let capture = &incident.capture;
    BatchIncident {
        id: incident.id,
        client_ip: &incident.client_ip,
        recorded_at: u64::try_from(incident.recorded_at).unwrap_or(0),
        evidence: capture.evidence,
        request_head: &capture.request_head,
        response_head: &capture.response_head,
        request_truncated: capture.request_truncated,
        response_truncated: capture.response_truncated,
        response_state: capture.response_state,
    }
}

async fn write_incident(
    tx: &mut Transaction,
    incident: &PreparedIncident,
    node: i64,
    end: i64,
) -> Result<(), StorageError> {
    let path_text = search::fts_text(&incident.path_tokens);
    let payload_text = search::fts_text(&incident.payload_tokens);
    let vector = match tx.dialect() {
        Dialect::Sqlite => String::new(),
        Dialect::Postgres => {
            search::tsvector_literal(&incident.path_tokens, &incident.payload_tokens)
        }
    };
    let row: [Param<'_>; 13] = [
        incident.id.into(),
        node.into(),
        incident.client_ip.as_str().into(),
        incident.user_agent.as_slice().into(),
        incident.method.as_str().into(),
        incident.path.as_slice().into(),
        incident.category.as_str().into(),
        incident.payload.as_slice().into(),
        incident.campaign.into(),
        incident.recorded_at.into(),
        incident.embedding.as_slice().into(),
        end.into(),
        vector.as_str().into(),
    ];
    // Both bounds are constants no larger than the array, so the slices are in bounds.
    let bound = match tx.dialect() {
        Dialect::Sqlite => &row[..SQLITE_INSERT_PARAMS],
        Dialect::Postgres => &row[..],
    };
    tx.execute(INSERT_INCIDENT, bound).await?;
    if tx.dialect() == Dialect::Sqlite {
        let fts: [Param<'_>; 5] = [
            incident.id.into(),
            path_text.as_str().into(),
            payload_text.as_str().into(),
            node.into(),
            end.into(),
        ];
        tx.execute(INSERT_FTS, &fts).await?;
    }
    if let Some(until) = incident.ban_until {
        let ban: [Param<'_>; 5] = [
            incident.client_ip.as_str().into(),
            until.into(),
            incident.recorded_at.into(),
            node.into(),
            end.into(),
        ];
        tx.execute(HONEYPOT, &ban).await?;
    }
    Ok(())
}

/// The incidents a retention batch removes: recorded before `$1`, oldest first, at most `$2`.
/// SQLite deletes the full-text rows first, with the same selection; PostgreSQL skips rows
/// another node's retention batch holds.
const DELETE_FTS: Sql = Sql::both(
    "DELETE FROM incidents_fts WHERE rowid IN (SELECT id FROM security_incidents \
     WHERE recorded_at < $1 ORDER BY recorded_at, id LIMIT $2)",
);
const DELETE_INCIDENTS: Sql = Sql {
    sqlite: "DELETE FROM security_incidents WHERE id IN (SELECT id FROM security_incidents \
             WHERE recorded_at < $1 ORDER BY recorded_at, id LIMIT $2)",
    postgres: "DELETE FROM security_incidents WHERE id IN (SELECT id FROM security_incidents \
               WHERE recorded_at < $1 ORDER BY recorded_at, id LIMIT $2 FOR UPDATE SKIP LOCKED)",
};

impl Database {
    /// Deletes at most `limit` incidents recorded before `before` (Unix seconds), oldest
    /// first, together with their `incidents_fts` rows on SQLite, in the caller's
    /// transaction (SID 0013, S36). The console's sidecars follow by `ON DELETE CASCADE`.
    /// Receipts are never deleted, so incident ids stay monotonic. Returns the number of
    /// incidents deleted.
    ///
    /// Fails with the driver's error.
    pub async fn delete_incidents(
        tx: &mut Transaction,
        before: u64,
        limit: u32,
    ) -> Result<u64, StorageError> {
        let params = [sql_time(before).into(), i64::from(limit).into()];
        if tx.dialect() == Dialect::Sqlite {
            tx.execute(DELETE_FTS, &params).await?;
        }
        tx.execute(DELETE_INCIDENTS, &params).await
    }
}

/// Returns the next sequence number of `node`: one past its largest stored id, or its
/// receipt when that is later. The receipt survives retention: deriving identity only from
/// the remaining rows could reuse ids and make the replay guard drop later batches.
///
/// Fails with [`StorageError::InvalidIncidentReceipt`] when the receipt is zero or beyond
/// 2^40, which the schema's `CHECK` already refuses.
pub(crate) async fn load_next_sequence(db: &Database, node: u32) -> Result<u64, StorageError> {
    let base = u64::from(node) << NODE_SHIFT;
    let low = i64::try_from(base).unwrap_or(i64::MAX);
    let high = i64::try_from(base + SEQUENCE_LIMIT).unwrap_or(i64::MAX);
    let params = [i64::from(node).into(), low.into(), high.into()];
    let rows = db.fetch_all(NEXT_SEQUENCE, &params).await?;
    let row = rows.into_iter().next().ok_or(StorageError::InvalidIncidentReceipt)?;
    let mut columns = Columns::new(row, "incident_receipts");
    let largest: u64 = columns.integer("id")?;
    let receipt: u64 = columns.integer("next_sequence")?;
    if receipt == 0 || receipt > SEQUENCE_LIMIT {
        return Err(StorageError::InvalidIncidentReceipt);
    }
    Ok(((largest & (SEQUENCE_LIMIT - 1)) + 1).max(receipt))
}

/// One incident found by [`Database::search_incidents`]. The user agent, path and payload
/// are the raw bytes the request carried (within the record's bounds), not necessarily
/// UTF-8; the reader chooses how to display them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncidentHit {
    /// The incident id, `(node << 40) | sequence`.
    pub id: i64,
    /// The client address.
    pub client_ip: String,
    /// The request method.
    pub method: String,
    /// The `User-Agent` bytes, at most 200.
    pub user_agent: Vec<u8>,
    /// The request path bytes, at most 512.
    pub path: Vec<u8>,
    /// The violation category.
    pub category: String,
    /// The offending payload bytes, at most 512.
    pub payload: Vec<u8>,
    /// The campaign the incident joined: the id of its first incident.
    pub campaign_id: i64,
}

impl Database {
    /// Searches the paths and payloads of recorded incidents with the search language of
    /// SID 0013 ([`Query`]) and returns at most `limit` (capped at [`MAX_SEARCH_RESULTS`])
    /// hits, best first: by FTS5's `bm25` on SQLite and `ts_rank` on PostgreSQL, ties by
    /// id. Both backends return the same set of matches; the order may differ. An empty
    /// query returns no hits.
    ///
    /// Fails with [`StorageError::Search`] for a query the language refuses (longer than
    /// [`MAX_SEARCH_QUERY`] bytes, for example), and with the driver's error.
    pub async fn search_incidents(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<Vec<IncidentHit>, StorageError> {
        let Some(query) = Query::parse(query).map_err(StorageError::Search)? else {
            return Ok(Vec::new());
        };
        let expression = query.expression(self.dialect());
        let limit = i64::from(limit.min(MAX_SEARCH_RESULTS));
        let rows = self.fetch_all(SEARCH, &[expression.as_str().into(), limit.into()]).await?;
        rows.into_iter().map(IncidentHit::decode).collect()
    }
}

impl IncidentHit {
    /// Decodes one row of [`SEARCH`]. Fails with [`StorageError::InvalidRow`] for a cell that
    /// does not have its column's type.
    fn decode(row: Row) -> Result<IncidentHit, StorageError> {
        let mut columns = Columns::new(row, "security_incidents");
        Ok(IncidentHit {
            id: columns.integer("id")?,
            client_ip: columns.text("client_ip")?,
            method: columns.text("method")?,
            user_agent: columns.bytes("user_agent")?,
            path: columns.bytes("path")?,
            category: columns.text("violation_category")?,
            payload: columns.bytes("offending_payload")?,
            campaign_id: columns.integer("campaign_id")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small xorshift generator, so the fuzz test is deterministic and dependency-free.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
        }
    }

    fn mutate(rng: &mut Xorshift, seeds: &[&[u8]], out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(seeds[rng.below(seeds.len())]);
        for _ in 0..rng.below(4) {
            match rng.below(5) {
                0 if !out.is_empty() => {
                    let at = rng.below(out.len());
                    out[at] ^= 1 << rng.below(8);
                }
                1 => out.truncate(rng.below(out.len() + 1)),
                2 => {
                    let copy = out.clone();
                    out.extend_from_slice(&copy);
                }
                3 => out.extend_from_slice(seeds[rng.below(seeds.len())]),
                _ => out.extend((0..rng.below(700)).map(|_| rng.next() as u8)),
            }
        }
    }

    /// Records copy any input without panicking, keep at most each capacity, and turn into
    /// bounded, NUL-free UTF-8 text.
    #[test]
    fn fuzz_record_copy_and_text_conversion() {
        let seeds: [&[u8]; 6] = [
            b"id=1' UNION SELECT username,password FROM users--",
            b"<img src=x onerror=alert(1)>",
            "caf\u{e9} \u{1f600}".as_bytes(),
            b"\x00\xff\xfe\x80",
            b"",
            &[b'a'; 600],
        ];
        let mut rng = Xorshift(0x5eed_1234_abcd_ef01);
        let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..100_000 {
            mutate(&mut rng, &seeds, &mut a);
            mutate(&mut rng, &seeds, &mut b);
            mutate(&mut rng, &seeds, &mut c);
            let ip = String::from_utf8_lossy(&c);
            let incident = Incident {
                client_ip: &ip,
                user_agent: &a,
                method: "GET",
                path: &b,
                category: "waf:sqli",
                payload: &a,
                now: rng.next(),
                ..Incident::default()
            };
            let record = IncidentRecord::from_incident(&incident);
            assert_eq!(record.user_agent.as_bytes(), &a[..a.len().min(200)]);
            assert_eq!(record.payload.as_bytes(), &a[..a.len().min(512)]);
            assert_eq!(record.path.as_bytes(), &b[..b.len().min(512)]);
            assert!(record.client_ip.as_bytes().len() <= 48);
            let path = render(record.path.as_bytes());
            assert!(!path.contains('\0'));
            // Each byte becomes at most one three-byte replacement character.
            assert!(path.len() <= 3 * 512);
        }
    }

    fn record(category: &str, payload: &[u8], now: u64) -> IncidentRecord {
        IncidentRecord::from_incident(&Incident {
            client_ip: "203.0.113.9",
            category,
            payload,
            now,
            ..Incident::default()
        })
    }

    #[test]
    fn prepare_assigns_ids_campaigns_and_honeypot_bans() {
        let embed = |payload: &[u8]| {
            let mut vector = [0.0f32; 64];
            vector[usize::from(payload.first().copied().unwrap_or(0) % 64)] = 1.0;
            vector
        };
        let window = CampaignWindow::new();
        let context = BatchContext {
            node: 3,
            first_sequence: 7,
            ban_seconds: 60,
            embed: &embed,
            window: &window,
        };
        let records = [record("waf:sqli", b"a1", 10), record("waf:sqli", b"a2", 11)];
        let mut more = records.to_vec();
        more.push(record("honeypot", b"", 12));
        let batch = prepare(&more, &context).unwrap();
        assert_eq!(batch.end, 10);
        let ids: Vec<i64> = batch.incidents.iter().map(|incident| incident.id).collect();
        assert_eq!(ids, [(3 << 40) | 7, (3 << 40) | 8, (3 << 40) | 9]);
        // The second incident joins the first one's campaign inside the batch.
        assert_eq!(batch.incidents[1].campaign, ids[0]);
        // The empty payload has a zero embedding, so it starts its own campaign.
        assert_eq!(batch.incidents[2].campaign, ids[2]);
        assert_eq!(batch.incidents[2].ban_until, Some(72));
        assert_eq!(batch.incidents[0].ban_until, None);
        let exhausted = BatchContext { first_sequence: SEQUENCE_LIMIT - 1, ..context };
        assert!(matches!(prepare(&more, &exhausted), Err(StorageError::IncidentIdExhausted)));
    }
}
