//! Incident records: the fixed-size copy a request thread queues, the prepared batch the
//! storage thread writes, the durable receipt, and forensic search.
//!
//! An incident id is `(node << 40) | sequence`. Each node keeps the receipt
//! `incident_cursor_<node>` in `sibuna_meta`: the sequence after its last committed batch.
//! The receipt advances in the same transaction as the batch, and every insert of the batch
//! is guarded by "the receipt is still below this batch's end". Replaying a batch whose
//! commit was not acknowledged therefore writes nothing twice, exactly as in the Zig daemon.

use sibuna_core::Incident;

use crate::campaigns::{
    CampaignWindow, Embedding, NODE_SHIFT, SEQUENCE_LIMIT, dot, embedding_bytes, normalize,
};
use crate::database::{Cell, Database, Dialect, Param, Sql, Transaction, int_at, text_at};
use crate::error::StorageError;
use crate::policy::sql_time;

/// The most incidents one transaction writes.
pub const INCIDENT_BATCH: usize = 32;
/// The number of slots of the incident ring.
pub const INCIDENT_QUEUE: usize = 512;
/// The longest full-text query accepted, in bytes.
pub const MAX_SEARCH_QUERY: usize = 1024;
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
/// request thread hands it over without allocating. The capacities are the Zig record's.
#[derive(Clone, Copy)]
pub(crate) struct IncidentRecord {
    client_ip: Field<48>,
    user_agent: Field<200>,
    method: Field<8>,
    path: Field<512>,
    category: Field<32>,
    payload: Field<512>,
    now: u64,
}

impl IncidentRecord {
    /// Copies `incident`, cutting each field at its capacity.
    pub(crate) fn from_incident(incident: &Incident<'_>) -> IncidentRecord {
        IncidentRecord {
            client_ip: Field::copy_from(incident.client_ip.as_bytes()),
            user_agent: Field::copy_from(incident.user_agent),
            method: Field::copy_from(incident.method.as_bytes()),
            path: Field::copy_from(incident.path),
            category: Field::copy_from(incident.category.as_bytes()),
            payload: Field::copy_from(incident.payload),
            now: incident.now,
        }
    }
}

/// Database text from captured bytes: invalid UTF-8 becomes U+FFFD and NUL bytes are
/// dropped, because PostgreSQL text cannot hold them (Zig's quoting dropped them too).
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().filter(|&c| c != '\0').collect()
}

/// One incident ready to write; everything derived (id, embedding, campaign) is fixed here
/// so a replay writes exactly the same rows.
#[derive(Clone, Debug)]
pub(crate) struct PreparedIncident {
    pub(crate) id: i64,
    client_ip: String,
    user_agent: String,
    method: String,
    path: String,
    category: String,
    payload: String,
    embedding: [u8; 256],
    pub(crate) unit: Embedding,
    pub(crate) campaign: i64,
    recorded_at: i64,
    /// For honeypot hits, the time the ban ends.
    ban_until: Option<i64>,
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
        let category = text(record.category.as_bytes());
        let ban_until = (category == "honeypot")
            .then(|| sql_time(record.now.saturating_add(context.ban_seconds)));
        incidents.push(PreparedIncident {
            id,
            client_ip: text(record.client_ip.as_bytes()),
            user_agent: text(record.user_agent.as_bytes()),
            method: text(record.method.as_bytes()),
            path: text(record.path.as_bytes()),
            category,
            payload: text(record.payload.as_bytes()),
            embedding: embedding_bytes(&embedding),
            unit,
            campaign,
            recorded_at: sql_time(record.now),
            ban_until,
        });
    }
    Ok(PreparedBatch { end, incidents })
}

/// The receipt guard shared by every insert: "the receipt is still below this batch's end".
macro_rules! guarded {
    ($head:literal, $key:literal, $end:literal) => {
        concat!(
            $head,
            " WHERE COALESCE((SELECT CAST(value AS BIGINT) FROM sibuna_meta WHERE key = ",
            $key,
            "), 0) < ",
            $end
        )
    };
}

const INSERT_INCIDENT: Sql = Sql::both(guarded!(
    "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
     violation_category, offending_payload, campaign_id, recorded_at, embedding) \
     SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11",
    "$12",
    "$13"
));

const INSERT_FTS: Sql = Sql::both(guarded!(
    "INSERT INTO incidents_fts (rowid, path, offending_payload) SELECT $1, $2, $3",
    "$4",
    "$5"
));

/// Zig's honeypot upsert: score -100, the later of the two ban ends, one more hit.
const HONEYPOT: Sql = Sql {
    sqlite: concat!(
        guarded!(
            "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, \
             trigger_rule, hits, last_seen) SELECT $1, -100, $2, 'honeypot', 1, $3",
            "$4",
            "$5"
        ),
        " ON CONFLICT (ip_or_cidr) DO UPDATE SET hits = ip_reputation.hits + 1, \
         reputation_score = -100, \
         banned_until = MAX(COALESCE(ip_reputation.banned_until, 0), excluded.banned_until), \
         trigger_rule = 'honeypot', \
         last_seen = MAX(ip_reputation.last_seen, excluded.last_seen)"
    ),
    postgres: concat!(
        guarded!(
            "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, \
             trigger_rule, hits, last_seen) SELECT $1, -100, $2, 'honeypot', 1, $3",
            "$4",
            "$5"
        ),
        " ON CONFLICT (ip_or_cidr) DO UPDATE SET hits = ip_reputation.hits + 1, \
         reputation_score = -100, \
         banned_until = GREATEST(COALESCE(ip_reputation.banned_until, 0), \
         excluded.banned_until), trigger_rule = 'honeypot', \
         last_seen = GREATEST(ip_reputation.last_seen, excluded.last_seen)"
    ),
};

const CURSOR: Sql = Sql {
    sqlite: "INSERT INTO sibuna_meta (key, value) VALUES ($1, $2) ON CONFLICT (key) \
             DO UPDATE SET value = MAX(CAST(sibuna_meta.value AS INTEGER), \
             CAST(excluded.value AS INTEGER))",
    postgres: "INSERT INTO sibuna_meta (key, value) VALUES ($1, $2) ON CONFLICT (key) \
               DO UPDATE SET value = CAST(GREATEST(CAST(sibuna_meta.value AS BIGINT), \
               CAST(excluded.value AS BIGINT)) AS TEXT)",
};

/// Taken first by a PostgreSQL batch that bans: the revision triggers lock this row, and
/// taking it before any reputation row keeps concurrent nodes from deadlocking.
const LOCK_REVISION: Sql =
    Sql::both("SELECT value FROM sibuna_meta WHERE key = 'policy_version' FOR UPDATE");

const LOAD_CURSOR: Sql = Sql::both(
    "SELECT CAST(COALESCE(MAX(id), 0) AS BIGINT), \
     COALESCE((SELECT value FROM sibuna_meta WHERE key = $1), '1') \
     FROM security_incidents WHERE id >= $2 AND id < $3",
);

const SEARCH: Sql = Sql {
    sqlite: "SELECT s.id, s.client_ip, s.violation_category, s.path, s.campaign_id \
             FROM incidents_fts f JOIN security_incidents s ON s.id = f.rowid \
             WHERE incidents_fts MATCH $1 ORDER BY rank LIMIT $2",
    postgres: "SELECT id, client_ip, violation_category, path, campaign_id \
               FROM security_incidents, websearch_to_tsquery('simple', $1) AS query \
               WHERE search @@ query ORDER BY ts_rank(search, query) DESC, id LIMIT $2",
};

/// Returns the `sibuna_meta` key of `node`'s receipt.
pub(crate) fn cursor_key(node: u32) -> String {
    format!("incident_cursor_{node}")
}

/// Writes `batch` for `node` and advances its receipt, all in one transaction.
pub(crate) async fn write_batch(
    db: &Database,
    node: u32,
    batch: &PreparedBatch,
) -> Result<(), StorageError> {
    let key = cursor_key(node);
    let end = i64::try_from(batch.end).unwrap_or(i64::MAX);
    let mut tx = db.begin().await?;
    let bans = batch.incidents.iter().any(|incident| incident.ban_until.is_some());
    if bans && tx.dialect() == Dialect::Postgres {
        tx.execute(LOCK_REVISION, &[]).await?;
    }
    for incident in &batch.incidents {
        write_incident(&mut tx, incident, node, &key, end).await?;
    }
    let end_text = batch.end.to_string();
    tx.execute(CURSOR, &[key.as_str().into(), end_text.as_str().into()]).await?;
    tx.commit().await
}

async fn write_incident(
    tx: &mut Transaction,
    incident: &PreparedIncident,
    node: u32,
    key: &str,
    end: i64,
) -> Result<(), StorageError> {
    let row: [Param<'_>; 13] = [
        incident.id.into(),
        i64::from(node).into(),
        incident.client_ip.as_str().into(),
        incident.user_agent.as_str().into(),
        incident.method.as_str().into(),
        incident.path.as_str().into(),
        incident.category.as_str().into(),
        incident.payload.as_str().into(),
        incident.campaign.into(),
        incident.recorded_at.into(),
        incident.embedding.as_slice().into(),
        key.into(),
        end.into(),
    ];
    tx.execute(INSERT_INCIDENT, &row).await?;
    if tx.dialect() == Dialect::Sqlite {
        let fts: [Param<'_>; 5] = [
            incident.id.into(),
            incident.path.as_str().into(),
            incident.payload.as_str().into(),
            key.into(),
            end.into(),
        ];
        tx.execute(INSERT_FTS, &fts).await?;
    }
    if let Some(until) = incident.ban_until {
        let ban: [Param<'_>; 5] = [
            incident.client_ip.as_str().into(),
            until.into(),
            incident.recorded_at.into(),
            key.into(),
            end.into(),
        ];
        tx.execute(HONEYPOT, &ban).await?;
    }
    Ok(())
}

/// Returns the next sequence number of `node`: one past its largest stored id, or its
/// receipt when that is later. The receipt survives retention: deriving identity only from
/// the remaining rows could reuse ids and make the replay guard drop later batches.
///
/// Fails with [`StorageError::InvalidIncidentCursor`] when the receipt is zero, beyond 2^40
/// or not a number.
pub(crate) async fn load_next_sequence(db: &Database, node: u32) -> Result<u64, StorageError> {
    let key = cursor_key(node);
    let base = u64::from(node) << NODE_SHIFT;
    let low = i64::try_from(base).unwrap_or(i64::MAX);
    let high = i64::try_from(base + SEQUENCE_LIMIT).unwrap_or(i64::MAX);
    let rows = db.fetch_all(LOAD_CURSOR, &[key.as_str().into(), low.into(), high.into()]).await?;
    let [row] = rows.as_slice() else {
        return Err(StorageError::InvalidIncidentCursor);
    };
    let largest = row.first().and_then(Cell::as_i64).and_then(|id| u64::try_from(id).ok());
    let receipt = row.get(1).and_then(Cell::as_i64).and_then(|value| u64::try_from(value).ok());
    let (Some(largest), Some(receipt)) = (largest, receipt) else {
        return Err(StorageError::InvalidIncidentCursor);
    };
    if receipt == 0 || receipt > SEQUENCE_LIMIT {
        return Err(StorageError::InvalidIncidentCursor);
    }
    Ok(((largest & (SEQUENCE_LIMIT - 1)) + 1).max(receipt))
}

/// One incident found by [`Database::search_incidents`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncidentHit {
    /// The incident id, `(node << 40) | sequence`.
    pub id: i64,
    /// The client address.
    pub client_ip: String,
    /// The violation category.
    pub category: String,
    /// The request path.
    pub path: String,
    /// The campaign the incident joined.
    pub campaign_id: Option<i64>,
}

impl Database {
    /// Searches the paths and payloads of recorded incidents and returns at most `limit`
    /// (capped at [`MAX_SEARCH_RESULTS`]) hits, best first. SQLite reads `query` as an FTS5
    /// `MATCH` expression; PostgreSQL as a web search (`websearch_to_tsquery`).
    ///
    /// Fails with [`StorageError::SearchQueryTooLong`] beyond [`MAX_SEARCH_QUERY`] bytes, and
    /// with the driver's error (for example an FTS5 syntax error).
    pub async fn search_incidents(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<Vec<IncidentHit>, StorageError> {
        if query.len() > MAX_SEARCH_QUERY {
            return Err(StorageError::SearchQueryTooLong);
        }
        let limit = i64::from(limit.min(MAX_SEARCH_RESULTS));
        let rows = self.fetch_all(SEARCH, &[query.into(), limit.into()]).await?;
        let table = "security_incidents";
        rows.iter()
            .map(|row| {
                Ok(IncidentHit {
                    id: int_at(row, 0, table, "id")?,
                    client_ip: text_at(row, 1, table, "client_ip")?,
                    category: text_at(row, 2, table, "violation_category")?,
                    path: text_at(row, 3, table, "path")?,
                    campaign_id: row.get(4).and_then(Cell::as_i64),
                })
            })
            .collect()
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
            let path = text(record.path.as_bytes());
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
