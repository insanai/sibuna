//! The subscription feed reads (Zig's `console_subscription_feed.zig`): pages of committed
//! incidents per issuing node and of audit rows, read below a captured watermark, for the
//! live `events` and `audit` topics of the console's hub (SID 0007, "The Real-Time
//! Protocol"), and the committed policy revision for the `policy` topic.
//!
//! These reads take no credential: the hub's feeder runs them in the background, and every
//! subscriber's stream rechecks its own session (SID 0007). They never write.
//!
//! # Watermarks and pages
//!
//! Each issuer has its own cursor: incident ids carry the issuing node in their top 24 bits,
//! and ids of different nodes are never compared. A feed's head is the larger of its durable
//! receipt and its largest stored id:
//!
//! ```text
//! events of node n:  max(n << 40 + next_sequence - 1   (incident_receipts),
//!                        MAX(id) of node n             (security_incidents))
//! audit:             max(last_id                       (console_audit_cursor),
//!                        MAX(id)                       (console_audit))
//! ```
//!
//! The receipt never moves back, so a cursor stays meaningful after retention deleted every
//! row, or after the migrations were applied again. A page reads the rows after `after` up
//! to `through` (the head, or the caller's earlier `through` while it pages a backlog), at
//! most [`PAGE_ROWS`] of them. Without `after`, a read starts [`RECENT_IDS`] ids below
//! `through`, so a new subscriber sees recent rows rather than the whole history. Ids in
//! the range without a row (deleted by retention, or never committed) are counted in
//! `missing_ids`, so the hub can tell its subscribers that summaries were lost.
//!
//! # Changes from the Zig version
//!
//! - The receipts are the rows of `incident_receipts` and `console_audit_cursor` instead of
//!   the `sibuna_meta` keys `incident_cursor_<node>` and `console_audit_cursor`.
//! - The page does not carry the producer's drop counter and boot: they are the daemon's
//!   counters, not stored rows, so the feeder fills them in. `observed_at` and
//!   `replica_observed_at` are the read's time, and `replica_quorum` is true: the database
//!   answered this read, which is what quorum means without a consensus log (SID 0007).
//! - A row's country attribution counts as recorded when its sidecar row exists, as on the
//!   Events page; the generation is never absent in such a row.

use sibuna_console_protocol::events::country;
use sibuna_console_protocol::subscription_feed::{
    Event, Kind, PAGE_ROWS, Page, RECENT_IDS, Request, Row, validate,
};
use sibuna_storage::{Param, Sql, StorageError, Transaction};

use crate::audit::decode_row;
use crate::error::ConsoleStorageError;
use crate::events::display;
use crate::row::{self, Fields};

/// The largest incident id of a node, relative to the node's base (`node << 40`).
const ISSUER_SPAN: u64 = (1 << 40) - 1;

const EVENTS_HEAD: Sql = Sql::both(
    "SELECT (SELECT MAX(id) FROM security_incidents WHERE id > $1 AND id <= $2), \
     (SELECT next_sequence FROM incident_receipts WHERE node_id = $3)",
);

const AUDIT_HEAD: Sql = Sql::both(
    "SELECT (SELECT MAX(id) FROM console_audit), \
     (SELECT last_id FROM console_audit_cursor WHERE id = 1)",
);

/// The incident columns, in the order [`decode_event`] reads them.
const EVENTS: Sql = Sql {
    sqlite: "SELECT s.id, s.node_id, s.recorded_at, s.client_ip, s.method, s.path, \
             s.violation_category, e.incident_id IS NOT NULL, e.query_bytes, c.country, \
             (CASE WHEN c.generation IS NULL THEN NULL ELSE lower(hex(c.generation)) END), \
             c.incident_id IS NOT NULL FROM security_incidents s \
             LEFT JOIN console_incident_evidence e ON e.incident_id = s.id \
             LEFT JOIN console_incident_country c ON c.incident_id = s.id \
             WHERE s.id > $1 AND s.id <= $2 ORDER BY s.id LIMIT $3",
    postgres: "SELECT s.id, s.node_id, s.recorded_at, s.client_ip, s.method, s.path, \
               s.violation_category, e.incident_id IS NOT NULL, e.query_bytes, c.country, \
               encode(c.generation, 'hex'), c.incident_id IS NOT NULL \
               FROM security_incidents s \
               LEFT JOIN console_incident_evidence e ON e.incident_id = s.id \
               LEFT JOIN console_incident_country c ON c.incident_id = s.id \
               WHERE s.id > $1 AND s.id <= $2 ORDER BY s.id LIMIT $3",
};

/// The audit columns, in the order [`decode_row`] reads them.
const AUDIT: Sql = Sql::both(
    "SELECT id, actor, subject, recorded_at, action, target, actor_role, client_ip \
     FROM console_audit WHERE id > $1 AND id <= $2 ORDER BY id LIMIT $3",
);

const COMMITTED: Sql = Sql::both("SELECT revision FROM policy_revision WHERE id = 1");

/// Reads the next page of the feed `input` names at `now` (Unix seconds); see the module
/// documentation. Borrows the request; returns an owned page whose producer fields are
/// unset.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a request [`validate`] refuses,
/// with [`ConsoleStorageError::Conflict`] when `after` lies beyond the head (the feed was
/// replaced), with [`StorageError::InvalidRow`] for a stored row the protocol cannot carry,
/// and with the driver's error.
pub async fn read_page(
    tx: &mut Transaction,
    input: &Request,
    now: u64,
) -> Result<Page, ConsoleStorageError> {
    validate(input).map_err(|_| ConsoleStorageError::InvalidInput("feed request"))?;
    let base = u64::from(input.node) << 40;
    let head = watermark(tx, input).await?;
    let through = input.through.map_or(head, |through| through.min(head));
    let after = input.after.unwrap_or_else(|| base.max(through.saturating_sub(RECENT_IDS as u64)));
    if after > through {
        return Err(ConsoleStorageError::Conflict);
    }
    let mut page = Page {
        kind: input.kind,
        node: input.node,
        head,
        through,
        next: after,
        observed_at: now,
        replica_observed_at: now,
        replica_quorum: true,
        ..Page::default()
    };
    let statement = if input.kind == Kind::Events { EVENTS } else { AUDIT };
    let lookahead = PAGE_ROWS as u64 + 1;
    let params: [Param<'_>; 3] =
        [row::int(after)?.into(), row::int(through)?.into(), row::int(lookahead)?.into()];
    let cells = tx.fetch_all(statement, &params).await?;
    page.more = cells.len() > PAGE_ROWS;
    for cells in cells.into_iter().take(PAGE_ROWS) {
        let row = match input.kind {
            Kind::Events => Row::Events(decode_event(Fields::new(cells, "security_incidents"))?),
            Kind::Audit => Row::Audit(decode_row(&mut Fields::new(cells, "console_audit"))?),
        };
        let id = match &row {
            Row::Events(event) => event.id,
            Row::Audit(audit) => audit.id,
        };
        // Rows come in id order after `next`, so `id > next` and the gap cannot underflow.
        page.missing_ids += id.saturating_sub(page.next).saturating_sub(1);
        page.next = id;
        page.rows.push(row);
    }
    if !page.more {
        page.missing_ids += through.saturating_sub(page.next);
        page.next = through;
    }
    Ok(page)
}

/// Returns the committed policy revision, for the `policy` topic; the applied revision is
/// the daemon's.
///
/// Fails with [`StorageError::MissingPolicyRevision`] when the revision row is gone and
/// with the driver's error.
pub async fn committed_revision(tx: &mut Transaction) -> Result<u64, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(COMMITTED, &[]).await?)
        .ok_or(StorageError::MissingPolicyRevision)?;
    Fields::new(cells, "policy_revision").integer("revision")
}

/// Returns the head of the feed: the larger of its receipt and its largest stored id.
async fn watermark(tx: &mut Transaction, input: &Request) -> Result<u64, ConsoleStorageError> {
    if input.kind == Kind::Audit {
        let cells = row::first(tx.fetch_all(AUDIT_HEAD, &[]).await?).unwrap_or_default();
        let mut fields = Fields::new(cells, "console_audit_cursor");
        let largest: Option<u64> = fields.optional_integer("max_id")?;
        let saved: Option<u64> = fields.optional_integer("last_id")?;
        return Ok(largest.unwrap_or(0).max(saved.unwrap_or(0)));
    }
    let base = u64::from(input.node) << 40;
    let params: [Param<'_>; 3] = [
        row::int(base)?.into(),
        row::int(base + ISSUER_SPAN)?.into(),
        i64::from(input.node).into(),
    ];
    let cells = row::first(tx.fetch_all(EVENTS_HEAD, &params).await?).unwrap_or_default();
    let mut fields = Fields::new(cells, "incident_receipts");
    let largest: Option<u64> = fields.optional_integer("max_id")?;
    // A node without a receipt has issued nothing: its next sequence is 1.
    let saved: u64 = fields.optional_integer("next_sequence")?.unwrap_or(1);
    if saved == 0 || saved > ISSUER_SPAN + 1 {
        return Err(fields.invalid("next_sequence"));
    }
    Ok((base + saved - 1).max(largest.unwrap_or(base)))
}

/// Decodes one row of [`EVENTS`] into the bounded summary the `events` topic carries.
fn decode_event(mut fields: Fields) -> Result<Event, ConsoleStorageError> {
    let id: u64 = fields.integer("id")?;
    let node: u32 = fields.integer("node_id")?;
    let time = fields.integer("recorded_at")?;
    if id >> 40 != u64::from(node) {
        return Err(fields.invalid("id"));
    }
    let (ip, ip_cut) = display::copy::<48>(fields.text("client_ip")?.as_bytes());
    let method = fields.optional_text("method")?.unwrap_or_default();
    let (method, method_cut) = display::copy::<8>(method.as_bytes());
    let stored_path = fields.optional_bytes("path")?.unwrap_or_default();
    let (path, query_cut) = display::without_query(&stored_path);
    let (path, path_cut) = display::copy::<128>(path);
    let category = fields.optional_text("violation_category")?.unwrap_or_default();
    let (category, category_cut) = display::copy::<32>(category.as_bytes());
    let evidence = fields.flag("evidence")?;
    let query_bytes: Option<u64> = fields.optional_integer("query_bytes")?;
    let geography = decode_geography(&mut fields)?;
    let query_captured = evidence && query_bytes.is_some_and(|bytes| bytes != 0);
    Ok(Event {
        geography,
        id,
        node,
        time,
        ip,
        method,
        path,
        category,
        display_truncated: ip_cut || method_cut || path_cut || category_cut,
        query_redacted: query_cut || query_captured,
    })
}

/// Decodes the country columns: code, generation as hex, and whether the sidecar exists.
fn decode_geography(fields: &mut Fields) -> Result<country::Mapping, ConsoleStorageError> {
    let code = fields.optional_text("country")?;
    let generation = fields.optional_text("generation")?;
    let recorded = fields.flag("recorded")?;
    let wire = country::Wire {
        code: code.as_deref(),
        generation: generation.as_deref(),
        mixed: false,
        recorded,
    };
    country::Mapping::from_wire(wire).map_err(|_| fields.invalid("country"))
}
