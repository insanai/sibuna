//! Incident reads for the Events page (SID 0007; SID 0013, "Search" and "Reads and writes
//! per route group"): pages of incidents or of source groups with their filters and the
//! search language, one incident's redacted heads ([`heads`]), the bounded similarity scan
//! ([`similar`]), and audited exports.
//!
//! These functions only read, except that an export appends `events.export_prepared`
//! through [`audit::record_export`] (S39) before its rows leave storage, so the caller
//! commits the transaction of an export. They read `security_incidents`, `incidents_fts`
//! (SQLite) or the `search` column (PostgreSQL), and the sidecars
//! `console_incident_evidence`, `console_incident_country` and `console_incident_heads`.
//!
//! A page is ordered by `(recorded_at, id)` descending and continues before a cursor of
//! that key, with or without a search, so both backends return the same rows on every page.
//! A search is parsed by [`sibuna_storage::search::Query`] and evaluated as one more filter.
//! A read with a search, and a grouped read, aggregate over a time window and run under the
//! work bound ([`crate::bound`]).
//!
//! # Changes from the Zig version
//!
//! - The search filter is new (SID 0013). The protocol's `events::Query` carries no search
//!   text, so [`query_events`] takes it as a separate argument.
//! - Paths and user agents are stored bytes; the display copy and the redaction of the
//!   query string work on bytes. Heads are stored bytes and leave storage as lowercase hex,
//!   the wire format Zig stored.
//! - Zig built the page's JSON text inside storage; [`query_events`] returns an
//!   [`EventPage`] whose [`EventPage::to_json`] writes the same bytes, and applies the same
//!   byte bound when it chooses the rows.

pub mod display;
pub mod heads;
pub mod similar;
mod sql;

use sibuna_console_protocol::MAX_MESSAGE;
use sibuna_console_protocol::codec::{Encode, to_json};
use sibuna_console_protocol::events::{self, Capture, Cursor, Row, country};
use sibuna_console_protocol::security::Module;
use sibuna_console_protocol::tokens::Scope;
use sibuna_storage::search;
use sibuna_storage::{Param, Row as Cells, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::audit::{self, Export};
use crate::bound::{self, WorkBound};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

pub(crate) use sql::classification;

/// What every Events read requires: any role with a browser session, or a token with the
/// `events_read` scope; kiosk sessions are refused.
pub const EVENTS_NEED: Need = Need::read(Some(Scope::EventsRead));

/// The bytes a page reserves beside its rows for separators, the cursor and the closing
/// fields, as Zig reserved them.
const PAGE_RESERVE: usize = 160;
/// The opening of a page's JSON text.
const PAGE_OPEN: &str = "{\"rows\":[";

/// One page of the Events view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventPage {
    /// The rows, newest first; at most the query's limit, and no more than fit in
    /// [`MAX_MESSAGE`] bytes of JSON.
    pub rows: Vec<Row>,
    /// The position to continue before, when more rows follow.
    pub next: Option<Cursor>,
}

impl EventPage {
    /// Writes the page as the console sends it: `{"rows":[...],"next":...}` with the
    /// cursor's id as a decimal string, the bytes Zig wrote.
    pub fn to_json(&self) -> String {
        let mut out = String::from(PAGE_OPEN);
        for (index, row) in self.rows.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&to_json(row));
        }
        out.push_str("],\"next\":");
        match self.next {
            Some(cursor) => {
                out.push_str(&format!("{{\"time\":{},\"id\":\"{}\"}}", cursor.time, cursor.id))
            }
            None => out.push_str("null"),
        }
        out.push('}');
        out
    }
}

/// Reads one page of incidents, or of groups by node and address, matching `input`'s
/// filters and the search `search` (empty for none); with `input.export_page`, the export
/// is audited (S39) before the page is returned. The credential is `credential`;
/// `input.session_digest` is not read. Borrows everything; returns an owned page.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses or a
/// search the language refuses (`"search query"`; parse it with
/// [`sibuna_storage::search::Query::parse`] for the diagnostic), like
/// [`access::authorize_in`] with [`EVENTS_NEED`], with [`ConsoleStorageError::Unavailable`]
/// when a search or grouped read passes `bound`, like [`audit::record_export`] for an
/// export, and with the driver's error.
pub async fn query_events(
    tx: &mut Transaction,
    credential: &Credential,
    input: &events::Query,
    search: &str,
    bound: WorkBound,
    now: u64,
) -> Result<EventPage, ConsoleStorageError> {
    events::validate(input).map_err(|_| ConsoleStorageError::InvalidInput("events query"))?;
    let search = search::Query::parse(search)
        .map_err(|_| ConsoleStorageError::InvalidInput("search query"))?;
    access::authorize_in(tx, credential, EVENTS_NEED, now).await?;
    let expression = search.map(|query| query.expression(tx.dialect()));
    let cells = read_rows(tx, input, expression.as_deref(), bound).await?;
    let page = assemble(cells, input)?;
    if input.export_page {
        audit::record_export(tx, credential, EVENTS_NEED, Export::Events, now).await?;
    }
    Ok(page)
}

/// Reads incident `id` with its evidence and country sidecars, the detail of the Events
/// page; `None` when no such incident is stored. Its heads are read by
/// [`heads::read_heads`].
///
/// Fails like [`query_events`].
pub async fn read_event(
    tx: &mut Transaction,
    credential: &Credential,
    id: u64,
    now: u64,
) -> Result<Option<Row>, ConsoleStorageError> {
    let input = events::Query { incident: id, limit: 1, ..events::Query::default() };
    let page = query_events(tx, credential, &input, "", WorkBound::default(), now).await?;
    Ok(page.rows.into_iter().next())
}

/// Runs the page's statement; grouped reads and searches run under `bound`.
async fn read_rows(
    tx: &mut Transaction,
    input: &events::Query,
    search: Option<&str>,
    bound: WorkBound,
) -> Result<Vec<Cells>, ConsoleStorageError> {
    let before = input.before.unwrap_or(Cursor { time: row::MAX_INTEGER, id: row::MAX_INTEGER });
    let module = input.module.map(|module| match module {
        Module::Inspection => 0i64,
        Module::Honeypot => 1,
        Module::Other => 2,
    });
    let nonzero = |value: u64| (value != 0).then(|| row::int(value)).transpose();
    let params: [Param<'_>; 14] = [
        row::int(input.from)?.into(),
        row::int(input.until)?.into(),
        nonzero(u64::from(input.node))?.into(),
        row::non_empty(input.category.as_str()).into(),
        row::non_empty(input.ip.as_str()).into(),
        input.path_prefix.as_bytes().into(),
        row::non_empty(input.country.as_str()).into(),
        module.into(),
        nonzero(input.campaign)?.into(),
        nonzero(input.incident)?.into(),
        row::int(before.time)?.into(),
        row::int(before.id)?.into(),
        (i64::from(input.limit) + 1).into(),
        search.unwrap_or_default().into(),
    ];
    let statement: Sql = match (input.grouped, search.is_some()) {
        (false, false) => sql::ROWS,
        (false, true) => sql::ROWS_SEARCH,
        (true, false) => sql::GROUPS,
        (true, true) => sql::GROUPS_SEARCH,
    };
    // The 14th value (the search) is bound only when the statement reads it.
    let bound_params = if search.is_some() { &params[..] } else { &params[..13] };
    if !(input.grouped || search.is_some()) {
        return Ok(tx.fetch_all(statement, bound_params).await?);
    }
    bound::begin(tx, bound).await?;
    let rows = bound::fetch(tx, statement, bound_params).await;
    // The bound ends also after a failed read, so later statements of the transaction run
    // without it.
    let ended = bound::end(tx).await;
    // A failed read reports its own error; PostgreSQL then refuses every statement.
    let rows = rows?;
    ended?;
    Ok(rows)
}

/// Decodes the rows and keeps those that fit the query's limit and the page's byte bound.
fn assemble(cells: Vec<Cells>, input: &events::Query) -> Result<EventPage, ConsoleStorageError> {
    let available = cells.len();
    let mut page = EventPage::default();
    let mut written = PAGE_OPEN.len();
    for cells in cells.into_iter().take(usize::from(input.limit)) {
        let row = Row { grouped: input.grouped, ..decode_row(Fields::new(cells, "events"))? };
        let length = encoded_length(&row);
        if length + written + PAGE_RESERVE > MAX_MESSAGE {
            break;
        }
        written += length + usize::from(!page.rows.is_empty());
        page.rows.push(row);
    }
    if page.rows.len() < available {
        page.next = page.rows.last().map(|row| Cursor { time: row.time, id: row.id });
    }
    Ok(page)
}

fn encoded_length(row: &Row) -> usize {
    let mut writer = sibuna_json::Writer::new(String::new());
    // Writing into a String cannot fail.
    let _ = row.encode(&mut writer);
    writer.into_inner().len()
}

/// Decodes one row of [`sql::ROWS`] or [`sql::GROUPS`].
fn decode_row(mut fields: Fields) -> Result<Row, ConsoleStorageError> {
    let id = fields.integer("id")?;
    let node = fields.integer("node_id")?;
    let time = fields.integer("recorded_at")?;
    let (ip, ip_cut) = display::copy::<48>(fields.text("client_ip")?.as_bytes());
    let method = fields.optional_text("method")?.unwrap_or_default();
    let (method, method_cut) = display::copy::<8>(method.as_bytes());
    let stored_path = fields.optional_bytes("path")?.unwrap_or_default();
    let (path, query_cut) = display::without_query(&stored_path);
    let (path, path_cut) = display::copy::<256>(path);
    let category = fields.optional_text("violation_category")?.unwrap_or_default();
    let (category, category_cut) = display::copy::<32>(category.as_bytes());
    let agent = fields.optional_bytes("user_agent")?.unwrap_or_default();
    let (user_agent, agent_cut) = display::copy::<128>(&agent);
    let campaign = fields.optional_integer("campaign_id")?;
    let count = fields.integer("count")?;
    let first_seen = fields.integer("first_seen")?;
    let capture = decode_capture(&mut fields)?;
    let geography = decode_geography(&mut fields)?;
    let redacted = query_cut || capture.is_some_and(|capture| capture.query_bytes != 0);
    Ok(Row {
        geography,
        capture,
        id,
        grouped: false,
        count,
        first_seen,
        node,
        time,
        ip,
        method,
        path,
        category,
        user_agent,
        campaign,
        display_truncated: ip_cut || method_cut || path_cut || category_cut || agent_cut,
        query_redacted: redacted,
    })
}

/// Decodes the evidence columns: present flag, status, query, body, declared body and
/// truncation bits.
fn decode_capture(fields: &mut Fields) -> Result<Option<Capture>, ConsoleStorageError> {
    let present = fields.flag("evidence")?;
    let selected_status = fields.optional_integer("selected_status")?;
    let query_bytes = fields.optional_integer("query_bytes")?;
    let body_bytes = fields.optional_integer("body_bytes")?;
    let declared_body_bytes = fields.optional_integer("declared_body_bytes")?;
    let truncated = fields.optional_integer("truncated")?;
    if !present {
        return Ok(None);
    }
    let (
        Some(selected_status),
        Some(query_bytes),
        Some(body_bytes),
        Some(declared_body_bytes),
        Some(truncated),
    ) = (selected_status, query_bytes, body_bytes, declared_body_bytes, truncated)
    else {
        return Err(fields.invalid("console_incident_evidence"));
    };
    Ok(Some(Capture {
        version: 1,
        selected_status,
        query_bytes,
        body_bytes,
        declared_body_bytes,
        truncated,
    }))
}

/// Decodes the country columns: code, generation as hex, mixed and recorded flags.
fn decode_geography(fields: &mut Fields) -> Result<country::Mapping, ConsoleStorageError> {
    let code = fields.optional_text("country")?;
    let generation = fields.optional_text("generation")?;
    let mixed = fields.flag("mixed")?;
    let recorded = fields.flag("recorded")?;
    let wire = country::Wire {
        code: code.as_deref(),
        generation: generation.as_deref(),
        mixed,
        recorded,
    };
    country::Mapping::from_wire(wire).map_err(|_| fields.invalid("country"))
}
