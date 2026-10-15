//! The routes `events/query`, `events/heads` and `events/similar` (Zig's `event_routes.zig`
//! and `similarity_routes.zig`).
//!
//! An events page is incidents, or source groups, newest first under the filters of the
//! form and the storage search language (`search`, SID 0013); a grouped read or a search
//! runs under the work bound. Heads are one incident's redacted request and response heads;
//! absent rows read as not recorded, never as empty. The similarity scan continues from a
//! cursor and answers ids as decimal strings so browsers keep them exact.

use std::fmt::{self, Write};

use sibuna_console_protocol::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, decimal_string, field,
};
use sibuna_console_protocol::events::{self, Cursor, MAX_SEARCH, country};
use sibuna_console_protocol::incident_heads::Read;
use sibuna_console_protocol::security::Module;
use sibuna_console_protocol::similarity::{self, Part};
use sibuna_console_protocol::{Text, storage::Failure};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::events::{
    EventPage, heads::read_heads, query_events, similar::similar,
};
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use super::policies::{decimal, spend, work_bound};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::Events => {
            spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
            let (_, page) = read_page(shared, context, call, false)?;
            Ok(reply::json_bytes(context, page.to_json().as_bytes(), &[])?)
        }
        Handler::EventsHeads => heads(shared, context, call),
        Handler::EventsSimilar => similar_page(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Maps a read's storage failure with `code` as Zig did: 401, 403 and 400 by kind and 503
/// for the rest; a database that failed is 503 `CONSOLEQUORUM`, as for every route.
pub(crate) fn read_error(failure: StorageFailure, code: &'static str) -> RouteError {
    let refused = match &failure {
        StorageFailure::Console(ConsoleStorageError::Storage(_)) => false,
        StorageFailure::Console(error) => !matches!(
            error.failure(),
            Failure::Unauthorized | Failure::Forbidden | Failure::InvalidInput
        ),
        _ => false,
    };
    if refused { RouteError::fail(503, code) } else { failure.route_error(code) }
}

/// A cursor as the interface sends it: the id as a decimal string.
struct CursorForm {
    time: u64,
    id: String,
}

impl Decode for CursorForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<CursorForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = CursorForm { time: fields.required("time")?, id: fields.required("id")? };
        fields.finish()?;
        Ok(form)
    }
}

impl CursorForm {
    fn cursor(&self) -> Result<Cursor, RouteError> {
        Ok(Cursor { time: self.time, id: decimal(&self.id)? })
    }
}

/// How an events page groups its rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Raw,
    Source,
}

impl WireEnum for View {
    const ALL: &'static [View] = &[View::Raw, View::Source];

    fn name(self) -> &'static str {
        match self {
            View::Raw => "raw",
            View::Source => "source",
        }
    }
}

/// How an export is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    /// The page's JSON text.
    Json,
    /// CSV with formula-like cells neutralised.
    Csv,
}

impl WireEnum for Format {
    const ALL: &'static [Format] = &[Format::Json, Format::Csv];

    fn name(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Csv => "csv",
        }
    }
}

/// The body of `events/query` and `events/export`.
struct EventsForm {
    view: View,
    format: Format,
    before: Option<CursorForm>,
    limit: u16,
    from: u64,
    until: Option<u64>,
    node: u32,
    campaign: String,
    incident: String,
    category: Text<32>,
    module: Option<Module>,
    country: country::Filter,
    ip: Text<48>,
    path_prefix: Text<256>,
    search: Text<MAX_SEARCH>,
}

impl Decode for EventsForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<EventsForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = EventsForm {
            view: fields.or("view", View::Raw)?,
            format: fields.or("format", Format::Json)?,
            before: fields.or_with("before", None, |value, path| match value {
                Value::Null => Ok(None),
                _ => CursorForm::decode(value, path).map(Some),
            })?,
            limit: fields.or("limit", 10)?,
            from: fields.or_default("from")?,
            until: fields.or_default("until")?,
            node: fields.or_default("node")?,
            campaign: fields.or_default("campaign")?,
            incident: fields.or_default("incident")?,
            category: fields.or_default("category")?,
            module: fields.or_default("module")?,
            country: fields.or_default("country")?,
            ip: fields.or_default("ip")?,
            path_prefix: fields.or_default("path_prefix")?,
            search: fields.or_default("search")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// Parses a campaign or incident filter: empty for none, else a decimal id.
fn identifier(text: &str) -> Result<u64, RouteError> {
    if text.is_empty() { Ok(0) } else { decimal(text) }
}

impl EventsForm {
    fn into_query(
        self,
        shared: &Shared,
        call: &Call,
        export: bool,
    ) -> Result<events::Query, RouteError> {
        Ok(events::Query {
            session_digest: [0; 32],
            require_totp: shared.config.behind_proxy,
            grouped: self.view == View::Source,
            export_page: export,
            before: self.before.as_ref().map(CursorForm::cursor).transpose()?,
            limit: self.limit,
            from: self.from,
            until: self.until.unwrap_or(i64::MAX as u64),
            node: self.node,
            campaign: identifier(&self.campaign)?,
            incident: identifier(&self.incident)?,
            category: self.category,
            country: self.country,
            module: self.module,
            ip: self.ip,
            path_prefix: self.path_prefix,
            search: self.search,
            client: Text::new(&call.origin.client).unwrap_or_default(),
        })
    }
}

/// Reads one events page; an export is audited by storage before its rows leave it.
/// Returns the format the form asked for with the page.
pub(crate) fn read_page(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    export: bool,
) -> Result<(Format, EventPage), RouteError> {
    let mut body = [0u8; 2048];
    let form: EventsForm = read_json(context, &mut body)?;
    let format = form.format;
    let input = form.into_query(shared, call, export)?;
    let credential = call.credential(shared)?;
    let now = call.now;
    let page = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { query_events(tx, &credential, &input, work_bound(), now).await })
        })
        .map_err(|failure| read_error(failure, "CONSOLEEVENTS"))?;
    Ok((format, page))
}

/// The body of `events/heads`.
struct HeadsForm {
    id: String,
}

impl Decode for HeadsForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<HeadsForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = HeadsForm { id: fields.required("id")? };
        fields.finish()?;
        Ok(form)
    }
}

/// `events/heads`: one incident's redacted heads.
fn heads(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    let mut body = [0u8; 256];
    let form: HeadsForm = read_json(context, &mut body)?;
    let input = Read {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        id: decimal(&form.id)?,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    let heads = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { read_heads(tx, &credential, &input, now).await })
        })
        .map_err(|failure| read_error(failure, "CONSOLEEVENTS"))?;
    Ok(reply::json(context, &heads)?)
}

/// The body of `events/similar`.
struct SimilarForm {
    source: String,
    generation: u32,
    from: u64,
    until: u64,
    before: Option<CursorForm>,
}

impl Decode for SimilarForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<SimilarForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = SimilarForm {
            source: fields.required("source")?,
            generation: fields.required("generation")?,
            from: fields.or_default("from")?,
            until: fields.required("until")?,
            before: fields.or_with("before", None, |value, path| match value {
                Value::Null => Ok(None),
                _ => CursorForm::decode(value, path).map(Some),
            })?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `events/similar`: one bounded scan for incidents near a source incident.
fn similar_page(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    let mut body = [0u8; 1024];
    let form: SimilarForm = read_json(context, &mut body)?;
    let input = similarity::Query {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        source: decimal(&form.source)?,
        from: form.from,
        until: form.until,
        before: form.before.as_ref().map(CursorForm::cursor).transpose()?,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    let part = shared
        .storage
        .transact(move |tx| Box::pin(async move { similar(tx, &credential, &input, now).await }))
        .map_err(|failure| read_error(failure, "CONSOLESIMILAR"))?;
    Ok(reply::json(context, &SimilarReply { part: &part, generation: form.generation })?)
}

/// A similarity scan in Zig's shape, with the interface's generation echoed.
struct SimilarReply<'a> {
    part: &'a Part,
    generation: u32,
}

impl Encode for SimilarReply<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let part = self.part;
        json.begin_object()?;
        field(json, "generation", &self.generation)?;
        field(json, "source_available", &part.source_available)?;
        field(json, "scanned", &part.scanned)?;
        field(json, "invalid", &part.invalid)?;
        json.key("rows")?;
        json.begin_array()?;
        for row in part.best.rows() {
            json.begin_object()?;
            json.key("id")?;
            decimal_string(json, row.id)?;
            field(json, "node", &row.node)?;
            field(json, "time", &row.time)?;
            field(json, "distance", &row.distance)?;
            json.end_object()?;
        }
        json.end_array()?;
        json.key("next")?;
        match part.next {
            Some(cursor) => {
                json.begin_object()?;
                field(json, "time", &cursor.time)?;
                json.key("id")?;
                decimal_string(json, cursor.id)?;
                json.end_object()?;
            }
            None => json.null()?,
        }
        json.end_object()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::{from_json, to_json};
    use sibuna_console_protocol::similarity::{Best, Match};

    #[test]
    fn events_forms_accept_the_interface_body() {
        let form: EventsForm = from_json(
            br#"{"format":"json","view":"raw","node":0,"campaign":"","incident":"",
            "before":null,"category":"","module":null,"country":"","ip":"","path_prefix":"",
            "until":172800,"from":0}"#,
        )
        .unwrap();
        assert_eq!((form.view, form.format, form.limit), (View::Raw, Format::Json, 10));
        let grouped: EventsForm = from_json(
            br#"{"view":"source","format":"csv","before":{"time":5,"id":"9007199254740993"},
            "module":"honeypot","search":"path:/admin"}"#,
        )
        .unwrap();
        assert_eq!(grouped.before.unwrap().cursor().unwrap().id, 9_007_199_254_740_993);
        assert_eq!(grouped.module, Some(Module::Honeypot));
        assert_eq!(identifier(""), Ok(0));
        assert_eq!(identifier("x"), Err(RouteError::BadRequest));
    }

    // similarity_routes.zig: "largest similarity response fits the bounded transport with
    // exact IDs".
    #[test]
    fn similarity_replies_keep_exact_ids() {
        let mut best = Best::default();
        for index in 0..10 {
            best.add(Match {
                id: u64::MAX - index,
                node: u32::MAX,
                time: u64::MAX,
                distance: 1.234_567_890_123_456,
            });
        }
        let part = Part { source_available: true, scanned: 64, invalid: 64, next: None, best };
        let text = to_json(&SimilarReply { part: &part, generation: u32::MAX });
        assert!(text.contains("\"18446744073709551615\""), "{text}");
        assert!(text.len() < 4096, "{}", text.len());
        assert!(text.ends_with(",\"next\":null}"));
        let form: SimilarForm = from_json(
            br#"{"source":"9007199254740993","generation":3,"before":null,"from":0,"until":200}"#,
        )
        .unwrap();
        assert_eq!(decimal(&form.source), Ok(9_007_199_254_740_993));
    }
}
