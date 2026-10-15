//! The Events page's actions and queries (Zig `events_actions.zig` and the event branches
//! of `main.zig`: `eventAction`, `eventQuery`, `incidentHeads`).

use std::fmt;

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::events::country::{self, Filter};
use sibuna_console_protocol::security::Module;
use sibuna_json::Value;

use super::heads::{self, Charset, Copied, IncidentHeads};
use super::model::{MAX_PAGES, Model};
use super::wire::{identifier, parse_integer};
use super::{Events, Investigation};
use crate::commands::{Field, Json, write_fields};
use crate::error::UiError;
use crate::json;
use crate::page::Context;
use crate::pages::similarity::Similarity;
use crate::scope;
use crate::state::Phase;

/// The largest identifier the server stores (`i64::MAX`).
const MAX_ID: u64 = i64::MAX as u64;

/// The time ranges the filter form offers, in hours.
const RANGES: [u32; 5] = [0, 1, 24, 168, 720];

/// What a query asks for: the page itself, or an export of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Query {
    /// The page, as a reply named `events`.
    View,
    /// A JSON download of the page.
    Json,
    /// A CSV download of the page.
    Csv,
}

impl Events {
    /// Handles the page's navigation, filter and paging actions; true when a query must
    /// follow (Zig `events_actions.act`).
    pub(super) fn act(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if !cx.state.is_full_access() {
            return Ok(false);
        }
        if self.country(cx, name)? || self.incident(cx, name)? || self.campaign(cx, name)? {
            return Ok(true);
        }
        let state = &mut *cx.state;
        let model = &mut self.model;
        if name == "events" {
            state.phase = Phase::Events;
            state.stats_busy = false;
            *model = Model { until: state.browser_time, ..Model::default() };
        } else {
            if state.phase != Phase::Events || model.busy {
                return Ok(false);
            }
            match name {
                "events-filter" => filter(model, fields, state.browser_time)?,
                "events-source" | "events-raw" => {
                    model.grouped = name == "events-source";
                    model.cursors.clear();
                }
                "events-next" => {
                    let Some(next) = model.next else { return Ok(false) };
                    if model.page() + 1 >= MAX_PAGES {
                        return Ok(false);
                    }
                    model.cursors.push(next);
                }
                "events-prev" => {
                    if model.cursors.pop().is_none() {
                        return Ok(false);
                    }
                }
                "events-refresh" => {
                    model.cursors.clear();
                    model.until = state.browser_time;
                    model.from = None;
                }
                _ => match name.strip_prefix("events-source-") {
                    Some(source) => select_source(model, source)?,
                    None => return Ok(false),
                },
            }
        }
        model.focus_results = name != "events";
        model.busy = true;
        model.export_ready = false;
        model.rows.clear();
        model.loaded = false;
        model.next = None;
        state.clear_message();
        Ok(true)
    }

    /// Opens the incidents of one country from the globe, for the last hour on the
    /// selected node; a wall display cannot leave its statistics.
    fn country(&mut self, cx: &mut Context<'_>, name: &str) -> Result<bool, UiError> {
        let Some(code) = name.strip_prefix("events-country-") else { return Ok(false) };
        if cx.state.kiosk {
            return Ok(false);
        }
        if code.is_empty() || !country::valid_filter(code) {
            return Err(UiError::InvalidRequest);
        }
        self.model = Model {
            country: Filter::new(code)?,
            node: scope::selected_node(cx.state).unwrap_or(0),
            until: cx.state.browser_time,
            hours: 1,
            busy: true,
            ..Model::default()
        };
        cx.state.phase = Phase::Events;
        cx.state.stats_busy = false;
        cx.state.clear_message();
        Ok(true)
    }

    /// Opens one incident (or clears the incident filter) from any page; a running
    /// similarity search pauses so its results survive the visit.
    fn incident(&mut self, cx: &mut Context<'_>, name: &str) -> Result<bool, UiError> {
        let clear = name == "events-clear-incident";
        let id = match name.strip_prefix("events-incident-") {
            _ if clear => 0,
            Some(text) => identifier(text)?,
            None => return Ok(false),
        };
        if id > MAX_ID || (!clear && id == 0) {
            return Err(UiError::InvalidRequest);
        }
        let until = cx.state.browser_time;
        self.model = Model { incident: id, until, busy: true, ..Model::default() };
        cx.state.phase = Phase::Events;
        if let Some(similarity) = cx.pages.find_mut::<Similarity>() {
            similarity.model.running = false;
        }
        cx.state.clear_message();
        Ok(true)
    }

    /// Narrows the page to one campaign candidate (or clears that filter). Membership
    /// spans addresses and nodes, so only the reader's time boundary is kept.
    fn campaign(&mut self, cx: &mut Context<'_>, name: &str) -> Result<bool, UiError> {
        let clear = name == "events-clear-campaign";
        let text = name.strip_prefix("events-campaign-");
        if !clear && text.is_none() {
            return Ok(false);
        }
        if cx.state.phase != Phase::Events || self.model.busy {
            return Ok(false);
        }
        let id = match text {
            Some(text) if !clear => identifier(text)?,
            _ => 0,
        };
        if id > MAX_ID || (!clear && id == 0) {
            return Err(UiError::InvalidRequest);
        }
        let (until, hours) = (self.model.until, self.model.hours);
        self.model = Model {
            campaign: id,
            until,
            hours,
            busy: true,
            focus_results: true,
            ..Model::default()
        };
        cx.state.clear_message();
        Ok(true)
    }

    /// Starts an export download of the page shown; ignored while one is in flight or
    /// the page is empty.
    pub(super) fn export(&mut self, cx: &mut Context<'_>, csv: bool) -> Result<(), UiError> {
        let model = &mut self.model;
        if model.busy || model.exporting || model.rows.is_empty() {
            return Ok(());
        }
        model.exporting = true;
        model.export_ready = false;
        cx.state.clear_message();
        query(model, cx, if csv { Query::Csv } else { Query::Json })
    }

    /// Handles the heads actions of the incident details: load, charset and copy.
    pub(super) fn heads_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
    ) -> Result<bool, UiError> {
        let Some(rest) = name.strip_prefix("events-heads-") else { return Ok(false) };
        if cx.state.phase != Phase::Events || !cx.state.is_full_access() {
            return Ok(false);
        }
        let model = &mut self.heads;
        match rest {
            "utf8" => model.charset = Charset::Utf8,
            "latin1" => model.charset = Charset::Latin1,
            "copy" => {
                // The plain command, not its HTML rendering, goes to the clipboard.
                if !model.loaded {
                    return Ok(true);
                }
                let Some(command) = heads::curl(&model.request, model.request_truncated) else {
                    return Ok(true);
                };
                model.copied = Copied::None;
                cx.commands.copy("events-heads-copy", &command)?;
            }
            _ => {
                let Some(id) = parse_integer::<u64>(rest) else { return Ok(false) };
                if model.busy {
                    return Ok(true);
                }
                *model = IncidentHeads { id, busy: true, ..IncidentHeads::default() };
                cx.post("events-heads", "/console/api/events/heads", |json| {
                    write_fields(json, &[("id", Field::Text(rest))])
                })?;
            }
        }
        Ok(true)
    }

    /// Opens the incidents behind a security overview row: the summary's node, period and
    /// selection, with the page's other filters cleared, and sends the query. The caller
    /// has checked that the session has full access, is not a wall display and shows the
    /// security overview (Zig `security_investigation.open`).
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the query cannot be written.
    pub fn investigate(
        &mut self,
        cx: &mut Context<'_>,
        investigation: Investigation,
    ) -> Result<(), UiError> {
        self.model = Model {
            module: investigation.module,
            category: investigation.category,
            ip: investigation.ip,
            path: investigation.path,
            node: investigation.node,
            from: Some(investigation.from),
            // Incident queries use inclusive endpoints; the summary's upper boundary is
            // exclusive.
            until: investigation.until.saturating_sub(1),
            hours: investigation.hours,
            busy: true,
            ..Model::default()
        };
        cx.state.phase = Phase::Events;
        cx.state.clear_message();
        query(&self.model, cx, Query::View)
    }
}

/// Applies the filter form. Every field is checked before any changes, so a refused form
/// leaves the query as it was.
fn filter(model: &mut Model, fields: &Value<'_>, browser_time: u64) -> Result<(), UiError> {
    let module_name = json::string(fields, "module");
    let module = Module::from_name(module_name);
    if !module_name.is_empty() && module.is_none() {
        return Err(UiError::InvalidRequest);
    }
    let category = Text::new(json::string(fields, "category"))?;
    let code = json::string(fields, "country");
    if !country::valid_filter(code) {
        return Err(UiError::InvalidRequest);
    }
    let country = Filter::new(code)?;
    let ip = Text::new(json::string(fields, "ip"))?;
    let path = Text::new(json::string(fields, "path_prefix"))?;
    let hours = parse_integer(json::string(fields, "hours")).ok_or(UiError::InvalidRequest)?;
    if !RANGES.contains(&hours) {
        return Err(UiError::InvalidRequest);
    }
    let node = match json::string(fields, "node") {
        "" => 0,
        text => parse_integer(text).ok_or(UiError::InvalidRequest)?,
    };
    model.module = module;
    model.from = None;
    model.category = category;
    model.country = country;
    model.ip = ip;
    model.path = path;
    model.node = node;
    model.hours = hours;
    model.cursors.clear();
    model.until = browser_time;
    Ok(())
}

/// Narrows the page to the raw incidents of one grouped source, `node/address`.
fn select_source(model: &mut Model, source: &str) -> Result<(), UiError> {
    let (node, address) = source.split_once('/').ok_or(UiError::InvalidRequest)?;
    let node = parse_integer(node).ok_or(UiError::InvalidRequest)?;
    model.ip = Text::new(address)?;
    model.node = node;
    model.grouped = false;
    model.cursors.clear();
    Ok(())
}

/// Sends the page's query, or an export of it, with the bridge's request or download
/// command (Zig `eventQuery`).
pub(super) fn query(model: &Model, cx: &mut Context<'_>, kind: Query) -> Result<(), UiError> {
    let csrf = cx.state.csrf.as_str();
    let (op, id, path) = match kind {
        Query::View => ("request", "events", "/console/api/events/query"),
        Query::Json | Query::Csv => ("download", "events-export", "/console/api/events/export"),
    };
    let csv = kind == Query::Csv;
    let filename = if csv { "sibuna-events.csv" } else { "sibuna-events.json" };
    cx.commands.emit(|json| {
        json.begin_object()?;
        let envelope =
            [("op", op), ("id", id), ("method", "POST"), ("filename", filename), ("path", path)];
        for (key, value) in envelope.into_iter().chain([("csrf", csrf)]) {
            json.key(key)?;
            json.string(value)?;
        }
        json.key("body")?;
        query_body(json, model, csv)?;
        json.end_object()
    })
}

/// Writes the query body in the member order of the Zig module.
fn query_body(json: &mut Json<'_>, model: &Model, csv: bool) -> fmt::Result {
    let identifier = |id: u64| if id == 0 { String::new() } else { id.to_string() };
    json.begin_object()?;
    json.key("format")?;
    json.string(if csv { "csv" } else { "json" })?;
    json.key("view")?;
    json.string(if model.grouped { "source" } else { "raw" })?;
    json.key("node")?;
    json.uint(u64::from(model.node))?;
    json.key("campaign")?;
    json.string(&identifier(model.campaign))?;
    json.key("incident")?;
    json.string(&identifier(model.incident))?;
    json.key("before")?;
    match model.cursors.last() {
        Some(cursor) => write_fields(
            json,
            &[("time", Field::Unsigned(cursor.time)), ("id", Field::Text(&cursor.id.to_string()))],
        )?,
        None => json.null()?,
    }
    let text = |json: &mut Json<'_>, key: &str, value: &str| {
        json.key(key)?;
        json.string(value)
    };
    text(json, "category", model.category.as_str())?;
    json.key("module")?;
    match model.module {
        Some(module) => json.string(module.name())?,
        None => json.null()?,
    }
    text(json, "country", model.country.as_str())?;
    text(json, "ip", model.ip.as_str())?;
    text(json, "path_prefix", model.path.as_str())?;
    json.key("until")?;
    json.uint(model.until)?;
    json.key("from")?;
    json.uint(model.range_start())?;
    json.end_object()
}
