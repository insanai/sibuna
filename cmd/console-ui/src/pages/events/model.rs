//! The Events page's query and its current page of incidents (Zig `events_state.zig`).

use sibuna_console_protocol::Text;
use sibuna_console_protocol::events::country::{self, Filter, Mapping};
use sibuna_console_protocol::events::{Capture, Cursor, MAX_LIMIT, Row};
use sibuna_console_protocol::security::Module;
use sibuna_json::Value;

use super::wire::{self, boolean, counter, nullable, number, or, required, text};
use crate::error::UiError;

/// The most incidents one page shows.
pub const PAGE_ROWS: usize = MAX_LIMIT as usize;

/// The most pages a reader may page through before narrowing the query. The operator sees
/// this bound: the footer asks for a narrower range when it is reached.
pub const MAX_PAGES: usize = 64;

/// The query of the Events page and the page of incidents it returned.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Model {
    /// The incidents (or address groups) shown, at most [`PAGE_ROWS`].
    pub rows: Vec<Row>,
    /// A page has arrived for the current query.
    pub loaded: bool,
    /// A query is in flight.
    pub busy: bool,
    /// Move focus to the results when they arrive.
    pub focus_results: bool,
    /// Group incidents by source address.
    pub grouped: bool,
    /// An export download is in flight.
    pub exporting: bool,
    /// The last export succeeded; the message then reads as a note, not a problem.
    pub export_ready: bool,
    /// One node, or 0 for all.
    pub node: u32,
    /// One campaign candidate, or 0 for none.
    pub campaign: u64,
    /// One incident, or 0 for none.
    pub incident: u64,
    /// Where the next page starts, when there is one.
    pub next: Option<Cursor>,
    /// The cursors that opened the pages after the first; the page shown is the
    /// `cursors.len()`-th after the first. At most [`MAX_PAGES`] minus one.
    pub cursors: Vec<Cursor>,
    /// One category, or empty for all.
    pub category: Text<32>,
    /// A country filter (`country::valid_filter`).
    pub country: Filter,
    /// One client address, or empty for all.
    pub ip: Text<48>,
    /// A path prefix, or empty for all.
    pub path: Text<256>,
    /// The time range in hours (0, 1, 24, 168 or 720); 0 for all recorded time.
    pub hours: u32,
    /// The fixed start of a security drill-down period, in Unix seconds.
    pub from: Option<u64>,
    /// One finding source, or `None` for all.
    pub module: Option<Module>,
    /// The page's fixed upper time boundary, in Unix seconds.
    pub until: u64,
}

impl Model {
    /// Returns the index of the page shown, 0 for the first.
    pub fn page(&self) -> usize {
        self.cursors.len()
    }

    /// Returns the start of the query's time range, in Unix seconds.
    pub fn range_start(&self) -> u64 {
        self.from.unwrap_or(match self.hours {
            0 => 0,
            hours => self.until.saturating_sub(u64::from(hours) * 3600),
        })
    }

    /// Takes a page of incidents. Nothing changes unless the whole page is valid.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for an identifier that is not a decimal number, an
    /// unknown evidence version or an invalid country; [`UiError::TooLarge`] for text
    /// beyond its field.
    pub fn accept(&mut self, page: &WirePage<'_>) -> Result<(), UiError> {
        if page.rows.len() > PAGE_ROWS {
            return Err(UiError::InvalidResponse);
        }
        let rows = page.rows.iter().map(WireRow::row).collect::<Result<Vec<Row>, UiError>>()?;
        let next = match page.next {
            Some((time, id)) => Some(Cursor { time, id: decimal(id)? }),
            None => None,
        };
        self.rows = rows;
        self.next = next;
        self.loaded = true;
        Ok(())
    }
}

/// Parses an identifier the server sent as a decimal string.
fn decimal(text: &str) -> Result<u64, UiError> {
    crate::json::parse_integer(text).ok_or(UiError::InvalidResponse)
}

/// A page of incidents as it crosses the wire, borrowing the reply.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WirePage<'v> {
    /// The rows, at most [`PAGE_ROWS`].
    pub rows: Vec<WireRow<'v>>,
    /// The next cursor: its time and its id as decimal text.
    pub next: Option<(u64, &'v str)>,
}

impl<'v> WirePage<'v> {
    /// Reads a page with the defaults of the Zig wire struct.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] when a member has the wrong type or there are more
    /// than [`PAGE_ROWS`] rows.
    pub fn read(value: &'v Value<'_>) -> Result<WirePage<'v>, UiError> {
        let value = wire::object(value)?;
        let rows = or(value, "rows", &[][..], |rows| wire::list(rows, PAGE_ROWS))?;
        let rows = rows.iter().map(WireRow::read).collect::<Result<Vec<_>, UiError>>()?;
        let next = or(value, "next", None, nullable(cursor))?;
        Ok(WirePage { rows, next })
    }
}

fn cursor<'v>(value: &'v Value<'_>) -> Option<(u64, &'v str)> {
    let value = wire::object(value).ok()?;
    Some((required(value, "time", counter).ok()?, required(value, "id", text).ok()?))
}

/// One incident row as it crosses the wire.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WireRow<'v> {
    /// The country attribution.
    pub geography: country::Wire<'v>,
    /// The incident id as decimal text.
    pub id: &'v str,
    /// A group of incidents from one address.
    pub grouped: bool,
    /// Incidents in the group.
    pub count: u64,
    /// The group's first time.
    pub first_seen: u64,
    /// The recording node.
    pub node: u32,
    /// The incident time.
    pub time: u64,
    /// The client address.
    pub ip: &'v str,
    /// The request method.
    pub method: &'v str,
    /// The request path.
    pub path: &'v str,
    /// The finding category.
    pub category: &'v str,
    /// The User-Agent.
    pub user_agent: &'v str,
    /// The query string was redacted.
    pub query_redacted: bool,
    /// A display field was truncated.
    pub display_truncated: bool,
    /// The campaign id as decimal text.
    pub campaign: Option<&'v str>,
    /// Capture metadata.
    pub capture: Option<Capture>,
}

impl<'v> WireRow<'v> {
    fn read(value: &'v Value<'_>) -> Result<WireRow<'v>, UiError> {
        let value = wire::object(value)?;
        let geography = match crate::json::field(value, "geography") {
            None => country::Wire::default(),
            Some(item) => geography(item)?,
        };
        Ok(WireRow {
            geography,
            id: required(value, "id", text)?,
            grouped: or(value, "grouped", false, boolean)?,
            count: or(value, "count", 1, counter)?,
            first_seen: or(value, "first_seen", 0, counter)?,
            node: or(value, "node", 0, number)?,
            time: or(value, "time", 0, counter)?,
            ip: or(value, "ip", "", text)?,
            method: or(value, "method", "", text)?,
            path: or(value, "path", "", text)?,
            category: or(value, "category", "", text)?,
            user_agent: or(value, "user_agent", "", text)?,
            query_redacted: or(value, "query_redacted", false, boolean)?,
            display_truncated: or(value, "display_truncated", false, boolean)?,
            campaign: or(value, "campaign", None, nullable(text))?,
            capture: or(value, "capture", None, nullable(|item| capture(item).ok()))?,
        })
    }

    /// Builds the row, as `events_state.Model.decode` did for each wire row.
    fn row(&self) -> Result<Row, UiError> {
        if self.capture.is_some_and(|capture| capture.version != 1) {
            return Err(UiError::InvalidResponse);
        }
        Ok(Row {
            id: decimal(self.id)?,
            grouped: self.grouped,
            count: self.count,
            first_seen: self.first_seen,
            node: self.node,
            time: self.time,
            ip: Text::new(self.ip)?,
            method: Text::new(self.method)?,
            path: Text::new(self.path)?,
            category: Text::new(self.category)?,
            user_agent: Text::new(self.user_agent)?,
            query_redacted: self.query_redacted,
            display_truncated: self.display_truncated,
            capture: self.capture,
            geography: Mapping::from_wire(self.geography).map_err(|_| UiError::InvalidResponse)?,
            campaign: self.campaign.map(decimal).transpose()?,
        })
    }
}

fn geography<'v>(value: &'v Value<'_>) -> Result<country::Wire<'v>, UiError> {
    let value = wire::object(value)?;
    Ok(country::Wire {
        code: or(value, "code", None, nullable(text))?,
        generation: or(value, "generation", None, nullable(text))?,
        mixed: or(value, "mixed", false, boolean)?,
        recorded: or(value, "recorded", false, boolean)?,
    })
}

fn capture(value: &Value<'_>) -> Result<Capture, UiError> {
    let value = wire::object(value)?;
    Ok(Capture {
        version: or(value, "version", 1, number)?,
        selected_status: required(value, "selected_status", number)?,
        query_bytes: required(value, "query_bytes", number)?,
        body_bytes: required(value, "body_bytes", number)?,
        declared_body_bytes: required(value, "declared_body_bytes", number)?,
        truncated: required(value, "truncated", number)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ported from `events_state.zig`: a reset restores every default.
    #[test]
    fn event_reset_restores_every_default() {
        let mut model =
            Model { loaded: true, next: Some(Cursor { time: 10, id: 8 }), ..Model::default() };
        model.rows.push(Row {
            path: Text::new("private incident path").unwrap(),
            capture: Some(Capture {
                selected_status: 403,
                query_bytes: 1,
                body_bytes: 2,
                declared_body_bytes: 2,
                ..Capture::default()
            }),
            ..Row::default()
        });
        model = Model::default();
        assert_eq!(model, Model::default());
        assert!(model.rows.is_empty());
    }

    #[test]
    fn pages_take_wire_defaults_and_refuse_bad_rows_whole() {
        let body = sibuna_json::parse(
            br#"{"rows":[{"id":"9007199254740993","campaign":"7","extra":1,
            "capture":{"selected_status":403,"query_bytes":1,"body_bytes":2,
            "declared_body_bytes":3,"truncated":64}}],"next":{"time":5,"id":"4"}}"#,
        )
        .unwrap();
        let page = WirePage::read(&body).unwrap();
        let mut model = Model::default();
        model.accept(&page).unwrap();
        assert_eq!(model.rows[0].id, 9_007_199_254_740_993);
        assert_eq!(model.rows[0].count, 1);
        assert_eq!(model.rows[0].campaign, Some(7));
        assert_eq!(model.next, Some(Cursor { time: 5, id: 4 }));
        let before = model.clone();
        let bad = sibuna_json::parse(br#"{"rows":[{"id":"1"},{"id":"x"}]}"#).unwrap();
        assert_eq!(model.accept(&WirePage::read(&bad).unwrap()), Err(UiError::InvalidResponse));
        assert_eq!(model, before);
        let version = sibuna_json::parse(
            br#"{"rows":[{"id":"1","capture":{"version":2,"selected_status":403,
            "query_bytes":0,"body_bytes":0,"declared_body_bytes":0,"truncated":0}}]}"#,
        )
        .unwrap();
        assert!(model.accept(&WirePage::read(&version).unwrap()).is_err());
        let eleven = format!("{{\"rows\":[{}]}}", ["{\"id\":\"1\"}"; 11].join(","));
        let eleven = sibuna_json::parse(eleven.as_bytes()).unwrap();
        assert!(WirePage::read(&eleven).is_err());
        assert!(WirePage::read(&Value::Null).is_err());
        assert_eq!(WirePage::read(&sibuna_json::parse(b"{}").unwrap()), Ok(WirePage::default()));
    }
}
