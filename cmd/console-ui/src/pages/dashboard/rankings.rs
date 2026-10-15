//! Sampled request paths of the current minute, with referring hosts and client
//! families (`rankings_controller.zig`, `rankings_panel.zig`). Request ids are serial and
//! survive sign-out, so a reply to an old session is never taken.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::client_family::{self, Browser, Os};
use sibuna_console_protocol::ranking_storage::Families;
use sibuna_console_protocol::rankings::{self, Encoding};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::Dashboard;
use crate::error::UiError;
use crate::json;
use crate::render::Html;
use crate::scope;
use crate::snippets;
use crate::state::{Phase, State};

/// The id prefix of ranking reads.
pub(super) const PREFIX: &str = "rankings-";

/// Operating-system families by histogram slot.
pub const OS_SLOTS: [Os; 8] =
    [Os::Unknown, Os::Windows, Os::Macos, Os::Ios, Os::Android, Os::Linux, Os::Other, Os::Bot];

/// Browser families by histogram slot.
pub const BROWSER_SLOTS: [Browser; 8] = [
    Browser::Unknown,
    Browser::Chrome,
    Browser::Firefox,
    Browser::Safari,
    Browser::Edge,
    Browser::Opera,
    Browser::Bot,
    Browser::Other,
];

/// One ranked key with its sample bounds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// The path prefix or host, as sent (hex digits for `hex` keys).
    pub key: Text<256>,
    /// How the key is written.
    pub encoding: Encoding,
    /// The upper bound of the key's samples.
    pub estimate: u64,
    /// How much the estimate may exceed the samples.
    pub error_bound: u64,
}

/// The shown rankings and their request state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    /// At most [`rankings::MAX_ROWS`] path rows.
    pub rows: Vec<Row>,
    /// At most [`rankings::MAX_ROWS`] referring hosts.
    pub referrers: Vec<Row>,
    /// Samples that carried a referring host.
    pub referrer_retained: u64,
    /// Exact histograms of client families and statuses.
    pub families: Families,
    /// The node the rankings belong to.
    pub node: u32,
    /// The ticket of the latest request; 0 for none.
    pub generation: u32,
    /// A request is outstanding.
    pub busy: bool,
    /// Rankings were decoded.
    pub loaded: bool,
    /// The shown rankings are not current.
    pub stale: bool,
    /// When the latest request was sent, in browser seconds.
    pub requested_at: u64,
    /// When the shown rankings arrived, in browser seconds.
    pub received_at: u64,
    /// The minute's start, in Unix seconds.
    pub minute_start: u64,
    /// Samples retained (N).
    pub retained: u64,
    /// Samples whose key was truncated.
    pub truncated: u64,
    /// Samples refused.
    pub rejected: u64,
    /// Samples lost to a full queue since boot.
    pub queue_loss: u64,
}

impl Default for Model {
    fn default() -> Model {
        Model {
            rows: Vec::new(),
            referrers: Vec::new(),
            referrer_retained: 0,
            families: Families::default(),
            node: 0,
            generation: 0,
            busy: false,
            loaded: false,
            stale: true,
            requested_at: 0,
            received_at: 0,
            minute_start: 0,
            retained: 0,
            truncated: 0,
            rejected: 0,
            queue_loss: 0,
        }
    }
}

/// Reads member `key` as an unsigned integer literal.
fn unsigned(value: &Value<'_>, key: &str) -> Result<u64, UiError> {
    json::field(value, key).map_or(Err(UiError::InvalidResponse), unsigned_value)
}

/// Reads an unsigned integer literal (Zig's `integer` or `number_string`); strings and
/// fractions are refused.
fn unsigned_value(value: &Value<'_>) -> Result<u64, UiError> {
    let number = value.as_number().filter(|number| number.is_integer_literal());
    number.and_then(|number| number.as_u64().ok()).ok_or(UiError::InvalidResponse)
}

impl Model {
    /// Takes a rankings reply; nothing changes unless the whole reply is valid. Older
    /// nodes answer without referrers or families; both then stay empty.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for another kind, capacity or probability, more than
    /// [`rankings::MAX_ROWS`] rows, an invalid row or histogram, or a missing counter.
    pub fn decode(&mut self, value: &Value<'_>) -> Result<(), UiError> {
        let rows = json::field(value, "rows").ok_or(UiError::InvalidResponse)?;
        let too_many = rows.as_array().is_none_or(|rows| rows.len() > rankings::MAX_ROWS);
        if too_many
            || unsigned(value, "counter_capacity")? != 256
            || json::string(value, "kind") != "path_prefix"
            || json::string(value, "sampling_probability") != "1/64"
        {
            return Err(UiError::InvalidResponse);
        }
        let mut next = Model {
            generation: self.generation,
            busy: self.busy,
            requested_at: self.requested_at,
            ..Model::default()
        };
        next.retained = unsigned(value, "retained_samples")?;
        next.rows = read_rows(rows, next.retained)?;
        if let Some(hosts) = json::field(value, "referrers") {
            next.referrer_retained = unsigned(value, "referrer_samples")?;
            if next.referrer_retained > next.retained {
                return Err(UiError::InvalidResponse);
            }
            next.referrers = read_rows(hosts, next.referrer_retained)?;
        }
        if let Some(families) = json::field(value, "families") {
            next.families = read_families(families, next.retained)?;
        }
        if json::field(value, "node").is_some() {
            next.node =
                u32::try_from(unsigned(value, "node")?).map_err(|_| UiError::InvalidResponse)?;
        }
        next.minute_start = unsigned(value, "minute_start")?;
        next.truncated = unsigned(value, "truncated_records")?;
        next.rejected = unsigned(value, "rejected_records")?;
        next.queue_loss = unsigned(value, "queue_loss_since_boot")?;
        next.loaded = true;
        next.stale = false;
        *self = next;
        Ok(())
    }
}

/// Reads at most [`rankings::MAX_ROWS`] rows whose bounds respect `retained` samples.
fn read_rows(source: &Value<'_>, retained: u64) -> Result<Vec<Row>, UiError> {
    let items = source.as_array().ok_or(UiError::InvalidResponse)?;
    if items.len() > rankings::MAX_ROWS {
        return Err(UiError::InvalidResponse);
    }
    items
        .iter()
        .map(|row| {
            let encoding = match json::string(row, "encoding") {
                "hex" => Encoding::Hex,
                "utf8" => Encoding::Utf8,
                _ => return Err(UiError::InvalidResponse),
            };
            let key = json::field(row, "key").and_then(Value::as_str);
            let limit = if encoding == Encoding::Hex { 256 } else { 128 };
            let key = key.filter(|key| key.len() <= limit).ok_or(UiError::InvalidResponse)?;
            let estimate = unsigned(row, "estimate")?;
            let error_bound = unsigned(row, "error_bound")?;
            if error_bound > estimate || error_bound > retained / 256 {
                return Err(UiError::InvalidResponse);
            }
            Ok(Row { key: Text::new(key)?, encoding, estimate, error_bound })
        })
        .collect()
}

/// Reads the three exact histograms; each sums to at most `retained`.
fn read_families(value: &Value<'_>, retained: u64) -> Result<Families, UiError> {
    let mut families = Families::default();
    let axes: [(&str, &mut [u64]); 3] = [
        ("os", &mut families.os),
        ("browser", &mut families.browser),
        ("status", &mut families.status),
    ];
    for (name, target) in axes {
        let list = json::field(value, name).and_then(Value::as_array);
        let list =
            list.filter(|list| list.len() == target.len()).ok_or(UiError::InvalidResponse)?;
        let mut total: u64 = 0;
        for (item, slot) in list.iter().zip(target.iter_mut()) {
            *slot = unsigned_value(item)?;
            total = total.checked_add(*slot).ok_or(UiError::InvalidResponse)?;
        }
        if total > retained {
            return Err(UiError::InvalidResponse);
        }
    }
    Ok(families)
}

/// Returns the id of the next rankings request, or `None` when none is due (one at a
/// time, at most every ten seconds).
pub(super) fn request(dashboard: &mut Dashboard, state: &State) -> Option<String> {
    let model = &mut dashboard.rankings;
    if scope::needs_retained_node(state)
        || !state.is_full_access()
        || state.kiosk
        || state.phase != Phase::Dashboard
        || state.paused
        || state.hidden
    {
        return None;
    }
    let recent =
        model.generation != 0 && state.browser_time.saturating_sub(model.requested_at) < 10;
    if model.busy || recent {
        return None;
    }
    let ticket = super::next_ticket(&mut dashboard.serials.rankings);
    model.generation = ticket;
    model.requested_at = state.browser_time;
    model.busy = true;
    Some(format!("{PREFIX}{ticket}"))
}

/// Handles a rankings reply; returns true when the session expired.
pub(super) fn response(
    model: &mut Model,
    state: &State,
    id: &str,
    status: i64,
    body: &Value<'_>,
) -> bool {
    let Some(ticket) = super::reply_ticket(id, PREFIX).and_then(|t| u32::try_from(t).ok()) else {
        return false;
    };
    if ticket == 0 || ticket != model.generation {
        return false;
    }
    model.busy = false;
    if !state.is_full_access() || state.kiosk || state.phase != Phase::Dashboard || state.paused {
        return false;
    }
    if status == 401 || status == 403 {
        return true;
    }
    model.stale = true;
    if status != 200 {
        return false;
    }
    if let Some(node) = scope::selected_node(state) {
        let echoed = json::field(body, "node").and_then(json::integer);
        if echoed != Some(i64::from(node)) {
            return false;
        }
    }
    if model.decode(body).is_ok() {
        model.received_at = state.browser_time;
    }
    false
}

/// Draws the rankings of the dashboard: a note when several nodes are combined (partial
/// winner lists cannot be summed), the panel otherwise.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn render(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    if scope::needs_retained_node(state) {
        return out.write_str(
            "<section class=\"sb-panel mt-6\"><h2>Sampled request paths</h2><p \
             class=\"sb-note\">Select one node for current-minute path rankings. Partial \
             winner lists cannot establish a cluster-wide ranking.</p></section>",
        );
    }
    panel(model, out, state.browser_time, state.paused || state.stale)
}

/// Draws the path panel and the other sampled panels of the same minute.
fn panel(model: &Model, out: &mut Html<'_>, now: u64, paused: bool) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel mt-6\" aria-labelledby=\"ranking-heading\"><h2 \
         id=\"ranking-heading\">Sampled request paths</h2><p class=\"sb-note\">Selected node \
         \u{b7} partial UTC minute \u{b7} updates every 10 seconds. Counts show samples at 1/64 \
         probability. 128-byte path prefixes. Sample counts lie between the bounds.</p>",
    )?;
    if !model.loaded {
        out.write_str("<p role=\"status\">")?;
        out.write_str(if model.generation != 0 && !model.busy {
            "Rankings unavailable. Retrying."
        } else {
            "Waiting for live path samples."
        })?;
        return out.write_str("</p></section>");
    }
    out.write_str("<p class=\"sb-note\">Node ")?;
    write_value(out, &model.node)?;
    out.write_str("</p>")?;
    let stale = model.stale || paused || now.saturating_sub(model.received_at) > 20;
    let (hour, minute) = (model.minute_start / 3600 % 24, model.minute_start / 60 % 60);
    out.write_str("<p class=\"sb-note\">Minute ")?;
    write!(out, "{hour:02}:{minute:02}")?;
    out.write_str(" UTC \u{b7} Up to 12 of 256 tracked prefixes.</p><p class=\"sb-note\">")?;
    out.write_str(if stale { "Stale or paused" } else { "Live" })?;
    out.write_str(" \u{b7} Updated ")?;
    write_value(out, &now.saturating_sub(model.received_at))?;
    let figures = [
        (" seconds ago \u{b7} ", model.retained),
        (" retained samples \u{b7} ", model.truncated),
        (" truncated sample records \u{b7} ", model.rejected),
        (" rejected samples \u{b7} ", model.queue_loss),
    ];
    for (text, figure) in figures {
        out.write_str(text)?;
        write_value(out, &figure)?;
    }
    out.write_str(
        " lost queue samples since boot.</p><div class=\"overflow-x-auto\"><table \
         class=\"table\"><caption class=\"sb-note\">Sample count bounds</caption><thead><tr>\
         <th>Path prefix</th><th>Estimate</th><th>Lower bound</th></tr></thead><tbody>",
    )?;
    rows(&model.rows, out)?;
    if model.rows.is_empty() {
        out.write_str("<tr><td colspan=\"3\">No path samples this minute.</td></tr>")?;
    }
    out.write_str("</tbody></table></div></section>")?;
    sampled(model, out)
}

/// Draws ranked rows with the `ranking-row` snippet.
fn rows(rows: &[Row], out: &mut Html<'_>) -> fmt::Result {
    for row in rows {
        snippets::render_ranking_row(
            out,
            &snippets::RankingRowValues {
                key: &row.key.as_str(),
                encoding: &if row.encoding == Encoding::Hex { " (hex bytes)" } else { "" },
                estimate: &row.estimate,
                lower: &row.estimate.saturating_sub(row.error_bound),
            },
        )?;
    }
    Ok(())
}

/// Draws the referring hosts and the client-family and status histograms of the minute.
fn sampled(model: &Model, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<div class=\"sb-panels\"><section class=\"sb-panel mt-6\" \
         aria-labelledby=\"referrer-heading\"><h2 id=\"referrer-heading\">Sampled referring \
         hosts</h2><p class=\"sb-note\">Same minute and 1/64 sampling. Host prefixes of 24 \
         bytes; ",
    )?;
    write_value(out, &model.referrer_retained)?;
    out.write_str(" of ")?;
    write_value(out, &model.retained)?;
    out.write_str(
        " retained samples carried a Referer.</p><div class=\"overflow-x-auto\"><table \
         class=\"table\"><caption class=\"sb-note\">Sample count bounds</caption><thead><tr>\
         <th>Referring host</th><th>Estimate</th><th>Lower bound</th></tr></thead><tbody>",
    )?;
    rows(&model.referrers, out)?;
    if model.referrers.is_empty() {
        out.write_str("<tr><td colspan=\"3\">No referring host samples this minute.</td></tr>")?;
    }
    out.write_str("</tbody></table></div></section>")?;
    let families = &model.families;
    let os = families.os.iter().zip(OS_SLOTS.map(client_family::os_label));
    histogram(out, "Sampled client operating systems", "Operating system", os)?;
    let browsers = families.browser.iter().zip(BROWSER_SLOTS.map(client_family::browser_label));
    histogram(out, "Sampled browsers", "Browser", browsers)?;
    let statuses = families.status.iter().enumerate();
    let statuses = statuses.map(|(slot, count)| (count, client_family::status_label(slot)));
    histogram(out, "Sampled response status", "Status", statuses)?;
    out.write_str("</div>")
}

/// Draws one exact histogram of `(count, label)` pairs, skipping empty labels.
fn histogram<'a>(
    out: &mut Html<'_>,
    title: &str,
    column: &str,
    counts: impl Iterator<Item = (&'a u64, &'static str)>,
) -> fmt::Result {
    out.write_str("<section class=\"sb-panel mt-6\"><h2>")?;
    out.escaped(title)?;
    out.write_str(
        "</h2><p class=\"sb-note\">Exact counts over the minute's 1/64 samples; labels are \
         display families from the User-Agent, never an admission input.</p><div \
         class=\"overflow-x-auto\"><table class=\"table\"><thead><tr><th>",
    )?;
    out.escaped(column)?;
    out.write_str("</th><th>Samples</th></tr></thead><tbody>")?;
    let mut shown = 0;
    for (count, label) in counts.filter(|(count, _)| **count != 0) {
        shown += 1;
        out.write_str("<tr><th scope=\"row\">")?;
        out.escaped(label)?;
        out.write_str("</th><td>")?;
        write_value(out, count)?;
        out.write_str("</td></tr>")?;
    }
    if shown == 0 {
        out.write_str("<tr><td colspan=\"2\">No samples this minute.</td></tr>")?;
    }
    out.write_str("</tbody></table></div></section>")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"{"kind":"path_prefix","counter_capacity":256,
        "sampling_probability":"1/64","minute_start":120,"retained_samples":5,
        "truncated_records":0,"rejected_records":0,"queue_loss_since_boot":0,
        "rows":[ROWS],"referrer_samples":2,
        "referrers":[{"key":"news.example.test","encoding":"utf8","estimate":2,"error_bound":0}],
        "families":{"os":[0,0,0,0,0,5,0,0],"browser":[0,0,5,0,0,0,0,0],
        "status":[3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0]}}"#;
    const ROW: &str = r#"{"key":"/<script>","encoding":"utf8","estimate":5,"error_bound":0}"#;

    fn decode(model: &mut Model, rows: usize) -> Result<(), UiError> {
        let text = SOURCE.replace("ROWS", &vec![ROW; rows].join(","));
        model.decode(&sibuna_json::parse(text.as_bytes()).unwrap())
    }

    #[test]
    fn rankings_own_their_keys_refuse_excess_rows_atomically_and_escape_paths() {
        let mut model = Model::default();
        decode(&mut model, 1).unwrap();
        assert_eq!(model.rows[0].key.as_str(), "/<script>");
        let old = model.clone();
        assert_eq!(decode(&mut model, 13), Err(UiError::InvalidResponse));
        assert_eq!(model, old);
        let mut text = String::new();
        panel(&model, &mut Html::new(&mut text, 64 * 1024), 0, false).unwrap();
        assert!(text.contains("&lt;script&gt;"));
        assert!(!text.contains("<script>"));
        assert!(text.contains("news.example.test"));
        assert!(text.contains("Firefox"));
        assert!(text.contains(">429<"));
        assert!(text.contains("Minute 00:02 UTC"));
        assert_eq!(model.families.os[5], 5);
        model = Model::default();
        assert!(model.rows.is_empty() && model.stale);
    }

    #[test]
    fn counters_must_be_integer_literals() {
        let value = sibuna_json::parse(br#"{"a":"5","b":5.0,"c":18446744073709551615}"#).unwrap();
        assert_eq!(unsigned(&value, "a"), Err(UiError::InvalidResponse));
        assert_eq!(unsigned(&value, "b"), Err(UiError::InvalidResponse));
        assert_eq!(unsigned(&value, "c"), Ok(u64::MAX));
        assert_eq!(unsigned(&value, "d"), Err(UiError::InvalidResponse));
    }
}
