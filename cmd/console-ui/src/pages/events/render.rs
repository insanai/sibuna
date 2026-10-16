//! The Events page markup (Zig `events_page.zig`, `filter_form.zig` and the form half of
//! `security_investigation.zig`).

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::events::Row;
use sibuna_console_protocol::events::country::Mapping;
use sibuna_console_protocol::security::Module;
use sibuna_console_protocol::{Action, Topic};
use sibuna_html::write_value;

use super::model::{MAX_PAGES, Model};
use super::{Events, heads};
use crate::charts;
use crate::format;
use crate::live;
use crate::page::View;
use crate::pages::similarity::Similarity;
use crate::render::Html;
use crate::snippets;

/// The capture truncation flags, by bit.
const TRUNCATION_NAMES: [&str; 8] = [
    "client address",
    "user agent",
    "method",
    "path",
    "category",
    "forensic payload",
    "body incomplete",
    "byte length saturated (shown as a lower bound)",
];

/// The time ranges of the filter form, in hours.
const TIME_RANGES: [(u32, &str); 5] = [
    (0, "All recorded time"),
    (1, "Last hour"),
    (24, "Last 24 hours"),
    (168, "Last 7 days"),
    (720, "Last 30 days"),
];

/// Draws the Events page.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn page(events: &Events, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let state = view.state;
    let model = &events.model;
    out.write_str(
        "<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>\
         <p class=\"sb-subtitle\">INVESTIGATION / RECORDED INCIDENTS</p>\
         <h1 id=\"page-heading\" tabindex=\"-1\">Events</h1>\
         <p class=\"sb-subtitle\">Inspect what your firewall recorded.</p></div>\
         <button class=\"btn\" data-action=\"dashboard\">Back to dashboard</button></header>",
    )?;
    if !state.message.is_empty() {
        out.write_str("<p class=\"")?;
        out.write_str(if model.export_ready { "sb-note" } else { "sb-error" })?;
        out.write_str("\" role=\"status\">")?;
        out.escaped(state.message.as_str())?;
        out.write_str("</p>")?;
    }
    // The current view is a pressed toggle, not a disabled button, which would read as
    // unavailable.
    out.write_str("<div class=\"join mt-6\" role=\"group\" aria-label=\"Incident view\">")?;
    toggle(out, "events-raw", "Raw incidents", !model.grouped, model.busy)?;
    toggle(out, "events-source", "By source address", model.grouped, model.busy)?;
    out.write_str("</div>")?;
    scope_notes(model, view, out)?;
    live::render_status(state, Topic::Events, out)?;
    filters(model, out)?;
    out.write_str(
        "<section id=\"incident-results\" tabindex=\"-1\" class=\"sb-panel mt-6\" \
         aria-label=\"Incident results\">",
    )?;
    if model.busy {
        out.write_str("<p role=\"status\">Loading incidents\u{2026}</p>")?;
    }
    if !model.busy && model.loaded && model.rows.is_empty() {
        out.write_str("<p>No recorded incidents match these filters.</p>")?;
    }
    let manage = state.allows(Action::ManagePolicy) && !state.kiosk;
    for row in &model.rows {
        incident(events, row, manage, out)?;
    }
    footer(model, out)
}

/// Draws the incident and campaign filters that narrow the page.
fn scope_notes(model: &Model, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    if model.incident != 0 {
        out.write_str("<p class=\"sb-note mt-4\">Incident #")?;
        write_value(out, &model.incident)?;
        out.write_str("</p>")?;
        button(out, "events-clear-incident", "Clear incident filter", model.busy)?;
        let similarity = view.pages.find::<Similarity>();
        if similarity.is_some_and(|similarity| similarity.model.source != 0) {
            button(out, "similarity-return", "Back to similarity results", model.busy)?;
        }
    }
    if model.campaign != 0 {
        out.write_str("<p class=\"sb-note mt-4\">Campaign candidate #")?;
        write_value(out, &model.campaign)?;
        out.write_str(
            ". Automated similarity grouping is not attribution or proof of a common \
             attacker. Membership uses the selected time range.</p>",
        )?;
        button(out, "events-clear-campaign", "Clear campaign filter", model.busy)?;
    }
    Ok(())
}

fn footer(model: &Model, out: &mut Html<'_>) -> fmt::Result {
    let page = model.page();
    let last_page = page + 1 == MAX_PAGES;
    out.write_str("<div class=\"flex flex-wrap gap-3 mt-6\"><span>Page ")?;
    write_value(out, &(page + 1))?;
    out.write_str("</span>")?;
    button(out, "events-prev", "Previous", model.busy || page == 0)?;
    button(out, "events-next", "Next", model.busy || model.next.is_none() || last_page)?;
    button(out, "events-refresh", "Latest results", model.busy)?;
    let export_disabled = model.busy || model.exporting || model.rows.is_empty();
    button(out, "events-export", "Export this page (JSON)", export_disabled)?;
    button(out, "events-export-csv", "Export this page (CSV)", export_disabled)?;
    if last_page && model.next.is_some() {
        out.write_str("<p>Narrow the time range or filters to browse more records.</p>")?;
    }
    out.write_str(
        "</div><p class=\"sb-note mt-4\">Records are ordered by capture time (UTC). Pages \
         retain the selected time boundary; use Latest results to include new incidents. \
         Missing historical evidence and capture coverage are not inferred.</p>\
         <p class=\"sb-note\">CSV prefixes formula-like text with \u{201c}Text: \u{201d}. \
         JSON preserves string values and exact identifiers.</p></section></main>",
    )
}

/// One text input of the filter form (Zig `filter_form.Input`).
#[derive(Clone, Copy)]
struct Input<'a> {
    name: &'a str,
    label: &'a str,
    value: &'a str,
    limit: usize,
    placeholder: &'a str,
    hint: &'a str,
    wide: bool,
}

impl Input<'_> {
    fn render(&self, out: &mut Html<'_>) -> fmt::Result {
        snippets::render_filter_input(
            out,
            &snippets::FilterInputValues {
                wide: &if self.wide { " sb-filter-wide" } else { "" },
                name: &self.name,
                label: &self.label,
                limit: &self.limit,
                value: &self.value,
                placeholder: &self.placeholder,
                hint: &self.hint,
            },
        )
    }
}

fn filters(model: &Model, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel sb-filters mt-6\"><h2>Filter incidents</h2>\
         <form id=\"events-filter\"><div class=\"sb-filter-grid\">",
    )?;
    module_filter(model, out)?;
    let plain =
        Input { name: "", label: "", value: "", limit: 0, placeholder: "", hint: "", wide: false };
    let category = model.category.as_str();
    Input { name: "category", label: "Category", value: category, limit: 32, ..plain }
        .render(out)?;
    Input {
        name: "country",
        label: "Country",
        value: model.country.as_str(),
        limit: 12,
        hint: "event-filter-help",
        placeholder: "e.g. US",
        ..plain
    }
    .render(out)?;
    let ip = model.ip.as_str();
    Input { name: "ip", label: "Client address", value: ip, limit: 48, ..plain }.render(out)?;
    let path = model.path.as_str();
    let label = "Path starts with";
    Input { name: "path_prefix", label, value: path, limit: 256, wide: true, ..plain }
        .render(out)?;
    let node = if model.node == 0 { String::new() } else { model.node.to_string() };
    let placeholder = "All nodes";
    Input { name: "node", label: "Node ID", value: &node, limit: 10, placeholder, ..plain }
        .render(out)?;
    out.write_str(
        "<div class=\"sb-filter-field\"><label for=\"hours\">Time range</label>\
         <select id=\"hours\" name=\"hours\" class=\"select select-bordered\">",
    )?;
    for (hours, label) in TIME_RANGES {
        out.write_str("<option value=\"")?;
        write_value(out, &hours)?;
        out.write_str(if model.hours == hours { "\" selected>" } else { "\">" })?;
        out.write_str(label)?;
        out.write_str("</option>")?;
    }
    out.write_str(
        "</select></div></div><p id=\"event-filter-help\" class=\"sb-note mt-4\">Leave \
         fields blank to include all values. Category and address match exactly. Country \
         accepts a two-letter code, unknown or not_recorded.</p>",
    )?;
    period(model, out)?;
    out.write_str(
        "<div class=\"sb-filter-actions\"><button type=\"submit\" class=\"btn btn-primary\"",
    )?;
    if model.busy {
        out.write_str(" disabled")?;
    }
    out.write_str(">Apply filters</button></div></form></section>")
}

/// The module select of the filter form (Zig `security_investigation.filter`).
fn module_filter(model: &Model, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<div class=\"sb-filter-field\"><label for=\"event-module\">Module</label>\
         <select class=\"select select-bordered\" id=\"event-module\" name=\"module\">\
         <option value=\"\">All recorded modules</option>",
    )?;
    for &module in Module::ALL {
        out.write_str("<option value=\"")?;
        out.write_str(module.name())?;
        out.write_str(if model.module == Some(module) { "\" selected>" } else { "\">" })?;
        out.write_str(module.name())?;
        out.write_str("</option>")?;
    }
    out.write_str("</select></div>")
}

/// The fixed period of a security drill-down (Zig `security_investigation.period`).
fn period(model: &Model, out: &mut Html<'_>) -> fmt::Result {
    let Some(from) = model.from else { return Ok(()) };
    out.write_str("<p class=\"sb-note\">Security drill-down uses the fixed period ")?;
    format::timestamp(out, from)?;
    out.write_str(" through ")?;
    format::timestamp(out, model.until)?;
    out.write_str(". Applying filters starts a new period.</p>")
}

fn incident(events: &Events, row: &Row, manage: bool, out: &mut Html<'_>) -> fmt::Result {
    if row.grouped {
        return source(row, out);
    }
    out.write_str(
        "<article class=\"border-b border-base-300 py-4\"><h2>\
         <span class=\"badge badge-outline sb-chip ",
    )?;
    out.write_str(charts::category_tone(row.category.as_str()))?;
    out.write_str("\">")?;
    out.escaped(row.category.as_str())?;
    out.write_str("</span> <span class=\"sb-note\">#")?;
    write_value(out, &row.id)?;
    out.write_str("</span></h2><p>")?;
    format::timestamp(out, row.time)?;
    out.write_str(" \u{b7} Node ")?;
    write_value(out, &row.node)?;
    out.write_str("</p><p class=\"break-all\">")?;
    out.escaped(row.ip.as_str())?;
    out.write_str(" \u{b7} ")?;
    out.escaped(row.method.as_str())?;
    out.write_str(" ")?;
    out.escaped(row.path.as_str())?;
    out.write_str(
        "</p><details class=\"mt-3\"><summary>Incident details</summary>\
         <dl class=\"grid gap-2 mt-3\"><dt>User agent</dt><dd class=\"break-all\">",
    )?;
    out.escaped(row.user_agent.as_str())?;
    out.write_str("</dd>")?;
    details(row, out)?;
    evidence(row, out)?;
    heads::render(&events.heads, row.id, out)?;
    out.write_str(
        "<div class=\"flex flex-wrap gap-2 mt-3\"><button class=\"btn\" \
         data-action=\"events-similar-",
    )?;
    write_value(out, &row.id)?;
    out.write_str("\">Find similar incidents</button>")?;
    if manage {
        address_actions(row, out)?;
    }
    out.write_str("</div>")?;
    if row.query_redacted {
        out.write_str("<p class=\"sb-note\">Query string removed.</p>")?;
    }
    if row.display_truncated {
        out.write_str("<p class=\"sb-note\">Display text truncated.</p>")?;
    }
    out.write_str("</details></article>")
}

/// The campaign, country, response and unrecorded fields of an incident's details.
fn details(row: &Row, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<dt>Campaign candidate</dt><dd>")?;
    match row.campaign {
        Some(id) => {
            write_value(out, &id)?;
            out.write_str(
                " (automated similarity grouping) <button class=\"btn btn-sm\" \
                 data-action=\"events-campaign-",
            )?;
            write_value(out, &id)?;
            out.write_str("\">Inspect candidate</button>")?;
        }
        None => out.write_str("Not recorded")?,
    }
    out.write_str("</dd><dt>Country at persistence</dt><dd>")?;
    geography(&row.geography, out)?;
    out.write_str("</dd><dt>Response</dt><dd>")?;
    match row.capture {
        Some(capture) => {
            out.write_str("Local denial: status ")?;
            write_value(out, &capture.selected_status)?;
            out.write_str(" selected; no origin response. Delivery is not recorded.")?;
        }
        None => out.write_str("Not recorded")?,
    }
    out.write_str(
        "</dd><dt>Matched rule and score terms</dt><dd>Not recorded</dd><dt>JA4 fingerprint\
         </dt><dd>Not recorded: requires bounded capture at a trusted ingress that \
         overwrites spoofed headers.</dd></dl>",
    )
}

/// Address actions open the IP groups form with this address; the operator chooses the
/// duration there and the saved prefix keeps its thirty-second undo (R18).
fn address_actions(row: &Row, out: &mut Html<'_>) -> fmt::Result {
    for (action, label) in [("deny", "Deny address\u{2026}"), ("allow", "Allow address\u{2026}")] {
        out.write_str("<button class=\"btn btn-outline\" data-action=\"events-")?;
        out.write_str(action)?;
        out.write_str("-")?;
        out.escaped(row.ip.as_str())?;
        out.write_str("\">")?;
        out.write_str(label)?;
        out.write_str("</button>")?;
    }
    Ok(())
}

/// A row grouping the incidents of one source address.
fn source(row: &Row, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<article class=\"border-b border-base-300 py-4\"><h2>")?;
    out.escaped(row.ip.as_str())?;
    out.write_str("</h2><p>")?;
    write_value(out, &row.count)?;
    out.write_str(" recorded incident")?;
    if row.count != 1 {
        out.write_str("s")?;
    }
    out.write_str(" \u{b7} Node ")?;
    write_value(out, &row.node)?;
    out.write_str("</p><p>First seen: ")?;
    format::timestamp(out, row.first_seen)?;
    out.write_str("</p><p>Last seen: ")?;
    format::timestamp(out, row.time)?;
    out.write_str("</p><p class=\"sb-note\">Country at persistence: ")?;
    geography(&row.geography, out)?;
    out.write_str("</p><button class=\"btn mt-3\" data-action=\"events-source-")?;
    write!(out, "{}/", row.node)?;
    out.escaped(row.ip.as_str())?;
    out.write_str("\">Inspect source incidents</button></article>")
}

fn geography(value: &Mapping, out: &mut Html<'_>) -> fmt::Result {
    if value.mixed {
        return out.write_str("Mixed recorded countries or mapping coverage");
    }
    if !value.code.is_empty() {
        out.escaped(value.code.as_str())?;
    } else if value.recorded {
        out.write_str("Unknown (address not mapped)")?;
    } else {
        return out.write_str("Not recorded");
    }
    if value.generation.is_empty() {
        return out.write_str(" \u{b7} Multiple GeoIP generations");
    }
    out.write_str(" <span class=\"break-all\">\u{b7} GeoIP generation ")?;
    out.escaped(value.generation.as_str())?;
    out.write_str("</span>")
}

/// Draws a view toggle, pressed when it shows the current view.
fn toggle(
    out: &mut Html<'_>,
    action: &str,
    label: &str,
    pressed: bool,
    disabled: bool,
) -> fmt::Result {
    out.write_str("<button class=\"btn join-item\" data-action=\"")?;
    out.write_str(action)?;
    out.write_str(if pressed { "\" aria-pressed=\"true\"" } else { "\" aria-pressed=\"false\"" })?;
    out.write_str(if disabled { " disabled>" } else { ">" })?;
    out.write_str(label)?;
    out.write_str("</button>")
}

fn button(out: &mut Html<'_>, action: &str, label: &str, disabled: bool) -> fmt::Result {
    out.write_str("<button class=\"btn\" data-action=\"")?;
    out.write_str(action)?;
    out.write_str(if disabled { "\" disabled>" } else { "\">" })?;
    out.write_str(label)?;
    out.write_str("</button>")
}

/// The capture metadata of an incident, or a note that it was not recorded.
fn evidence(row: &Row, out: &mut Html<'_>) -> fmt::Result {
    let Some(capture) = row.capture else {
        return out.write_str(
            "<p class=\"sb-note mt-3\">Versioned evidence and capture truncation: Not \
             recorded. Historical payloads are withheld because they lack redaction \
             metadata.</p>",
        );
    };
    out.write_str("<h3 class=\"mt-4\">Evidence metadata v")?;
    write_value(out, &capture.version)?;
    out.write_str("</h3><p>Firewall response selected: ")?;
    write_value(out, &capture.selected_status)?;
    out.write_str(". Delivery is not recorded.</p><p>Query: ")?;
    write_value(out, &capture.query_bytes)?;
    out.write_str(" bytes. Received body: ")?;
    write_value(out, &capture.body_bytes)?;
    out.write_str(" bytes. Declared body: ")?;
    write_value(out, &capture.declared_body_bytes)?;
    out.write_str(
        " bytes.</p><p class=\"sb-note\">Query values, body contents, cookies and other \
         headers are omitted from this evidence view. This is not a reconstructed request.\
         </p>",
    )?;
    if capture.truncated == 0 {
        return out.write_str("<p class=\"sb-note\">No capture truncation recorded.</p>");
    }
    out.write_str("<p class=\"sb-note\">Capture limits: ")?;
    let names = TRUNCATION_NAMES
        .iter()
        .enumerate()
        .filter(|(bit, _)| capture.truncated & (1 << bit) != 0)
        .map(|(_, name)| *name);
    for (index, name) in names.enumerate() {
        if index != 0 {
            out.write_str(", ")?;
        }
        out.write_str(name)?;
    }
    out.write_str(".</p>")
}
