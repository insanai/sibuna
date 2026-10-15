//! IP groups on the policies page (`reputation_state.zig`, `reputation_controller.zig`
//! and `reputation_panel.zig`): paged reputation prefixes, revision-checked edits and
//! removals with a thirty-second undo that posts the inverse as a new mutation, and the
//! country builder's preview and apply.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::{Action, Text};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::{Policies, parse_int, success};
use crate::commands::Field;
use crate::error::UiError;
use crate::json;
use crate::page::Context;
use crate::render::Html;
use crate::snippets;
use crate::state::{Phase, State};

/// What the newest reputation request does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    /// Reads a page of prefixes.
    #[default]
    Query,
    /// Adds or changes a prefix.
    Edit,
    /// Removes a prefix.
    Remove,
    /// Previews a country block.
    Preview,
    /// Reads the next page of a preview.
    PreviewPage,
    /// Applies the reviewed country block.
    Apply,
}

/// The inverse of the last successful edit or removal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Undo {
    /// The prefix.
    pub prefix: Text<48>,
    /// Restore a removed row with `action`, rather than remove an added one.
    pub restore: bool,
    /// The action to restore.
    pub action: Text<8>,
    /// The note to restore.
    pub note: Text<128>,
    /// The duration in hours of the edit; 0 keeps the row until removed.
    pub hours: u64,
    /// When the undo expires, in browser seconds; 0 for no undo.
    pub expires_at: u64,
}

/// One listed prefix, read leniently.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrefixRow {
    /// The prefix.
    pub prefix: String,
    /// The row has a `score` member.
    pub has_score: bool,
    /// The score, when it is an integer: negative denies, positive allows.
    pub score: Option<i64>,
    /// When the row expires; empty for never.
    pub banned_until: String,
    /// What created the row; empty for the console.
    pub trigger: String,
    /// The row's source.
    pub source: String,
    /// The operator's note.
    pub note: String,
    /// The hits.
    pub hits: String,
}

/// A page of prefixes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrefixPage {
    /// Trie nodes in use.
    pub nodes: u64,
    /// The rows.
    pub rows: Vec<PrefixRow>,
}

impl PrefixPage {
    fn read(body: &Value<'_>) -> PrefixPage {
        let nodes = json::field(body, "nodes").and_then(json::integer);
        let rows = json::field(body, "rows").and_then(Value::as_array).unwrap_or_default();
        PrefixPage {
            nodes: nodes.and_then(|number| u64::try_from(number).ok()).unwrap_or(0),
            rows: rows
                .iter()
                .map(|row| {
                    let score = json::field(row, "score");
                    PrefixRow {
                        prefix: json::string(row, "prefix").to_owned(),
                        has_score: score.is_some(),
                        score: score.and_then(json::integer),
                        banned_until: json::string(row, "banned_until").to_owned(),
                        trigger: json::string(row, "trigger").to_owned(),
                        source: json::string(row, "source").to_owned(),
                        note: json::string(row, "note").to_owned(),
                        hits: json::string(row, "hits").to_owned(),
                    }
                })
                .collect(),
        }
    }
}

/// A country preview, read leniently: numbers outside 0 to 65,535 read as zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CountrySummary {
    /// The counts: prefixes, added, removed, retained, overlaps, nodes before and after.
    pub counts: [u16; 7],
    /// The previous GeoIP generation.
    pub previous_generation: String,
    /// The GeoIP generation, at most 12 bytes of it.
    pub generation: String,
    /// The first sampled prefix.
    pub first: String,
    /// The obsolete prefixes, when the reply lists any.
    pub removed_sample: Option<Vec<String>>,
    /// The reviewed changes of this page, when the reply has a list.
    pub changes: Option<Vec<(String, String)>>,
}

/// The count members of a country preview, in [`CountrySummary::counts`] order.
const COUNTS: [&str; 7] =
    ["prefixes", "added", "removed", "retained", "overlaps", "nodes_before", "nodes_after"];

impl CountrySummary {
    fn read(body: &Value<'_>) -> CountrySummary {
        let count = |key: &str| {
            let number = json::field(body, key).and_then(json::integer);
            number.and_then(|number| u16::try_from(number).ok()).unwrap_or(0)
        };
        let sample = json::field(body, "sample").and_then(Value::as_array);
        let first = sample.and_then(|items| items.first()).and_then(Value::as_str);
        let generation = json::string(body, "generation");
        let mut end = generation.len().min(12);
        while !generation.is_char_boundary(end) {
            end -= 1;
        }
        let removed = json::field(body, "removed_sample").and_then(Value::as_array);
        let changes = json::field(body, "changes").and_then(Value::as_array);
        CountrySummary {
            counts: COUNTS.map(count),
            previous_generation: json::string(body, "previous_generation").to_owned(),
            generation: generation.get(..end).unwrap_or_default().to_owned(),
            first: first.unwrap_or_default().to_owned(),
            removed_sample: removed
                .filter(|items| !items.is_empty())
                .map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
            changes: changes.map(|items| {
                let text = |row: &Value<'_>, key: &str| json::string(row, key).to_owned();
                items.iter().map(|row| (text(row, "prefix"), text(row, "kind"))).collect()
            }),
        }
    }
}

/// The IP groups state.
#[derive(Debug)]
pub struct Reputation {
    /// The reputation revision.
    pub committed: Text<20>,
    /// The cursor of the next page.
    pub next: Text<48>,
    /// The cursor of the current page.
    pub after: Text<48>,
    /// Prefixes of the reviewed country block.
    pub summary_prefixes: u16,
    /// The reviewed country, upper case.
    pub country: Text<2>,
    /// The reviewed country action.
    pub country_action: Text<8>,
    /// The reviewed expiry, in Unix seconds; 0 for none.
    pub country_until: u64,
    /// The review digest of the preview; empty when nothing is reviewed.
    pub country_review: Text<64>,
    /// The revision the preview was built on.
    pub country_revision: Text<20>,
    /// The offset of the next preview page.
    pub country_next: Option<u16>,
    /// The undo of the last change.
    pub undo: Undo,
    /// An address carried from an incident into the prefix form; never submitted by
    /// itself.
    pub draft_prefix: Text<48>,
    /// The drafted address is denied rather than allowed.
    pub draft_deny: bool,
    /// A request is in flight.
    pub busy: bool,
    /// A page has been loaded.
    pub loaded: bool,
    /// What the newest request does.
    pub kind: Kind,
    /// The newest request's id; empty for none.
    pub ticket: String,
    /// The current page.
    pub page: Option<PrefixPage>,
    /// The current country preview.
    pub summary: Option<CountrySummary>,
}

impl Default for Reputation {
    fn default() -> Reputation {
        Reputation {
            committed: Text::default(),
            next: Text::default(),
            after: Text::default(),
            summary_prefixes: 0,
            country: Text::default(),
            country_action: Text::default(),
            country_until: 0,
            country_review: Text::default(),
            country_revision: Text::default(),
            country_next: None,
            undo: Undo::default(),
            draft_prefix: Text::default(),
            draft_deny: true,
            busy: false,
            loaded: false,
            kind: Kind::Query,
            ticket: String::new(),
            page: None,
            summary: None,
        }
    }
}

impl Reputation {
    /// Forgets everything shown.
    pub fn clear(&mut self) {
        *self = Reputation::default();
    }

    /// Forgets the country preview.
    fn clear_summary(&mut self) {
        self.summary = None;
        self.country_review = Text::default();
        self.country_next = None;
    }

    /// The undo window closed; the button disappears on the next render.
    pub fn tick(&mut self, now: u64) {
        if self.undo.expires_at <= now {
            self.undo = Undo::default();
        }
    }

    /// Returns the undo of removing `prefix`: the row restored as it was listed.
    fn row_undo(&self, prefix: &str) -> Result<Undo, UiError> {
        let mut undo = Undo {
            prefix: Text::new(prefix)?,
            restore: true,
            action: Text::new("deny")?,
            ..Undo::default()
        };
        let rows = self.page.iter().flat_map(|page| &page.rows);
        for row in rows.filter(|row| row.prefix == prefix && row.has_score) {
            if row.score.is_some_and(|score| score > 0) {
                undo.action = Text::new("allow")?;
            }
            undo.note = Text::new(&row.note)?;
        }
        Ok(undo)
    }
}

/// The fields of an edit.
struct Edit<'a> {
    prefix: &'a str,
    action: &'a str,
    note: &'a str,
    hours: u64,
}

/// Reads the duration field: blank keeps the row until removed, otherwise 1 to 87,600
/// hours.
fn hours(fields: &Value<'_>) -> Result<u64, UiError> {
    let text = json::string(fields, "hours");
    if text.is_empty() {
        return Ok(0);
    }
    let value = parse_int::<u64>(text).ok_or(UiError::InvalidRequest)?;
    if value == 0 || value > 87_600 {
        return Err(UiError::InvalidRequest);
    }
    Ok(value)
}

impl Policies {
    /// Reloads the first page of prefixes, if the role may manage them.
    pub(super) fn reputation_refresh(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        if self.reputation.busy || !cx.state.allows(Action::ManagePolicy) {
            return Ok(());
        }
        self.reputation.after = Text::default();
        self.reputation_query(cx)
    }

    /// Handles the `reputation-` actions and the country builder's actions.
    pub(super) fn reputation_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let country = matches!(name, "country-preview" | "country-next" | "country-apply");
        if !name.starts_with("reputation-") && !country {
            return Ok(false);
        }
        let model = &mut self.reputation;
        if !cx.state.allows(Action::ManagePolicy)
            || cx.state.phase != Phase::Policies
            || model.busy
        {
            return Ok(true);
        }
        if name == "reputation-refresh" {
            model.after = Text::default();
            self.reputation_query(cx)?;
        } else if name == "reputation-next" && !model.next.is_empty() {
            model.after = model.next.clone();
            self.reputation_query(cx)?;
        } else if name == "reputation-edit" {
            let (prefix, action) =
                (json::string(fields, "prefix"), json::string(fields, "action"));
            let (note, hours) = (json::string(fields, "note"), hours(fields)?);
            self.edit(cx, &Edit { prefix, action, note, hours })?;
        } else if let Some(prefix) = name.strip_prefix("reputation-remove:") {
            self.remove(cx, prefix)?;
        } else if name == "reputation-undo" && model.undo.expires_at > cx.state.browser_time {
            let undo = std::mem::take(&mut model.undo);
            if undo.restore {
                let edit = Edit {
                    prefix: undo.prefix.as_str(),
                    action: undo.action.as_str(),
                    note: undo.note.as_str(),
                    hours: undo.hours,
                };
                self.edit(cx, &edit)?;
            } else {
                self.remove(cx, undo.prefix.as_str())?;
            }
        } else if name == "country-preview" {
            self.country(cx, fields, Kind::Preview)?;
        } else if name == "country-next" && model.country_next.is_some() {
            self.country(cx, fields, Kind::PreviewPage)?;
        } else if name == "country-apply" && !model.country_review.is_empty() {
            self.country(cx, fields, Kind::Apply)?;
        }
        Ok(true)
    }

    /// Issues the next reputation ticket for a request of `kind`.
    fn reputation_ticket(&mut self, kind: Kind) -> Result<(), UiError> {
        let generation = self.tickets.reputation.checked_add(1).ok_or(UiError::InvalidRequest)?;
        self.tickets.reputation = generation;
        let model = &mut self.reputation;
        model.ticket = format!("reputation-{generation}");
        model.kind = kind;
        model.busy = true;
        Ok(())
    }

    /// Posts a reputation request with the current ticket; a failed post releases it.
    fn reputation_post(
        &mut self,
        cx: &mut Context<'_>,
        path: &str,
        fields: &[(&str, Field<'_>)],
    ) -> Result<(), UiError> {
        let ticket = self.reputation.ticket.clone();
        let result = cx.post(&ticket, path, |json| crate::commands::write_fields(json, fields));
        if result.is_err() {
            self.reputation.busy = false;
        }
        result
    }

    fn reputation_query(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        self.reputation_ticket(Kind::Query)?;
        let after = self.reputation.after.clone();
        let fields = [("after", Field::Text(after.as_str()))];
        self.reputation_post(cx, "/console/api/reputation/query", &fields)
    }

    /// Adds or changes a prefix; the undo removes it again.
    fn edit(&mut self, cx: &mut Context<'_>, edit: &Edit<'_>) -> Result<(), UiError> {
        if edit.prefix.is_empty() || edit.prefix.len() > 48 || edit.note.len() > 128 {
            cx.state.set_message("Enter an address or CIDR of at most 48 characters.");
            return Ok(());
        }
        self.reputation_ticket(Kind::Edit)?;
        let undo = Text::new(edit.prefix)
            .and_then(|prefix| Ok((prefix, Text::new(edit.action)?, Text::new(edit.note)?)));
        let Ok((prefix, action, note)) = undo else {
            self.reputation.busy = false;
            return Err(UiError::InvalidRequest);
        };
        let model = &mut self.reputation;
        model.draft_prefix = Text::default();
        model.undo =
            Undo { prefix, restore: false, action, note, hours: edit.hours, expires_at: 0 };
        let until = (edit.hours != 0)
            .then(|| cx.state.browser_time.saturating_add(edit.hours * 3600).to_string());
        let committed = model.committed.clone();
        let fields = [
            ("prefix", Field::Text(edit.prefix)),
            ("expected_revision", Field::Text(committed.as_str())),
            ("action", Field::Text(edit.action)),
            ("until", until.as_deref().map_or(Field::Null, Field::Text)),
            ("note", Field::Text(edit.note)),
        ];
        self.reputation_post(cx, "/console/api/reputation/edit", &fields)
    }

    /// Removes a prefix; the undo restores it as it was listed.
    fn remove(&mut self, cx: &mut Context<'_>, prefix: &str) -> Result<(), UiError> {
        self.reputation_ticket(Kind::Remove)?;
        let Ok(undo) = self.reputation.row_undo(prefix) else {
            self.reputation.busy = false;
            return Err(UiError::InvalidRequest);
        };
        self.reputation.undo = undo;
        let committed = self.reputation.committed.clone();
        let fields = [
            ("prefix", Field::Text(prefix)),
            ("expected_revision", Field::Text(committed.as_str())),
        ];
        self.reputation_post(cx, "/console/api/reputation/remove", &fields)
    }

    /// Previews a country block, reads a further page of the preview, or applies it.
    /// The apply uses the reviewed country, action and expiry even if the form changed.
    fn country(
        &mut self,
        cx: &mut Context<'_>,
        fields: &Value<'_>,
        kind: Kind,
    ) -> Result<(), UiError> {
        let model = &mut self.reputation;
        if kind == Kind::Preview {
            model.clear_summary();
            let code = json::string(fields, "country");
            if code.len() != 2 {
                cx.state.set_message("Enter a two-letter country code.");
                return Ok(());
            }
            model.country = Text::new(&code.to_ascii_uppercase())?;
            model.country_action = Text::new(json::string(fields, "action"))?;
            let duration = hours(fields)?;
            model.country_until =
                if duration == 0 { 0 } else { cx.state.browser_time + duration * 3600 };
            model.country_revision = model.committed.clone();
        }
        self.reputation_ticket(kind)?;
        let model = &self.reputation;
        let until = (model.country_until != 0).then(|| model.country_until.to_string());
        let offset = if kind == Kind::PreviewPage { model.country_next.unwrap_or(0) } else { 0 };
        let (country, action) = (model.country.clone(), model.country_action.clone());
        let (revision, review) = (model.country_revision.clone(), model.country_review.clone());
        let fields = [
            ("country", Field::Text(country.as_str())),
            ("expected_revision", Field::Text(revision.as_str())),
            ("action", Field::Text(action.as_str())),
            ("until", until.as_deref().map_or(Field::Null, Field::Text)),
            ("review", Field::Text(review.as_str())),
            ("offset", Field::Unsigned(u64::from(offset))),
        ];
        let path = if kind == Kind::Apply {
            "/console/api/geoip/country/apply"
        } else {
            "/console/api/geoip/country/preview"
        };
        self.reputation_post(cx, path, &fields)
    }

    /// Handles a reply to the newest reputation request.
    pub(super) fn reputation_response(
        &mut self,
        cx: &mut Context<'_>,
        id: &str,
        status: i64,
        body: &Value<'_>,
    ) -> Result<(), UiError> {
        let model = &mut self.reputation;
        if cx.state.phase != Phase::Policies || id != model.ticket {
            return Ok(());
        }
        let kind = model.kind;
        model.busy = false;
        if status == 401 {
            cx.reset_session(Phase::Login);
            return Ok(());
        }
        if status != 200 {
            model.undo = Undo::default();
            if matches!(kind, Kind::Apply | Kind::Preview | Kind::PreviewPage) {
                model.clear_summary();
            }
            cx.state.set_message(failure(status, json::string(body, "error")));
            return Ok(());
        }
        match kind {
            Kind::Query => {
                let (committed, next) = (
                    Text::new(json::string(body, "committed"))?,
                    Text::new(json::string(body, "next"))?,
                );
                model.page = Some(PrefixPage::read(body));
                model.committed = committed;
                model.next = next;
                model.loaded = true;
            }
            Kind::Edit | Kind::Remove | Kind::Apply => self.changed(cx, kind)?,
            Kind::Preview | Kind::PreviewPage => {
                let review = json::string(body, "review");
                if review.len() != 64 {
                    return Err(UiError::InvalidResponse);
                }
                model.country_review = Text::new(review)?;
                model.summary = Some(CountrySummary::read(body));
                let next = json::field(body, "next_offset").and_then(json::integer);
                model.country_next =
                    next.and_then(|n| u16::try_from(n).ok()).filter(|n| *n <= 2048);
                let prefixes = json::field(body, "prefixes").and_then(json::integer);
                model.summary_prefixes =
                    prefixes.map_or(0, |n| u16::try_from(n.clamp(0, 65_535)).unwrap_or(0));
            }
        }
        Ok(())
    }

    /// A change was saved: offer its undo (or forget the country review) and reload.
    fn changed(&mut self, cx: &mut Context<'_>, kind: Kind) -> Result<(), UiError> {
        let model = &mut self.reputation;
        if kind == Kind::Apply {
            success(
                cx.state,
                "Country block applied. The data plane serves it after the next rebuild.",
            );
            model.undo = Undo::default();
            model.clear_summary();
            model.summary_prefixes = 0;
        } else {
            success(cx.state, "Saved. Undo is available for thirty seconds.");
            model.undo.expires_at = cx.state.browser_time + 30;
            cx.commands.timer("reputation-undo", 30_000)?;
        }
        model.after = Text::default();
        self.reputation_query(cx)
    }

    /// Draws the IP groups panel, if the role may manage them.
    pub(super) fn render_reputation(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        if !state.allows(Action::ManagePolicy) {
            return Ok(());
        }
        let model = &self.reputation;
        let busy = if model.busy { " disabled" } else { "" };
        out.write_str(
            "<section class=\"sb-panel\"><h2>IP groups</h2><p class=\"sb-note\">Reputation \
             prefixes the console manages beside the data plane's own bans. Deny prefixes refuse \
             before any rule; allow prefixes bypass rules. Revision ",
        )?;
        out.escaped(model.committed.as_str())?;
        out.write_str(" \u{b7} ")?;
        write_value(out, &model.page.as_ref().map_or(0, |page| page.nodes))?;
        out.write_str(
            " trie nodes of 8,192.</p><div class=\"overflow-x-auto\"><table class=\"table\">\
             <thead><tr><th>Prefix</th><th>Action (score)</th><th>Expires</th><th>Trigger</th>\
             <th>Source</th><th>Note</th><th>Hits</th><th></th></tr></thead><tbody>",
        )?;
        for row in model.page.iter().flat_map(|page| &page.rows) {
            prefix_row(out, row, busy)?;
        }
        out.write_str(
            "</tbody></table></div><div class=\"flex flex-wrap gap-2 mt-3\">\
             <button class=\"btn btn-sm\" data-action=\"reputation-refresh\"",
        )?;
        out.write_str(busy)?;
        out.write_str(">")?;
        out.write_str(if model.loaded { "Reload" } else { "Load IP groups" })?;
        out.write_str("</button><button class=\"btn btn-sm\" data-action=\"reputation-next\"")?;
        if model.busy || model.next.is_empty() {
            out.write_str(" disabled")?;
        }
        out.write_str(">Next page</button></div>")?;
        render_forms(out, state, model, busy)?;
        out.write_str("</form></section>")
    }
}

/// Returns the message of a refused reputation request.
fn failure(status: i64, code: &str) -> &'static str {
    match (code, status) {
        ("CONSOLEGEOIP", _) => {
            "No GeoIP generation is active. Import country data before building a block."
        }
        ("CONSOLECAPACITY", _) => "Refused: the address trie would exceed its capacity.",
        (_, 409) => {
            "Policy, GeoIP or ownership changed. Reload and preview again; independently \
             managed prefixes cannot be overwritten by a country action."
        }
        (_, 400) => "The prefix or country was refused. Check the value and try again.",
        _ => "The change could not be saved. Check the connection and try again.",
    }
}

/// Draws one listed prefix.
fn prefix_row(out: &mut Html<'_>, row: &PrefixRow, busy: &str) -> fmt::Result {
    let denied = row.score.is_none_or(|score| score < 0);
    snippets::render_reputation_row(
        out,
        &snippets::ReputationRowValues {
            prefix: &row.prefix.as_str(),
            action: &if denied { "deny" } else { "allow" },
            score: &row.score.unwrap_or(0),
            expires: &if row.banned_until.is_empty() {
                "never"
            } else {
                row.banned_until.as_str()
            },
            trigger: &if row.trigger.is_empty() { "console" } else { row.trigger.as_str() },
            source: &row.source.as_str(),
            note: &row.note.as_str(),
            hits: &row.hits.as_str(),
            busy: &busy,
        },
    )
}

/// Draws the prefix form with its undo, and the country form with its preview.
fn render_forms(out: &mut Html<'_>, state: &State, model: &Reputation, busy: &str) -> fmt::Result {
    snippets::render_reputation_form(
        out,
        &snippets::ReputationFormValues {
            busy: &busy,
            prefix: &model.draft_prefix.as_str(),
            deny: &if model.draft_deny { " selected" } else { "" },
            allow: &if model.draft_deny { "" } else { " selected" },
        },
    )?;
    if model.undo.expires_at > state.browser_time {
        out.write_str(
            "<button class=\"btn btn-outline\" type=\"button\" data-action=\"reputation-undo\">\
             Undo (",
        )?;
        write_value(out, &(model.undo.expires_at - state.browser_time))?;
        out.write_str(" s)</button>")?;
    }
    out.write_str("</div></form>")?;
    snippets::render_country_form(
        out,
        &snippets::CountryFormValues {
            busy: &busy,
            apply: &if model.busy || model.country_review.is_empty() { " disabled" } else { "" },
            prefixes: &model.summary_prefixes,
            country: &model.country.as_str(),
            action: &model.country_action.as_str(),
            next: &if model.busy || model.country_next.is_none() { " disabled" } else { "" },
        },
    )?;
    if let Some(summary) = &model.summary {
        country_summary(out, summary)?;
    }
    Ok(())
}

/// Draws a country preview: its counts, the obsolete prefixes and the reviewed changes.
fn country_summary(out: &mut Html<'_>, summary: &CountrySummary) -> fmt::Result {
    let [prefixes, added, removed, retained, overlaps, before, after] = summary.counts;
    write!(
        out,
        "<p role=\"status\" class=\"sb-note mt-3\">{prefixes} prefixes; {added} added, {removed} \
         removed, {retained} retained. trie nodes {before} \u{2192} {after}; {overlaps} already \
         listed; first "
    )?;
    out.escaped(&summary.first)?;
    out.write_str("; generation ")?;
    out.escaped(&summary.previous_generation)?;
    out.write_str(" \u{2192} ")?;
    out.escaped(&summary.generation)?;
    out.write_str(".</p>")?;
    if let Some(items) = &summary.removed_sample {
        out.write_str("<p>First obsolete prefixes to remove (up to eight):</p><ul>")?;
        for prefix in items {
            out.write_str("<li>")?;
            out.escaped(prefix)?;
            out.write_str("</li>")?;
        }
        out.write_str("</ul>")?;
    }
    if let Some(changes) = &summary.changes {
        out.write_str(
            "<table class=\"table\"><caption>Reviewed prefix changes (eight per page)</caption>\
             <thead><tr><th>Prefix</th><th>Change</th></tr></thead><tbody>",
        )?;
        for (prefix, kind) in changes {
            out.write_str("<tr><td>")?;
            out.escaped(prefix)?;
            out.write_str("</td><td>")?;
            out.escaped(kind)?;
            out.write_str("</td></tr>")?;
        }
        out.write_str("</tbody></table>")?;
    }
    Ok(())
}
