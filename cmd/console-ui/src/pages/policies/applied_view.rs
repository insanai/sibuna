//! The applied-rules page (`policies_page.zig`, the markup of `inspection_form.zig` and
//! `rule_hit_today.zig`).

use std::fmt::{self, Write as _};

use sibuna_console_protocol::rule_hit_history::Today;
use sibuna_console_protocol::{Action, Topic};
use sibuna_html::write_value;

use super::Policies;
use super::applied::{Applied, Evaluation};
use super::data::{AppliedPage, Inspection, Mode, Modes, Row};
use super::limits;
use super::sparkline;
use crate::format;
use crate::live;
use crate::render::{self, Html};
use crate::snippets;
use crate::state::State;

/// Returns the decision class of a rule action: one colour per decision (R8), shared
/// with the outcome palette of the traffic tiles.
pub fn action_tone(action: &str) -> &'static str {
    match action {
        "allow" => "sb-decision-admitted",
        "deny" => "sb-decision-denied",
        "challenge" => "sb-decision-challenged",
        _ => "sb-decision-info",
    }
}

/// Returns the protection surface with its plain-language gloss (R3).
fn surface(value: Option<&str>) -> &'static str {
    match value {
        Some("shield") => "Shield (challenge plus semantic inspection)",
        Some("gate") => "Gate (challenge only)",
        _ => "Not reported",
    }
}

/// Returns the node-local limits sentence, or "Not reported" when a value is missing.
fn limits_text(page: &AppliedPage) -> String {
    let (Some(limit), Some(window), Some(ban)) =
        (page.rate_limit, page.rate_window_seconds, page.ban_seconds)
    else {
        return "Not reported".to_owned();
    };
    format!(
        "{limit} requests per {window} s per client address; honeypot ban {ban} s. Per-rule \
         limits below override the global limiter on this node."
    )
}

/// Draws a page button; the tester's button submits its form.
fn button(out: &mut Html<'_>, action: &str, label: &str, disabled: bool) -> fmt::Result {
    let submit = action == "policy-run";
    out.write_str("<button class=\"btn\" type=\"")?;
    out.write_str(if submit { "submit" } else { "button" })?;
    out.write_str("\"")?;
    if !submit {
        out.write_str(" data-action=\"")?;
        out.escaped(action)?;
        out.write_str("\"")?;
    }
    if disabled {
        out.write_str(" disabled")?;
    }
    out.write_str(">")?;
    out.escaped(label)?;
    out.write_str("</button>")
}

impl Policies {
    /// Draws the applied rules, the inspection modes, the tester and the IP groups.
    pub(super) fn render_applied(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        let model = &self.applied;
        snippets::render_policies_header(out, &snippets::PoliciesHeaderValues)?;
        render::message(state, out)?;
        live::render_status(state, Topic::Policy, out)?;
        let Some(snapshot) = &model.snapshot else {
            return out.write_str(if model.busy {
                "<p role=\"status\">Loading applied policies\u{2026}</p></main>"
            } else {
                "<p>No applied policy snapshot is available.</p></main>"
            });
        };
        let Some(page) = &snapshot.page else {
            return out.write_str("<p>Invalid policy snapshot. Refresh to retry.</p></main>");
        };
        summary(out, page)?;
        for row in &page.rows {
            policy_row(out, row)?;
        }
        out.write_str("</section><div class=\"flex flex-wrap gap-3 my-4\">")?;
        button(out, "policies-refresh", "First page / refresh", model.busy)?;
        let next_disabled = model.busy || model.stale || page.next.is_none();
        button(out, "policies-next", "Next rules", next_disabled)?;
        out.write_str("</div>")?;
        inspection(out, state, model, page)?;
        let request = &model.request;
        snippets::render_policies_test(
            out,
            &snippets::PoliciesTestValues {
                path: &if request.path.is_empty() { "/" } else { request.path.as_str() },
                ip: &if request.ip.is_empty() { "8.8.8.8" } else { request.ip.as_str() },
                query: &request.query.as_str(),
                user_agent: &request.user_agent.as_str(),
                body: &request.body.as_str(),
                headers: &request.headers.as_str(),
            },
        )?;
        let run_disabled = model.testing || model.busy || model.stale;
        button(out, "policy-run", "Evaluate policy", run_disabled)?;
        out.write_str("</form>")?;
        decision(out, model)?;
        out.write_str("</section>")?;
        self.render_reputation(state, out)?;
        out.write_str("</main>")
    }
}

/// Draws the applied configuration.
fn summary(out: &mut Html<'_>, page: &AppliedPage) -> fmt::Result {
    snippets::render_policies_summary(
        out,
        &snippets::PoliciesSummaryValues {
            surface: &surface(page.surface.as_deref()),
            committed: &page.committed.as_str(),
            applied: &page.applied.as_str(),
            total: &page.total,
            waf: &if page.waf { "Enabled" } else { "Disabled" },
            difficulty: &page.default_difficulty,
            algorithm: &page.default_algorithm.as_str(),
            limits: &limits_text(page),
        },
    )
}

/// Draws one applied rule.
fn policy_row(out: &mut Html<'_>, row: &Row) -> fmt::Result {
    snippets::render_policies_row(
        out,
        &snippets::PoliciesRowValues {
            index: &(u16::from(row.index) + 1),
            name: &row.name.as_str(),
            action: &row.action.as_str(),
            tone: &action_tone(&row.action),
            path: &if row.path.is_empty() { "Any path" } else { row.path.as_str() },
            user_agent: &if row.user_agent.is_empty() {
                "Any user agent"
            } else {
                row.user_agent.as_str()
            },
            headers: &row.header_count,
            cidrs: &row.cidr_count,
            weight: &row.weight,
            algorithm: &row.algorithm.as_deref().unwrap_or("Inherit"),
        },
    )?;
    match row.difficulty {
        Some(difficulty) => {
            out.write_str("<p>Configured difficulty override: ")?;
            write_value(out, &difficulty)?;
            out.write_str("</p>")?;
        }
        None => out.write_str("<p>Difficulty: inherit</p>")?,
    }
    limits::summary(out, row.limits)?;
    today(out, &row.history_key, row.today.as_ref())?;
    if row.truncated {
        out.write_str(
            "<p class=\"sb-note\">Display shortened or invalid text replaced. Evaluation uses \
             the full applied matchers.</p>",
        )?;
    }
    out.write_str("</article>")
}

/// Draws the tester's latest result.
pub fn decision(out: &mut Html<'_>, model: &Applied) -> fmt::Result {
    let result = match &model.decision {
        None => return Ok(()),
        Some(Evaluation::Invalid) => {
            return out.write_str("<p>Invalid evaluation result. Please retry.</p>");
        }
        Some(Evaluation::Decided(result)) => result,
    };
    let revision = result.committed.as_deref().unwrap_or(&result.applied);
    snippets::render_policies_decision(
        out,
        &snippets::PoliciesDecisionValues {
            kind: &if result.preview { "Draft decision" } else { "Policy decision" },
            revision_label: &if result.preview {
                "Draft committed revision"
            } else {
                "Applied revision"
            },
            action: &result.action.as_str(),
            rule: &result.rule.as_str(),
            revision: &revision,
            difficulty: &result.difficulty,
            algorithm: &result.algorithm.as_str(),
            score: &result.score,
        },
    )?;
    findings(out, result.audited)?;
    limits::summary(out, result.limits)?;
    out.write_str(
        "<p class=\"sb-note\">This preview does not consume quota or simulate session cookies, \
         existing local bans or global rate limits.</p>",
    )
}

/// Draws the inspection categories a decision audited.
fn findings(out: &mut Html<'_>, audited: Option<u8>) -> fmt::Result {
    out.write_str("<p>Audit findings: ")?;
    match audited {
        None => out.write_str("Not recorded.")?,
        Some(mask) => {
            if mask == 0 {
                out.write_str("None.")?;
            }
            for (index, label) in Modes::LABELS.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    out.write_str(label)?;
                    out.write_str(". ")?;
                }
            }
        }
    }
    out.write_str("</p>")
}

/// Draws the inspection modes form, unless the page has no inspection member.
fn inspection(
    out: &mut Html<'_>,
    state: &State,
    model: &Applied,
    page: &AppliedPage,
) -> fmt::Result {
    let applied_modes = match page.inspection {
        Inspection::Absent => return Ok(()),
        Inspection::Invalid => {
            return out.write_str("<p>Inspection modes unavailable. Refresh to retry.</p>");
        }
        Inspection::Modes(modes) => modes,
    };
    let modes = model.inspection_draft.unwrap_or(applied_modes);
    let pending = page.committed != page.applied;
    let disabled = model.busy
        || model.testing
        || model.stale
        || pending
        || !state.allows(Action::ManagePolicy);
    snippets::render_inspection_header(out, &snippets::InspectionHeaderValues)?;
    if pending {
        out.write_str(
            "<p role=\"status\">Waiting for this node to apply the committed revision. Refresh \
             before editing.</p>",
        )?;
    }
    for ((name, label), selected) in Modes::NAMES.iter().zip(Modes::LABELS).zip(modes.0) {
        out.write_str("<label class=\"form-control\" for=\"inspection-")?;
        out.write_str(name)?;
        out.write_str("\">")?;
        out.write_str(label)?;
        out.write_str("<select class=\"select\" id=\"inspection-")?;
        out.write_str(name)?;
        out.write_str("\" name=\"")?;
        out.write_str(name)?;
        out.write_str("\"")?;
        if disabled {
            out.write_str(" disabled")?;
        }
        out.write_str(">")?;
        for mode in Mode::ALL {
            out.write_str("<option value=\"")?;
            out.write_str(mode.name())?;
            out.write_str("\"")?;
            if mode == selected {
                out.write_str(" selected")?;
            }
            out.write_str(">")?;
            out.write_str(mode.label())?;
            out.write_str("</option>")?;
        }
        out.write_str("</select></label>")?;
    }
    snippets::render_inspection_footer(
        out,
        &snippets::InspectionFooterValues { disabled: &if disabled { "disabled" } else { "" } },
    )
}

/// Draws a rule's recorded hits today and the button that opens its history.
fn today(out: &mut Html<'_>, key: &str, today: Option<&Today>) -> fmt::Result {
    out.write_str("<div class=\"my-3\"><p class=\"font-semibold\">Recorded hits today (UTC)</p>")?;
    match today {
        Some(value) => today_values(out, value)?,
        None => out.write_str("<p>Unavailable until rule history is recorded.</p>")?,
    }
    if !key.is_empty() {
        out.write_str(
            "<form data-submit=\"rule-hits-open\" class=\"my-2\">\
             <input type=\"hidden\" name=\"key\" value=\"",
        )?;
        out.escaped(key)?;
        out.write_str("\"><button class=\"btn btn-sm\">Compare rule hits</button></form>")?;
    }
    out.write_str("</div>")
}

/// Draws today's count, its sparkline and its hourly table.
fn today_values(out: &mut Html<'_>, value: &Today) -> fmt::Result {
    out.write_str("<p class=\"text-xl tabular-nums\">")?;
    if value.partial {
        out.write_str("Incomplete")?;
    } else if let Some(hits) = value.hits {
        format::count(out, hits)?;
    } else {
        out.write_str("Unavailable")?;
    }
    out.write_str("</p><p class=\"sb-note\">Snapshot: ")?;
    format::timestamp(out, value.observed_at)?;
    out.write_str(". Refresh policies for newer observations.</p>")?;
    sparkline::render(
        out,
        &value.hours,
        "Recorded hourly matches today; gaps have no observations",
    )?;
    out.write_str("<p class=\"sb-note\">")?;
    write_value(out, &value.complete)?;
    out.write_str(" complete intervals among ")?;
    write_value(out, &value.rows)?;
    out.write_str(" recorded intervals. The newest minute may still be pending.</p>")?;
    if value.partial || value.unconfirmed != 0 {
        out.write_str(
            "<p class=\"sb-note\">Coverage is incomplete or a storage acknowledgement is \
             missing. Open history to inspect a bounded period.</p>",
        )?;
    }
    out.write_str(
        "<details><summary>Hourly values</summary><div class=\"overflow-x-auto\">\
         <table class=\"table table-xs\"><caption>Recorded UTC hourly cohorts</caption>\
         <thead><tr><th scope=\"col\">Hour</th><th scope=\"col\">Matches</th>\
         </tr></thead><tbody>",
    )?;
    for (hour, count) in value.hours.iter().enumerate() {
        write!(out, "<tr><th scope=\"row\">{hour:02}:00</th><td class=\"tabular-nums\">")?;
        match count {
            Some(count) => format::count(out, *count)?,
            None => out.write_str("Not recorded")?,
        }
        out.write_str("</td></tr>")?;
    }
    out.write_str("</tbody></table></div></details>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> AppliedPage {
        AppliedPage {
            committed: "1".into(),
            applied: "1".into(),
            default_difficulty: 8,
            default_algorithm: "posw".into(),
            ..AppliedPage::default()
        }
    }

    /// Ported from `policies_page.zig`.
    #[test]
    fn policy_controls_retain_their_button_types_under_escaped_template_substitution() {
        let mut text = String::new();
        let mut out = Html::new(&mut text, 4096);
        button(&mut out, "policy-run", "Evaluate", false).unwrap();
        button(&mut out, "policies", "Refresh", true).unwrap();
        assert!(text.contains("type=\"submit\""));
        assert!(text.contains("type=\"button\""));
        assert!(text.contains("data-action=\"policies\" disabled"));
        assert!(!text.contains("&quot;"));
    }

    /// Ported from `policies_page.zig`.
    #[test]
    fn older_snapshots_without_surface_or_limit_fields_stay_honest() {
        let page = page();
        assert_eq!(surface(page.surface.as_deref()), "Not reported");
        assert_eq!(limits_text(&page), "Not reported");
        assert_eq!(surface(Some("gate")), "Gate (challenge only)");
        assert_eq!(action_tone("allow"), "sb-decision-admitted");
        assert_eq!(action_tone("weigh"), "sb-decision-info");
    }

    /// The Zig module printed this sentence into 128 bytes and showed "Not reported" when
    /// it did not fit.
    #[test]
    fn long_limits_are_reported_in_full() {
        let page = AppliedPage {
            rate_limit: Some(1_000_000),
            rate_window_seconds: Some(86_400),
            ban_seconds: Some(86_400),
            ..page()
        };
        assert!(limits_text(&page).starts_with("1000000 requests per 86400 s per client"));
    }
}
