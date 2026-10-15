//! Decision tones, metric names and the counter sparkline, shared by the dashboard, the
//! security overview, the Events page and the policies page.
//!
//! Colour appears only through the `sb-decision-*` classes (principle R8), one per
//! decision, so a decision has the same colour on every page. The counter sparkline is
//! `counter_sparkline.zig`: it draws retained counts beside tables that keep the exact
//! values.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::StatsSnapshot;
use sibuna_console_protocol::dashboard::Rates;
pub use sibuna_console_protocol::minute_summary::Metric;

use crate::format;
use crate::render::Html;

/// Every metric, in the order of [`Rates`] (and of the traffic tiles).
pub const METRICS: [Metric; 9] = [
    Metric::Requests,
    Metric::Admitted,
    Metric::Challenged,
    Metric::Denied,
    Metric::Banned,
    Metric::RateLimited,
    Metric::Other,
    Metric::Origin4xx,
    Metric::Origin5xx,
];

/// The six disjoint local outcomes, in stacking order.
pub const OUTCOMES: [Metric; 6] = [
    Metric::Admitted,
    Metric::Challenged,
    Metric::Denied,
    Metric::Banned,
    Metric::RateLimited,
    Metric::Other,
];

/// The tone of an admitted request or an allowing rule.
const ADMITTED: &str = "sb-decision-admitted";
/// The tone of a challenge.
const CHALLENGED: &str = "sb-decision-challenged";
/// The tone of a denial, including rate limiting.
const DENIED: &str = "sb-decision-denied";
/// The tone of a ban.
const BANNED: &str = "sb-decision-banned";
/// The tone of everything that only informs.
const INFO: &str = "sb-decision-info";

/// Returns the decision tone class of `metric`.
pub fn tone(metric: Metric) -> &'static str {
    match metric {
        Metric::Admitted => ADMITTED,
        Metric::Challenged => CHALLENGED,
        Metric::Denied | Metric::RateLimited => DENIED,
        Metric::Banned => BANNED,
        _ => INFO,
    }
}

/// Returns the decision tone class of a rule action (`allow`, `deny`, `challenge`;
/// anything else, such as `weigh`, only informs).
pub fn action_tone(action: &str) -> &'static str {
    match action {
        "allow" => ADMITTED,
        "deny" => DENIED,
        "challenge" => CHALLENGED,
        _ => INFO,
    }
}

/// Returns the decision tone class of a recorded finding: honeypot hits ban, audit
/// findings only inform, and every other recorded category denied the request.
pub fn category_tone(category: &str) -> &'static str {
    if category == "honeypot" {
        BANNED
    } else if category.starts_with("audit:") {
        INFO
    } else {
        DENIED
    }
}

/// Returns the tone of the active-bans gauge.
pub fn ban_tone() -> &'static str {
    BANNED
}

/// Returns the tone of a gauge that only informs.
pub fn info_tone() -> &'static str {
    INFO
}

/// Returns the short name of `metric`, as the timeline legend shows it.
pub fn name(metric: Metric) -> &'static str {
    match metric {
        Metric::Requests => "Requests",
        Metric::Admitted => "Admitted",
        Metric::Challenged => "Challenged",
        Metric::Denied => "Denied",
        Metric::Banned => "Banned",
        Metric::RateLimited => "Rate limited",
        Metric::Other => "Other",
        Metric::Origin4xx => "Origin 4xx",
        Metric::Origin5xx => "Origin 5xx",
    }
}

/// Returns the rate of `metric` in `rates`.
pub fn rate(rates: &Rates, metric: Metric) -> f64 {
    match metric {
        Metric::Requests => rates.requests,
        Metric::Admitted => rates.admitted,
        Metric::Challenged => rates.challenged,
        Metric::Denied => rates.denied,
        Metric::Banned => rates.banned,
        Metric::RateLimited => rates.rate_limited,
        Metric::Other => rates.other,
        Metric::Origin4xx => rates.origin_4xx,
        Metric::Origin5xx => rates.origin_5xx,
    }
}

/// Returns the live boot total of `metric` in `stats`.
pub fn counter(stats: &StatsSnapshot, metric: Metric) -> u64 {
    match metric {
        Metric::Requests => stats.requests,
        Metric::Admitted => stats.admitted,
        Metric::Challenged => stats.challenged,
        Metric::Denied => stats.denied,
        Metric::Banned => stats.banned,
        Metric::RateLimited => stats.rate_limited,
        Metric::Other => stats.other,
        Metric::Origin4xx => stats.origin_4xx,
        Metric::Origin5xx => stats.origin_5xx,
    }
}

/// Returns true for the origin response classes, which only a reverse proxy observes.
pub fn is_origin(metric: Metric) -> bool {
    matches!(metric, Metric::Origin4xx | Metric::Origin5xx)
}

/// Draws a retained counter series (oldest first, `None` for no observation) as a 240 by
/// 48 line with a dot per observation; a missing value breaks the line. Pixel projection
/// may round; the tables beside it keep exact values and tell missing data from an
/// observed zero. Nothing is drawn for an empty series (Zig asserted a non-empty one).
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn counter_sparkline(out: &mut Html<'_>, values: &[Option<u64>], label: &str) -> fmt::Result {
    if values.is_empty() {
        return Ok(());
    }
    let maximum = values.iter().flatten().fold(1, |maximum: u64, count| maximum.max(*count));
    let point = |index: usize, value: u64| {
        let x = if values.len() == 1 {
            120.0
        } else {
            4.0 + index as f64 * 232.0 / (values.len() - 1) as f64
        };
        (x, 44.0 - value as f64 * 40.0 / maximum as f64)
    };
    out.write_str(
        "<svg viewBox=\"0 0 240 48\" width=\"240\" height=\"48\" class=\"max-w-full \
         text-primary\" role=\"img\" aria-label=\"",
    )?;
    out.escaped(label)?;
    out.write_str("\"><path fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" d=\"")?;
    let mut pen = false;
    for (index, value) in values.iter().enumerate() {
        let Some(count) = value else {
            pen = false;
            continue;
        };
        let (x, y) = point(index, *count);
        out.write_str(if pen { "L" } else { "M" })?;
        coordinates(out, x, y, " ")?;
        out.write_str(" ")?;
        pen = true;
    }
    out.write_str("\"/>")?;
    for (index, value) in values.iter().enumerate() {
        let Some(count) = value else { continue };
        let (x, y) = point(index, *count);
        out.write_str("<circle cx=\"")?;
        coordinates(out, x, y, "\" cy=\"")?;
        out.write_str("\" r=\"2\" fill=\"currentColor\"/>")?;
    }
    out.write_str("</svg>")
}

/// Writes `x`, `separator` and `y` with two decimals each.
fn coordinates(out: &mut Html<'_>, x: f64, y: f64, separator: &str) -> fmt::Result {
    format::decimal(out, x, 2)?;
    out.write_str(separator)?;
    format::decimal(out, y, 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sparkline(values: &[Option<u64>], label: &str) -> String {
        let mut text = String::new();
        counter_sparkline(&mut Html::new(&mut text, 4096), values, label).unwrap();
        text
    }

    #[test]
    fn counter_sparklines_break_at_missing_values_and_scale_to_the_maximum() {
        assert_eq!(
            sparkline(&[Some(0), None, Some(10)], "Rule <hits>"),
            "<svg viewBox=\"0 0 240 48\" width=\"240\" height=\"48\" class=\"max-w-full \
             text-primary\" role=\"img\" aria-label=\"Rule &lt;hits&gt;\"><path fill=\"none\" \
             stroke=\"currentColor\" stroke-width=\"2\" d=\"M4.00 44.00 M236.00 4.00 \"/>\
             <circle cx=\"4.00\" cy=\"44.00\" r=\"2\" fill=\"currentColor\"/><circle \
             cx=\"236.00\" cy=\"4.00\" r=\"2\" fill=\"currentColor\"/></svg>"
        );
        assert!(sparkline(&[Some(3)], "One").contains("d=\"M120.00 4.00 \""));
    }

    /// Ported from the policies page's copy of `counter_sparkline.zig`.
    #[test]
    fn gaps_break_the_line_and_a_single_point_is_centred() {
        let text = sparkline(&[Some(2), None, Some(1)], "x");
        assert!(text.contains("d=\"M4.00 4.00 M236.00 24.00 \""));
        assert_eq!(text.matches("<circle").count(), 2);
        assert!(sparkline(&[Some(0)], "x").contains("d=\"M120.00 44.00 \""));
        assert!(sparkline(&[], "x").is_empty());
    }

    #[test]
    fn decisions_share_one_tone_on_every_page() {
        assert_eq!(action_tone("allow"), tone(Metric::Admitted));
        assert_eq!(action_tone("deny"), tone(Metric::RateLimited));
        assert_eq!(action_tone("challenge"), tone(Metric::Challenged));
        assert_eq!(action_tone("weigh"), "sb-decision-info");
        assert_eq!(category_tone("honeypot"), tone(Metric::Banned));
        assert_eq!(category_tone("audit:headers"), info_tone());
        assert_eq!(category_tone("waf:sqli"), "sb-decision-denied");
        assert_eq!(ban_tone(), "sb-decision-banned");
    }
}
