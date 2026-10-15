//! The Challenges page markup (Zig `challenges_page.zig`), and the panels the retained
//! window shares with it.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::challenges::{Algorithm, Defaults, Snapshot};
use sibuna_html::write_value;

use super::{Challenges, records, window};
use crate::page::View;
use crate::render::Html;

/// The rejection causes, by ordinal.
pub const CAUSE_NAMES: [&str; 13] = [
    "Address banned",
    "Body too large",
    "Missing challenge ID",
    "Malformed solution",
    "Malformed challenge",
    "Invalid challenge tag",
    "Expired challenge",
    "Fingerprint mismatch",
    "Difficulty not met",
    "Invalid proof",
    "Wrong solution type",
    "Replay",
    "Capacity exhausted",
];

/// Draws the Challenges page.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn page(model: &Challenges, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let state = view.state;
    out.write_str(
        "<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>\
         <p class=\"sb-subtitle\">SINGLE NODE / PROOF VERIFICATION</p>\
         <h1 id=\"page-heading\" tabindex=\"-1\">Challenges</h1>\
         <p class=\"sb-subtitle\">Understand proof issuance and verification.</p></div>\
         <button class=\"btn\" data-action=\"dashboard\">Back to dashboard</button></header>",
    )?;
    if !state.message.is_empty() {
        out.write_str("<p class=\"sb-error\" role=\"status\">")?;
        out.escaped(state.message.as_str())?;
        out.write_str("</p>")?;
    }
    if model.busy {
        out.write_str("<p role=\"status\">Refreshing challenge observations\u{2026}</p>")?;
    }
    out.write_str("<button class=\"btn mt-4\" data-action=\"challenges-refresh\"")?;
    if model.busy {
        out.write_str(" disabled")?;
    }
    out.write_str(">Refresh observations</button>")?;
    window::render(&model.window, state, out)?;
    let Some(snapshot) = &model.snapshot else {
        return out
            .write_str("<p class=\"sb-note mt-4\">No observations received yet.</p></main>");
    };
    out.write_str("<p class=\"sb-note mt-4\">")?;
    out.write_str(if model.stale { "Disconnected / stale" } else { "Live" })?;
    out.write_str(" \u{b7} Received ")?;
    write_value(out, &state.browser_time.saturating_sub(model.received_at))?;
    out.write_str(
        " seconds ago. Totals since this boot; live flow updates.</p><div class=\"sb-panels\">\
         <section class=\"sb-panel mt-6\"><h2>Challenge flow</h2><table class=\"table\"><tbody>",
    )?;
    row(out, "Issued", snapshot.issued)?;
    row(out, "Submitted", snapshot.submitted)?;
    row(out, "Accepted", snapshot.accepted)?;
    row(out, "Rejected", snapshot.rejected)?;
    out.write_str(
        "</tbody></table><p class=\"sb-note\">Parsed verification requests only. Retries, \
         abandonment and overlapping observations prevent a cohort conversion rate. Counters \
         are individually atomic, so concurrent totals may differ briefly.</p></section>",
    )?;
    parameters(snapshot, out)?;
    out.write_str(
        "</div><div class=\"sb-panels\"><p class=\"sb-note\">Timing partition last observed ",
    )?;
    write_value(out, &state.browser_time.saturating_sub(model.timing_received_at))?;
    out.write_str(
        " seconds ago. Refresh observations to update a selected non-default partition.</p>",
    )?;
    timing(snapshot, model.busy, "challenges-bin", out)?;
    rejection(snapshot, true, out)?;
    out.write_str("</div>")?;
    records::render(&model.records, state, out)?;
    out.write_str("</main>")
}

/// Draws one table row of a label and a count.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn row(out: &mut Html<'_>, label: &str, count: u64) -> fmt::Result {
    out.write_str("<tr><th scope=\"row\">")?;
    out.escaped(label)?;
    out.write_str("</th><td>")?;
    write_value(out, &count)?;
    out.write_str("</td></tr>")
}

fn parameters(snapshot: &Snapshot, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel mt-6\"><h2>Difficulty and parameters</h2>\
         <p>Configured default difficulty: ",
    )?;
    write_value(out, &snapshot.configured.difficulty)?;
    out.write_str("</p><p>Default effective parameters: ")?;
    parameter_text(&snapshot.configured, out)?;
    out.write_str("</p><p>Most recently issued parameters: ")?;
    match &snapshot.last_issued {
        Some(last) => parameter_text(last, out)?,
        None => out.write_str("No challenge issued during this boot.")?,
    }
    out.write_str(
        "</p><p class=\"sb-note mt-4\">Rule overrides and adaptive difficulty can change \
         issued parameters. PoSW depth and Hashcash bits describe different work. PoSW uses \
         2^(depth + 1) \u{2212} 1 labels; Hashcash expects 2^bits trials.</p></section>",
    )
}

fn parameter_text(value: &Defaults, out: &mut Html<'_>) -> fmt::Result {
    match value.algorithm {
        Algorithm::Hashcash => write!(out, "Hashcash, {} work bits", value.parameter),
        Algorithm::Posw => {
            write!(out, "PoSW, depth {}, {} openings", value.parameter, value.openings)
        }
    }
}

/// Draws the solve-timing panel of `snapshot` with its partition form `form`.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn timing(snapshot: &Snapshot, busy: bool, form: &str, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel mt-6\"><h2>Accepted client solve timing</h2>\
         <p class=\"sb-note\">Untrusted client telemetry, measured before verification. \
         Missing, invalid and over-one-hour durations are excluded from the histogram.</p>\
         <form id=\"",
    )?;
    out.escaped(form)?;
    out.write_str(
        "\" class=\"sb-filter-toolbar mt-4\"><div class=\"sb-filter-field\"><label for=\"",
    )?;
    out.escaped(form)?;
    out.write_str("-select\">Authenticated parameter partition</label><select id=\"")?;
    out.escaped(form)?;
    out.write_str("-select\" name=\"bin\" class=\"select w-full\">")?;
    for (bin, &count) in snapshot.bin_accepted.iter().enumerate() {
        let selected = bin == usize::from(snapshot.selected);
        if count == 0 && !selected {
            continue;
        }
        out.write_str("<option value=\"")?;
        write_value(out, &bin)?;
        out.write_str(if selected { "\" selected>" } else { "\">" })?;
        // There are 256 partitions, so `bin` fits a byte.
        bin_text(u8::try_from(bin).unwrap_or(u8::MAX), out)?;
        out.write_str(" \u{b7} ")?;
        write_value(out, &count)?;
        out.write_str(" accepted</option>")?;
    }
    out.write_str("</select></div><button class=\"btn\" type=\"submit\"")?;
    if busy {
        out.write_str(" disabled")?;
    }
    out.write_str(
        ">View partition</button></form><table class=\"table mt-4\">\
         <caption>Accepted durations in milliseconds</caption><thead><tr>\
         <th scope=\"col\">Duration</th><th scope=\"col\">Count</th></tr></thead><tbody>",
    )?;
    for (bucket, &count) in snapshot.buckets.iter().enumerate() {
        out.write_str("<tr><th scope=\"row\">")?;
        match bucket {
            0 => out.write_str("0 \u{2264} ms &lt; 1")?,
            15 => out.write_str("ms \u{2265} 16384")?,
            _ => {
                let low = 1_u32 << (bucket - 1);
                write!(out, "{low} \u{2264} ms &lt; {}", low * 2)?;
            }
        }
        out.write_str("</th><td>")?;
        write_value(out, &count)?;
        out.write_str("</td></tr>")?;
    }
    row(out, "Timing not supplied", snapshot.missing)?;
    row(out, "Invalid timing", snapshot.invalid)?;
    row(out, "Reported Wasm solver", snapshot.wasm)?;
    row(out, "Reported JavaScript solver", snapshot.javascript)?;
    row(out, "Unknown solver", snapshot.unknown_solver)?;
    out.write_str("</tbody></table></section>")
}

/// Names a parameter partition: its algorithm and the range of parameters it covers.
fn bin_text(bin: u8, out: &mut Html<'_>) -> fmt::Result {
    let parameter = u16::from((bin % 128) / 4) * 8;
    if bin < 128 {
        return write!(out, "Hashcash bits {parameter}\u{2013}{}", parameter + 7);
    }
    let openings = u16::from(bin % 4) * 16;
    let last = if openings == 48 { 255 } else { openings + 15 };
    write!(
        out,
        "PoSW depth {parameter}\u{2013}{}, openings {openings}\u{2013}{last}",
        parameter + 7
    )
}

/// Draws the rejection causes of `snapshot`; with `records`, each cause links to the
/// per-address records it produced.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn rejection(snapshot: &Snapshot, records: bool, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel mt-6\"><h2>Rejection causes</h2><table class=\"table\">\
         <tbody>",
    )?;
    for (cause, (name, count)) in CAUSE_NAMES.iter().zip(snapshot.causes).enumerate() {
        out.write_str("<tr><th scope=\"row\">")?;
        out.write_str(name)?;
        out.write_str("</th><td>")?;
        write_value(out, &count)?;
        out.write_str("</td><td>")?;
        if records {
            out.write_str("<button class=\"btn btn-sm\" data-action=\"challenges-records-cause-")?;
            write_value(out, &cause)?;
            out.write_str("\">Show addresses</button>")?;
        }
        out.write_str("</td></tr>")?;
    }
    out.write_str("</tbody></table></section>")
}
