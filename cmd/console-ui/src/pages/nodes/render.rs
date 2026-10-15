//! The Nodes page markup: the local node, the command confirmation and the receipt
//! (`nodes_page.zig`).

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Action;
use sibuna_console_protocol::nodes::{Kind, Receipt, State as Effect, Status};

use super::{Busy, MAX_REVISION, Nodes, members};
use crate::format;
use crate::render::{Html, value};
use crate::snippets;
use crate::state::State;

/// Returns `text` when `on`, otherwise nothing.
fn when(on: bool, text: &'static str) -> &'static str {
    if on { text } else { "" }
}

/// Draws the Nodes page.
pub(super) fn page(model: &Nodes, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let busy = model.busy != Busy::Idle;
    snippets::render_nodes_header(
        out,
        &snippets::NodesHeaderValues { busy: &when(busy, " disabled") },
    )?;
    if !state.is_full_access() {
        return out.write_str("<p>Sign in to view nodes.</p></main>");
    }
    if !state.message.is_empty() {
        out.write_str("<p id=\"console-message\" tabindex=\"-1\" role=\"status\">")?;
        out.escaped(state.message.as_str())?;
        out.write_str("</p>")?;
    }
    match &model.status {
        Some(node) => status(model, state, node, out)?,
        None => {
            out.write_str("<p role=\"status\">")?;
            out.write_str(if busy {
                "Loading node state\u{2026}"
            } else {
                "Node state unavailable. Refresh to retry."
            })?;
            out.write_str("</p>")?;
        }
    }
    if let Some(pending) = &model.pending {
        confirmation(model, pending.kind, pending.id.as_str(), out)?;
    }
    if let Some(receipt) = &model.receipt {
        result(receipt, out)?;
    }
    members::render(model, state, out)?;
    members::render_peers(model, state, out)?;
    out.write_str("</main>")
}

/// Returns the gauge text of the serving node, from the live snapshot when it is this
/// node's; another node's selection or a snapshot without the gauge reads as not recorded.
fn gauge(state: &State, node: u32, memory: bool) -> String {
    let Some(stats) = state.stats.as_ref().filter(|stats| stats.node == node) else {
        return "Not recorded".to_owned();
    };
    match (memory, stats.rss_kib, stats.cpu_permille) {
        (true, Some(kib), _) => format!("{kib} KiB"),
        (false, _, Some(permille)) => format!("{}.{} %", permille / 10, permille % 10),
        _ => "Not recorded".to_owned(),
    }
}

fn status(model: &Nodes, state: &State, node: &Status, out: &mut Html<'_>) -> fmt::Result {
    let fresh = model.is_fresh(state.browser_time);
    snippets::render_nodes_status(
        out,
        &snippets::NodesStatusValues {
            node: &node.node,
            admission: &if node.draining { "Draining" } else { "Accepting connections" },
            freshness: &if fresh { "Current" } else { "Stale; refresh before changes" },
            age: &state.browser_time.saturating_sub(node.observed_at),
            connections: &node.connections,
            bans: &node.active_ban_entries,
            committed: &node.committed,
            applied: &node.applied,
            revision: &node.control_revision,
            uptime: &(node.uptime_ms / 1000),
            memory: &gauge(state, node.node, true),
            cpu: &gauge(state, node.node, false),
            boot: &node.boot.as_str(),
            pending: &if node.completion_pending {
                "A local effect is awaiting durable completion. New commands are paused."
            } else {
                "Status refreshes every five seconds while no confirmation is open."
            },
        },
    )?;
    if state.stats.as_ref().is_some_and(|stats| stats.node == node.node) {
        out.write_str(
            "<div class=\"sb-panels\"><figure><figcaption>Resident memory, KiB</figcaption>",
        )?;
        members::gauge_sparkline(state, true, "Resident memory", out)?;
        out.write_str("</figure><figure><figcaption>CPU, percent of one core</figcaption>")?;
        members::gauge_sparkline(state, false, "CPU", out)?;
        out.write_str("</figure></div>")?;
    }
    if state.allows(Action::ControlNode) {
        let disabled = !fresh
            || model.busy != Busy::Idle
            || model.pending.is_some()
            || node.completion_pending
            || node.control_revision >= MAX_REVISION;
        snippets::render_nodes_controls(
            out,
            &snippets::NodesControlsValues {
                drain: &when(disabled || node.draining, " disabled"),
                resume: &when(disabled || !node.draining, " disabled"),
                clear: &when(disabled || node.active_ban_entries == 0, " disabled"),
            },
        )?;
    } else {
        out.write_str("<p>An operator or administrator can change this node.</p>")?;
    }
    out.write_str("</section>")
}

fn confirmation(model: &Nodes, kind: Kind, id: &str, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<section class=\"sb-panel\" id=\"nodes-confirmation\" tabindex=\"-1\"><h2>")?;
    out.write_str(if model.attempted {
        "Operation awaiting confirmation"
    } else {
        "Review node change"
    })?;
    out.write_str("</h2><p>")?;
    out.write_str(match kind {
        Kind::Drain => {
            "New connections will receive 503. Existing connections can finish. The console \
             remains available; restarting this node resumes admission."
        }
        Kind::Resume => "This node will accept new connections again.",
        Kind::ClearLocalBans => {
            "Temporary local ban entries will be cleared. Replicated policy and reputation \
             denials still apply. Later traffic can create new bans."
        }
    })?;
    out.write_str("</p><p>Operation: <code class=\"break-all\">")?;
    out.escaped(id)?;
    out.write_str("</code></p>")?;
    if let Some(node) = &model.status {
        out.write_str("<p>Preview: ")?;
        value(out, &node.connections)?;
        out.write_str(" open connections; ")?;
        value(out, &node.active_ban_entries)?;
        out.write_str(" active local ban entries. Counts can change before execution.</p>")?;
    }
    let busy = when(model.busy != Busy::Idle, " disabled");
    if model.attempted {
        out.write_str(
            "<div class=\"flex flex-wrap gap-2\"><button class=\"btn btn-primary\" \
             data-action=\"nodes-receipt\"",
        )?;
        out.write_str(busy)?;
        out.write_str(
            ">Inspect receipt</button><button class=\"btn btn-outline\" \
             data-action=\"nodes-retry\"",
        )?;
        out.write_str(busy)?;
        out.write_str(">Retry same operation</button></div>")?;
        if model.receipt.as_ref().is_some_and(|receipt| receipt.state == Effect::Uncertain) {
            out.write_str("<button class=\"btn btn-sm\" data-action=\"nodes-acknowledge\"")?;
            out.write_str(busy)?;
            out.write_str(">Acknowledge uncertainty and refresh</button>")?;
        }
    } else {
        out.write_str(
            "<div class=\"flex flex-wrap gap-2\"><button class=\"btn btn-primary\" \
             data-action=\"nodes-confirm\"",
        )?;
        out.write_str(busy)?;
        out.write_str(
            ">Confirm change</button><button class=\"btn\" data-action=\"nodes-cancel\"",
        )?;
        out.write_str(busy)?;
        out.write_str(">Cancel</button></div>")?;
    }
    out.write_str("</section>")
}

fn result(receipt: &Receipt, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel\" id=\"nodes-receipt\" tabindex=\"-1\"><h2>Command receipt: ",
    )?;
    out.write_str(match receipt.state {
        Effect::Applied => "Applied locally",
        Effect::Rejected => "Not applied",
        Effect::Intent => "Intent recorded",
        Effect::Uncertain => "Outcome uncertain",
    })?;
    out.write_str("</h2><p>")?;
    out.write_str(if receipt.completion_persisted {
        "Completion and audit are recorded."
    } else if receipt.state == Effect::Applied {
        "Completion has not yet been persisted. Inspect again."
    } else {
        "No completion is recorded. This command will not replay automatically."
    })?;
    out.write_str("</p><p>Operation: <code class=\"break-all\">")?;
    out.escaped(receipt.id.as_str())?;
    out.write_str("</code></p>")?;
    if let Some(count) = receipt.cleared_entries {
        out.write_str("<p>Cleared local ban entries: ")?;
        value(out, &count)?;
        out.write_str("</p>")?;
    }
    out.write_str("<p>Node ")?;
    value(out, &receipt.node)?;
    out.write_str(" \u{b7} Expected control revision ")?;
    value(out, &receipt.expected_revision)?;
    out.write_str("</p><p>Boot: <code class=\"break-all\">")?;
    out.escaped(receipt.boot.as_str())?;
    out.write_str("</code></p><p>Requested: ")?;
    format::timestamp(out, receipt.requested_at)?;
    if let Some(time) = receipt.completed_at {
        out.write_str("</p><p>Completed: ")?;
        format::timestamp(out, time)?;
    }
    out.write_str("</p>")?;
    if let Some(revision) = receipt.applied_revision {
        out.write_str("<p>Applied control revision: ")?;
        value(out, &revision)?;
        out.write_str("</p>")?;
    }
    out.write_str("</section>")
}
