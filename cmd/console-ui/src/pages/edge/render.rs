//! The edge page markup (SID 0031): the node, the refusals by cause, the frontends, the
//! pools, the commands and the fleet.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Action;
use sibuna_console_protocol::edge::{Fleet, Node, NodeState, Pool, View};

use super::{Edge, MAX_ROWS};
use crate::format;
use crate::render::{Html, message, value};
use crate::state::State;

const TABLE: &str = "<div class=\"overflow-x-auto\"><table class=\"table\">";
const END_TABLE: &str = "</tbody></table></div>";

/// Draws the edge page.
pub(super) fn page(model: &Edge, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<main class=\"sb-main\"><header class=\"sb-header\"><div>\
         <p class=\"sb-subtitle\">LOAD BALANCER</p>\
         <h1 id=\"page-heading\" tabindex=\"-1\">Edge</h1>\
         <p class=\"sb-subtitle\">Health, drains, flows, latency and drops of this node, \
         and the fleet.</p></div>\
         <button class=\"btn btn-sm\" data-action=\"edge-refresh\">Refresh</button></header>",
    )?;
    message(state, out)?;
    match &model.view {
        Some(view) => {
            node(&view.node, view, out)?;
            refusals(&view.node, out)?;
            frontends(view, out)?;
            for pool in &view.pools {
                pool_table(pool, out)?;
            }
            if state.allows(Action::ControlNode) {
                commands(model, out)?;
            }
        }
        None => out.write_str("<p role=\"status\">Reading the edge\u{2026}</p>")?,
    }
    if let Some(fleet) = &model.fleet {
        fleet_table(fleet, model.view.as_ref(), out)?;
    }
    out.write_str("</main>")
}

/// What a state means for new flows, in one sentence.
fn meaning(state: NodeState) -> (&'static str, &'static str) {
    match state {
        NodeState::Serving => ("Serving", "The node admits new flows."),
        NodeState::Draining => {
            ("Draining", "The node is stopping. It refuses new flows and finishes the open ones.")
        }
        NodeState::Full => (
            "Full",
            "The flow table is full. The node refuses new flows for lack of capacity, \
             not because it drains.",
        ),
    }
}

fn row(
    out: &mut Html<'_>,
    label: &str,
    write: impl FnOnce(&mut Html<'_>) -> fmt::Result,
) -> fmt::Result {
    out.write_str("<tr><th scope=\"row\">")?;
    out.write_str(label)?;
    out.write_str("</th><td>")?;
    write(out)?;
    out.write_str("</td></tr>")
}

fn pair(out: &mut Html<'_>, left: u64, right: u64) -> fmt::Result {
    format::count(out, left)?;
    out.write_str(" / ")?;
    format::count(out, right)
}

fn node(node: &Node, view: &View, out: &mut Html<'_>) -> fmt::Result {
    let (name, sentence) = meaning(node.state);
    out.write_str("<section class=\"sb-panel\" aria-labelledby=\"edge-node-heading\">")?;
    out.write_str("<h2 id=\"edge-node-heading\">Node ")?;
    value(out, &node.node)?;
    out.write_str(" \u{b7} ")?;
    out.write_str(name)?;
    out.write_str("</h2><p role=\"status\">")?;
    out.write_str(sentence)?;
    out.write_str("</p>")?;
    out.write_str(TABLE)?;
    out.write_str("<caption class=\"sr-only\">State of this node</caption><tbody>")?;
    row(out, "Flows: active / limit", |out| pair(out, node.flows, node.max_flows))?;
    row(out, "Drops", |out| format::count(out, node.drops))?;
    row(out, "Servers: all / drained / down", |out| {
        value(out, &node.servers)?;
        out.write_str(" / ")?;
        value(out, &node.servers_drained)?;
        out.write_str(" / ")?;
        value(out, &node.servers_down)
    })?;
    row(out, "Reloads / run-time changes", |out| pair(out, node.reloads, node.runtime_changes))?;
    row(out, "Routing regime", |out| out.escaped(&node.regime))?;
    row(out, "Revision: digest of the file", |out| digest(out, node.file_digest.as_deref()))?;
    row(out, "Revision: database authority", |out| authority(out, node.authority_revision))?;
    row(out, "Log lines dropped: requests / flows", |out| {
        pair(out, view.queues.access_log_dropped, view.queues.flow_log_dropped)
    })?;
    row(out, "Version", |out| out.escaped(&node.version))?;
    row(out, "Uptime", |out| {
        value(out, &node.uptime_seconds)?;
        out.write_str(" s")
    })?;
    out.write_str(END_TABLE)?;
    out.write_str("</section>")
}

fn digest(out: &mut Html<'_>, digest: Option<&str>) -> fmt::Result {
    match digest {
        Some(digest) => {
            out.write_str("<code>")?;
            out.escaped(digest)?;
            out.write_str("</code>")
        }
        None => out.write_str("No file"),
    }
}

/// The revision of the database authority of SID 0028. A node without one reports none.
fn authority(out: &mut Html<'_>, revision: Option<u64>) -> fmt::Result {
    match revision {
        Some(revision) => value(out, &revision),
        None => out.write_str("Not reported"),
    }
}

fn refusals(node: &Node, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<section class=\"sb-panel\" aria-labelledby=\"edge-refused-heading\">")?;
    out.write_str("<h2 id=\"edge-refused-heading\">Refused, by cause</h2>")?;
    // Pressure mode admits known clients first while the flow table is nearly full.
    out.write_str("<p>Pressure mode: <strong>")?;
    out.write_str(if node.pressure { "on" } else { "off" })?;
    out.write_str("</strong></p>")?;
    out.write_str(TABLE)?;
    out.write_str("<thead><tr><th scope=\"col\">Cause</th><th scope=\"col\">Count</th></tr>")?;
    out.write_str("</thead><tbody>")?;
    for refused in &node.refused {
        out.write_str("<tr><th scope=\"row\"><code>")?;
        out.escaped(&refused.reason)?;
        out.write_str("</code></th><td>")?;
        format::count(out, refused.count)?;
        out.write_str("</td></tr>")?;
    }
    out.write_str(END_TABLE)?;
    sources(node, out)?;
    out.write_str("</section>")
}

/// The addresses with the most refusals in the current minute (SID 0034).
fn sources(node: &Node, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<h3>Most refused addresses this minute</h3>")?;
    if node.top_refused.is_empty() {
        return out.write_str("<p>None this minute.</p>");
    }
    head(out, &["Address", "Refusals", "Last cause"])?;
    for source in &node.top_refused {
        out.write_str("<tr><td><code>")?;
        out.escaped(&source.address)?;
        out.write_str("</code></td>")?;
        cell(out, |out| format::count(out, source.count))?;
        out.write_str("<td><code>")?;
        out.escaped(&source.reason)?;
        out.write_str("</code></td></tr>")?;
    }
    out.write_str(END_TABLE)
}

fn head(out: &mut Html<'_>, columns: &[&str]) -> fmt::Result {
    out.write_str(TABLE)?;
    out.write_str("<thead><tr>")?;
    for column in columns {
        out.write_str("<th scope=\"col\">")?;
        out.write_str(column)?;
        out.write_str("</th>")?;
    }
    out.write_str("</tr></thead><tbody>")
}

fn cell(out: &mut Html<'_>, write: impl FnOnce(&mut Html<'_>) -> fmt::Result) -> fmt::Result {
    out.write_str("<td>")?;
    write(out)?;
    out.write_str("</td>")
}

/// A latency in milliseconds: the mean and the bound of the 95th percentile.
fn latency(out: &mut Html<'_>, mean_micros: u64, p95_micros: Option<u64>) -> fmt::Result {
    format::decimal(out, mean_micros as f64 / 1000.0, 1)?;
    out.write_str(" / ")?;
    match p95_micros {
        Some(bound) => format::decimal(out, bound as f64 / 1000.0, 1),
        None => out.write_str("-"),
    }
}

fn frontends(view: &View, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<section class=\"sb-panel\" aria-labelledby=\"edge-fronts-heading\">")?;
    out.write_str("<h2 id=\"edge-fronts-heading\">Frontends</h2>")?;
    head(out, &["Frontend", "Requests", "Flows", "Bytes in", "Bytes out", "ms: mean / p95"])?;
    for front in &view.frontends {
        out.write_str("<tr><th scope=\"row\">")?;
        out.escaped(&front.name)?;
        out.write_str("</th>")?;
        for count in [front.requests, front.flows, front.bytes_in, front.bytes_out] {
            cell(out, |out| format::count(out, count))?;
        }
        cell(out, |out| latency(out, front.mean_micros, front.p95_micros))?;
        out.write_str("</tr>")?;
    }
    out.write_str(END_TABLE)?;
    out.write_str("</section>")
}

fn pool_table(pool: &Pool, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<section class=\"sb-panel\"><h2>Pool ")?;
    out.escaped(&pool.name)?;
    out.write_str("</h2>")?;
    let columns = [
        "Server",
        "Address",
        "State",
        "Weight",
        "Flows",
        "Health",
        "Changed",
        "Requests",
        "Failures",
        "Active",
        "First byte ms: mean / p95",
    ];
    head(out, &columns)?;
    for server in &pool.servers {
        out.write_str("<tr><th scope=\"row\">")?;
        out.escaped(&server.name)?;
        out.write_str("</th>")?;
        for text in [&server.address, &server.state] {
            cell(out, |out| out.escaped(text))?;
        }
        cell(out, |out| value(out, &server.weight))?;
        cell(out, |out| format::count(out, server.flows))?;
        for text in [&server.health, &server.changed] {
            cell(out, |out| out.escaped(text))?;
        }
        for count in [server.requests, server.failures, server.active] {
            cell(out, |out| format::count(out, count))?;
        }
        cell(out, |out| latency(out, server.mean_micros, server.p95_micros))?;
        out.write_str("</tr>")?;
    }
    out.write_str(END_TABLE)?;
    if pool.more > 0 {
        out.write_str("<p class=\"sb-note\">")?;
        value(out, &pool.more)?;
        out.write_str(" more servers are not shown. <code>show servers</code> lists all.</p>")?;
    }
    out.write_str("</section>")
}

fn commands(model: &Edge, out: &mut Html<'_>) -> fmt::Result {
    let busy = if model.busy { " disabled" } else { "" };
    out.write_str(
        "<section class=\"sb-panel\" aria-labelledby=\"edge-commands-heading\">\
         <h2 id=\"edge-commands-heading\">Commands</h2>\
         <p class=\"sb-note\">Each command is a line of the admin socket. The same checks \
         apply, and a change reaches the other nodes over the mesh unless it is kept on \
         this node.</p><form id=\"edge-change\" class=\"sb-settings-form\">\
         <label for=\"edge-server\">Server</label>\
         <select class=\"select\" id=\"edge-server\" name=\"server\">",
    )?;
    let pools = model.view.iter().flat_map(|view| view.pools.iter());
    let servers = pools.flat_map(|pool| pool.servers.iter().map(move |server| (pool, server)));
    for (index, (pool, server)) in servers.take(MAX_ROWS).enumerate() {
        out.write_str("<option value=\"")?;
        value(out, &index)?;
        out.write_str("\">")?;
        out.escaped(&pool.name)?;
        out.write_str("/")?;
        out.escaped(&server.name)?;
        out.write_str("</option>")?;
    }
    out.write_str(
        "</select><label for=\"edge-kind\">Change</label>\
         <select class=\"select\" id=\"edge-kind\" name=\"change\">\
         <option value=\"drain\">Drain</option>\
         <option value=\"ready\">Return to service</option>\
         <option value=\"weight\">Set weight</option></select>\
         <label for=\"edge-weight\">Weight</label>\
         <input class=\"input\" id=\"edge-weight\" name=\"weight\" inputmode=\"numeric\" \
         maxlength=\"5\">\
         <label><input type=\"checkbox\" name=\"local\"> This node only</label>\
         <button class=\"btn btn-primary\" type=\"submit\"",
    )?;
    out.write_str(busy)?;
    out.write_str(">Apply</button></form><div class=\"flex flex-wrap gap-2\">")?;
    for (action, label) in [
        ("edge-show-servers", "show servers"),
        ("edge-show-cluster", "show cluster"),
        ("edge-show-certs", "show certs"),
        ("edge-show-ca", "show ca"),
    ] {
        out.write_str("<button class=\"btn btn-outline\" data-action=\"")?;
        out.write_str(action)?;
        out.write_str("\"")?;
        out.write_str(busy)?;
        out.write_str(">")?;
        out.write_str(label)?;
        out.write_str("</button>")?;
    }
    out.write_str(
        "</div><form id=\"edge-reload\" class=\"sb-settings-form\">\
         <label><input type=\"checkbox\" name=\"confirmed\" required> Reload the file of \
         this node and send it to every node</label>\
         <button class=\"btn btn-outline\" type=\"submit\"",
    )?;
    out.write_str(busy)?;
    out.write_str(">reload cluster</button></form>")?;
    answer(model, out)?;
    out.write_str("</section>")
}

/// The newest command and what the edge answered: its text, or its failure with the
/// hint of the admin socket.
fn answer(model: &Edge, out: &mut Html<'_>) -> fmt::Result {
    let Some((line, answer)) = &model.answer else { return Ok(()) };
    out.write_str("<div id=\"edge-answer\" tabindex=\"-1\" role=\"status\"><p><code>")?;
    out.escaped(line)?;
    out.write_str("</code>: ")?;
    if model.busy {
        return out.write_str("in progress\u{2026}</p></div>");
    }
    if answer.ok {
        out.write_str("done.</p>")?;
        if !answer.text.is_empty() {
            out.write_str("<pre class=\"overflow-x-auto\">")?;
            out.escaped(&answer.text)?;
            out.write_str("</pre>")?;
        }
        return out.write_str("</div>");
    }
    out.write_str("refused.</p><p class=\"sb-error\"><code>")?;
    out.escaped(&answer.code)?;
    out.write_str("</code> ")?;
    out.escaped(&answer.title)?;
    out.write_str(". ")?;
    out.escaped(&answer.message)?;
    out.write_str("</p><p class=\"sb-note\">Hint: ")?;
    out.escaped(&answer.hint)?;
    out.write_str("</p></div>")
}

fn fleet_table(fleet: &Fleet, own: Option<&View>, out: &mut Html<'_>) -> fmt::Result {
    let own_digest = own.and_then(|view| view.node.file_digest.as_deref());
    out.write_str("<section class=\"sb-panel\" aria-labelledby=\"edge-fleet-heading\">")?;
    out.write_str("<h2 id=\"edge-fleet-heading\">Fleet: ")?;
    value(out, &fleet.members.len())?;
    out.write_str(" members</h2>")?;
    let columns = [
        "Node",
        "Link",
        "State",
        "Flows: active / limit",
        "Drops",
        "Servers: all / drained / down",
        "File",
        "Authority",
        "Version",
    ];
    head(out, &columns)?;
    for member in &fleet.members {
        out.write_str("<tr><th scope=\"row\">")?;
        value(out, &member.node)?;
        out.write_str("</th>")?;
        cell(out, |out| out.escaped(&member.link))?;
        let Some(node) = &member.summary else {
            out.write_str("<td colspan=\"7\">No answer</td></tr>")?;
            continue;
        };
        cell(out, |out| out.write_str(meaning(node.state).0))?;
        cell(out, |out| pair(out, node.flows, node.max_flows))?;
        cell(out, |out| format::count(out, node.drops))?;
        cell(out, |out| {
            value(out, &node.servers)?;
            out.write_str(" / ")?;
            value(out, &node.servers_drained)?;
            out.write_str(" / ")?;
            value(out, &node.servers_down)
        })?;
        cell(out, |out| {
            digest(out, node.file_digest.as_deref())?;
            // A member whose file is another one serves other routes.
            let differs = own_digest.is_some() && node.file_digest.as_deref() != own_digest;
            out.write_str(if differs { " differs" } else { "" })
        })?;
        cell(out, |out| authority(out, node.authority_revision))?;
        cell(out, |out| out.escaped(&node.version))?;
        out.write_str("</tr>")?;
    }
    out.write_str(END_TABLE)?;
    out.write_str("</section>")
}
