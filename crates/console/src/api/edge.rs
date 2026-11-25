//! The routes `edge`, `edge/fleet` and `edge/command` (SID 0031): the load balancer of
//! this node, the fleet, and the commands of the admin socket.
//!
//! ```text
//! GET  edge          -> EdgeHost::view            the worker's table and the counters
//! GET  edge/fleet    -> one peer query per member, all at once, at most five seconds
//! POST edge/command  -> is_listed -> audit intent -> EdgeHost::run -> audit result
//! ```
//!
//! The console adds no power. A line is run by the function of the admin socket, behind
//! [`EdgeHost`], and only a line that [`is_listed`] accepts gets that far. The dispatcher
//! has already checked the session, the role (`control_node`), the origin, the CSRF token
//! and the mutation allowance. A console without an edge answers 404 `CONSOLE404`.

use std::time::Instant;

use sibuna_console_protocol::codec::{WireEnum, from_json, to_json};
use sibuna_console_protocol::edge::{Command, Fleet, MAX_LINE, Member, Node};
use sibuna_console_storage::audit::{AuditAction, AuditRow, append_audit};
use sibuna_serve::Context;

use super::policies::spend;
use crate::dispatch::Call;
use crate::host::EdgeHost;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::peer::{Cursor, Kind, Outcome, TIMEOUT, Ticket};
use crate::routes::Handler;
use crate::shared::Shared;

/// The failure code of this module's routes.
const CODE: &str = "CONSOLEEDGE";

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with 404 `CONSOLE404` on a console without an edge, 429 `CONSOLEQUERY` past the
/// query allowance (reads), 400 `CONSOLEEDGE` for a line that is malformed or not on the
/// list, and 503 `CONSOLEEDGE` when the edge worker does not answer or the audit row
/// cannot be written.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let Some(edge) = shared.edge.as_deref() else {
        return Err(RouteError::fail(404, "CONSOLE404"));
    };
    match call.route.handler {
        Handler::EdgeView => {
            spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
            let view = edge.view().ok_or_else(|| RouteError::fail(503, CODE))?;
            Ok(reply::json(context, &view)?)
        }
        Handler::EdgeFleet => {
            spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
            Ok(reply::json(context, &fleet(shared, edge, call.now))?)
        }
        Handler::EdgeCommand => command(shared, edge, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Returns whether `line` is a command the console offers. The list is a subset of the
/// admin socket's: changes to servers and bans, the reload of the cluster, and four
/// tables. It names words only. The admin parser checks every value.
pub fn is_listed(line: &str) -> bool {
    let mut words: Vec<&str> = line.split_ascii_whitespace().take(9).collect();
    // The last word `local` keeps a change on this node, as on the socket.
    if matches!(words.first(), Some(&"set" | &"add" | &"del")) && words.last() == Some(&"local") {
        words.pop();
    }
    matches!(
        words.as_slice(),
        ["set", "server", _, "state" | "weight", _]
            | ["add", "server", _, _]
            | ["add", "server", _, _, "weight", _]
            | ["del", "server" | "ban", _]
            | ["reload", "cluster"]
            | ["show", "servers" | "cluster" | "certs" | "ca"]
    )
}

/// Returns whether a listed line changes what is served. Such a line is audited.
fn changes(line: &str) -> bool {
    line.split_ascii_whitespace().next() != Some("show")
}

/// `edge/fleet`: this node, then every configured peer with its link and, when it
/// answers in time, its summary.
fn fleet(shared: &Shared, edge: &dyn EdgeHost, now: u64) -> Fleet {
    let own = shared.identity.node_id;
    let summary = edge.view().map(|view| view.node);
    let mut members = vec![Member { node: own, link: "self".to_owned(), summary }];
    let mut reports = Vec::new();
    shared.peers.reports(now, &mut reports);
    // Every query is on its way before the first answer is awaited.
    let asked: Vec<(u32, &'static str, Option<Ticket>)> = reports
        .iter()
        .map(|peer| {
            let ticket = shared.peers.submit(peer.node, Kind::Edge, Cursor::default(), now).ok();
            (peer.node, peer.status.name(), ticket)
        })
        .collect();
    let deadline = Instant::now() + TIMEOUT;
    for (node, link, ticket) in asked {
        let outcome = ticket.and_then(|ticket| ticket.wait(deadline, || shared.is_stopping()));
        let summary = match outcome {
            Some(Outcome::Page(page)) => from_json::<Node>(page.as_bytes()).ok(),
            _ => None,
        };
        members.push(Member { node, link: link.to_owned(), summary });
    }
    Fleet { self_node: own, members }
}

/// `edge/command`: one listed line, audited when it changes state, run by the admin path.
fn command(
    shared: &Shared,
    edge: &dyn EdgeHost,
    context: &mut Context<'_>,
    call: &Call,
) -> Result<(), RouteError> {
    let mut buffer = [0u8; 2 * MAX_LINE];
    let request: Command = read_json(context, &mut buffer)?;
    let line = request.line.trim();
    let printable = line.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
    if line.len() > MAX_LINE || !printable || !is_listed(line) {
        return Err(RouteError::fail(400, CODE));
    }
    if !changes(line) {
        return Ok(reply::json(context, &edge.run(line, ""))?);
    }
    let principal = call.principal()?;
    let row = |action: AuditAction, after: String| AuditRow {
        target: Some("edge".to_owned()),
        client_ip: Some(call.origin.client.clone()).filter(|c| (1..=48).contains(&c.len())),
        after: Some(after),
        ..AuditRow::by(principal, action, call.now)
    };
    // No change without its intent on record.
    let intent = row(AuditAction::NodeCommandIntent, to_json(&Command { line: line.to_owned() }));
    append(shared, intent).map_err(|()| RouteError::fail(503, CODE))?;
    let who = format!("account {}", principal.actor);
    let answer = edge.run(line, &who);
    let (action, code) = match answer.ok {
        true => (AuditAction::NodeCommandApplied, "ok"),
        false => (AuditAction::NodeCommandRejected, answer.code.as_str()),
    };
    let result = ResultSummary { line, code };
    // The change is made. A result row that cannot be written leaves the intent.
    let _ = append(shared, row(action, result.json()));
    Ok(reply::json(context, &answer)?)
}

/// The summary of a result row: the line and `ok` or the code of the failure.
struct ResultSummary<'a> {
    line: &'a str,
    code: &'a str,
}

impl ResultSummary<'_> {
    fn json(&self) -> String {
        let line = to_json(self.line);
        let code = to_json(self.code);
        format!("{{\"line\":{line},\"result\":{code}}}")
    }
}

/// Appends one audit row in a transaction of its own.
fn append(shared: &Shared, row: AuditRow) -> Result<(), ()> {
    shared
        .storage
        .transact(move |tx| Box::pin(async move { append_audit(tx, &row).await.map(drop) }))
        .map_err(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_the_changes_to_servers_the_cluster_reload_and_four_tables() {
        for line in [
            "set server app/a state drain",
            "set server app/a state ready local",
            "set server app/a weight 7",
            "add server app/b 10.0.0.2:80",
            "add server app/b 10.0.0.2:80 weight 3 local",
            "del server app/b",
            "del ban 2001:db8::7 local",
            "reload cluster",
            "show servers",
            "show cluster",
            "show certs",
            "show ca",
            "  show   ca ",
        ] {
            assert!(is_listed(line), "{line}");
        }
    }

    #[test]
    fn every_other_line_of_the_socket_is_refused() {
        for line in [
            "",
            "reload",
            "reload cluster now",
            "reopen log",
            "show info",
            "show stats",
            "help",
            "show servers local",
            "set server app/a",
            "set server app/a maxconn 5",
            "add server app/b",
            "del frontend web",
            "shutdown",
            "set server a state drain x y z w v u t s",
        ] {
            assert!(!is_listed(line), "{line}");
        }
    }

    #[test]
    fn only_a_change_is_audited() {
        assert!(changes("set server app/a state drain") && changes("reload cluster"));
        assert!(!changes("show servers") && !changes(" show ca"));
        let result = ResultSummary { line: "del ban \"x\"", code: "ADM005" };
        assert_eq!(result.json(), r#"{"line":"del ban \"x\"","result":"ADM005"}"#);
    }
}
