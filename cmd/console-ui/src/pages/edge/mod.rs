//! The edge (phase `edge`; SID 0031): the load balancer of this node, the fleet, and the
//! commands of the admin socket.
//!
//! ```text
//! edge            -> GET edge, GET edge/fleet       open the page
//! timer `age`     -> GET edge every 5 s, the fleet every 15 s
//! edge-change     -> POST edge/command  "set server <pool>/<name> state|weight ..."
//! edge-show-*     -> POST edge/command  "show servers|cluster|certs|ca"
//! edge-reload     -> POST edge/command  "reload cluster"
//! ```
//!
//! The page writes lines of the admin socket and nothing else. The server refuses a line
//! that is not on its list, and the admin parser checks every value. The navigation
//! shows the page only when the session reply says that the node has an edge.

mod render;

use sibuna_console_protocol::Action;
use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::edge::{Answer, Command, Fleet, MAX_LINE, Server, View as EdgeView};
use sibuna_json::Value;

use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, SESSION_ENDED, Screen, View};
use crate::pages::management::{Ticket, is_on};
use crate::render::Html;
use crate::state::Phase;

/// How often the view of the node is read while the page is open, in seconds.
const VIEW_SECONDS: u64 = 5;
/// How often the fleet is read, in seconds. A read asks every member.
const FLEET_SECONDS: u64 = 15;
/// The most servers the change form offers and the page draws. The view has no more.
pub(super) const MAX_ROWS: usize = 256;

/// The page's state.
#[derive(Debug, Default)]
pub struct Edge {
    /// The newest view of this node.
    pub view: Option<EdgeView>,
    /// The newest fleet.
    pub fleet: Option<Fleet>,
    /// The line of the newest command and its answer.
    pub answer: Option<(String, Answer)>,
    /// A command is in flight.
    pub busy: bool,
    view_ticket: Ticket,
    fleet_ticket: Ticket,
    command_ticket: Ticket,
    /// When the view and the fleet were last asked for, in browser seconds.
    view_asked: u64,
    fleet_asked: u64,
}

impl Edge {
    /// Returns to the defaults, keeping the ticket generations.
    fn clear(&mut self) {
        *self = Edge {
            view_ticket: self.view_ticket.forget(),
            fleet_ticket: self.fleet_ticket.forget(),
            command_ticket: self.command_ticket.forget(),
            ..Edge::default()
        };
    }

    /// Returns the pool and the server at `index`, counted over all pools in order.
    pub(super) fn server(&self, index: usize) -> Option<(&str, &Server)> {
        let pools = self.view.as_ref()?.pools.iter();
        let mut rows = pools.flat_map(|pool| pool.servers.iter().map(|s| (pool.name.as_str(), s)));
        rows.nth(index)
    }

    fn read_view(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        self.view_asked = cx.state.browser_time;
        let id = self.view_ticket.issue("edge-view")?.to_owned();
        cx.get(&id, "/console/api/edge")
    }

    fn read_fleet(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        self.fleet_asked = cx.state.browser_time;
        let id = self.fleet_ticket.issue("edge-fleet")?.to_owned();
        cx.get(&id, "/console/api/edge/fleet")
    }

    /// Sends one line of the admin socket.
    fn run(&mut self, cx: &mut Context<'_>, line: String) -> Result<(), UiError> {
        if line.len() > MAX_LINE {
            return Err(UiError::InvalidRequest);
        }
        let id = self.command_ticket.issue("edge-command")?.to_owned();
        cx.state.clear_message();
        self.busy = true;
        let command = Command { line };
        let result = cx.post_value(&id, "/console/api/edge/command", &command);
        self.answer = Some((command.line, Answer::default()));
        self.busy &= result.is_ok();
        result
    }

    /// Builds the line of the change form: a drain, a return to service or a weight for
    /// the chosen server, on every node or on this one.
    fn change_line(&self, fields: &Value<'_>) -> Option<String> {
        let index: usize = json::string(fields, "server").parse().ok()?;
        let (pool, server) = self.server(index)?;
        let name = &server.name;
        let mut line = match json::string(fields, "change") {
            "drain" => format!("set server {pool}/{name} state drain"),
            "ready" => format!("set server {pool}/{name} state ready"),
            "weight" => {
                let weight: u32 = json::string(fields, "weight").parse().ok()?;
                format!("set server {pool}/{name} weight {weight}")
            }
            _ => return None,
        };
        if is_on(fields, "local") {
            line.push_str(" local");
        }
        Some(line)
    }

    fn page_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        let line = match name {
            "edge-refresh" => {
                self.read_view(cx)?;
                return self.read_fleet(cx);
            }
            _ if !cx.state.allows(Action::ControlNode) || self.busy => return Ok(()),
            "edge-change" => match self.change_line(fields) {
                Some(line) => line,
                None => {
                    cx.state.set_message("Choose a server and a change. A weight is a number.");
                    return Ok(());
                }
            },
            "edge-reload" if is_on(fields, "confirmed") => "reload cluster".to_owned(),
            "edge-show-servers" => "show servers".to_owned(),
            "edge-show-cluster" => "show cluster".to_owned(),
            "edge-show-certs" => "show certs".to_owned(),
            "edge-show-ca" => "show ca".to_owned(),
            _ => return Ok(()),
        };
        self.run(cx, line)
    }

    /// Takes the answer to a command and reads the view again.
    fn answered(
        &mut self,
        cx: &mut Context<'_>,
        status: i64,
        body: &Value<'_>,
    ) -> Result<(), UiError> {
        self.busy = false;
        let Some((_, answer)) = self.answer.as_mut() else { return Ok(()) };
        if status != 200 {
            self.answer = None;
            cx.state.set_message(failure(status));
            return Ok(());
        }
        match Answer::decode(body, Path::Root) {
            Ok(decoded) => *answer = decoded,
            Err(_) => {
                self.answer = None;
                cx.state.set_message("Could not read the answer. Refresh before retrying.");
                return Ok(());
            }
        }
        cx.commands.focus("#edge-answer")?;
        self.read_view(cx)
    }
}

impl Page for Edge {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Edge))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> std::fmt::Result {
        render::page(self, view.state, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let open = cx.state.is_full_access() && cx.state.edge;
        if name == "edge" && open {
            self.clear();
            cx.state.phase = Phase::Edge;
            cx.state.clear_message();
            cx.state.stats_busy = false;
            cx.state.stale = true;
            self.read_view(cx)?;
            self.read_fleet(cx)?;
            return Ok(true);
        }
        if !name.starts_with("edge-") {
            return Ok(false);
        }
        if open && cx.state.phase == Phase::Edge {
            self.page_action(cx, name, fields)?;
        }
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if !reply.id.starts_with("edge-") {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        if cx.state.phase != Phase::Edge || !cx.state.is_full_access() {
            return Ok(true);
        }
        if status == 401 {
            cx.end_session(SESSION_ENDED)?;
            return Ok(true);
        }
        if self.command_ticket.is(reply.id) {
            self.answered(cx, status, body)?;
        } else if self.view_ticket.is(reply.id) {
            match (status, EdgeView::decode(body, Path::Root)) {
                (200, Ok(view)) => self.view = Some(view),
                _ => cx.state.set_message("Could not read the edge. The page shows older data."),
            }
        } else if self.fleet_ticket.is(reply.id)
            && let (200, Ok(fleet)) = (status, Fleet::decode(body, Path::Root))
        {
            self.fleet = Some(fleet);
        }
        Ok(true)
    }

    fn timer(&mut self, cx: &mut Context<'_>, _id: &str) -> Result<bool, UiError> {
        if cx.state.phase != Phase::Edge || !cx.state.is_full_access() {
            return Ok(false);
        }
        let now = cx.state.browser_time;
        let due = |asked: u64, every: u64| now < asked || now - asked >= every;
        if !self.busy && due(self.view_asked, VIEW_SECONDS) {
            self.read_view(cx)?;
        }
        if due(self.fleet_asked, FLEET_SECONDS) {
            self.read_fleet(cx)?;
        }
        Ok(false)
    }

    fn reset(&mut self) {
        self.clear();
    }
}

/// Returns the message for a refused command.
fn failure(status: i64) -> &'static str {
    match status {
        400 => "The console does not offer this command, or the line is malformed.",
        403 => "Changing the edge requires an operator or an administrator.",
        429 => "Too many changes. Wait a minute, then refresh.",
        0 | 503 => "Outcome unknown. Refresh the page before retrying.",
        _ => "The command failed. Refresh the page before retrying.",
    }
}

#[cfg(test)]
mod tests;
