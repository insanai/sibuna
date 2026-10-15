//! Cluster members and local node control (phase `nodes`): the serving node's status, the
//! drain, resume and clear-bans commands with a fresh preview and a durable receipt, the
//! replicated member rows with this console's probes, and the management peers' live
//! telemetry.
//!
//! Ported from `nodes_state.zig`, `nodes_controller.zig`, `nodes_page.zig`,
//! `peer_page.zig` and the `nodes` branches of `live_controller.zig`. A command keeps its
//! operation id across retries; a durable intent alone never proves a runtime effect.
//!
//! Deliberate change: member rows no longer show the consensus log slots
//! (`applied_slot`, `decided_slot`) and the replication lag derived from them. The Rust
//! port has no consensus log (SID 0013); a member row shows its applied policy revision.

mod members;
mod model;
mod render;

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::nodes::{Kind, Receipt, State as Effect, Status};
use sibuna_console_protocol::subscriptions::Args;
use sibuna_console_protocol::{Action, Topic};
use sibuna_json::Value;

use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::page::{Context, Page, Reply, SESSION_ENDED, Screen, View};
use crate::render::Html;
use crate::state::{Phase, State};
pub use model::{Busy, Input, MAX_REVISION, Peers};

/// How long a status preview stays fresh, in seconds.
const FRESH_SECONDS: u64 = 10;
/// How often the open page polls the status, in seconds.
const POLL_SECONDS: u64 = 5;

/// The Nodes page.
#[derive(Debug, Default)]
pub struct Nodes {
    /// The serving node's latest status.
    pub status: Option<Status>,
    /// The latest receipt of the pending command.
    pub receipt: Option<Receipt>,
    /// The previewed or attempted command.
    pub pending: Option<Input>,
    /// The pending command was sent at least once.
    pub attempted: bool,
    /// The status is current (no command or refresh since it arrived).
    pub loaded: bool,
    /// When the status arrived, in browser seconds.
    pub received_at: u64,
    /// When the status was last requested, in browser seconds.
    pub last_attempt: u64,
    /// The newest status or command request id.
    pub ticket: String,
    /// What that request does.
    pub busy: Busy,
    /// The cluster view.
    pub peers: Peers,
    /// The newest member page request id.
    pub members_ticket: String,
    /// The shared generation of both ticket kinds; it survives a reset.
    generation: u64,
}

impl Nodes {
    /// Returns true when the status arrived at most ten seconds before `now`.
    pub fn is_fresh(&self, now: u64) -> bool {
        self.loaded && now >= self.received_at && now - self.received_at <= FRESH_SECONDS
    }

    /// Returns the next generation.
    fn next_generation(&mut self) -> Result<u64, UiError> {
        self.generation = self.generation.checked_add(1).ok_or(UiError::InvalidRequest)?;
        Ok(self.generation)
    }

    /// Issues the next status or command request id.
    fn ticket(&mut self, state: &mut State, busy: Busy) -> Result<String, UiError> {
        self.ticket = format!("nodes-{}", self.next_generation()?);
        self.busy = busy;
        state.clear_message();
        state.message_success = false;
        Ok(self.ticket.clone())
    }

    /// Requests the status and, unless one is in flight, the member view.
    fn refresh(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let id = self.ticket(cx.state, Busy::Status)?;
        self.loaded = false;
        self.last_attempt = cx.state.browser_time;
        if let Err(error) = cx.get(&id, "/console/api/nodes/local") {
            self.busy = Busy::Idle;
            return Err(error);
        }
        if self.peers.busy {
            return Ok(());
        }
        let Ok(generation) = self.next_generation() else { return Ok(()) };
        self.members_ticket = format!("nodes-m-{generation}");
        self.peers.busy = true;
        let result = cx.get(&self.members_ticket, "/console/api/nodes");
        self.peers.busy &= result.is_ok();
        result
    }

    /// Sends the pending command.
    fn submit(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        if !cx.state.allows(Action::ControlNode) {
            return Ok(());
        }
        let Some(pending) = self.pending.clone() else { return Ok(()) };
        let id = self.ticket(cx.state, Busy::Command)?;
        self.attempted = true;
        self.loaded = false;
        let revision = pending.revision.to_string();
        let result = cx.post(&id, "/console/api/nodes/command", &mut |json| {
            write_fields(
                json,
                &[
                    ("id", Field::Text(pending.id.as_str())),
                    ("boot", Field::Text(pending.boot.as_str())),
                    ("node", Field::Unsigned(u64::from(pending.node))),
                    ("expected_revision", Field::Text(&revision)),
                    ("kind", Field::Text(pending.kind.name())),
                ],
            )
        });
        if result.is_err() {
            self.busy = Busy::Idle;
        }
        result
    }

    /// Previews command `kind` against the fresh status.
    fn select(&mut self, cx: &mut Context<'_>, kind: &str) -> Result<(), UiError> {
        if !cx.state.allows(Action::ControlNode)
            || !self.is_fresh(cx.state.browser_time)
            || self.pending.is_some()
        {
            return Ok(());
        }
        let Some(kind) = Kind::from_name(kind) else { return Ok(()) };
        let Some(current) = &self.status else { return Ok(()) };
        let refused = current.completion_pending
            || current.control_revision >= MAX_REVISION
            || (kind == Kind::Drain && current.draining)
            || (kind == Kind::Resume && !current.draining)
            || (kind == Kind::ClearLocalBans && current.active_ban_entries == 0);
        if refused {
            return Ok(());
        }
        self.pending = Some(Input {
            id: current.operation_id.clone(),
            boot: current.boot.clone(),
            node: current.node,
            revision: current.control_revision,
            kind,
        });
        self.attempted = false;
        self.receipt = None;
        cx.commands.focus("#nodes-confirmation")
    }

    /// Handles the page's own actions once the page is open and idle.
    fn page_action(&mut self, cx: &mut Context<'_>, name: &str) -> Result<(), UiError> {
        if let Some(kind) = name.strip_prefix("nodes-select-") {
            return self.select(cx, kind);
        }
        match name {
            "nodes-refresh" => {
                if !self.attempted {
                    self.pending = None;
                }
                self.refresh(cx)
            }
            "nodes-confirm" if !self.attempted => {
                if self.is_fresh(cx.state.browser_time) {
                    return self.submit(cx);
                }
                self.pending = None;
                self.refresh(cx)?;
                cx.state
                    .set_message("Preview expired. Review the refreshed node before confirming.");
                Ok(())
            }
            "nodes-retry" if self.attempted => self.submit(cx),
            "nodes-receipt" => {
                let Some(pending) = self.pending.clone() else { return Ok(()) };
                let id = self.ticket(cx.state, Busy::Receipt)?;
                let result = cx.post(&id, "/console/api/nodes/command/read", &mut |json| {
                    write_fields(json, &[("id", Field::Text(pending.id.as_str()))])
                });
                if result.is_err() {
                    self.busy = Busy::Idle;
                }
                result
            }
            "nodes-cancel" if !self.attempted => {
                self.pending = None;
                cx.commands.focus_top("#page-heading")
            }
            "nodes-acknowledge"
                if self
                    .receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.state == Effect::Uncertain) =>
            {
                self.pending = None;
                self.attempted = false;
                self.refresh(cx)
            }
            _ => Ok(()),
        }
    }

    /// Takes a reply to the member page request.
    fn members_reply(&mut self, state: &State, status: i64, body: &Value<'_>) {
        if !self.peers.busy {
            return;
        }
        self.peers.busy = false;
        if status != 200 {
            return;
        }
        if let Ok(peers) = model::read_members(body) {
            self.peers = Peers { received_at: state.browser_time, ..peers };
        }
    }

    /// Takes a refused status, command or receipt request.
    fn refused(&mut self, cx: &mut Context<'_>, busy: Busy, status: i64) -> Result<(), UiError> {
        if busy == Busy::Command && matches!(status, 400 | 403 | 409) {
            self.pending = None;
            self.attempted = false;
            self.refresh(cx)?;
            cx.state
                .set_message("Command refused. Review the refreshed node before trying again.");
            return Ok(());
        }
        cx.state.set_message(if busy == Busy::Status {
            "Node status unavailable. Refresh to obtain a current snapshot."
        } else {
            "Outcome not confirmed. Inspect the receipt or retry the same operation."
        });
        cx.commands.focus("#console-message")
    }
}

impl Page for Nodes {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Nodes))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> std::fmt::Result {
        render::page(self, view.state, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        _fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if name == "nodes" && cx.state.is_full_access() {
            cx.state.phase = Phase::Nodes;
            cx.state.stats_busy = false;
            cx.state.stale = true;
            self.busy = Busy::Idle;
            if !self.attempted {
                self.pending = None;
            }
            self.refresh(cx)?;
            return Ok(true);
        }
        if !name.starts_with("nodes-") {
            return Ok(false);
        }
        if cx.state.phase == Phase::Nodes && cx.state.is_full_access() && self.busy == Busy::Idle {
            self.page_action(cx, name)?;
        }
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if !reply.id.starts_with("nodes-") {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        if cx.state.phase != Phase::Nodes {
            return Ok(true);
        }
        if !self.members_ticket.is_empty() && reply.id == self.members_ticket {
            self.members_reply(cx.state, status, body);
            return Ok(true);
        }
        if self.ticket.is_empty() || reply.id != self.ticket {
            return Ok(true);
        }
        let busy = std::mem::take(&mut self.busy);
        if busy == Busy::Idle {
            return Ok(true);
        }
        if status == 401 {
            cx.end_session(SESSION_ENDED)?;
            return Ok(true);
        }
        if status != 200 {
            self.refused(cx, busy, status)?;
            return Ok(true);
        }
        if busy == Busy::Status {
            self.status = Some(model::read_status(body)?);
            self.loaded = true;
            self.received_at = cx.state.browser_time;
            return Ok(true);
        }
        let pending = self.pending.as_ref().ok_or(UiError::InvalidResponse)?;
        let receipt = model::read_receipt(body, pending)?;
        if receipt.completion_persisted {
            self.pending = None;
        }
        self.receipt = Some(receipt);
        if self.pending.is_none() {
            self.refresh(cx)?;
        }
        cx.commands.focus("#nodes-receipt")?;
        Ok(true)
    }

    fn timer(&mut self, cx: &mut Context<'_>, _id: &str) -> Result<bool, UiError> {
        if cx.state.phase != Phase::Nodes {
            return Ok(false);
        }
        let now = cx.state.browser_time;
        let idle = self.busy == Busy::Idle && self.pending.is_none();
        let due = now < self.last_attempt || now - self.last_attempt >= POLL_SECONDS;
        if idle && cx.state.is_full_access() && due {
            self.refresh(cx)?;
        }
        Ok(true)
    }

    fn subscription(&self, state: &State, topic: Topic) -> Option<Args> {
        (topic == Topic::Nodes && state.phase == Phase::Nodes).then(Args::default)
    }

    fn publish(
        &mut self,
        cx: &mut Context<'_>,
        topic: Topic,
        view: &Value<'_>,
    ) -> Result<(), UiError> {
        if topic == Topic::Nodes {
            let peers = model::read_members(view)?;
            self.peers = Peers { received_at: cx.state.browser_time, ..peers };
        }
        Ok(())
    }

    fn reset(&mut self) {
        *self = Nodes { generation: self.generation, ..Nodes::default() };
    }
}

#[cfg(test)]
mod tests;
