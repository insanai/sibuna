//! The policies page (phase `policies`): the applied rules of this node with the private
//! policy tester and the inspection modes, the managed-rule editor with its change review,
//! history, ordering, replay, import and export, the IP groups (reputation prefixes and
//! the country builder), and the rule hit history comparison.
//!
//! Ported from `policies_page.zig`, `policy_controller.zig`, `policy_data.zig`,
//! `policy_form.zig`, `policy_limits.zig`, `policy_matchers.zig`, `policy_manager.zig`,
//! `policy_changes.zig`, `policy_replay.zig`, `policy_transfer.zig`,
//! `managed_controller.zig`, `workflow_controller.zig`, `inspection_form.zig`,
//! `reputation_*.zig` and `rule_hit_*.zig`. The tester's request headers are parsed by
//! [`crate::pages::request_headers`]; the response pages (`pages_*.zig`) belong to the
//! settings page.
//!
//! # Dispatch
//!
//! One module serves every action, reply and timer of the page. Its names never collide
//! with another module's, so its place in the registry only has to precede the events
//! page (which handles the other `events-` actions): `events-deny-<address>` and
//! `events-allow-<address>` open the IP groups form here. Replies are claimed by the id
//! prefixes `policies-`, `policy-test-`, `managed-`, `reputation-` and `rule-hits-`.
//!
//! The audit page opens a recorded policy revision with the action
//! [`REVIEW_REVISION_ACTION`] and the fields `{"id": "<rule id>", "revision": "<n>"}`,
//! after it has checked that its selected record is a policy edit (Zig's
//! `managed_controller.fromAudit`, which read the audit state directly).
//!
//! # Changes from the Zig module
//!
//! - Replies are decoded once, when they arrive, into typed values; Zig stored their JSON
//!   text in fixed buffers (4 KiB pages, a 1 KiB decision, a 2 KiB replay, a 4 KiB
//!   reputation page, a 2 KiB country summary) and parsed it again on every render. The
//!   buffers refused larger replies with the generic error; the event input bound
//!   ([`crate::INPUT_LIMIT`]) remains. Missing and mistyped members read as Zig read them.
//! - Rule hit parts and the hourly cohorts of a row decode as the protocol's
//!   `rule_hit_history` types, which refuse members they do not know where the Zig wire
//!   decoder ignored them.
//! - Header matchers are kept as rows, not as JSON text; the change review prints the
//!   same JSON text. The compact documents of a policy set keep their number literals as
//!   written, where Zig printed floats again in its own notation.
//! - The staged documents of a policy set, the replay summary and the request counters
//!   were module-level variables in Zig. The documents and the replay now belong to the
//!   page and are dropped at sign-out (Zig kept the replay); the counters still survive a
//!   session reset, so a late reply to an earlier session is never accepted.
//! - Bugs fixed: the node-local limits sentence was cut to "Not reported" when its numbers
//!   did not fit a 128-byte buffer (for example 10,000 requests); the IP groups claimed
//!   every `country-` action, which hid the globe's country buttons on the dashboard;
//!   reputation errors kept the success style of an earlier message, the success messages
//!   of a rule move and a policy set import were shown in the error style (the message
//!   setter cleared the flag set just before it), a reputation 401 reset the appearance,
//!   and a country preview with a malformed review digest was half applied. SID 0007
//!   records these fixes (2026-10-15).
//!
//! A differential run against the Zig module (both fed the same 86 events covering the
//! applied page, the tester, inspection, IP groups, the country builder, the editor,
//! history, replay, import, export, ordering and rule hit history) produced identical
//! pages and command lists apart from these fixes.

mod applied;
mod applied_view;
mod changes;
mod data;
mod form;
mod limits;
mod manager;
mod replay;
mod reputation;
mod rule_hits;
mod workflow;

use std::fmt;

use sibuna_console_protocol::subscriptions::Args;
use sibuna_console_protocol::{Action, Topic};
use sibuna_json::Value;

use crate::commands::Field;
use crate::error::UiError;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::render::Html;
use crate::state::{Phase, State};

use applied::Applied;
use manager::Manager;
use reputation::Reputation;
use rule_hits::RuleHits;

/// The action the audit page sends to open a recorded revision of a managed rule; its
/// fields are `id` (the rule id) and `revision` (decimal).
pub const REVIEW_REVISION_ACTION: &str = "policies-review-revision";

/// The request counters of the page. They survive a session reset, as Zig's module-level
/// counters did, so a reply to a request of an earlier session never matches.
#[derive(Clone, Copy, Debug, Default)]
struct Tickets {
    /// The generation of policy, test and managed requests (wrapping, as in Zig).
    policy: u32,
    /// The last reputation request.
    reputation: u64,
    /// The last rule hit history request.
    rule_hits: u64,
}

/// The state of the policies page.
#[derive(Debug, Default)]
pub struct Policies {
    applied: Applied,
    manager: Manager,
    reputation: Reputation,
    rule_hits: RuleHits,
    tickets: Tickets,
}

impl Page for Policies {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Policies))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        let state = view.state;
        if self.rule_hits.open {
            return self.rule_hits.render(state, out);
        }
        if self.manager.active {
            return self.render_manager(state, out);
        }
        self.render_applied(state, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if name == REVIEW_REVISION_ACTION {
            self.review_revision(cx, fields)?;
            return Ok(true);
        }
        Ok(self.rule_hit_action(cx, name, fields)?
            || self.reputation_action(cx, name, fields)?
            || self.transfer(cx, name, fields)?
            || self.inspection(cx, name, fields)?
            || self.managed_action(cx, name, fields)?
            || self.address_action(cx, name)?
            || self.policy_action(cx, name, fields)?)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        let id = reply.id;
        let rule_hits = id.starts_with("rule-hits-");
        let reputation = id.starts_with("reputation-");
        let policy = id.starts_with("policies-")
            || id.starts_with("policy-test-")
            || id.starts_with("managed-");
        if !(rule_hits || reputation || policy) {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        if rule_hits {
            self.rule_hit_response(cx, id, status, body)?;
        } else if reputation {
            self.reputation_response(cx, id, status, body)?;
        } else {
            self.policy_response(cx, id, status, body)?;
        }
        Ok(true)
    }

    fn timer(&mut self, cx: &mut Context<'_>, id: &str) -> Result<bool, UiError> {
        if id != "reputation-undo" {
            return Ok(false);
        }
        self.reputation.tick(cx.state.browser_time);
        Ok(true)
    }

    fn subscription(&self, state: &State, topic: Topic) -> Option<Args> {
        (topic == Topic::Policy && state.phase == Phase::Policies).then(Args::default)
    }

    fn reset(&mut self) {
        let tickets = self.tickets;
        *self = Policies::default();
        self.tickets = tickets;
    }
}

impl Policies {
    /// Opens a recorded revision of a managed rule from the audit page: the current
    /// document is read first, then the recorded one is compared with it.
    fn review_revision(
        &mut self,
        cx: &mut Context<'_>,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        if cx.state.phase != Phase::Audit || !cx.state.allows(Action::ManagePolicy) {
            return Ok(());
        }
        let id = crate::json::string(fields, "id");
        let revision = crate::json::string(fields, "revision");
        let valid_id = !id.is_empty()
            && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if !valid_id
            || crate::json::parse_integer::<u64>(revision).is_none_or(|number| number == 0)
        {
            return Ok(());
        }
        cx.state.phase = Phase::Policies;
        cx.state.clear_message();
        self.applied.busy = false;
        self.applied.testing = false;
        self.applied.decision = None;
        self.manager.open_revision(id, revision)?;
        let fields = [("kind", Field::Text("document")), ("id", Field::Text(id))];
        manager::managed_post(
            cx,
            &mut self.tickets.policy,
            &mut self.applied.busy,
            "baseline",
            &fields,
        )
    }
}

/// Shows `text` as a success message.
fn success(state: &mut State, text: &str) {
    state.set_message(text);
    state.message_success = true;
}

#[cfg(test)]
mod tests;
