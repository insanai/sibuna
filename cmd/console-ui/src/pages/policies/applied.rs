//! The applied rules of this node, the private policy tester and the inspection modes
//! (`policy_controller.zig` and the controller half of `inspection_form.zig`).

use sibuna_console_protocol::{Action, Text};
use sibuna_json::Value;

use super::Policies;
use super::data::{Decision, Modes, Snapshot};
use super::manager::managed_post;
use crate::commands::{Field, Json, write_fields};
use crate::error::UiError;
use crate::json;
use crate::json::parse_integer;
use crate::page::{Context, SESSION_ENDED};
use crate::pages::request_headers;
use crate::state::Phase;

/// The fields of a test request, kept to refill the tester.
#[derive(Debug, Default)]
pub struct TestRequest {
    /// The request path.
    pub path: Text<512>,
    /// The client address.
    pub ip: Text<48>,
    /// The User-Agent.
    pub user_agent: Text<256>,
    /// The query string, without `?`.
    pub query: Text<512>,
    /// The body.
    pub body: Text<2048>,
    /// The headers, one `Name: value` per line.
    pub headers: Text<2048>,
}

/// A tester result: a decision, or a reply that is not one.
#[derive(Clone, Debug, PartialEq)]
pub enum Evaluation {
    /// The decision.
    Decided(Decision),
    /// The reply was not a valid decision.
    Invalid,
}

/// The applied-rules view and the flags the whole page shares.
#[derive(Debug, Default)]
pub struct Applied {
    /// Inspection modes the operator saved, shown until the page is opened again.
    pub inspection_draft: Option<Modes>,
    /// The tester's request.
    pub request: TestRequest,
    /// The current page of applied rules.
    pub snapshot: Option<Snapshot>,
    /// The tester's latest result.
    pub decision: Option<Evaluation>,
    /// The applied revision the pages follow.
    pub applied: Text<20>,
    /// The offset of the current page.
    pub offset: u8,
    /// The offset of the next page.
    pub next: Option<u8>,
    /// A policy request is in flight.
    pub busy: bool,
    /// A tester request is in flight.
    pub testing: bool,
    /// The shown policy is not current; edits wait for a refresh.
    pub stale: bool,
}

impl Policies {
    /// Handles the navigation, paging and tester actions.
    pub(super) fn policy_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if !cx.state.is_full_access() {
            return Ok(false);
        }
        let on_page = cx.state.phase == Phase::Policies;
        match name {
            "policies" | "policies-refresh" => self.navigate(cx)?,
            "policies-next" if on_page => self.next_page(cx)?,
            "policy-run" if on_page => self.run_test(cx, fields)?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Opens the applied rules from their first page and reloads the IP groups.
    pub(super) fn navigate(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let model = &mut self.applied;
        if cx.state.phase == Phase::Policies && (model.busy || model.testing) {
            return Ok(());
        }
        model.testing = false;
        self.manager.active = false;
        self.rule_hits.clear();
        model.inspection_draft = None;
        cx.state.phase = Phase::Policies;
        cx.state.clear_message();
        model.offset = 0;
        model.applied = Text::default();
        model.decision = None;
        model.busy = true;
        query(cx, &mut self.tickets.policy, false, &mut |json| {
            write_fields(json, &[("offset", Field::Unsigned(0))])
        })?;
        self.reputation.clear();
        self.reputation_refresh(cx)
    }

    fn next_page(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let model = &mut self.applied;
        if model.busy || model.testing || model.stale {
            return Ok(());
        }
        let Some(offset) = model.next else { return Ok(()) };
        model.offset = offset;
        model.busy = true;
        let applied = model.applied.as_str();
        query(cx, &mut self.tickets.policy, false, &mut |json| {
            write_fields(
                json,
                &[
                    ("offset", Field::Unsigned(u64::from(offset))),
                    ("applied", Field::Text(applied)),
                ],
            )
        })
    }

    /// Evaluates the tester's request against the applied policy, or against the
    /// editor's draft while the managed rules are open.
    fn run_test(&mut self, cx: &mut Context<'_>, fields: &Value<'_>) -> Result<(), UiError> {
        let model = &self.applied;
        if model.testing || model.busy || model.stale {
            return Ok(());
        }
        let active = self.manager.active;
        if (!active && model.applied.is_empty()) || !self.manager.review.is_empty() {
            return Ok(());
        }
        let draft = if active {
            let Some(document) = self.capture_document(cx, fields)? else { return Ok(()) };
            Some(document)
        } else {
            None
        };
        let request = &mut self.applied.request;
        request.path.set(json::string(fields, "path"))?;
        request.ip.set(json::string(fields, "ip"))?;
        request.query.set(json::string(fields, "query"))?;
        request.user_agent.set(json::string(fields, "user_agent"))?;
        request.body.set(json::string(fields, "body"))?;
        request.headers.set(json::string(fields, "headers"))?;
        let request = &self.applied.request;
        let Ok(headers) = request_headers::parse(request.headers.as_str()) else {
            cx.state
                .set_message("Use up to eight unique request headers, one Name: value per line.");
            return cx.commands.focus("#console-message");
        };
        self.applied.testing = true;
        self.applied.decision = None;
        cx.state.clear_message();
        let applied = (!active).then_some(self.applied.applied.as_str());
        let committed = active.then_some(self.manager.committed.as_str());
        query(cx, &mut self.tickets.policy, true, &mut |json| {
            json.begin_object()?;
            let members = [
                ("applied", nullable(applied)),
                ("draft", nullable(draft.as_deref())),
                ("committed", nullable(committed)),
                ("path", Field::Text(request.path.as_str())),
                ("ip", Field::Text(request.ip.as_str())),
                ("query", Field::Text(request.query.as_str())),
                ("user_agent", Field::Text(request.user_agent.as_str())),
                ("body", Field::Text(request.body.as_str())),
            ];
            for (key, value) in members {
                json.key(key)?;
                write_field(json, value)?;
            }
            json.key("headers")?;
            json.begin_array()?;
            for header in &headers {
                write_fields(
                    json,
                    &[("name", Field::Text(header.name)), ("value", Field::Text(header.value))],
                )?;
            }
            json.end_array()?;
            json.end_object()
        })
    }

    /// Handles a reply to a policy, test or managed request. Only the newest request's
    /// reply counts.
    pub(super) fn policy_response(
        &mut self,
        cx: &mut Context<'_>,
        id: &str,
        status: i64,
        body: &Value<'_>,
    ) -> Result<(), UiError> {
        let generation = id.rsplit_once('-').and_then(|(_, number)| parse_integer::<u32>(number));
        if generation != Some(self.tickets.policy) {
            return Ok(());
        }
        self.applied.busy = false;
        self.applied.testing = false;
        if cx.state.phase != Phase::Policies {
            return Ok(());
        }
        if status == 401 || status == 403 {
            return cx.end_session(SESSION_ENDED);
        }
        if status != 200 {
            self.applied.stale = status != 400 && status != 429;
            self.import_failed(id);
            cx.state.set_message(match status {
                400 => "Check the request, rule settings, headers and networks, then try again.",
                409 => "Policy or reputation changed. Refresh and review the current rules.",
                429 => "Too many queries. Wait a minute before trying again.",
                _ => "Policy data is unavailable. Refresh to retry; previous data may be stale.",
            });
            return cx.commands.focus("#console-message");
        }
        if id.starts_with("managed-") {
            return self.managed_response(cx, id, body);
        }
        if id.starts_with("policies-") {
            self.page_received(body)?;
        } else {
            self.applied.decision =
                Some(Decision::decode(body).map_or(Evaluation::Invalid, Evaluation::Decided));
            cx.commands.focus("#policy-result")?;
        }
        cx.state.clear_message();
        Ok(())
    }

    /// Takes a page of applied rules; its revision and continuation must be valid.
    fn page_received(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let applied = json::string(body, "applied");
        parse_integer::<u64>(applied).ok_or(UiError::InvalidResponse)?;
        let next = json::field(body, "next").ok_or(UiError::InvalidResponse)?;
        let next = match next {
            Value::Null => None,
            value => {
                let offset = json::integer(value).and_then(|number| u8::try_from(number).ok());
                Some(offset.filter(|offset| *offset <= 128).ok_or(UiError::InvalidResponse)?)
            }
        };
        let applied = Text::new(applied)?;
        let model = &mut self.applied;
        model.snapshot = Some(Snapshot::new(body));
        model.applied = applied;
        model.next = next;
        model.stale = false;
        Ok(())
    }

    /// Saves the inspection modes against the applied revision.
    pub(super) fn inspection(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if name != "inspection-save" {
            return Ok(false);
        }
        let model = &self.applied;
        if cx.state.phase != Phase::Policies
            || !cx.state.allows(Action::ManagePolicy)
            || model.busy
            || model.testing
            || model.stale
        {
            return Ok(true);
        }
        let Some((revision, modes)) = submit(model.snapshot.as_ref(), fields) else {
            cx.state.set_message(
                "Refresh the applied revision, choose all four modes and confirm your review.",
            );
            return Ok(true);
        };
        self.applied.inspection_draft = Some(modes);
        let document = modes.document();
        let fields = [
            ("expected_revision", Field::Text(revision.as_str())),
            ("document", Field::Text(&document)),
        ];
        managed_post(cx, &mut self.tickets.policy, &mut self.applied.busy, "inspection", &fields)?;
        Ok(true)
    }

    /// Opens the IP groups form with an incident's address drafted; nothing is submitted
    /// until the operator chooses a duration and saves.
    pub(super) fn address_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
    ) -> Result<bool, UiError> {
        let (deny, address) = if let Some(address) = name.strip_prefix("events-deny-") {
            (true, address)
        } else if let Some(address) = name.strip_prefix("events-allow-") {
            (false, address)
        } else {
            return Ok(false);
        };
        if cx.state.kiosk || !cx.state.allows(Action::ManagePolicy) {
            return Ok(true);
        }
        if address.is_empty() || address.len() > 48 {
            return Err(UiError::InvalidRequest);
        }
        let draft = Text::new(address)?;
        self.navigate(cx)?;
        self.reputation.draft_prefix = draft;
        self.reputation.draft_deny = deny;
        cx.commands.focus("#reputation-prefix")?;
        Ok(true)
    }
}

/// Posts a catalog query (`policies-<n>`) or a test (`policy-test-<n>`) with the next
/// policy generation. The body writer is a trait object, so every caller shares one copy
/// of the command code.
fn query(
    cx: &mut Context<'_>,
    generation: &mut u32,
    testing: bool,
    body: &mut dyn FnMut(&mut Json<'_>) -> std::fmt::Result,
) -> Result<(), UiError> {
    *generation = generation.wrapping_add(1);
    let (id, path) = if testing {
        (format!("policy-test-{generation}"), "/console/api/policies/test")
    } else {
        (format!("policies-{generation}"), "/console/api/policies/query")
    };
    cx.post(&id, path, body)
}

/// Returns a text member, or null.
fn nullable(value: Option<&str>) -> Field<'_> {
    value.map_or(Field::Null, Field::Text)
}

/// Writes one scalar member value.
fn write_field(json: &mut Json<'_>, value: Field<'_>) -> std::fmt::Result {
    match value {
        Field::Text(text) => json.string(text),
        Field::Unsigned(number) => json.uint(number),
        Field::Signed(number) => json.int(number),
        Field::Bool(flag) => json.bool(flag),
        Field::Null => json.null(),
    }
}

/// Checks an inspection form against the applied page: the committed revision must be
/// applied, the review confirmed and all four modes chosen. Returns the revision and the
/// modes.
fn submit(snapshot: Option<&Snapshot>, fields: &Value<'_>) -> Option<(Text<20>, Modes)> {
    let snapshot = snapshot?;
    parse_integer::<u64>(&snapshot.committed)?;
    if snapshot.committed != snapshot.applied || json::string(fields, "reviewed") != "on" {
        return None;
    }
    let modes = Modes::decode(fields).ok()?;
    Some((Text::new(&snapshot.committed).ok()?, modes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pages::policies::data::Mode;

    /// Ported from `inspection_form.zig`.
    #[test]
    fn inspection_form_requires_the_complete_reviewed_matrix_and_current_applied_revision() {
        let fields = sibuna_json::parse(
            concat!(
                r#"{"path_traversal":"enforce","sqli":"audit","xss":"disabled","#,
                r#""rce":"enforce","reviewed":"on"}"#
            )
            .as_bytes(),
        )
        .unwrap();
        let page = Snapshot { committed: "7".into(), applied: "7".into(), page: None };
        let (revision, modes) = submit(Some(&page), &fields).unwrap();
        assert_eq!(revision.as_str(), "7");
        assert_eq!(modes.0[1], Mode::Audit);
        assert!(modes.document().contains("audit"));
        assert_eq!(
            modes.document(),
            "{\"path_traversal\":\"enforce\",\"sqli\":\"audit\",\"xss\":\"disabled\",\
             \"rce\":\"enforce\"}"
        );
        let conflict = Snapshot { committed: "8".into(), ..page.clone() };
        assert!(submit(Some(&conflict), &fields).is_none());
        assert!(submit(Some(&page), &Value::Null).is_none());
        assert!(submit(None, &fields).is_none());
    }
}
