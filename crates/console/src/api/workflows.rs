//! The routes `policies/order`, `policies/replay`, `reputation/query`, `reputation/edit`,
//! `reputation/remove` and `policies/import` (Zig's `workflow_routes.zig`).
//!
//! Every mutation names the policy revision the operator saw; storage decides, and this
//! layer only shapes bounded requests and replies. A policy set import is one request of at
//! most 128 documents (SID 0013, decision 1 of the port); Zig staged it in chunks.

use std::fmt::{self, Write};

use sibuna_console_protocol::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, counter_field, decimal_string,
    decode_list, field, optional_counter_field,
};
use sibuna_console_protocol::workflows::{
    self, Direction, MAX_NOTE, MAX_PREFIX, Order, Replay, ReplaySummary, ReputationAction,
    ReputationEdit, ReputationPage, ReputationQuery, ReputationRemove,
};
use sibuna_console_protocol::{Text, policies};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::policy::{self as stored, Import};
use sibuna_console_storage::reputation::{self, PrefixChange};
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use super::policies::{Base, Revisions, spend, work_bound};
use crate::dispatch::Call;
use crate::http::body::{MAX_BODY, read_json};
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::PolicyOrder => order(shared, context, call),
        Handler::PolicyReplay => replay(shared, context, call),
        Handler::ReputationQuery => reputation_query(shared, context, call),
        Handler::ReputationEdit => reputation_edit(shared, context, call),
        Handler::ReputationRemove => reputation_remove(shared, context, call),
        Handler::PolicyImport => import(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Parses an expected revision: 1 to 19 decimal digits, at most 2^63 - 1 (Zig's
/// `workflow_routes.revision`).
///
/// Fails with [`RouteError::BadRequest`] for anything else.
pub(crate) fn revision(text: &str) -> Result<u64, RouteError> {
    if text.is_empty() || text.len() > 19 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RouteError::BadRequest);
    }
    match text.parse::<u64>() {
        Ok(value) if value <= i64::MAX as u64 => Ok(value),
        _ => Err(RouteError::BadRequest),
    }
}

/// Maps a workflow's storage failure as Zig did: storage that cannot answer is 503
/// `CONSOLEQUORUM`, a full trie or table 422 `CONSOLECAPACITY`, every other refusal
/// `CONSOLEPOLICY` with the common statuses.
pub(crate) fn workflow_error(failure: StorageFailure) -> RouteError {
    match &failure {
        StorageFailure::Console(ConsoleStorageError::Unavailable) => {
            RouteError::fail(503, "CONSOLEQUORUM")
        }
        StorageFailure::Console(ConsoleStorageError::Capacity) => {
            RouteError::fail(422, "CONSOLECAPACITY")
        }
        _ => failure.route_error("CONSOLEPOLICY"),
    }
}

/// Answers a committed workflow with its revision and the node's applied one.
pub(crate) fn committed(
    shared: &Shared,
    context: &mut Context<'_>,
    committed: u64,
) -> Result<(), RouteError> {
    let applied = shared.node.applied_revision();
    Ok(reply::json(context, &Revisions { committed, applied })?)
}

/// A rule move's direction by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectionName(Direction);

impl WireEnum for DirectionName {
    const ALL: &'static [DirectionName] =
        &[DirectionName(Direction::Up), DirectionName(Direction::Down)];

    fn name(self) -> &'static str {
        match self.0 {
            Direction::Up => "up",
            Direction::Down => "down",
        }
    }
}

/// A reputation action by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActionName(pub ReputationAction);

impl WireEnum for ActionName {
    const ALL: &'static [ActionName] =
        &[ActionName(ReputationAction::Deny), ActionName(ReputationAction::Allow)];

    fn name(self) -> &'static str {
        match self.0 {
            ReputationAction::Deny => "deny",
            ReputationAction::Allow => "allow",
        }
    }
}

/// The body of `policies/order`.
struct OrderForm {
    id: Text<128>,
    expected_revision: String,
    direction: DirectionName,
}

impl Decode for OrderForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<OrderForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = OrderForm {
            id: fields.required("id")?,
            expected_revision: fields.required("expected_revision")?,
            direction: fields.required("direction")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `policies/order`: moves one rule up or down (S15).
fn order(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 512];
    let form: OrderForm = read_json(context, &mut body)?;
    let input = Order {
        auth: call.auth(shared)?,
        expected_revision: revision(&form.expected_revision)?,
        id: form.id,
        direction: form.direction.0,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    let revision = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { stored::order_rules(tx, &credential, &input, now).await })
        })
        .map_err(workflow_error)?;
    committed(shared, context, revision)
}

/// The body of `policies/replay`.
struct ReplayForm {
    rule: Text<128>,
    hours: u16,
    draft: Option<Text<{ policies::MAX_DOCUMENT }>>,
    committed: Option<String>,
}

impl Decode for ReplayForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ReplayForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = ReplayForm {
            rule: fields.or_default("rule")?,
            hours: fields.or("hours", 24)?,
            draft: fields.or_default("draft")?,
            committed: fields.or_default("committed")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `policies/replay`: retained incidents against the committed policy or a draft.
fn replay(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    let mut body = vec![0u8; 8 * 1024];
    let form: ReplayForm = read_json(context, &mut body)?;
    let input = Replay {
        auth: call.auth(shared)?,
        committed: form.committed.as_deref().map(revision).transpose()?,
        draft: form.draft,
        rule: form.rule,
        hours: form.hours,
    };
    let credential = call.credential(shared)?;
    let (base, now) = (Base::of(shared), call.now);
    let mut summary = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                let options = base.options();
                stored::replay(tx, &credential, &options, &input, work_bound(), now).await
            })
        })
        .map_err(workflow_error)?;
    // Storage has no engine: the applied revision is the node's.
    summary.applied = shared.node.applied_revision();
    Ok(reply::json(context, &SummaryReply(&summary))?)
}

/// A replay summary in Zig's shape.
struct SummaryReply<'a>(&'a ReplaySummary);

impl Encode for SummaryReply<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let summary = self.0;
        json.begin_object()?;
        field(json, "total", &summary.total)?;
        field(json, "matched", &summary.matched)?;
        field(json, "inconclusive", &summary.inconclusive)?;
        json.key("applied")?;
        decimal_string(json, summary.applied)?;
        json.key("committed")?;
        decimal_string(json, summary.committed)?;
        field(json, "preview", &summary.preview)?;
        json.key("rows")?;
        json.begin_array()?;
        for row in &summary.rows {
            json.begin_object()?;
            counter_field(json, "id", row.id)?;
            field(json, "ip", &row.ip)?;
            field(json, "path", &row.path)?;
            field(json, "action", &row.action)?;
            field(json, "rule", &row.rule)?;
            field(json, "conclusive", &row.conclusive)?;
            field(json, "matched", &row.matched)?;
            json.end_object()?;
        }
        json.end_array()?;
        json.end_object()
    }
}

/// The body of `reputation/query`.
struct QueryForm {
    after: Text<MAX_PREFIX>,
}

impl Decode for QueryForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<QueryForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = QueryForm { after: fields.or_default("after")? };
        fields.finish()?;
        Ok(form)
    }
}

/// `reputation/query`: eight entries after a prefix, with the trie size the node serves.
fn reputation_query(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    let mut body = [0u8; 512];
    let form: QueryForm = read_json(context, &mut body)?;
    let input = ReputationQuery { auth: call.auth(shared)?, after: form.after };
    let credential = call.credential(shared)?;
    let now = call.now;
    let mut page = shared
        .storage
        .transact(move |tx| {
            Box::pin(
                async move { reputation::query_reputation(tx, &credential, &input, now).await },
            )
        })
        .map_err(workflow_error)?;
    // The trie belongs to the engine the node serves, which storage does not hold.
    let nodes = shared.node.engine().map_or(0, |engine| engine.reputation_node_count());
    page.nodes = u16::try_from(nodes).unwrap_or(u16::MAX);
    Ok(reply::json(context, &PageReply(&page))?)
}

/// A reputation page in Zig's shape.
struct PageReply<'a>(&'a ReputationPage);

impl Encode for PageReply<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let page = self.0;
        json.begin_object()?;
        json.key("committed")?;
        decimal_string(json, page.committed)?;
        field(json, "nodes", &page.nodes)?;
        json.key("rows")?;
        json.begin_array()?;
        for row in &page.rows {
            json.begin_object()?;
            field(json, "prefix", &row.prefix)?;
            field(json, "score", &row.score)?;
            optional_counter_field(json, "banned_until", row.banned_until)?;
            field(json, "trigger", &row.trigger)?;
            field(json, "source", &row.source)?;
            field(json, "note", &row.note)?;
            counter_field(json, "hits", row.hits)?;
            counter_field(json, "last_seen", row.last_seen)?;
            json.end_object()?;
        }
        json.end_array()?;
        field(json, "next", &page.next)?;
        json.end_object()
    }
}

/// The body of `reputation/edit`.
struct EditForm {
    prefix: Text<MAX_PREFIX>,
    expected_revision: String,
    action: ActionName,
    until: Option<String>,
    note: Text<MAX_NOTE>,
}

impl Decode for EditForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<EditForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = EditForm {
            prefix: fields.required("prefix")?,
            expected_revision: fields.required("expected_revision")?,
            action: fields.or("action", ActionName(ReputationAction::Deny))?,
            until: fields.or_default("until")?,
            note: fields.or_default("note")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `reputation/edit`: adds or changes one prefix (S17).
fn reputation_edit(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
) -> Result<(), RouteError> {
    let mut body = [0u8; 1024];
    let form: EditForm = read_json(context, &mut body)?;
    let input = ReputationEdit {
        auth: call.auth(shared)?,
        expected_revision: revision(&form.expected_revision)?,
        prefix: form.prefix,
        action: form.action.0,
        until: form.until.as_deref().map(revision).transpose()?,
        note: form.note,
    };
    let credential = call.credential(shared)?;
    let (base, now) = (Base::of(shared), call.now);
    let committed_revision = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                let options = base.options();
                let change = PrefixChange::Edit(&input);
                reputation::change_prefix(tx, &credential, &options, change, now).await
            })
        })
        .map_err(workflow_error)?;
    committed(shared, context, committed_revision)
}

/// The body of `reputation/remove`.
struct RemoveForm {
    prefix: Text<MAX_PREFIX>,
    expected_revision: String,
}

impl Decode for RemoveForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<RemoveForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = RemoveForm {
            prefix: fields.required("prefix")?,
            expected_revision: fields.required("expected_revision")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `reputation/remove`: deletes one prefix (S17).
fn reputation_remove(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
) -> Result<(), RouteError> {
    let mut body = [0u8; 512];
    let form: RemoveForm = read_json(context, &mut body)?;
    let input = ReputationRemove {
        auth: call.auth(shared)?,
        expected_revision: revision(&form.expected_revision)?,
        prefix: form.prefix,
    };
    let credential = call.credential(shared)?;
    let (base, now) = (Base::of(shared), call.now);
    let committed_revision = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                let options = base.options();
                let change = PrefixChange::Remove(&input);
                reputation::change_prefix(tx, &credential, &options, change, now).await
            })
        })
        .map_err(workflow_error)?;
    committed(shared, context, committed_revision)
}

/// The body of `policies/import`.
struct ImportForm {
    expected_revision: String,
    documents: Vec<Text<{ workflows::MAX_IMPORT_DOCUMENT }>>,
}

impl Decode for ImportForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ImportForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = ImportForm {
            expected_revision: fields.required("expected_revision")?,
            documents: fields.required_with("documents", |value, path| {
                decode_list(value, path, workflows::MAX_IMPORT_DOCUMENTS)
            })?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `policies/import`: replaces every managed rule with one set (S16).
fn import(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = vec![0u8; MAX_BODY];
    let form: ImportForm = read_json(context, &mut body)?;
    let protocol = workflows::Import {
        auth: call.auth(shared)?,
        expected_revision: revision(&form.expected_revision)?,
        documents: form.documents,
    };
    workflows::validate_import(&protocol).map_err(|_| RouteError::BadRequest)?;
    let input = Import {
        expected_revision: protocol.expected_revision,
        documents: protocol.documents.into_iter().map(Text::into_string).collect(),
    };
    let credential = call.credential(shared)?;
    let (base, now) = (Base::of(shared), call.now);
    let committed_revision = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                let options = base.options();
                stored::import_rules(tx, &credential, &options, &input, now).await
            })
        })
        .map_err(workflow_error)?;
    committed(shared, context, committed_revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    #[test]
    fn revisions_are_bounded_decimal_text() {
        assert_eq!(revision("7"), Ok(7));
        assert_eq!(revision("9223372036854775807"), Ok(i64::MAX as u64));
        for bad in ["", "9223372036854775808", "12345678901234567890", "-1", "1e3", "0x1"] {
            assert_eq!(revision(bad), Err(RouteError::BadRequest), "{bad}");
        }
    }

    #[test]
    fn workflow_failures_map_as_zig_did() {
        let capacity = StorageFailure::Console(ConsoleStorageError::Capacity);
        assert_eq!(workflow_error(capacity), RouteError::fail(422, "CONSOLECAPACITY"));
        let conflict = StorageFailure::Console(ConsoleStorageError::Conflict);
        assert_eq!(workflow_error(conflict), RouteError::fail(409, "CONSOLEPOLICY"));
        let busy = StorageFailure::Console(ConsoleStorageError::Unavailable);
        assert_eq!(workflow_error(busy), RouteError::fail(503, "CONSOLEQUORUM"));
    }

    #[test]
    fn forms_accept_the_interface_bodies() {
        let edit: EditForm = from_json(
            br#"{"prefix":"192.0.2.0/24","expected_revision":"4","action":"allow","until":null,
            "note":"partner"}"#,
        )
        .unwrap();
        assert_eq!(edit.action.0, ReputationAction::Allow);
        let order: OrderForm =
            from_json(br#"{"id":"a","expected_revision":"3","direction":"down"}"#).unwrap();
        assert_eq!(order.direction.0, Direction::Down);
        let replay: ReplayForm =
            from_json(br#"{"rule":"B","hours":24,"draft":"{}","committed":"7"}"#).unwrap();
        assert_eq!(replay.hours, 24);
        let import: ImportForm = from_json(
            br#"{"expected_revision":"7","documents":["{\"id\":\"a\"}","{\"id\":\"b\"}"]}"#,
        )
        .unwrap();
        assert_eq!(import.documents.len(), 2);
        let many = format!(
            "{{\"expected_revision\":\"1\",\"documents\":[{}]}}",
            vec!["\"{}\""; 129].join(",")
        );
        assert!(from_json::<ImportForm>(many.as_bytes()).is_err());
        assert!(
            from_json::<OrderForm>(br#"{"id":"a","expected_revision":"3","direction":"x"}"#)
                .is_err()
        );
    }
}
