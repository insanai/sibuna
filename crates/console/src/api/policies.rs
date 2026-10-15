//! The routes `policies/query`, `policies/test`, `policies/edit`, `inspection/edit` and
//! `policies/read` (Zig's `policy_routes.zig` and `policy_read_routes.zig`), and the
//! helpers every management route of unit U3 shares: the query allowance, decimal fields,
//! the work bound and the policy base.
//!
//! The applied page lists the rules of the engine the node serves ([`crate::Node::engine`]),
//! as Zig read its published engine, with each rule's history key from the node's rule-hit
//! generation and today's hits from storage. Tests and edits run one storage function each
//! on the candidate options of [`PolicyBase`].

use std::fmt::{self, Write};
use std::sync::Arc;

use sibuna_console_protocol::codec::{
    Decode, DecodeError, Encode, Fields, Path, counter_field, decimal_string, decode_list, field,
    optional_str,
};
use sibuna_console_protocol::policies::{self, Header, Selection};
use sibuna_console_protocol::rule_hit_history::Today;
use sibuna_console_protocol::{Text, rule_hits};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::policy::{self as stored, PolicyRead, TestResult};
use sibuna_console_storage::rule_hits::read_today;
use sibuna_json::{Value, Writer};
use sibuna_policy::candidate::Options;
use sibuna_policy::{Engine, Limits, PolicyRule};
use sibuna_serve::Context;
use sibuna_storage::WorkBound;

use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The longest display text of a rule field, in bytes (Zig's `display`).
const DISPLAY: usize = 128;
/// The body bound of the policy query, test and edit routes.
const BODY: usize = 8 * 1024;

/// The daemon's policy settings that every candidate engine and the policy page start
/// from: the WAF switch and policy file of `Options`, the global limiter and honeypot ban
/// the page shows, and the built-in challenge page the page editor resets to. The default
/// difficulty and algorithm are the console's challenge defaults.
#[derive(Clone, Debug)]
pub struct PolicyBase {
    /// Whether the WAF runs (`--waf`); also names the protection surface.
    pub waf: bool,
    /// The startup policy file, if any.
    pub file: Option<Arc<[u8]>>,
    /// The global limiter's requests per window, when the daemon reports it.
    pub rate_limit: Option<u32>,
    /// The global limiter's window, in seconds.
    pub rate_window_seconds: Option<u64>,
    /// The honeypot ban, in seconds.
    pub ban_seconds: Option<u64>,
    /// The daemon's built-in challenge page; `None` means the policy crate's minimal page.
    pub challenge_page: Option<Arc<str>>,
}

impl Default for PolicyBase {
    /// The WAF on, no policy file, nothing reported, the minimal challenge page.
    fn default() -> PolicyBase {
        PolicyBase {
            waf: true,
            file: None,
            rate_limit: None,
            rate_window_seconds: None,
            ban_seconds: None,
            challenge_page: None,
        }
    }
}

impl PolicyBase {
    /// Returns the candidate options with `default_difficulty`; borrows the policy file.
    pub fn options(&self, default_difficulty: u32) -> Options<'_> {
        Options { default_difficulty, waf: self.waf, file: self.file.as_deref() }
    }

    /// Returns the built-in challenge page source.
    pub fn challenge_page(&self) -> &str {
        self.challenge_page.as_deref().unwrap_or(sibuna_policy::pages::DEFAULT_CHALLENGE_MINIMAL)
    }
}

/// What a storage job needs to compose a candidate: owned, so it can move to the storage
/// thread.
#[derive(Clone, Debug)]
pub(crate) struct Base {
    policy: PolicyBase,
    difficulty: u32,
}

impl Base {
    /// Captures the shared policy base.
    pub(crate) fn of(shared: &Shared) -> Base {
        Base {
            policy: shared.policy.clone(),
            difficulty: shared.identity.challenge_defaults.difficulty,
        }
    }

    /// Returns the candidate options; borrows `self`.
    pub(crate) fn options(&self) -> Options<'_> {
        self.policy.options(self.difficulty)
    }
}

// ---- Helpers shared by the management routes -----------------------------------------------

/// Spends one `spend` of the caller's query allowance, refusing with 429 `code` (Zig's
/// `query_budget.allow` at the top of each read).
///
/// Fails with [`RouteError::Unavailable`] on a public route, which has no credential.
pub(crate) fn spend(
    shared: &Shared,
    call: &Call,
    spend: Spend,
    code: &'static str,
) -> Result<(), RouteError> {
    let presented = call.presented.as_ref().ok_or(RouteError::Unavailable)?;
    if shared.query_budget.allow(&presented.digest, call.now, spend) {
        Ok(())
    } else {
        Err(RouteError::fail(429, code))
    }
}

/// Parses a decimal `u64` (Zig's `parseInt(u64, text, 10)` over digits).
///
/// Fails with [`RouteError::BadRequest`] for anything else.
pub(crate) fn decimal(text: &str) -> Result<u64, RouteError> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RouteError::BadRequest);
    }
    text.parse().map_err(|_| RouteError::BadRequest)
}

/// Parses an optional decimal field; `None` stays `None`.
///
/// Fails like [`decimal`].
pub(crate) fn optional_decimal(text: Option<&str>) -> Result<Option<u64>, RouteError> {
    text.map(decimal).transpose()
}

/// The work bound of aggregate reads: `--console-query-steps` SQLite steps
/// ([`crate::Config::query_steps`]) and SID 0013's PostgreSQL statement timeout.
pub(crate) fn work_bound(shared: &Shared) -> WorkBound {
    WorkBound { sqlite_steps: shared.config.query_steps, ..WorkBound::default() }
}

/// Returns `text` cut to [`DISPLAY`] bytes at a character boundary, and whether it was
/// cut (Zig's `display`; Rust strings are always valid UTF-8).
pub(crate) fn display(text: &str) -> (&str, bool) {
    if text.len() <= DISPLAY {
        return (text, false);
    }
    let end = (0..=DISPLAY).rev().find(|&end| text.is_char_boundary(end)).unwrap_or(0);
    (text.get(..end).unwrap_or_default(), true)
}

/// Maps a policy route's storage failure: storage that cannot answer is 503
/// `CONSOLEQUORUM`; refusals are `CONSOLEPOLICY` with Zig's statuses.
fn policy_error(failure: StorageFailure) -> RouteError {
    match &failure {
        StorageFailure::Console(ConsoleStorageError::Unavailable) => {
            RouteError::fail(503, "CONSOLEQUORUM")
        }
        _ => failure.route_error("CONSOLEPOLICY"),
    }
}

// ---- Routes --------------------------------------------------------------------------------

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::Policies => query(shared, context, call),
        Handler::PoliciesTest => test(shared, context, call),
        Handler::PolicyEdit => edit(shared, context, call, false),
        Handler::InspectionEdit => edit(shared, context, call, true),
        Handler::PolicyRead => read(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// The body of `policies/query` and `policies/test`.
#[derive(Debug, Default)]
struct QueryForm {
    offset: u8,
    applied: Option<String>,
    path: Text<512>,
    query: Text<512>,
    ip: Text<48>,
    user_agent: Text<256>,
    body: Text<2048>,
    draft: Option<Text<{ policies::MAX_DOCUMENT }>>,
    committed: Option<String>,
    headers: Vec<Header>,
}

impl Decode for QueryForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<QueryForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = QueryForm {
            offset: fields.or_default("offset")?,
            applied: fields.or_default("applied")?,
            path: fields.or_default("path")?,
            query: fields.or_default("query")?,
            ip: fields.or_default("ip")?,
            user_agent: fields.or_default("user_agent")?,
            body: fields.or_default("body")?,
            draft: fields.or_default("draft")?,
            committed: fields.or_default("committed")?,
            headers: fields.or_with("headers", Vec::new(), decode_headers)?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// One request header of a test body.
struct HeaderForm(Header);

impl Decode for HeaderForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<HeaderForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let header = Header { name: fields.required("name")?, value: fields.required("value")? };
        fields.finish()?;
        Ok(HeaderForm(header))
    }
}

fn decode_headers(value: &Value<'_>, path: Path<'_>) -> Result<Vec<Header>, DecodeError> {
    let headers: Vec<HeaderForm> = decode_list(value, path, policies::MAX_HEADERS)?;
    Ok(headers.into_iter().map(|header| header.0).collect())
}

/// `policies/query`: one page of the applied engine's rules.
fn query(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    let mut body = vec![0u8; BODY];
    let form: QueryForm = read_json(context, &mut body)?;
    let engine = shared.node.engine().ok_or(RouteError::Unavailable)?;
    let applied = shared.node.applied_revision();
    let request = policies::Query {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        offset: form.offset,
        applied: optional_decimal(form.applied.as_deref())?,
    };
    let keys = history_keys(shared, &engine, form.offset);
    let credential = call.credential(shared)?;
    let (node, now) = (shared.identity.node_id, call.now);
    let (committed, days) = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                let page = stored::rule_page(tx, &credential, &request, now).await?;
                if request.applied.is_some_and(|expected| expected != applied) {
                    return Err(ConsoleStorageError::Conflict);
                }
                let mut days = Vec::with_capacity(keys.len());
                for key in keys {
                    let today = match key {
                        Some(key) => {
                            let today = read_today(tx, &key, node, now).await?;
                            Some((key, today))
                        }
                        None => None,
                    };
                    days.push(today);
                }
                Ok((page.committed, days))
            })
        })
        .map_err(policy_error)?;
    let page = AppliedPage { shared, engine: &engine, committed, applied, offset: form.offset };
    Ok(reply::json(context, &AppliedRows { page, days: &days })?)
}

/// Returns the history key of each rule on the page from `offset`, from the node's rule-hit
/// generation when it describes this engine; `None` where unknown.
fn history_keys(shared: &Shared, engine: &Engine, offset: u8) -> Vec<Option<rule_hits::Key>> {
    let mut sample = crate::host::RuleHitSample::default();
    let known = shared.node.sample_rule_hits(&mut sample)
        && sample.generation.rules.len() == engine.rule_count();
    let first = usize::from(offset);
    let last = engine.rule_count().min(first + 8);
    (first..last)
        .map(|index| {
            let identity = sample.generation.rules.get(index).filter(|_| known)?;
            Some(identity.key.clone())
        })
        .collect()
}

/// The applied page's top-level facts.
struct AppliedPage<'a> {
    shared: &'a Shared,
    engine: &'a Engine,
    committed: u64,
    applied: u64,
    offset: u8,
}

/// The applied page with the rows and today's hits.
struct AppliedRows<'a> {
    page: AppliedPage<'a>,
    days: &'a [Option<(rule_hits::Key, Today)>],
}

impl Encode for AppliedRows<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let page = &self.page;
        let base = &page.shared.policy;
        let defaults = &page.shared.identity.challenge_defaults;
        json.begin_object()?;
        json.key("committed")?;
        decimal_string(json, page.committed)?;
        json.key("applied")?;
        decimal_string(json, page.applied)?;
        field(json, "total", &(page.engine.rule_count() as u64))?;
        field(json, "waf", &page.engine.waf_enabled)?;
        field(json, "default_difficulty", &page.engine.default_difficulty)?;
        field(json, "default_algorithm", &defaults.algorithm)?;
        field(json, "surface", if base.waf { "shield" } else { "gate" })?;
        field(json, "rate_limit", &base.rate_limit)?;
        field(json, "rate_window_seconds", &base.rate_window_seconds)?;
        field(json, "ban_seconds", &base.ban_seconds)?;
        json.key("inspection")?;
        inspection(json, &page.engine.inspection_modes)?;
        json.key("rows")?;
        json.begin_array()?;
        let first = usize::from(page.offset);
        let rules = page.engine.rules().iter().enumerate().skip(first).take(8);
        for ((index, rule), today) in rules.zip(self.days) {
            rule_row(json, index, rule, today.as_ref())?;
        }
        json.end_array()?;
        json.key("next")?;
        let next = first + 8;
        if next < page.engine.rule_count() { json.uint(next as u64) } else { json.null() }?;
        json.end_object()
    }
}

fn inspection<W: Write>(json: &mut Writer<W>, modes: &sibuna_policy::Modes) -> fmt::Result {
    json.begin_object()?;
    field(json, "path_traversal", modes.path_traversal.name())?;
    field(json, "sqli", modes.sqli.name())?;
    field(json, "xss", modes.xss.name())?;
    field(json, "rce", modes.rce.name())?;
    json.end_object()
}

/// One applied rule (Zig's `summary`).
fn rule_row<W: Write>(
    json: &mut Writer<W>,
    index: usize,
    rule: &PolicyRule,
    today: Option<&(rule_hits::Key, Today)>,
) -> fmt::Result {
    let (name, name_cut) = display(&rule.name);
    let (path, path_cut) = display(rule.path_pattern.as_deref().unwrap_or_default());
    let (agent, agent_cut) = display(rule.ua_pattern.as_deref().unwrap_or_default());
    json.begin_object()?;
    field(json, "index", &(index as u64))?;
    if let Some((key, today)) = today {
        field(json, "history_key", key)?;
        field(json, "today", today)?;
    }
    field(json, "name", name)?;
    field(json, "action", rule.action.name())?;
    field(json, "path", path)?;
    field(json, "user_agent", agent)?;
    field(json, "truncated", &(name_cut || path_cut || agent_cut))?;
    field(json, "header_count", &(rule.headers.len() as u64))?;
    field(json, "cidr_count", &(rule.cidrs.len() as u64))?;
    field(json, "difficulty", &rule.difficulty)?;
    json.key("algorithm")?;
    optional_str(json, rule.algorithm.map(|algorithm| algorithm.name()))?;
    field(json, "weight", &rule.weight)?;
    json.key("limits")?;
    limits(json, rule.limits.as_ref())?;
    json.end_object()
}

/// Writes a quota as `{"rate":..,"window_seconds":..,"ban_seconds":..}` or `null`.
fn limits<W: Write>(json: &mut Writer<W>, limits: Option<&Limits>) -> fmt::Result {
    let Some(limits) = limits else { return json.null() };
    json.begin_object()?;
    field(json, "rate", &limits.rate)?;
    field(json, "window_seconds", &limits.window_seconds)?;
    field(json, "ban_seconds", &limits.ban_seconds)?;
    json.end_object()
}

/// `policies/test`: one request against the committed policy or a private draft.
fn test(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    let mut body = vec![0u8; BODY];
    let form: QueryForm = read_json(context, &mut body)?;
    let applied = shared.node.applied_revision();
    let input = policies::Test {
        query: policies::Query {
            session_digest: [0; 32],
            require_totp: shared.config.behind_proxy,
            offset: form.offset,
            applied: optional_decimal(form.applied.as_deref())?,
        },
        path: form.path,
        query_string: form.query,
        ip: form.ip,
        user_agent: form.user_agent,
        body: form.body,
        headers: form.headers,
        draft: form.draft,
        committed: optional_decimal(form.committed.as_deref())?,
    };
    let credential = call.credential(shared)?;
    let (base, now) = (Base::of(shared), call.now);
    let result = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                let options = base.options();
                let result = stored::test_request(tx, &credential, &options, &input, now).await?;
                if input.query.applied.is_some_and(|expected| expected != applied) {
                    return Err(ConsoleStorageError::Conflict);
                }
                Ok(result)
            })
        })
        .map_err(policy_error)?;
    let decision =
        Decision { result: &result, applied, default: shared.identity.challenge_defaults };
    Ok(reply::json(context, &decision)?)
}

/// The tester's reply: the decision with the node's applied revision.
struct Decision<'a> {
    result: &'a TestResult,
    applied: u64,
    default: sibuna_console_protocol::challenges::Defaults,
}

impl Encode for Decision<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let result = self.result;
        json.begin_object()?;
        json.key("applied")?;
        decimal_string(json, self.applied)?;
        field(json, "preview", &result.preview)?;
        json.key("committed")?;
        if result.preview { decimal_string(json, result.committed) } else { json.null() }?;
        field(json, "action", result.action.name())?;
        field(json, "rule", result.rule.as_str())?;
        field(json, "difficulty", &result.difficulty)?;
        match result.algorithm {
            Some(algorithm) => field(json, "algorithm", algorithm.name())?,
            None => field(json, "algorithm", &self.default.algorithm)?,
        }
        field(json, "score", &result.score)?;
        field(json, "audited_categories", &result.audited)?;
        json.key("limits")?;
        limits(json, result.limits.as_ref())?;
        json.end_object()
    }
}

/// The body of `policies/edit` and `inspection/edit`.
#[derive(Debug)]
struct EditForm {
    expected_revision: String,
    document: Text<{ policies::MAX_DOCUMENT }>,
}

impl Decode for EditForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<EditForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = EditForm {
            expected_revision: fields.required("expected_revision")?,
            document: fields.required("document")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `policies/edit` (one rule, S13) or `inspection/edit` (the four modes, S14).
fn edit(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    inspection: bool,
) -> Result<(), RouteError> {
    let mut body = vec![0u8; BODY];
    let form: EditForm = read_json(context, &mut body)?;
    let auth = call.auth(shared)?;
    let input = policies::Edit {
        session_digest: auth.session_digest,
        csrf_digest: auth.csrf_digest,
        require_totp: auth.require_totp,
        expected_revision: decimal(&form.expected_revision)?,
        document: form.document,
        client: auth.client,
    };
    let credential = call.credential(shared)?;
    let (base, now) = (Base::of(shared), call.now);
    let committed = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                let options = base.options();
                if inspection {
                    stored::edit_inspection(tx, &credential, &options, &input, now).await
                } else {
                    stored::edit_rule(tx, &credential, &options, &input, now).await
                }
            })
        })
        .map_err(policy_error)?;
    let applied = shared.node.applied_revision();
    Ok(reply::json(context, &Revisions { committed, applied })?)
}

/// `{"committed":"<n>","applied":"<n>"}`: a workflow's committed revision and the node's
/// applied one, as decimal strings.
pub(crate) struct Revisions {
    /// The revision the workflow committed.
    pub committed: u64,
    /// The revision the node serves.
    pub applied: u64,
}

impl Encode for Revisions {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        json.key("committed")?;
        decimal_string(json, self.committed)?;
        json.key("applied")?;
        decimal_string(json, self.applied)?;
        json.end_object()
    }
}

/// The body of `policies/read`.
#[derive(Debug, Default)]
struct ReadForm {
    kind: String,
    id: Text<128>,
    after: Text<128>,
    committed: Option<String>,
    revision: Option<String>,
    before: Option<String>,
    previous: bool,
}

impl Decode for ReadForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ReadForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = ReadForm {
            kind: fields.or("kind", "catalog".to_owned())?,
            id: fields.or_default("id")?,
            after: fields.or_default("after")?,
            committed: fields.or_default("committed")?,
            revision: fields.or_default("revision")?,
            before: fields.or_default("before")?,
            previous: fields.or_default("previous")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

impl ReadForm {
    /// Returns the storage selection. An empty `committed` means unknown, as the interface
    /// sends before its first read.
    fn into_read(self, require_totp: bool) -> Result<policies::Read, RouteError> {
        let committed = self.committed.as_deref().filter(|text| !text.is_empty());
        let selection = match self.kind.as_str() {
            "catalog" => Selection::Catalog(self.after),
            "document" => Selection::Document {
                id: self.id,
                revision: optional_decimal(self.revision.as_deref())?,
                previous: self.previous,
            },
            "history" => Selection::History {
                id: self.id,
                before: optional_decimal(self.before.as_deref())?,
            },
            _ => return Err(RouteError::BadRequest),
        };
        Ok(policies::Read {
            session_digest: [0; 32],
            require_totp,
            committed: optional_decimal(committed)?,
            selection,
        })
    }
}

/// `policies/read`: the catalogue, one document or one rule's history.
fn read(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    let mut body = [0u8; 2048];
    let form: ReadForm = read_json(context, &mut body)?;
    let input = form.into_read(shared.config.behind_proxy)?;
    let credential = call.credential(shared)?;
    let now = call.now;
    let result = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { stored::read_policy(tx, &credential, &input, now).await })
        })
        .map_err(policy_error)?;
    Ok(reply::json(context, &ReadReply(&result))?)
}

/// The reply of `policies/read`, in Zig's shapes.
struct ReadReply<'a>(&'a PolicyRead);

impl Encode for ReadReply<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        match self.0 {
            PolicyRead::Document(document) => {
                json.key("committed")?;
                decimal_string(json, document.revision)?;
                field(json, "document", &document.document)?;
            }
            PolicyRead::Catalog(page) => {
                json.key("committed")?;
                decimal_string(json, page.committed)?;
                json.key("rows")?;
                json.begin_array()?;
                for row in &page.rows {
                    let (name, truncated) = display(&row.name);
                    json.begin_object()?;
                    field(json, "id", row.id.as_str())?;
                    field(json, "name", name)?;
                    field(json, "truncated", &truncated)?;
                    field(json, "priority", &row.priority)?;
                    field(json, "enabled", &row.enabled)?;
                    field(json, "action", row.action.name())?;
                    json.end_object()?;
                }
                json.end_array()?;
                field(json, "next", &page.next)?;
            }
            PolicyRead::History(page) => {
                json.key("committed")?;
                decimal_string(json, page.committed)?;
                json.key("rows")?;
                json.begin_array()?;
                for row in &page.rows {
                    json.begin_object()?;
                    json.key("revision")?;
                    decimal_string(json, row.revision)?;
                    json.key("actor")?;
                    decimal_string(json, row.actor.unwrap_or(0))?;
                    counter_field(json, "recorded_at", row.recorded_at)?;
                    field(json, "kind", row.kind.as_str())?;
                    json.end_object()?;
                }
                json.end_array()?;
                json.key("next")?;
                match page.next {
                    Some(next) => decimal_string(json, next)?,
                    None => json.null()?,
                }
            }
        }
        json.end_object()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::{from_json, to_json};

    #[test]
    fn decimals_and_display_text_follow_zig() {
        assert_eq!(decimal("0"), Ok(0));
        assert_eq!(decimal("18446744073709551615"), Ok(u64::MAX));
        for bad in ["", "-1", "+1", "1.0", "18446744073709551616", " 1", "x"] {
            assert_eq!(decimal(bad), Err(RouteError::BadRequest), "{bad}");
        }
        assert_eq!(display("short"), ("short", false));
        let long = format!("{}{}", "x".repeat(127), "\u{e9}");
        assert_eq!(display(&long), (&long[..127], true));
    }

    #[test]
    fn query_forms_accept_the_interface_bodies() {
        let first: QueryForm = from_json(br#"{"offset":0}"#).unwrap();
        assert_eq!(first.offset, 0);
        let next: QueryForm = from_json(br#"{"offset":8,"applied":"2"}"#).unwrap();
        assert_eq!(next.applied.as_deref(), Some("2"));
        let test: QueryForm = from_json(
            br#"{"applied":null,"draft":"{}","committed":"3","path":"/","ip":"::1","query":"",
            "user_agent":"","body":"","headers":[{"name":"a","value":"b"}]}"#,
        )
        .unwrap();
        assert_eq!(test.headers.len(), 1);
        assert!(from_json::<QueryForm>(br#"{"other":1}"#).is_err());
        let nine = format!("{{\"headers\":[{}]}}", [r#"{"name":"a","value":"b"}"#; 9].join(","));
        assert!(from_json::<QueryForm>(nine.as_bytes()).is_err());
    }

    #[test]
    fn read_forms_map_to_selections() {
        let form: ReadForm = from_json(br#"{"kind":"catalog"}"#).unwrap();
        let read = form.into_read(false).unwrap();
        assert_eq!(read.selection, Selection::Catalog(Text::default()));
        let form: ReadForm =
            from_json(br#"{"kind":"document","id":"a","revision":"3","committed":""}"#).unwrap();
        let read = form.into_read(true).unwrap();
        assert_eq!(read.committed, None);
        assert!(matches!(read.selection, Selection::Document { revision: Some(3), .. }));
        let form: ReadForm = from_json(br#"{"kind":"other"}"#).unwrap();
        assert_eq!(form.into_read(false).unwrap_err(), RouteError::BadRequest);
        let revisions = Revisions { committed: 4, applied: 3 };
        assert_eq!(to_json(&revisions), r#"{"committed":"4","applied":"3"}"#);
    }
}
