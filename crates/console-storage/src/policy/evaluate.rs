//! The private policy test and the replay of retained incidents. Both evaluate a candidate
//! engine composed from storage at the committed revision, with a draft document in place
//! of its stored rule when the request carries one; neither writes anything, and neither
//! counts rule hits.
//!
//! Zig evaluated a request without a draft against the node's published engine. Storage
//! has no engine, so it composes the committed policy instead; once the node applied the
//! committed revision the two agree, and the console server reports the applied revision
//! beside the result.

use sibuna_console_protocol::workflows::{self, ReplayRow, ReplaySummary};
use sibuna_console_protocol::{Text, policies};
use sibuna_policy::candidate::Options;
use sibuna_policy::ja4::Fingerprint;
use sibuna_policy::{Action, Algorithm, Engine, Header, Limits, RequestView, management};
use sibuna_storage::{Param, Sql, Transaction};

use super::{Inputs, POLICY_READ, bounded, refusal};
use crate::access::{self, Credential};
use crate::bound::{self, WorkBound};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

const REVISION: Sql = Sql::both("SELECT revision FROM policy_revision WHERE id = 1");

async fn committed(tx: &mut Transaction) -> Result<u64, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(REVISION, &[]).await?)
        .ok_or(sibuna_storage::StorageError::MissingPolicyRevision)?;
    Fields::new(cells, "policy_revision").integer("revision")
}

/// Composes the engine to evaluate on `base`: the committed policy, with `draft` in place
/// of (or added to) its rule when given, in which case `expected` must be the committed
/// revision. Returns the engine and the committed revision.
async fn engine(
    tx: &mut Transaction,
    base: &Options<'_>,
    expected: Option<u64>,
    draft: Option<&str>,
    now: u64,
) -> Result<(Engine, u64), ConsoleStorageError> {
    let revision = committed(tx).await?;
    let mut inputs = Inputs::load(tx, now, None).await?;
    if let Some(draft) = draft {
        if expected != Some(revision) {
            return Err(ConsoleStorageError::Conflict);
        }
        let document = management::parse(draft.as_bytes())
            .map_err(|error| ConsoleStorageError::InvalidInput(error.name()))?;
        inputs.replace(&document.id, draft);
    }
    let engine = inputs.compose(base).map_err(refusal)?;
    Ok((engine, revision))
}

/// The decision of a private policy test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestResult {
    /// The committed revision the candidate was composed at.
    pub committed: u64,
    /// A draft was evaluated.
    pub preview: bool,
    /// What the policy decided.
    pub action: Action,
    /// The deciding rule.
    pub rule: String,
    /// The challenge difficulty in work bits.
    pub difficulty: u32,
    /// The deciding rule's algorithm; `None` means the daemon's default.
    pub algorithm: Option<Algorithm>,
    /// The WEIGH score.
    pub score: i32,
    /// The audited WAF categories with a finding (`inspection::bit` bits).
    pub audited: u8,
    /// The deciding rule's quota.
    pub limits: Option<Limits>,
}

/// Evaluates the request `test` describes against the committed policy, or against the
/// committed policy with `test.draft` applied (S13's candidate, unsaved). The credential
/// is `credential`; `test.query.applied` is the console server's to check.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a refused request, a client
/// address that does not parse, a JA4 value that is neither empty nor a fingerprint
/// (`"ja4 fingerprint"`, by `sibuna_policy::ja4::Fingerprint::parse`), or a draft or
/// candidate that does not validate, like
/// [`access::authorize_in`] for policy readers, with [`ConsoleStorageError::Conflict`] when
/// the draft's committed revision is stale, and with the driver's error.
pub async fn test_request(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    test: &policies::Test,
    now: u64,
) -> Result<TestResult, ConsoleStorageError> {
    let ja4 = test_fingerprint(test)?;
    policies::validate_test(test).map_err(|_| ConsoleStorageError::InvalidInput("test"))?;
    let address = sibuna_cidr::parse_ip(test.ip.as_bytes())
        .map_err(|_| ConsoleStorageError::InvalidInput("client address"))?;
    access::authorize_in(tx, credential, POLICY_READ, now).await?;
    let draft = test.draft.as_ref().map(Text::as_str);
    let (engine, revision) = engine(tx, base, test.committed, draft, now).await?;
    let headers: Vec<Header<'_>> = test
        .headers
        .iter()
        .map(|header| Header { name: header.name.as_bytes(), value: header.value.as_bytes() })
        .collect();
    let view = RequestView {
        path: test.path.as_bytes(),
        query: test.query_string.as_bytes(),
        client_ip: test.ip.as_bytes(),
        client_address: Some(address),
        user_agent: test.user_agent.as_bytes(),
        ja4,
        headers: &headers,
        body: test.body.as_bytes(),
    };
    let decision = engine.evaluate(&view);
    Ok(TestResult {
        committed: revision,
        preview: draft.is_some(),
        action: decision.action,
        rule: decision.rule_name.to_owned(),
        difficulty: decision.difficulty,
        algorithm: decision.algorithm,
        score: decision.score,
        audited: decision.audited,
        limits: decision.limits,
    })
}

/// Returns the test's JA4 fingerprint, `None` when the field is empty. The policy crate's
/// grammar is the authority; checked before the protocol's bounds, so the refusal names the
/// field.
fn test_fingerprint(
    test: &policies::Test,
) -> Result<Option<Fingerprint<'_>>, ConsoleStorageError> {
    if test.ja4.is_empty() {
        return Ok(None);
    }
    Fingerprint::parse(test.ja4.as_bytes())
        .map(Some)
        .ok_or(ConsoleStorageError::InvalidInput("ja4 fingerprint"))
}

const RETAINED: Sql = Sql::both(
    "SELECT i.id, i.client_ip, i.path, i.user_agent, i.ja4, e.query_bytes, e.body_bytes, \
     e.truncated FROM security_incidents i \
     LEFT JOIN console_incident_evidence e ON e.incident_id = i.id \
     WHERE i.recorded_at >= $1 ORDER BY i.recorded_at DESC, i.id DESC LIMIT $2",
);

/// Replays the newest retained incidents (at most 64, within `replay.hours`) against the
/// committed policy or a draft. Only the path, address, User-Agent and JA4 fingerprint
/// are replayed; an incident counts as conclusive when its evidence shows no query, no body
/// and nothing truncated. The request path's rate, ban and session state is never
/// reproduced. Matches are decisions of the named rule, or any non-allow decision without a
/// name. The scan of retained incidents runs under `work` (SID 0013's work bound of
/// aggregate reads). The summary's `applied` is 0: the console server fills in its node's
/// applied revision.
///
/// Fails like [`test_request`], and with [`ConsoleStorageError::Unavailable`] when the scan
/// passes `work`.
pub async fn replay(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    replay: &workflows::Replay,
    work: WorkBound,
    now: u64,
) -> Result<ReplaySummary, ConsoleStorageError> {
    workflows::validate_replay(replay).map_err(|_| ConsoleStorageError::InvalidInput("replay"))?;
    access::authorize_in(tx, credential, POLICY_READ, now).await?;
    let draft = replay.draft.as_ref().map(Text::as_str);
    let (engine, revision) = engine(tx, base, replay.committed, draft, now).await?;
    let since = now.saturating_sub(u64::from(replay.hours) * 3600);
    let params: [Param<'_>; 2] =
        [row::int(since)?.into(), row::int(workflows::REPLAY_SCAN as u64)?.into()];
    let mut summary = ReplaySummary {
        committed: revision,
        preview: draft.is_some(),
        ..ReplaySummary::default()
    };
    bound::begin(tx, work).await?;
    let retained = bound::fetch(tx, RETAINED, &params).await?;
    bound::end(tx).await?;
    for cells in retained {
        let mut fields = Fields::new(cells, "security_incidents");
        let id = fields.integer("id")?;
        let ip = fields.text("client_ip")?;
        let path = fields.bytes("path")?;
        let user_agent = fields.bytes("user_agent")?;
        let stored_ja4 = fields.optional_text("ja4")?;
        let query: Option<u64> = fields.optional_integer("query_bytes")?;
        let body: Option<u64> = fields.optional_integer("body_bytes")?;
        let truncated: Option<u8> = fields.optional_integer("truncated")?;
        if sibuna_cidr::parse_ip(ip.as_bytes()).is_err() {
            continue;
        }
        // The schema keeps a stored fingerprint in the JA4 form; parsing makes the check
        // explicit, and a value that is not one is replayed as absent.
        let ja4 = stored_ja4.as_deref().and_then(|text| Fingerprint::parse(text.as_bytes()));
        let request = RequestView { ja4, ..RequestView::new(&path, ip.as_bytes(), &user_agent) };
        let decision = engine.evaluate(&request);
        let conclusive =
            query == Some(0) && body == Some(0) && truncated.is_some_and(|bits| bits & 0xf == 0);
        let matched = if replay.rule.is_empty() {
            decision.action != Action::Allow
        } else {
            decision.rule_name == replay.rule.as_str()
        };
        summary.total += 1;
        summary.matched += u32::from(matched);
        summary.inconclusive += u32::from(!conclusive);
        if summary.rows.len() < workflows::REPLAY_ROWS {
            summary.rows.push(ReplayRow {
                id,
                ip: bounded(&ip),
                path: bounded(&String::from_utf8_lossy(&path)),
                action: bounded(decision.action.name()),
                rule: bounded(decision.rule_name),
                conclusive,
                matched,
            });
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_text_cuts_at_a_character_boundary() {
        let text: Text<4> = bounded("ab\u{e9}\u{e9}");
        assert_eq!(text.as_str(), "ab\u{e9}");
        let text: Text<3> = bounded("ab\u{e9}");
        assert_eq!(text.as_str(), "ab");
        let text: Text<8> = bounded("short");
        assert_eq!(text.as_str(), "short");
    }
}
