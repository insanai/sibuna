//! S13 and S14: editing one rule and editing the inspection modes.

use sibuna_console_protocol::policies;
use sibuna_policy::candidate::Options;
use sibuna_policy::management::{self, Document};
use sibuna_policy::{Mode, Modes};
use sibuna_storage::{Param, Sql, Transaction};

use super::candidate::{self, Inputs};
use super::summary::{modes_summary, rule_summary};
use super::{HistoryKind, POLICY_WRITE, insert_history, policy_audit};
use crate::access::{self, Credential};
use crate::audit::{self, AuditAction};
use crate::error::ConsoleStorageError;
use crate::revision;
use crate::row;

/// Checks the bounds the protocol states for an edit: a non-empty document and an expected
/// revision below 2^63 - 1.
fn validate(edit: &policies::Edit) -> Result<(), ConsoleStorageError> {
    if edit.document.is_empty() {
        return Err(ConsoleStorageError::InvalidInput("an empty document"));
    }
    if edit.expected_revision >= row::MAX_INTEGER {
        return Err(ConsoleStorageError::InvalidInput("expected revision"));
    }
    Ok(())
}

const HAS_HISTORY: Sql = Sql::both("SELECT 1 FROM console_policy_history WHERE policy_id = $1");

/// Writes the rule of `edit.document` at `edit.expected_revision` (S13): validates the
/// document and the whole candidate engine on `base`, records the stored rule as a
/// baseline history row when it had none, upserts the rule, records the edit history row,
/// advances the policy revision to exactly the expected revision plus one, and audits
/// `policy.edit` with redacted summaries before and after. Returns the committed revision.
/// The credential is `credential`; the digests and address inside `edit` are not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a document or candidate that does
/// not validate (the text names Zig's error), like [`access::authorize_in`] for policy
/// writers (operators and administrators with a CSRF digest, or tokens with
/// `policy_write`), with [`ConsoleStorageError::Conflict`] for a stale revision, and with
/// the driver's error.
pub async fn edit_rule(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    edit: &policies::Edit,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    validate(edit)?;
    let document = management::parse(edit.document.as_bytes())
        .map_err(|error| ConsoleStorageError::InvalidInput(error.name()))?;
    let principal = access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    let lock = revision::lock(tx, edit.expected_revision).await?;
    let mut inputs = Inputs::load(tx, now, None).await?;
    let previous = inputs.replace(&document.id, edit.document.as_str());
    inputs.compose(base).map_err(candidate::refusal)?;
    let expected = lock.expected();
    let committed = expected.checked_add(1).ok_or(ConsoleStorageError::Capacity)?;
    if let Some(previous) = &previous
        && tx.fetch_all(HAS_HISTORY, &[document.id.as_str().into()]).await?.is_empty()
    {
        let baseline = (HistoryKind::Baseline, None);
        insert_history(tx, &document.id, expected, baseline, now, previous).await?;
    }
    super::rules::store(tx, &document, now).await?;
    let edited = (HistoryKind::Edit, Some(principal.actor));
    insert_history(tx, &document.id, committed, edited, now, edit.document.as_str()).await?;
    let revision = revision::advance(tx, lock).await?;
    // The stored row was a valid document (the candidate composed it), so it parses.
    let before = previous
        .and_then(|text| management::parse(text.as_bytes()).ok())
        .map(|previous: Document| rule_summary(&previous));
    let row = audit::AuditRow {
        target: Some(document.id.clone()),
        before,
        after: Some(rule_summary(&document)),
        ..policy_audit(&principal, credential, AuditAction::PolicyEdit, revision, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(revision)
}

/// The field names of an inspection document, in `Modes` order.
const FAMILIES: [&str; 4] = ["path_traversal", "sqli", "xss", "rce"];

/// Parses an inspection document: an object with exactly the four families, each a mode
/// given by name or, as Zig's `std.json` accepted for enumerations, by its tag number
/// (0 to 2) as a number or a string of digits. Unknown, missing and repeated fields are
/// refused, so an omitted family never silently returns to enforcement.
pub fn parse_modes(source: &[u8]) -> Option<Modes> {
    let value = sibuna_json::parse(source).ok()?;
    let object = value.as_object()?;
    let mut modes = [None; 4];
    for (key, value) in object.iter() {
        let slot = FAMILIES.iter().position(|family| *family == key)?;
        let text = match value.as_number() {
            Some(number) => number.as_str(),
            None => value.as_str()?,
        };
        modes[slot] = Some(mode(text)?);
    }
    let [Some(path_traversal), Some(sqli), Some(xss), Some(rce)] = modes else { return None };
    Some(Modes { path_traversal, sqli, xss, rce })
}

fn mode(text: &str) -> Option<Mode> {
    if let Some(mode) = Mode::parse(text.as_bytes()) {
        return Some(mode);
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<usize>().ok().and_then(|tag| Mode::ALL.get(tag).copied())
}

const STORE_MODES: Sql = Sql::both(
    "INSERT INTO policy_inspection (id, path_traversal, sqli, xss, rce) \
     VALUES (1, $1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET \
     path_traversal = excluded.path_traversal, sqli = excluded.sqli, xss = excluded.xss, \
     rce = excluded.rce",
);

const INSERT_MODES_HISTORY: Sql = Sql::both(
    "INSERT INTO console_inspection_history (revision, actor, recorded_at, path_traversal, \
     sqli, xss, rce, previous_path_traversal, previous_sqli, previous_xss, previous_rce) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
);

/// Replaces the four inspection modes with those of `edit.document` at
/// `edit.expected_revision` (S14): composes the current candidate on `base` to learn the
/// modes in force (the stored override, or the policy file's), stores the new modes,
/// records them and the previous ones in `console_inspection_history`, advances the policy
/// revision to the expected revision plus one, and audits `inspection.edit` with both
/// mode sets. Returns the committed revision. The credential is `credential`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a document that is not exactly
/// the four modes, or a stored policy whose candidate does not compose, like
/// [`access::authorize_in`] for policy writers, with [`ConsoleStorageError::Conflict`] for
/// a stale revision, and with the driver's error.
pub async fn edit_inspection(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    edit: &policies::Edit,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    validate(edit)?;
    let modes = parse_modes(edit.document.as_bytes())
        .ok_or(ConsoleStorageError::InvalidInput("inspection modes"))?;
    let principal = access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    let lock = revision::lock(tx, edit.expected_revision).await?;
    let current = Inputs::load(tx, now, None).await?.compose(base).map_err(candidate::refusal)?;
    let previous = current.inspection_modes;
    let committed = lock.expected().checked_add(1).ok_or(ConsoleStorageError::Capacity)?;
    let names = |modes: Modes| [modes.path_traversal, modes.sqli, modes.xss, modes.rce];
    let new: Vec<Param<'_>> = names(modes).iter().map(|mode| mode.name().into()).collect();
    tx.execute(STORE_MODES, &new).await?;
    let mut params: Vec<Param<'_>> = vec![
        row::int(committed)?.into(),
        row::int(principal.actor)?.into(),
        row::int(now)?.into(),
    ];
    params.extend(new);
    params.extend(names(previous).iter().map(|mode| Param::from(mode.name())));
    tx.execute(INSERT_MODES_HISTORY, &params).await?;
    let revision = revision::advance(tx, lock).await?;
    let row = audit::AuditRow {
        target: Some("inspection".to_owned()),
        before: Some(modes_summary(previous)),
        after: Some(modes_summary(modes)),
        ..policy_audit(&principal, credential, AuditAction::InspectionEdit, revision, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_documents_name_all_four_modes_exactly() {
        let all = br#"{"path_traversal":"enforce","sqli":"audit","xss":"disabled","rce":2}"#;
        let modes = parse_modes(all).unwrap();
        assert_eq!(
            (modes.path_traversal, modes.sqli, modes.xss, modes.rce),
            (Mode::Enforce, Mode::Audit, Mode::Disabled, Mode::Enforce)
        );
        let tags = br#"{"rce":"0","xss":"1","sqli":2,"path_traversal":"audit"}"#;
        assert_eq!(parse_modes(tags).unwrap().rce, Mode::Disabled);
        for refused in [
            &br#"{}"#[..],
            br#"{"sqli":"ignore"}"#,
            br#"{"path_traversal":"enforce","sqli":"audit","xss":"disabled"}"#,
            br#"{"path_traversal":"enforce","sqli":"audit","xss":"disabled","rce":3}"#,
            br#"{"path_traversal":"enforce","sqli":"audit","xss":"disabled","rce":1.0}"#,
            br#"{"path_traversal":"enforce","sqli":"AUDIT","xss":"disabled","rce":"audit"}"#,
            br#"{"path_traversal":"a","sqli":"audit","xss":"disabled","rce":"audit","x":1}"#,
            br#"{"sqli":"audit","sqli":"audit","xss":"disabled","rce":"audit"}"#,
            br#"[]"#,
        ] {
            assert_eq!(parse_modes(refused), None, "{}", String::from_utf8_lossy(refused));
        }
    }
}
