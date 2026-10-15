//! The engine built from stored policy (SID 0005, SID 0011), and the storage wiring.
//!
//! The storage thread reads a [`PolicySnapshot`] at one policy revision and hands it to the
//! publish hook. The hook builds a complete engine from the startup policy file, the
//! inspection override, the managed rules (ahead of the file's rules, so a generic admission
//! rule cannot hide an operator's live denial) and the reputation rows, then publishes it.
//! Any invalid row refuses the snapshot: the old engine stays live and the revision stays
//! unapplied until the row is repaired. This is the port of `persistent_policy.zig`,
//! `policy_inspection.zig` and `policy_limits.zig`; the SQL lives in `sibuna-storage`.

use std::sync::Arc;

use sibuna_core::{Config, Metrics};
use sibuna_policy::limits::{Limits, StoredLimitError, managed_identity};
use sibuna_policy::loader::Diagnostic;
use sibuna_policy::matchers::{self, MatcherError};
use sibuna_policy::{Action, Algorithm, Engine, Mode, Modes, PolicyRule, RuleError};
use sibuna_storage::{Hooks, InspectionRow, PolicyRow, PolicySnapshot, Storage, StorageError};

use crate::recipe::{BuildError, Recipe};
use crate::slot::EngineSlot;

/// Builds the engine of `snapshot` on top of `recipe`.
///
/// Fails with the first [`BuildError`]; the caller then keeps the engine it has.
pub fn build_engine(recipe: &Recipe, snapshot: &PolicySnapshot) -> Result<Engine, BuildError> {
    let mut engine = recipe.base_engine(&mut Diagnostic::default())?;
    if let Some(row) = &snapshot.inspection {
        engine.inspection_modes = inspection_modes(row)?;
    }
    for (index, row) in snapshot.rules.iter().enumerate() {
        let rule = decode_rule(row)?;
        engine.insert_rule(index, rule).map_err(|error| match error {
            RuleError::TooManyRules => BuildError::TooManyRules,
            other => invalid(row, other.name()),
        })?;
    }
    for row in &snapshot.reputation {
        let action = if row.reputation_score < 0 { Action::Deny } else { Action::Allow };
        engine
            .insert_reputation(row.ip_or_cidr.as_bytes(), action)
            .map_err(|_| BuildError::InvalidReputation(row.ip_or_cidr.clone()))?;
    }
    Ok(engine)
}

fn inspection_modes(row: &InspectionRow) -> Result<Modes, BuildError> {
    let mode = |text: &str| Mode::parse(text.as_bytes()).ok_or(BuildError::InvalidInspectionMode);
    Ok(Modes {
        path_traversal: mode(&row.path_traversal)?,
        sqli: mode(&row.sqli)?,
        xss: mode(&row.xss)?,
        rce: mode(&row.rce)?,
    })
}

fn invalid(row: &PolicyRow, problem: &str) -> BuildError {
    BuildError::InvalidStoredPolicy { id: row.id.clone(), problem: problem.to_owned() }
}

/// Decodes one stored rule, checking its cells in the order the Zig loader did.
fn decode_rule(row: &PolicyRow) -> Result<PolicyRule, BuildError> {
    let action = Action::parse(row.action.as_bytes()).ok_or_else(|| invalid(row, "action"))?;
    let mut rule = PolicyRule::new(&row.name, action);
    rule.limit_identity = managed_identity(row.id.as_bytes());
    if let Some(text) = &row.limit_config {
        rule.limits = stored_limits(text).map_err(|error| invalid(row, error_name(&error)))?;
    }
    rule.path_pattern = row.path_pattern.clone();
    rule.ua_pattern = row.ua_pattern.clone();
    if let Some(value) = row.difficulty {
        rule.difficulty = Some(u32::try_from(value).map_err(|_| invalid(row, "difficulty"))?);
    }
    if let Some(name) = &row.algorithm {
        let algorithm =
            Algorithm::parse(name.as_bytes()).ok_or_else(|| invalid(row, "algorithm"))?;
        rule.algorithm = Some(algorithm);
    }
    rule.weight = i32::try_from(row.weight).map_err(|_| invalid(row, "weight"))?;
    if let Some(text) = &row.header_matchers {
        rule.headers = matchers::headers_from_json(text.as_bytes())
            .map_err(|error| invalid(row, matcher_name(error)))?;
    }
    if let Some(text) = &row.cidr_matchers {
        rule.cidrs = matchers::cidrs_from_json(text.as_bytes())
            .map_err(|error| invalid(row, matcher_name(error)))?;
    }
    Ok(rule)
}

fn stored_limits(text: &str) -> Result<Option<Limits>, StoredLimitError> {
    Limits::from_json(text.as_bytes())
}

fn error_name(error: &StoredLimitError) -> &'static str {
    match error {
        StoredLimitError::InvalidRuleLimit => "InvalidRuleLimit",
        StoredLimitError::Json(_) => "InvalidRuleLimit",
    }
}

fn matcher_name(error: MatcherError) -> &'static str {
    error.name()
}

/// Starts the storage layer `config` selects. The first snapshot is built and published
/// into `slot` before this returns; later ones are published as the policy changes.
/// Incidents are embedded with the SID 0006 embedding, and recovered storage errors are
/// reported on standard error.
///
/// Fails with the storage layer's error, including a refused first snapshot.
pub fn start_storage(
    config: &Config,
    recipe: Recipe,
    slot: Arc<EngineSlot>,
    metrics: Arc<Metrics>,
) -> Result<Storage, StorageError> {
    let hooks = Hooks {
        embed: Box::new(sibuna_policy::embedding::embed),
        publish: Box::new(move |snapshot: PolicySnapshot| {
            match build_engine(&recipe, &snapshot) {
                Ok(engine) => {
                    slot.publish(engine);
                    true
                }
                Err(error) => {
                    crate::cli::report(&format!(
                        "storage: policy revision {} not applied: {error}",
                        snapshot.revision
                    ));
                    false
                }
            }
        }),
        on_error: Some(Box::new(|error: &StorageError| {
            crate::cli::report(&format!("storage: {error}"));
        })),
        metrics,
        ..Hooks::default()
    };
    Storage::start(config, hooks)
}

#[cfg(test)]
mod tests {
    use sibuna_policy::RequestView;
    use sibuna_storage::ReputationRow;

    use super::*;

    fn row(id: &str, action: &str, path: &str) -> PolicyRow {
        PolicyRow {
            id: id.into(),
            name: id.into(),
            action: action.into(),
            path_pattern: Some(path.into()),
            ..PolicyRow::default()
        }
    }

    fn recipe() -> Recipe {
        Recipe { default_difficulty: 16, waf: true, policy_file: None }
    }

    #[test]
    fn managed_rules_precede_file_rules_and_reputation_applies() {
        let recipe = Recipe {
            policy_file: Some(
                br#"{"rules":[{"name":"open","path":"/*","action":"ALLOW"}]}"#.into(),
            ),
            ..recipe()
        };
        let mut snapshot =
            PolicySnapshot { rules: vec![row("live", "deny", "/admin*")], ..Default::default() };
        snapshot.reputation.push(ReputationRow {
            ip_or_cidr: "198.51.100.0/24".into(),
            reputation_score: -100,
            banned_until: None,
        });
        let engine = build_engine(&recipe, &snapshot).unwrap();
        let admin = engine.evaluate(&RequestView::new(b"/admin/x", b"8.8.8.8", b"curl"));
        assert_eq!((admin.action, admin.rule_name), (Action::Deny, "live"));
        let open = engine.evaluate(&RequestView::new(b"/home", b"8.8.8.8", b"curl"));
        assert_eq!((open.action, open.rule_name), (Action::Allow, "open"));
        let banned = engine.evaluate(&RequestView::new(b"/home", b"198.51.100.7", b"curl"));
        assert_eq!(banned.action, Action::Deny);
    }

    #[test]
    fn invalid_stored_matchers_and_limits_refuse_the_snapshot() {
        type Corruption = (&'static str, fn(&mut PolicyRow));
        let cases: [Corruption; 7] = [
            ("[] headers", |r| r.header_matchers = Some("[]".into())),
            ("numeric header", |r| r.header_matchers = Some(r#"{"X-Api":7}"#.into())),
            ("duplicate header", |r| {
                r.header_matchers = Some(r#"{"X-Api":"v2","x-api":"v1"}"#.into());
            }),
            ("five headers", |r| {
                r.header_matchers = Some(r#"{"A":"1","B":"2","C":"3","D":"4","E":"5"}"#.into());
            }),
            ("bad cidr", |r| r.cidr_matchers = Some(r#"["invalid"]"#.into())),
            ("nine cidrs", |r| {
                r.cidr_matchers = Some(format!("[{}]", ["\"10.0.0.0/8\""; 9].join(",")))
            }),
            ("bad limit", |r| r.limit_config = Some(r#"{"rate":0,"window_seconds":60}"#.into())),
        ];
        for (label, corrupt) in cases {
            let mut stored = row("limited", "allow", "/private");
            corrupt(&mut stored);
            let snapshot = PolicySnapshot { rules: vec![stored], ..Default::default() };
            assert!(
                matches!(
                    build_engine(&recipe(), &snapshot),
                    Err(BuildError::InvalidStoredPolicy { .. })
                ),
                "{label}"
            );
        }
        let mut good = row("limited", "allow", "/private");
        good.header_matchers = Some(r#"{"X-Api":"v2"}"#.into());
        good.cidr_matchers = Some(r#"["10.0.0.0/8"]"#.into());
        good.limit_config = Some(r#"{"rate":1,"window_seconds":60}"#.into());
        let snapshot = PolicySnapshot { rules: vec![good], ..Default::default() };
        let engine = build_engine(&recipe(), &snapshot).unwrap();
        let headers = [sibuna_policy::Header { name: b"X-Api", value: b"v2" }];
        let view =
            RequestView { headers: &headers, ..RequestView::new(b"/private", b"10.1.2.3", b"") };
        let decision = engine.evaluate(&view);
        assert_eq!(decision.action, Action::Allow);
        assert_eq!(decision.limits.map(|limits| limits.rate), Some(1));
    }

    #[test]
    fn stored_inspection_overrides_the_file_and_falls_back_without_a_row() {
        let recipe =
            Recipe { policy_file: Some(br#"{"inspection":{"rce":"audit"}}"#.into()), ..recipe() };
        let inspection = InspectionRow {
            path_traversal: "disabled".into(),
            sqli: "audit".into(),
            xss: "enforce".into(),
            rce: "enforce".into(),
        };
        let mut snapshot = PolicySnapshot { inspection: Some(inspection), ..Default::default() };
        let engine = build_engine(&recipe, &snapshot).unwrap();
        assert_eq!(engine.inspection_modes.sqli, Mode::Audit);
        assert_eq!(engine.inspection_modes.rce, Mode::Enforce);
        snapshot.inspection = None;
        let engine = build_engine(&recipe, &snapshot).unwrap();
        assert_eq!(engine.inspection_modes.sqli, Mode::Enforce);
        assert_eq!(engine.inspection_modes.rce, Mode::Audit);
        snapshot.inspection = Some(InspectionRow { sqli: "loud".into(), ..Default::default() });
        assert_eq!(
            build_engine(&recipe, &snapshot).err(),
            Some(BuildError::InvalidInspectionMode)
        );
    }

    #[test]
    fn legacy_rows_without_limits_load_and_unknown_actions_refuse() {
        let snapshot =
            PolicySnapshot { rules: vec![row("legacy", "deny", "/legacy")], ..Default::default() };
        let engine = build_engine(&recipe(), &snapshot).unwrap();
        let decision = engine.evaluate(&RequestView::new(b"/legacy", b"8.8.8.8", b""));
        assert_eq!(decision.action, Action::Deny);
        assert!(decision.limits.is_none());
        let snapshot =
            PolicySnapshot { rules: vec![row("odd", "maybe", "/")], ..Default::default() };
        assert!(build_engine(&recipe(), &snapshot).is_err());
    }
}
