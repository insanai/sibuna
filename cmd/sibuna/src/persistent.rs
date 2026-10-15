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
use sibuna_policy::limits::{Limits, managed_identity};
use sibuna_policy::loader::Diagnostic;
use sibuna_policy::matchers::{self, MatcherError};
use sibuna_policy::{Action, Algorithm, Engine, Mode, Modes, PolicyRule, RuleError};
use sibuna_storage::{
    ChallengeAlgorithm, Hooks, InspectionMode, InspectionRow, PolicyAction, PolicyRow,
    PolicySnapshot, RuleLimits, Storage, StorageError,
};

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
    Ok(Modes {
        path_traversal: mode(row.path_traversal),
        sqli: mode(row.sqli),
        xss: mode(row.xss),
        rce: mode(row.rce),
    })
}

/// The stored enums mirror the policy crate's; the database's CHECK constraints keep any
/// other value out, so the conversions are total.
fn mode(stored: InspectionMode) -> Mode {
    match stored {
        InspectionMode::Disabled => Mode::Disabled,
        InspectionMode::Audit => Mode::Audit,
        InspectionMode::Enforce => Mode::Enforce,
    }
}

fn action(stored: PolicyAction) -> Action {
    match stored {
        PolicyAction::Allow => Action::Allow,
        PolicyAction::Deny => Action::Deny,
        PolicyAction::Challenge => Action::Challenge,
        PolicyAction::Weigh => Action::Weigh,
    }
}

fn algorithm(stored: ChallengeAlgorithm) -> Algorithm {
    match stored {
        ChallengeAlgorithm::Hashcash => Algorithm::Hashcash,
        ChallengeAlgorithm::Posw => Algorithm::Posw,
    }
}

fn invalid(row: &PolicyRow, problem: &str) -> BuildError {
    BuildError::InvalidStoredPolicy { id: row.id.clone(), problem: problem.to_owned() }
}

/// Decodes one stored rule, checking its cells in the order the Zig loader did.
fn decode_rule(row: &PolicyRow) -> Result<PolicyRule, BuildError> {
    let mut rule = PolicyRule::new(&row.name, action(row.action));
    rule.limit_identity = managed_identity(row.id.as_bytes());
    if let Some(stored) = row.limits {
        rule.limits = Some(rule_limits(stored).map_err(|_| invalid(row, "InvalidRuleLimit"))?);
    }
    rule.path_pattern = row.path_pattern.clone();
    rule.ua_pattern = row.ua_pattern.clone();
    rule.difficulty = row.difficulty;
    rule.algorithm = row.algorithm.map(algorithm);
    rule.weight = row.weight;
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

/// The stored quota as the engine's limits, validated with the engine's own bounds.
fn rule_limits(stored: RuleLimits) -> Result<Limits, sibuna_policy::limits::InvalidRuleLimit> {
    let limits = Limits {
        rate: stored.rate,
        window_seconds: stored.window_seconds,
        ban_seconds: stored.ban_seconds,
    };
    limits.validate()?;
    Ok(limits)
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

    fn row(id: &str, action: PolicyAction, path: &str) -> PolicyRow {
        PolicyRow {
            id: id.into(),
            name: id.into(),
            action,
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
            PolicySnapshot { rules: vec![row("live", PolicyAction::Deny, "/admin*")], ..Default::default() };
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
            ("bad limit", |r| {
                r.limits = Some(RuleLimits { rate: 0, window_seconds: 60, ban_seconds: 0 });
            }),
        ];
        for (label, corrupt) in cases {
            let mut stored = row("limited", PolicyAction::Allow, "/private");
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
        let mut good = row("limited", PolicyAction::Allow, "/private");
        good.header_matchers = Some(r#"{"X-Api":"v2"}"#.into());
        good.cidr_matchers = Some(r#"["10.0.0.0/8"]"#.into());
        good.limits = Some(RuleLimits { rate: 1, window_seconds: 60, ban_seconds: 0 });
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
            path_traversal: InspectionMode::Disabled,
            sqli: InspectionMode::Audit,
            xss: InspectionMode::Enforce,
            rce: InspectionMode::Enforce,
        };
        let mut snapshot = PolicySnapshot { inspection: Some(inspection), ..Default::default() };
        let engine = build_engine(&recipe, &snapshot).unwrap();
        assert_eq!(engine.inspection_modes.sqli, Mode::Audit);
        assert_eq!(engine.inspection_modes.rce, Mode::Enforce);
        snapshot.inspection = None;
        let engine = build_engine(&recipe, &snapshot).unwrap();
        assert_eq!(engine.inspection_modes.sqli, Mode::Enforce);
        assert_eq!(engine.inspection_modes.rce, Mode::Audit);
    }

    #[test]
    fn rows_without_limits_load() {
        let snapshot = PolicySnapshot {
            rules: vec![row("legacy", PolicyAction::Deny, "/legacy")],
            ..Default::default()
        };
        let engine = build_engine(&recipe(), &snapshot).unwrap();
        let decision = engine.evaluate(&RequestView::new(b"/legacy", b"8.8.8.8", b""));
        assert_eq!(decision.action, Action::Deny);
        assert!(decision.limits.is_none());
    }
}
