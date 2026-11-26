//! The engine built from stored policy (SID 0005, SID 0011), and the storage wiring.
//!
//! The storage thread reads a [`PolicySnapshot`] at one policy revision and hands it to the
//! publish hook. The hook builds a complete engine from the startup policy file, the
//! inspection override and the managed rules (ahead of the file's rules, so a generic
//! admission rule cannot hide an operator's live denial), then publishes it. Any invalid row
//! refuses the snapshot: the old engine stays live and the revision stays unapplied until
//! the row is repaired. This is the port of `persistent_policy.zig`,
//! `policy_inspection.zig`, `policy_limits.zig` and `console_pages_load.zig`; the SQL lives
//! in `sibuna-storage`.
//!
//! Reputation is not part of the engine (SID 0033). The storage thread hands the
//! [`ReputationFollower`] the changes of `ip_reputation` after its cursor at every tick; the
//! follower applies them to a [`ReputationBuilder`] and publishes the set beside the engine.
//! A row the set cannot hold is refused alone and reported.
//!
//! The operator's page templates (read by the console's snapshot hook) are compiled into
//! the engine too. A stored template that no longer compiles never refuses the snapshot:
//! the page keeps its default, marked as a fallback, and a warning names the page. With the
//! console, every published engine also carries fresh rule-hit counters
//! ([`Publisher::observed`]).

use std::sync::Arc;

use sibuna_core::{Config, Metrics};
use sibuna_policy::limits::{Limits, managed_identity};
use sibuna_policy::loader::Diagnostic;
use sibuna_policy::matchers::{self, MatcherError};
use sibuna_policy::pages::{Kind, PageError, Template};
use sibuna_policy::{
    Action, Algorithm, Engine, Mode, Modes, PolicyRule, ReputationBuilder, ReputationError,
    RuleError,
};
use sibuna_storage::{
    ChallengeAlgorithm, Hooks, InspectionMode, InspectionRow, PageTemplate, PolicyAction,
    PolicyRow, PolicySnapshot, ReputationBatch, RuleLimits, Storage, StorageError, decides,
};

use crate::recipe::{BuildError, Recipe};
use crate::slot::EngineSlot;

/// Builds the engine of `snapshot` on top of `recipe`. A stored page template that does
/// not compile keeps the default page, marked as a fallback.
///
/// Fails with the first [`BuildError`]; the caller then keeps the engine it has.
pub fn build_engine(recipe: &Recipe, snapshot: &PolicySnapshot) -> Result<Engine, BuildError> {
    build_engine_reporting(recipe, snapshot, &mut |_, _| {})
}

/// As [`build_engine`], calling `ignored` with the kind and error of each stored page
/// template that did not compile.
fn build_engine_reporting(
    recipe: &Recipe,
    snapshot: &PolicySnapshot,
    ignored: &mut dyn FnMut(Kind, PageError),
) -> Result<Engine, BuildError> {
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
    install_pages(&mut engine, &snapshot.pages, ignored);
    Ok(engine)
}

/// Compiles the stored templates into `engine`'s pages. A template of an unknown kind is
/// skipped; one that does not compile leaves the page as it was, marked as a fallback, and
/// is reported to `ignored`.
fn install_pages(
    engine: &mut Engine,
    templates: &[PageTemplate],
    ignored: &mut dyn FnMut(Kind, PageError),
) {
    for stored in templates {
        let Some(kind) = Kind::parse(stored.kind.as_bytes()) else { continue };
        match Template::compile(kind, stored.html.as_bytes()) {
            Ok(mut template) => {
                template.revision = stored.revision;
                engine.pages.set(kind, template);
            }
            Err(error) => {
                let mut fallback: Template = engine.pages.page(kind).clone();
                fallback.customized = false;
                fallback.fallback = true;
                engine.pages.set(kind, fallback);
                ignored(kind, error);
            }
        }
    }
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
    if let Some(text) = &row.ja4_pattern {
        let pattern = sibuna_policy::ja4::Pattern::parse(text.as_bytes());
        rule.ja4 = Some(pattern.ok_or_else(|| invalid(row, "InvalidJa4"))?);
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

/// Builds and publishes the engine of each snapshot the storage thread reads.
pub struct Publisher {
    recipe: Recipe,
    slot: Arc<EngineSlot>,
    /// Numbers the rule-hit generations while the console runs.
    #[cfg(feature = "console")]
    generations: Option<crate::console::hits::Generations>,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher").field("recipe", &self.recipe).finish_non_exhaustive()
    }
}

impl Publisher {
    /// Returns a publisher building on `recipe` and publishing into `slot`.
    pub fn new(recipe: Recipe, slot: Arc<EngineSlot>) -> Publisher {
        Publisher {
            recipe,
            slot,
            #[cfg(feature = "console")]
            generations: None,
        }
    }

    /// Publishes every engine with fresh rule-hit counters numbered by `generations`.
    #[cfg(feature = "console")]
    pub fn observed(self, generations: crate::console::hits::Generations) -> Publisher {
        Publisher { generations: Some(generations), ..self }
    }

    /// Builds the engine of `snapshot` and publishes it; returns false, reporting why and
    /// keeping the published engine (and its counters), when the snapshot is refused.
    pub fn publish(&mut self, snapshot: &PolicySnapshot) -> bool {
        let mut ignored = |kind: Kind, error: PageError| {
            crate::cli::report(&format!(
                "storage: page template {} ignored: {}; default retained",
                kind.name(),
                error.name()
            ));
        };
        let engine = match build_engine_reporting(&self.recipe, snapshot, &mut ignored) {
            Ok(engine) => engine,
            Err(error) => {
                crate::cli::report(&format!(
                    "storage: policy revision {} not applied: {error}",
                    snapshot.revision
                ));
                return false;
            }
        };
        #[cfg(feature = "console")]
        if let Some(generations) = self.generations.as_mut() {
            let managed: Vec<&str> = snapshot.rules.iter().map(|row| row.id.as_str()).collect();
            return match generations.next(&engine, snapshot.revision, &managed) {
                Ok(hits) => {
                    self.slot.publish_observed(engine, hits);
                    true
                }
                Err(error) => {
                    crate::cli::report(&format!(
                        "storage: policy revision {} not applied: {error}",
                        snapshot.revision
                    ));
                    false
                }
            };
        }
        self.slot.publish(engine);
        true
    }
}

/// Applies the reputation of each storage tick and publishes it beside the engine
/// (SID 0033). It lives on the storage thread.
#[derive(Debug)]
pub struct ReputationFollower {
    builder: ReputationBuilder,
    slot: Arc<EngineSlot>,
}

impl ReputationFollower {
    /// Returns a follower that publishes into `slot`, holding no reputation yet.
    pub fn new(slot: Arc<EngineSlot>) -> ReputationFollower {
        ReputationFollower { builder: ReputationBuilder::new(), slot }
    }

    /// Applies `batch`: on a full load forgets every entry and takes the loaded rows, then
    /// applies the changes in order and removes the entries that ended at `batch.now`.
    /// Publishes a new set only when something changed. A row the set cannot hold is
    /// refused alone; the count and the first reason are reported.
    pub fn apply(&mut self, batch: &ReputationBatch<'_>) {
        let mut refused = Refused::default();
        let mut changed = !batch.changes.is_empty();
        if let Some(rows) = batch.reset {
            self.builder.clear();
            changed = true;
            for row in rows {
                let (score, until) = (row.reputation_score, row.banned_until);
                refused.note(self.decide(&row.ip_or_cidr, score, until, false, batch.now));
            }
        }
        for change in batch.changes {
            let (score, until) = (change.reputation_score, change.banned_until);
            let result = self.decide(&change.ip_or_cidr, score, until, change.removed, batch.now);
            refused.note(result);
        }
        changed |= self.builder.expire(batch.now) > 0;
        if changed {
            let (set, ranges) = self.builder.publish();
            refused.note(ranges.map_or(Ok(()), Err));
            self.slot.publish_reputation(set);
        }
        if let Some(error) = refused.first {
            let count = refused.count;
            crate::cli::report(&format!(
                "storage: {count} reputation row(s) not applied: {error}"
            ));
        }
    }

    /// Sets or removes one key, as the query of a full load would hold it.
    fn decide(
        &mut self,
        cidr: &str,
        score: i32,
        until: Option<u64>,
        removed: bool,
        now: u64,
    ) -> Result<(), ReputationError> {
        if removed || !decides(score, until, now) {
            return self.builder.remove(cidr.as_bytes());
        }
        let action = if score < 0 { Action::Deny } else { Action::Allow };
        self.builder.set(cidr.as_bytes(), action, until)
    }
}

/// The rows of one batch the set refused: how many, and the first reason.
#[derive(Default)]
struct Refused {
    count: usize,
    first: Option<ReputationError>,
}

impl Refused {
    fn note(&mut self, result: Result<(), ReputationError>) {
        if let Err(error) = result {
            self.count += 1;
            self.first.get_or_insert(error);
        }
    }
}

/// Starts the storage layer `config` selects. The first snapshot is built and published by
/// `publisher` before this returns; later ones are published as the policy changes.
/// Incidents are embedded with the SID 0006 embedding, and recovered storage errors are
/// reported on standard error. `extend` adds further hooks (the console's).
///
/// Fails with the storage layer's error, including a refused first snapshot.
pub fn start_storage(
    config: &Config,
    mut publisher: Publisher,
    metrics: Arc<Metrics>,
    extend: impl FnOnce(&mut Hooks),
) -> Result<Storage, StorageError> {
    let mut follower = ReputationFollower::new(Arc::clone(&publisher.slot));
    let mut hooks = Hooks {
        embed: Box::new(sibuna_policy::embedding::embed),
        publish: Box::new(move |snapshot: PolicySnapshot| publisher.publish(&snapshot)),
        on_reputation: Box::new(move |batch| follower.apply(batch)),
        on_error: Some(Box::new(|error: &StorageError| {
            crate::cli::report(&format!("storage: {error}"));
        })),
        metrics,
        ..Hooks::default()
    };
    extend(&mut hooks);
    Storage::start(config, hooks)
}

/// Returns the startup lines about the PostgreSQL connection's protection: one line when it
/// is encrypted and verified (or local), and a warning with a hint otherwise. Returns `None`
/// for SQLite, and when the URL cannot be read (storage has then already refused it). The
/// lines never contain the URL.
#[cfg(feature = "postgres")]
pub fn database_banner(config: &Config) -> Option<String> {
    let Ok(sibuna_storage::Target::Postgres(url)) = sibuna_storage::Target::from_config(config)
    else {
        return None;
    };
    sibuna_storage::PostgresTls::from_url(&url).ok().map(describe_database)
}

/// The text of [`database_banner`] for `tls` in this build.
#[cfg(feature = "postgres")]
fn describe_database(tls: sibuna_storage::PostgresTls) -> String {
    use sibuna_storage::{POSTGRES_TLS, SslMode};
    let protection = tls.protection();
    let mut mode = format!("sslmode={}", tls.mode);
    if tls.effective_mode() != tls.mode {
        mode.push_str(" with sslrootcert, verified as verify-ca");
    }
    if tls.mode == SslMode::Prefer && !POSTGRES_TLS {
        mode.push_str("; this build lacks the postgres-tls feature");
    }
    if protection.is_secure() {
        return format!("Database: {} ({mode}).\n", protection.summary());
    }
    let build = if POSTGRES_TLS { "" } else { "build with the postgres-tls feature and " };
    format!(
        "WARNING: {} ({mode}).\nHint: {build}put sslmode=verify-full&sslrootcert=<CA file> in \
         the database URL.\n",
        protection.summary()
    )
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
        let snapshot = PolicySnapshot {
            rules: vec![row("live", PolicyAction::Deny, "/admin*")],
            ..Default::default()
        };
        let slot = Arc::new(EngineSlot::new(build_engine(&recipe, &snapshot).unwrap()));
        let mut follower = ReputationFollower::new(Arc::clone(&slot));
        let ban = ReputationRow {
            ip_or_cidr: "198.51.100.0/24".into(),
            reputation_score: -100,
            banned_until: None,
        };
        follower.apply(&ReputationBatch { reset: Some(&[ban]), changes: &[], now: 10 });
        let mut cache = crate::slot::EngineCache::new();
        let (engine, reputation) = cache.refresh_in(&slot);
        let decide = |path: &[u8], ip: &[u8]| {
            let decision = engine.evaluate_in(&RequestView::new(path, ip, b"curl"), reputation);
            (decision.action, decision.rule_name.to_owned())
        };
        assert_eq!(decide(b"/admin/x", b"8.8.8.8"), (Action::Deny, "live".to_owned()));
        assert_eq!(decide(b"/home", b"8.8.8.8"), (Action::Allow, "open".to_owned()));
        assert_eq!(decide(b"/home", b"198.51.100.7").0, Action::Deny);
    }

    #[test]
    fn the_follower_applies_changes_expires_and_publishes_only_on_a_change() {
        use sibuna_storage::ReputationChange;

        let slot = Arc::new(EngineSlot::new(Engine::new(8)));
        let mut follower = ReputationFollower::new(Arc::clone(&slot));
        let change = |seq, ip: &str, score, until, removed| ReputationChange {
            seq,
            ip_or_cidr: ip.into(),
            reputation_score: score,
            banned_until: until,
            removed,
        };
        let verdict = |ip: &str| {
            let mut cache = crate::slot::EngineCache::new();
            let (_, set) = cache.refresh_in(&slot);
            set.lookup(ip.parse().unwrap()).map(|(_, action)| action)
        };
        let changes = [
            change(1, "192.0.2.1", -100, Some(100), false),
            change(2, "192.0.2.2", -100, None, false),
            // A score that does not decide removes the key; so does a removal.
            change(3, "192.0.2.2", -10, None, false),
            change(4, "not an address", -100, None, false),
            change(5, "192.0.2.3", 80, None, false),
            change(6, "192.0.2.3", 80, None, true),
        ];
        let generation = slot.generation();
        follower.apply(&ReputationBatch { reset: None, changes: &changes, now: 50 });
        assert_eq!(slot.generation(), generation + 1);
        assert_eq!(verdict("192.0.2.1"), Some(Action::Deny));
        assert_eq!(verdict("192.0.2.2"), None);
        assert_eq!(verdict("192.0.2.3"), None);
        // A tick with nothing new and nothing ended publishes nothing.
        follower.apply(&ReputationBatch { reset: None, changes: &[], now: 60 });
        assert_eq!(slot.generation(), generation + 1);
        // The ban ends at its time, with no change from the database.
        follower.apply(&ReputationBatch { reset: None, changes: &[], now: 100 });
        assert_eq!(slot.generation(), generation + 2);
        assert_eq!(verdict("192.0.2.1"), None);
        // A new engine keeps the published reputation beside it.
        follower.apply(&ReputationBatch { reset: None, changes: &changes[1..2], now: 100 });
        slot.publish(Engine::new(9));
        assert_eq!(verdict("192.0.2.2"), Some(Action::Deny));
    }

    #[test]
    fn invalid_stored_matchers_and_limits_refuse_the_snapshot() {
        type Corruption = (&'static str, fn(&mut PolicyRow));
        let cases: [Corruption; 8] = [
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
            ("bad ja4", |r| r.ja4_pattern = Some("x13d*".into())),
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

    fn page(kind: &str, html: &str, revision: u64) -> PageTemplate {
        PageTemplate { kind: kind.into(), html: html.into(), revision }
    }

    // console_pages_test.zig (daemon side): the rebuilt engine carries the stored template;
    // other kinds keep their defaults; a stored template that no longer validates keeps the
    // default as a fallback, and an unknown kind is skipped.
    #[test]
    fn stored_pages_compile_into_the_engine_or_fall_back_to_the_default() {
        let custom = "<!doctype html><p>Blocked: {{ reason }} ({{ status }})</p>";
        let mut snapshot = PolicySnapshot {
            pages: vec![page("denied", custom, 1), page("unknown", custom, 1)],
            ..Default::default()
        };
        let engine = build_engine(&recipe(), &snapshot).unwrap();
        let denied = engine.pages.page(Kind::Denied);
        assert!(denied.customized && denied.revision == 1 && !denied.fallback);
        assert_eq!(denied.source(), custom);
        assert!(!engine.pages.page(Kind::Banned).customized);
        snapshot.pages = vec![page("denied", "<script>x</script>", 2)];
        let mut ignored = Vec::new();
        let engine = build_engine_reporting(&recipe(), &snapshot, &mut |kind, error| {
            ignored.push((kind, error));
        })
        .unwrap();
        let denied = engine.pages.page(Kind::Denied);
        assert!(!denied.customized && denied.fallback);
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].0, Kind::Denied);
    }

    // console_limits_test.zig (engine side): a managed rule's quota scope follows its id
    // through renames and unrelated revisions, and invalid stored limits refuse the snapshot
    // so the published engine (and its scope) stays.
    #[test]
    fn rule_limits_follow_the_managed_id_and_invalid_limits_keep_the_old_engine() {
        let mut quota = row("quota", PolicyAction::Challenge, "/quota");
        quota.limits = Some(RuleLimits { rate: 2, window_seconds: 60, ban_seconds: 3 });
        let applied = |slot: &EngineSlot| {
            let engine = slot.load();
            let decision = engine.evaluate(&RequestView::new(b"/quota", b"8.8.8.8", b""));
            (decision.limits, decision.limit_scope)
        };
        let slot = Arc::new(EngineSlot::new(Engine::new(8)));
        let mut publisher = Publisher::new(recipe(), Arc::clone(&slot));
        let mut snapshot = PolicySnapshot { rules: vec![quota.clone()], ..Default::default() };
        assert!(publisher.publish(&snapshot));
        let (limits, scope) = applied(&slot);
        assert_eq!(limits.map(|limits| limits.rate), Some(2));
        snapshot.rules.push(row("other", PolicyAction::Deny, "/other"));
        snapshot.rules[0].name = "Renamed".into();
        assert!(publisher.publish(&snapshot));
        assert_eq!(applied(&slot).1, scope);
        let mut broken = snapshot.clone();
        broken.rules[0].limits = Some(RuleLimits { rate: 0, window_seconds: 60, ban_seconds: 0 });
        assert!(!publisher.publish(&broken));
        assert_eq!(applied(&slot), (limits, scope));
        snapshot.rules[0].limits = None;
        assert!(publisher.publish(&snapshot));
        assert!(applied(&slot).0.is_none());
    }

    // console_rule_hits_test.zig: "published rule generations retain identities and a
    // failed rebuild cannot reset counters".
    #[cfg(feature = "console")]
    #[test]
    fn published_generations_keep_identities_and_a_failed_rebuild_keeps_the_counters() {
        use sibuna_console::{ManualClock, RuleHitSample};
        use sibuna_policy::RuleMatches;

        use crate::console::hits::Generations;

        let slot = Arc::new(EngineSlot::new(Engine::new(8)));
        let clock = Arc::new(ManualClock::new(100, 1));
        let generations = Generations::new(1, [1; 16], clock);
        let mut publisher = Publisher::new(recipe(), Arc::clone(&slot)).observed(generations);
        let mut tracked = row("tracked", PolicyAction::Allow, "/tracked");
        tracked.name = "Tracked".into();
        let mut snapshot =
            PolicySnapshot { revision: 4, rules: vec![tracked], ..Default::default() };
        assert!(publisher.publish(&snapshot));
        let first = slot.load_hits().unwrap();
        let engine = slot.load();
        let mut matches = RuleMatches::new();
        engine
            .evaluate_with_matches(&RequestView::new(b"/tracked", b"8.8.8.8", b""), &mut matches);
        first.record(&matches, engine.rule_count());
        assert_eq!(first.generation().rules[0].key.as_str(), "m:tracked");
        let number = first.generation().number;
        // A refused snapshot publishes nothing: the counters keep their hit.
        let mut broken = snapshot.clone();
        broken.rules[0].header_matchers = Some("[]".into());
        assert!(!publisher.publish(&broken));
        let unchanged = slot.load_hits().unwrap();
        assert_eq!(unchanged.generation().number, number);
        let mut sample = RuleHitSample::default();
        unchanged.sample(&mut sample);
        assert_eq!(sample.counts.values[0], 1);
        // A renamed rule is a new generation with the same key and fresh counters.
        snapshot.revision = 5;
        snapshot.rules[0].name = "Renamed".into();
        assert!(publisher.publish(&snapshot));
        let replaced = slot.load_hits().unwrap();
        assert!(replaced.generation().number > number);
        assert_eq!(replaced.generation().revision, 5);
        assert_eq!(replaced.generation().rules[0].key.as_str(), "m:tracked");
        assert_eq!(replaced.generation().rules[0].name.as_str(), "Renamed");
        replaced.sample(&mut sample);
        assert_eq!(sample.counts.values[0], 0);
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn the_database_banner_warns_unless_the_connection_is_verified() {
        use sibuna_storage::{POSTGRES_TLS, PostgresTls, SslMode};
        let tcp = |mode| PostgresTls { mode, ..PostgresTls::default() };
        let verified = describe_database(tcp(SslMode::VerifyFull));
        assert!(verified.starts_with("Database: ") && verified.contains("host name are verified"));
        assert!(!verified.contains("WARNING"));
        for mode in [SslMode::Disable, SslMode::Prefer, SslMode::Require, SslMode::VerifyCa] {
            let text = describe_database(tcp(mode));
            assert!(text.starts_with("WARNING: "), "{text}");
            assert!(text.contains(&format!("(sslmode={mode}")), "{text}");
            assert!(text.contains("Hint: ") && text.contains("sslmode=verify-full"), "{text}");
            assert_eq!(text.contains("postgres-tls"), !POSTGRES_TLS, "{text}");
        }
        assert!(describe_database(tcp(SslMode::Disable)).contains("not encrypted"));
        let upgraded = PostgresTls { mode: SslMode::Require, root_cert: true, unix_socket: false };
        assert!(describe_database(upgraded).contains("verified as verify-ca"));
        let local = PostgresTls { unix_socket: true, ..tcp(SslMode::Prefer) };
        assert!(describe_database(local).starts_with("Database: "));
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn the_database_banner_reads_the_configured_url_and_never_shows_it() {
        let config = Config {
            database_url: Some("postgres://sibuna:hunter2@db.internal/x?sslmode=disable".into()),
            cluster_node: Some(1),
            ..Config::default()
        };
        let text = database_banner(&config).unwrap();
        assert!(text.contains("not encrypted"), "{text}");
        assert!(!text.contains("hunter2") && !text.contains("db.internal"), "{text}");
        assert!(database_banner(&Config::default()).is_none());
    }
}
