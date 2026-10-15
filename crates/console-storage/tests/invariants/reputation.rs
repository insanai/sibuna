//! S17 and S18: console reputation edits, country replacements with their staged review,
//! and the reputation page.

use sibuna_console_protocol::workflows::{
    self, ChangeKind, CountryApply, CountryChunk, CountryPreflight, CountrySummary,
    ReputationAction, ReputationEdit, ReputationQuery, ReputationRemove,
};
use sibuna_console_protocol::{Role, Text, users};
use sibuna_console_storage::reputation::{self, PrefixChange};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::{Database, Sql, Transaction};

use crate::common::{
    NOW, audit_rows, cookie, create_account, for_each_backend, join, scalar, sign_in, summaries,
};
use crate::policy::{admin, base, revision};

fn edit(
    prefix: &str,
    action: ReputationAction,
    until: Option<u64>,
    expected: u64,
) -> ReputationEdit {
    ReputationEdit {
        auth: users::Auth::default(),
        expected_revision: expected,
        prefix: Text::new(prefix).expect("prefix"),
        action,
        until,
        note: Text::new("abuse").expect("note"),
    }
}

fn remove(prefix: &str, expected: u64) -> ReputationRemove {
    ReputationRemove {
        auth: users::Auth::default(),
        expected_revision: expected,
        prefix: Text::new(prefix).expect("prefix"),
    }
}

async fn change(
    tx: &mut Transaction,
    change: PrefixChange<'_>,
) -> Result<u64, ConsoleStorageError> {
    reputation::change_prefix(tx, &cookie(10), &base(), change, NOW).await
}

/// Inserts a decisive reputation row directly, as the data plane would.
async fn insert_prefix(tx: &mut Transaction, prefix: &str, score: i64) {
    let sql = Sql::both(
        "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, trigger_rule, hits, \
         last_seen) VALUES ($1, $2, 'waf', 1, 0)",
    );
    tx.execute(sql, &[prefix.into(), score.into()]).await.expect("prefix");
}

async fn count(tx: &mut Transaction, sql: &'static str) -> i64 {
    scalar(tx, sql).await
}

#[test]
fn reputation_change_records_ownership_and_audit() {
    for_each_backend("reputation_change", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let start = revision(&mut tx).await;
        let input = edit("192.0.2.0/24", ReputationAction::Deny, Some(NOW + 3600), start);
        assert_eq!(change(&mut tx, PrefixChange::Edit(&input)).await.expect("edit"), start + 1);
        assert_eq!(revision(&mut tx).await, start + 1);
        let row = Sql::both(
            "SELECT reputation_score, banned_until, trigger_rule, hits, last_seen \
             FROM ip_reputation WHERE ip_or_cidr = '192.0.2.0/24'",
        );
        let rows = tx.fetch_all(row, &[]).await.expect("row");
        assert_eq!(rows[0][0].as_i64(), Some(-100));
        assert_eq!(rows[0][1].as_i64(), Some(NOW as i64 + 3600));
        assert_eq!(rows[0][2].as_str(), Some("console"));
        assert_eq!((rows[0][3].as_i64(), rows[0][4].as_i64()), (Some(0), Some(NOW as i64)));
        let owned = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_reputation_sources \
                     WHERE ip_or_cidr = '192.0.2.0/24' AND country IS NULL AND note = 'abuse'";
        assert_eq!(count(&mut tx, owned).await, 1);
        let audit = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(audit.action, "reputation.edit");
        assert_eq!(
            (audit.subject, audit.target.as_deref()),
            (Some(start as i64 + 1), Some("192.0.2.0/24"))
        );
        let (_, after) = summaries(&mut tx, audit.id).await;
        let after = after.expect("after");
        assert!(
            after.contains("\"score\":-100")
                && after.contains(&format!("\"expires\":{}", NOW + 3600))
        );
        // An allow without an end replaces it.
        let allow = edit("192.0.2.0/24", ReputationAction::Allow, None, start + 1);
        change(&mut tx, PrefixChange::Edit(&allow)).await.expect("allow");
        let allowed = "SELECT CAST(COUNT(*) AS BIGINT) FROM ip_reputation \
                       WHERE reputation_score = 100 AND banned_until IS NULL";
        assert_eq!(count(&mut tx, allowed).await, 1);
        // Refused requests change nothing.
        let current = revision(&mut tx).await;
        for refused in [
            edit("192.0.2.0/33", ReputationAction::Deny, None, current),
            edit("192.0.2.0/24", ReputationAction::Deny, Some(NOW), current),
        ] {
            let outcome = change(&mut tx, PrefixChange::Edit(&refused)).await;
            assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
        }
        let unknown =
            change(&mut tx, PrefixChange::Remove(&remove("198.51.100.0/24", current))).await;
        assert!(matches!(unknown, Err(ConsoleStorageError::InvalidInput(_))));
        let stale =
            change(&mut tx, PrefixChange::Remove(&remove("192.0.2.0/24", current - 1))).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
        // A removal deletes the row and its ownership.
        let removed =
            change(&mut tx, PrefixChange::Remove(&remove("192.0.2.0/24", current))).await;
        assert_eq!(removed.expect("remove"), current + 1);
        assert_eq!(count(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM ip_reputation").await, 0);
        let sources = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_reputation_sources";
        assert_eq!(count(&mut tx, sources).await, 0);
        let audit = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(
            (audit.action.as_str(), audit.subject),
            ("reputation.remove", Some(current as i64 + 1))
        );
        assert_eq!(summaries(&mut tx, audit.id).await, (None, None));
    });
}

#[test]
fn a_prefix_that_exhausts_the_trie_is_refused() {
    for_each_backend("reputation_capacity", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        // The most single addresses the trie holds, found with the trie itself.
        let addresses: Vec<String> = (1..=256).map(|i| format!("{i:x}::1/128")).collect();
        let mut trie = sibuna_cidr::PrefixTrie::<()>::new();
        let fit = addresses
            .iter()
            .take_while(|address| trie.insert_cidr(address.as_bytes(), ()).is_ok())
            .count();
        for address in &addresses[..fit] {
            insert_prefix(&mut tx, address, -100).await;
        }
        let current = revision(&mut tx).await;
        let input = edit(&addresses[fit], ReputationAction::Deny, None, current);
        let outcome = change(&mut tx, PrefixChange::Edit(&input)).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Capacity)), "{outcome:?}");
        // An entry the trie already holds still fits.
        let input = edit(&addresses[0], ReputationAction::Allow, None, current);
        assert_eq!(change(&mut tx, PrefixChange::Edit(&input)).await.expect("edit"), current + 1);
    });
}

#[test]
fn the_reputation_page_shows_owners_and_pages_by_prefix() {
    for_each_backend("reputation_page", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        for index in 0..9 {
            insert_prefix(&mut tx, &format!("10.0.{index}.0/24"), -60).await;
        }
        let current = revision(&mut tx).await;
        let input = edit("10.0.9.0/24", ReputationAction::Deny, None, current);
        change(&mut tx, PrefixChange::Edit(&input)).await.expect("edit");
        let query = |after: &str| ReputationQuery {
            auth: users::Auth::default(),
            after: Text::new(after).expect("after"),
        };
        let page = reputation::query_reputation(&mut tx, &cookie(10), &query(""), NOW)
            .await
            .expect("page");
        assert_eq!(page.rows.len(), 8);
        assert_eq!(page.committed, revision(&mut tx).await);
        assert_eq!(page.rows[0].prefix.as_str(), "10.0.0.0/24");
        assert_eq!((page.rows[0].source.as_str(), page.rows[0].trigger.as_str()), ("", "waf"));
        let next = page.next.expect("next");
        assert_eq!(next.as_str(), "10.0.7.0/24");
        let rest = reputation::query_reputation(&mut tx, &cookie(10), &query(next.as_str()), NOW)
            .await
            .expect("rest");
        assert_eq!(rest.rows.len(), 2);
        assert_eq!(rest.next, None);
        let owned = &rest.rows[1];
        assert_eq!(
            (owned.prefix.as_str(), owned.source.as_str(), owned.note.as_str()),
            ("10.0.9.0/24", "console", "abuse")
        );
    });
}

/// Stages `prefixes` under the digest `[seed; 32]` and returns the US deny replacement at
/// the current revision.
async fn stage(tx: &mut Transaction, prefixes: &[&str], seed: u8) -> CountryApply {
    for (ordinal, chunk) in prefixes.chunks(32).enumerate() {
        let chunk = CountryChunk {
            digest: [seed; 32],
            ordinal: u16::try_from(ordinal).expect("ordinal"),
            prefixes: chunk.iter().map(|prefix| Text::new(prefix).expect("prefix")).collect(),
        };
        reputation::stage_country_chunk(tx, &cookie(10), &chunk, NOW).await.expect("stage");
    }
    CountryApply {
        auth: users::Auth::default(),
        expected_revision: revision(tx).await,
        digest: [seed; 32],
        count: u16::try_from(prefixes.len()).expect("count"),
        country: *b"US",
        action: ReputationAction::Deny,
        until: None,
        geo_generation: Text::new(&if seed == 1 { "ab" } else { "cd" }.repeat(32))
            .expect("generation"),
    }
}

fn preflight(apply: &CountryApply, diff_offset: u16) -> CountryPreflight {
    CountryPreflight {
        auth: users::Auth::default(),
        expected_revision: apply.expected_revision,
        digest: apply.digest,
        count: apply.count,
        country: apply.country,
        action: apply.action,
        diff_offset,
    }
}

async fn preview(
    tx: &mut Transaction,
    apply: &CountryApply,
    diff_offset: u16,
) -> Result<CountrySummary, ConsoleStorageError> {
    reputation::preview_country(tx, &cookie(10), &base(), &preflight(apply, diff_offset), NOW)
        .await
}

async fn apply(tx: &mut Transaction, apply: &CountryApply) -> Result<u64, ConsoleStorageError> {
    reputation::apply_country(tx, &cookie(10), &base(), apply, NOW).await
}

const US_OWNED: &str =
    "SELECT CAST(COUNT(*) AS BIGINT) FROM console_reputation_sources WHERE country = 'US'";

#[test]
fn country_replacement_removes_unreviewed_prefixes() {
    for_each_backend("country_replace", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let first = stage(&mut tx, &["192.0.2.0/24", "198.51.100.0/24"], 1).await;
        let committed = apply(&mut tx, &first).await.expect("first");
        assert_eq!(committed, first.expected_revision + 1);
        assert_eq!(revision(&mut tx).await, committed);
        let staged = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_country_chunks";
        assert_eq!(count(&mut tx, staged).await, 0);
        let next = stage(&mut tx, &["198.51.100.0/24", "203.0.113.0/24"], 2).await;
        let review = preview(&mut tx, &next, 0).await.expect("preview");
        assert_eq!((review.added, review.removed, review.retained), (1, 1, 1));
        assert_eq!((review.prefixes, review.previous, review.overlaps), (2, 2, 1));
        assert_eq!(review.previous_generation.as_str(), "ab".repeat(32));
        let removed: Vec<&str> = review.removed_sample.iter().map(Text::as_str).collect();
        assert_eq!(removed, ["192.0.2.0/24"]);
        let changes: Vec<(&str, ChangeKind)> =
            review.changes.iter().map(|c| (c.prefix.as_str(), c.kind)).collect();
        assert_eq!(
            changes,
            [
                ("192.0.2.0/24", ChangeKind::Removed),
                ("198.51.100.0/24", ChangeKind::Retained),
                ("203.0.113.0/24", ChangeKind::Added)
            ]
        );
        // The counts cover the whole candidate trie, the root and the IPv4 path included.
        let empty = sibuna_policy::Engine::new(16).reputation_node_count();
        assert!(usize::from(review.nodes_before) > empty);
        assert!(usize::from(review.nodes_after) > empty);
        assert_eq!(review.sample.len(), 2);
        apply(&mut tx, &next).await.expect("next");
        let gone =
            "SELECT CAST(COUNT(*) AS BIGINT) FROM ip_reputation WHERE ip_or_cidr = '192.0.2.0/24'";
        assert_eq!(count(&mut tx, gone).await, 0);
        assert_eq!(count(&mut tx, US_OWNED).await, 2);
        let generation = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_reputation_sources \
                          WHERE country = 'US' AND note = ''";
        assert_eq!(count(&mut tx, generation).await, 2);
        let audit = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(
            (audit.action.as_str(), audit.target.as_deref()),
            ("reputation.country", Some("US"))
        );
        let (before, after) = summaries(&mut tx, audit.id).await;
        let before = before.expect("before");
        assert!(before.contains("\"count\":2") && before.contains("\"removed\":1"));
        assert!(before.contains(&"ab".repeat(32)));
        let after = after.expect("after");
        assert!(after.contains("\"score\":-100") && after.contains(&"cd".repeat(32)));
        // An empty set removes the whole country.
        let empty = stage(&mut tx, &[], 3).await;
        assert_eq!(preview(&mut tx, &empty, 0).await.expect("empty").removed, 2);
        apply(&mut tx, &empty).await.expect("empty");
        assert_eq!(count(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM ip_reputation").await, 0);
        let actions = crate::common::audit_actions(&mut tx).await;
        assert_eq!(actions.iter().filter(|action| *action == "reputation.country").count(), 3);
        // Nothing staged and nothing owned is incomplete.
        let nothing = stage(&mut tx, &[], 4).await;
        assert!(matches!(
            preview(&mut tx, &nothing, 0).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
    });
}

#[test]
fn country_refresh_preserves_independent_ownership() {
    for_each_backend("country_ownership", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let initial = stage(&mut tx, &["192.0.2.0/24"], 1).await;
        apply(&mut tx, &initial).await.expect("initial");
        let reviewed = stage(&mut tx, &["198.51.100.0/24"], 2).await;
        preview(&mut tx, &reviewed, 0).await.expect("preview");
        let independent =
            edit("198.51.100.0/24", ReputationAction::Allow, None, reviewed.expected_revision);
        change(&mut tx, PrefixChange::Edit(&independent)).await.expect("independent edit");
        let stale = apply(&mut tx, &reviewed).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)), "{stale:?}");
        let updated = stage(&mut tx, &["198.51.100.0/24"], 2).await;
        let conflict = preview(&mut tx, &updated, 0).await;
        assert!(matches!(conflict, Err(ConsoleStorageError::Conflict)), "{conflict:?}");
        assert!(matches!(apply(&mut tx, &updated).await, Err(ConsoleStorageError::Conflict)));
        let console = "SELECT CAST(COUNT(*) AS BIGINT) FROM ip_reputation r \
                       JOIN console_reputation_sources s ON s.ip_or_cidr = r.ip_or_cidr \
                       WHERE s.country IS NULL AND r.reputation_score = 100";
        assert_eq!(count(&mut tx, console).await, 1);
        assert_eq!(count(&mut tx, US_OWNED).await, 1);
        assert_eq!(count(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM ip_reputation").await, 2);
        // A direct deletion of a reputation row takes its ownership with it.
        tx.execute(Sql::both("DELETE FROM ip_reputation WHERE ip_or_cidr = '192.0.2.0/24'"), &[])
            .await
            .expect("delete");
        assert_eq!(count(&mut tx, US_OWNED).await, 0);
    });
}

#[test]
fn country_diff_and_audit_fit_at_maximum_cardinality() {
    for_each_backend("country_capacity", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let prefixes: Vec<String> =
            (0..1024).map(|value| format!("10.{}.{}.0/24", value / 256, value % 256)).collect();
        let prefixes: Vec<&str> = prefixes.iter().map(String::as_str).collect();
        let initial = stage(&mut tx, &prefixes, 1).await;
        apply(&mut tx, &initial).await.expect("initial");
        let refresh = stage(&mut tx, &prefixes, 2).await;
        let first = preview(&mut tx, &refresh, 0).await.expect("first");
        assert_eq!((first.retained, first.next_offset), (1024, Some(8)));
        let last = preview(&mut tx, &refresh, 1024 - 8).await.expect("last");
        assert_eq!((last.changes.len(), last.next_offset), (8, None));
        assert!(matches!(
            preview(&mut tx, &refresh, 2049).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        apply(&mut tx, &refresh).await.expect("refresh");
        assert_eq!(count(&mut tx, US_OWNED).await, 1024);
    });
}

#[test]
fn staged_chunks_are_checked_and_replace_their_slot() {
    for_each_backend("country_stage", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let chunk = |ordinal: u16, prefixes: &[&str]| CountryChunk {
            digest: [7; 32],
            ordinal,
            prefixes: prefixes.iter().map(|prefix| Text::new(prefix).expect("prefix")).collect(),
        };
        for refused in [chunk(32, &["192.0.2.0/24"]), chunk(0, &["192.0.2.0/33"]), chunk(0, &[])] {
            let outcome =
                reputation::stage_country_chunk(&mut tx, &cookie(10), &refused, NOW).await;
            assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
        }
        let stranger = Credential { digest: [99; 32], ..cookie(10) };
        let outcome =
            reputation::stage_country_chunk(&mut tx, &stranger, &chunk(0, &["192.0.2.0/24"]), NOW)
                .await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Unauthorized)));
        // A repeated prefix moves to its new slot, so the set of two is incomplete.
        reputation::stage_country_chunk(
            &mut tx,
            &cookie(10),
            &chunk(0, &["192.0.2.0/24", "192.0.2.0/24"]),
            NOW,
        )
        .await
        .expect("stage");
        let staged = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_country_chunks";
        assert_eq!(count(&mut tx, staged).await, 1);
        let apply_input = CountryApply {
            auth: users::Auth::default(),
            expected_revision: revision(&mut tx).await,
            digest: [7; 32],
            count: 2,
            country: *b"US",
            action: ReputationAction::Deny,
            until: None,
            geo_generation: Text::new(&"ab".repeat(32)).expect("generation"),
        };
        assert!(matches!(
            preview(&mut tx, &apply_input, 0).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        let wrong = CountryApply { count: 1, country: *b"QQ", ..apply_input.clone() };
        assert!(matches!(apply(&mut tx, &wrong).await, Err(ConsoleStorageError::InvalidInput(_))));
        let wrong = CountryApply {
            count: 1,
            geo_generation: Text::new("ab").expect("g"),
            ..apply_input.clone()
        };
        assert!(matches!(apply(&mut tx, &wrong).await, Err(ConsoleStorageError::InvalidInput(_))));
        let wrong = CountryApply { count: 1, until: Some(NOW), ..apply_input.clone() };
        assert!(matches!(apply(&mut tx, &wrong).await, Err(ConsoleStorageError::InvalidInput(_))));
        let right = CountryApply { count: 1, until: Some(NOW + 60), ..apply_input };
        apply(&mut tx, &right).await.expect("apply");
        let expiring =
            "SELECT CAST(COUNT(*) AS BIGINT) FROM ip_reputation WHERE banned_until IS NOT NULL";
        assert_eq!(count(&mut tx, expiring).await, 1);
    });
}

#[test]
fn at_most_sixteen_country_sets_are_staged_at_once() {
    for_each_backend("country_stage_sets", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let chunk = |seed: u8, ordinal: u16| CountryChunk {
            digest: [seed; 32],
            ordinal,
            prefixes: vec![Text::new(&format!("192.0.{seed}.0/24")).expect("prefix")],
        };
        let mut stage = async |seed: u8, ordinal: u16, now: u64| {
            reputation::stage_country_chunk(&mut tx, &cookie(10), &chunk(seed, ordinal), now).await
        };
        for seed in 1..=16 {
            stage(seed, 0, NOW).await.expect("one of sixteen sets");
        }
        let outcome = stage(17, 0, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Capacity)), "{outcome:?}");
        // A staged set may still grow, and sets older than the window no longer count.
        stage(16, 1, NOW).await.expect("a further chunk of a staged set");
        let later = NOW + workflows::STAGE_SECONDS + 1;
        stage(17, 0, later).await.expect("a set once the others aged out");
    });
}

async fn apply_and_commit(db: &Database, input: CountryApply) -> Result<u64, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let revision = reputation::apply_country(&mut tx, &cookie(10), &base(), &input, NOW).await?;
    tx.commit().await?;
    Ok(revision)
}

#[test]
fn two_nodes_applying_countries_at_one_revision_one_wins() {
    for_each_backend("country_race", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let first = stage(&mut tx, &["192.0.2.0/24"], 1).await;
        let second =
            CountryApply { country: *b"DE", ..stage(&mut tx, &["198.51.100.0/24"], 2).await };
        tx.commit().await.expect("commit");
        let expected = first.expected_revision;
        let (one, two) = join(apply_and_commit(&db, first), apply_and_commit(&db, second)).await;
        let conflict = |outcome: &Result<u64, ConsoleStorageError>| {
            matches!(outcome, Err(ConsoleStorageError::Conflict))
        };
        assert!(one.is_ok() && conflict(&two) || two.is_ok() && conflict(&one), "{one:?} {two:?}");
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(revision(&mut tx).await, expected + 1);
        let owned = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_reputation_sources";
        assert_eq!(count(&mut tx, owned).await, 1);
    });
}

#[test]
fn country_previews_need_a_policy_writer() {
    for_each_backend("country_writer", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        let viewer = create_account(&mut tx, &credential, "viewer", Role::Viewer).await;
        let viewer = sign_in(&mut tx, viewer, 1, 20).await;
        let staged = stage(&mut tx, &["192.0.2.0/24"], 1).await;
        let outcome =
            reputation::preview_country(&mut tx, &viewer, &base(), &preflight(&staged, 0), NOW)
                .await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Forbidden)), "{outcome:?}");
    });
}
