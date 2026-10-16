//! JA4 fingerprints in the console (SID 0014): managed rules store, read, import and
//! evaluate a JA4 criterion; the private test and the replay match a fingerprint; incidents
//! carry their fingerprint to the Events page and the live feed; and the Events filter takes
//! a fingerprint or a prefix with the same rows on both backends.

use sibuna_console_protocol::events::Query;
use sibuna_console_protocol::policies::{self, Selection};
use sibuna_console_protocol::subscription_feed::{Kind, Request, Row as FeedRow};
use sibuna_console_protocol::{Text, workflows};
use sibuna_console_storage::bound::WorkBound;
use sibuna_console_storage::policy::{self, Import, PolicyRead};
use sibuna_console_storage::{ConsoleStorageError, Credential, events, feed};
use sibuna_policy::Action;
use sibuna_storage::{Sql, Transaction};

use crate::common::{NOW, for_each_backend};
use crate::events::{Stored, store};
use crate::policy::{admin, base, edit, revision, save};

const CHROME: &str = "t13d1516h2_8daaf6152771_02713d6af862";
const OLD_TLS: &str = "t12i0407h1_cd1e4f5c0b2a_0123456789ab";
const TLS13_RULE: &str = r#"{"id":"tls13","name":"TLS 1.3","action":"deny","ja4":"t13d*"}"#;

/// Returns the stored `ja4_pattern` of rule `id`.
async fn stored_pattern(tx: &mut Transaction, id: &str) -> Option<String> {
    let sql = Sql::both("SELECT ja4_pattern FROM policies WHERE id = $1");
    let rows = tx.fetch_all(sql, &[id.into()]).await.expect("pattern");
    rows[0][0].as_str().map(str::to_owned)
}

/// Reads the current document of rule `id`.
async fn document(tx: &mut Transaction, credential: &Credential, id: &str) -> String {
    let selection =
        Selection::Document { id: Text::new(id).expect("id"), revision: None, previous: false };
    let input = policies::Read {
        session_digest: [0; 32],
        require_totp: false,
        committed: None,
        selection,
    };
    match policy::read_policy(tx, credential, &input, NOW).await.expect("read") {
        PolicyRead::Document(document) => document.document.as_str().to_owned(),
        other => panic!("expected a document, got {other:?}"),
    }
}

#[test]
fn ja4_rules_round_trip_through_edits_reads_and_imports() {
    for_each_backend("ja4_rules", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        save(&mut tx, TLS13_RULE).await;
        assert_eq!(stored_pattern(&mut tx, "tls13").await.as_deref(), Some("t13d*"));
        let query = policies::Query::default();
        let page = policy::rule_page(&mut tx, &credential, &query, NOW).await.expect("page");
        assert_eq!(page.rows[0].ja4_pattern.as_deref(), Some("t13d*"));
        let text = document(&mut tx, &credential, "tls13").await;
        assert!(text.ends_with(",\"ja4\":\"t13d*\"}"), "{text}");
        // A rule without a criterion has none, and its document does not name one.
        save(&mut tx, r#"{"id":"plain","name":"Plain","action":"deny","path":"/x"}"#).await;
        assert_eq!(stored_pattern(&mut tx, "plain").await, None);
        assert!(!document(&mut tx, &credential, "plain").await.contains("ja4"));
        let import = Import {
            expected_revision: revision(&mut tx).await,
            documents: vec![format!(
                r#"{{"id":"exact","name":"Exact","action":"allow","ja4":"{CHROME}"}}"#
            )],
        };
        policy::import_rules(&mut tx, &credential, &base(), &import, NOW).await.expect("import");
        assert_eq!(stored_pattern(&mut tx, "exact").await.as_deref(), Some(CHROME));
        tx.commit().await.expect("commit");
    });
}

#[test]
fn ja4_patterns_no_fingerprint_could_match_are_refused() {
    for_each_backend("ja4_refused", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        let start = revision(&mut tx).await;
        for pattern in ["t13d", "x13*", "T13D*", "**", ""] {
            let document =
                format!(r#"{{"id":"bad","name":"Bad","action":"deny","ja4":"{pattern}"}}"#);
            let outcome =
                policy::edit_rule(&mut tx, &credential, &base(), &edit(&document, start), NOW)
                    .await;
            assert!(
                matches!(outcome, Err(ConsoleStorageError::InvalidInput("InvalidJa4"))),
                "{pattern}: {outcome:?}"
            );
        }
        assert_eq!(revision(&mut tx).await, start, "nothing was written");
    });
}

/// Runs the private test of a request to `/` that carries the fingerprint `ja4`.
async fn evaluate(
    tx: &mut Transaction,
    credential: &Credential,
    ja4: &str,
) -> Result<policy::TestResult, ConsoleStorageError> {
    let input = policies::Test {
        path: Text::new("/").expect("path"),
        ip: Text::new("192.0.2.7").expect("ip"),
        ja4: Text::new(ja4).expect("ja4"),
        ..policies::Test::default()
    };
    policy::test_request(tx, credential, &base(), &input, NOW).await
}

#[test]
fn private_tests_and_replays_match_the_fingerprint() {
    for_each_backend("ja4_tests", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        save(&mut tx, TLS13_RULE).await;
        let matched = evaluate(&mut tx, &credential, CHROME).await.expect("chrome");
        assert_eq!((matched.action, matched.rule.as_str()), (Action::Deny, "TLS 1.3"));
        let old = evaluate(&mut tx, &credential, OLD_TLS).await.expect("old");
        assert_ne!(old.rule.as_str(), "TLS 1.3");
        let none = evaluate(&mut tx, &credential, "").await.expect("none");
        assert_ne!(none.rule.as_str(), "TLS 1.3", "no fingerprint matches no criterion");
        let prefix = evaluate(&mut tx, &credential, "t13d*").await;
        assert!(
            matches!(prefix, Err(ConsoleStorageError::InvalidInput("ja4 fingerprint"))),
            "{prefix:?}"
        );
        let carried = Stored { ja4: Some(CHROME), ..Stored::new(1, NOW - 60) };
        store(&mut tx, &carried).await;
        store(&mut tx, &Stored::new(2, NOW - 120)).await;
        let replay = workflows::Replay {
            rule: Text::new("TLS 1.3").expect("rule"),
            hours: 1,
            ..workflows::Replay::default()
        };
        let summary =
            policy::replay(&mut tx, &credential, &base(), &replay, WorkBound::default(), NOW)
                .await
                .expect("replay");
        assert_eq!((summary.total, summary.matched), (2, 1));
        assert!(summary.rows[0].matched && !summary.rows[1].matched);
    });
}

/// Stores three incidents: one with a TLS 1.3 fingerprint, one with a TLS 1.2 fingerprint
/// and one without, newest first in that order.
async fn three_incidents(tx: &mut Transaction) {
    store(tx, &Stored { ja4: Some(CHROME), ..Stored::new(3, 300) }).await;
    store(tx, &Stored { ja4: Some(OLD_TLS), ip: "203.0.113.2", ..Stored::new(2, 200) }).await;
    store(tx, &Stored { ip: "203.0.113.3", ..Stored::new(1, 100) }).await;
}

/// Returns the fingerprints of the rows the filter `ja4` selects, newest first.
async fn filtered(
    tx: &mut Transaction,
    credential: &Credential,
    ja4: &str,
    grouped: bool,
) -> Result<Vec<Option<String>>, ConsoleStorageError> {
    let input = Query { ja4: Text::new(ja4).expect("ja4"), grouped, ..Query::default() };
    let page = events::query_events(tx, credential, &input, WorkBound::default(), NOW).await?;
    Ok(page.rows.iter().map(|row| row.ja4.as_ref().map(|ja4| ja4.as_str().to_owned())).collect())
}

#[test]
fn events_carry_and_filter_ja4_fingerprints_on_both_backends() {
    for_each_backend("ja4_events", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let credential = crate::events::admin(&mut tx).await;
        three_incidents(&mut tx).await;
        let chrome = Some(CHROME.to_owned());
        let old = Some(OLD_TLS.to_owned());
        let all = filtered(&mut tx, &credential, "", false).await.expect("all");
        assert_eq!(all, [chrome.clone(), old.clone(), None]);
        for (filter, expected) in [
            (CHROME, vec![chrome.clone()]),
            ("t13d*", vec![chrome.clone()]),
            ("t1*", vec![chrome.clone(), old.clone()]),
            ("*", vec![chrome.clone(), old.clone()]),
            (&format!("{OLD_TLS}*"), vec![old.clone()]),
            ("q*", vec![]),
        ] {
            let rows = filtered(&mut tx, &credential, filter, false).await.expect(filter);
            assert_eq!(rows, expected, "{filter}");
        }
        // A grouped read keeps the sources with a matching incident.
        let groups = filtered(&mut tx, &credential, "t1*", true).await.expect("groups");
        assert_eq!(groups.len(), 2);
        for refused in ["t13d", "x*", "t13d_*", "%", "t13d%*"] {
            let outcome = filtered(&mut tx, &credential, refused, false).await;
            assert!(
                matches!(outcome, Err(ConsoleStorageError::InvalidInput("ja4 filter"))),
                "{refused}: {outcome:?}"
            );
        }
        let id = (1u64 << 40) | 3;
        let detail = events::read_event(&mut tx, &credential, id, NOW).await.expect("detail");
        assert_eq!(detail.and_then(|row| row.ja4).as_ref().map(Text::as_str), Some(CHROME));
    });
}

#[test]
fn the_live_feed_carries_the_fingerprint() {
    for_each_backend("ja4_feed", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        three_incidents(&mut tx).await;
        let input = Request { kind: Kind::Events, node: 1, after: Some(1 << 40), through: None };
        let page = feed::read_page(&mut tx, &input, NOW).await.expect("feed");
        let fingerprints: Vec<Option<&str>> = page
            .rows
            .iter()
            .map(|row| match row {
                FeedRow::Events(event) => event.ja4.as_ref().map(Text::as_str),
                FeedRow::Audit(_) => panic!("an audit row in the events feed"),
            })
            .collect();
        assert_eq!(fingerprints, [None, Some(OLD_TLS), Some(CHROME)]);
    });
}
