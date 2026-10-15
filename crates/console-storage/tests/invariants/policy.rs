//! S13 to S16: rule edits, inspection edits, ordering and imports, with the policy reads,
//! the private test and the replay; and two nodes racing a policy workflow.

use sibuna_console_protocol::policies::{self, Selection};
use sibuna_console_protocol::tokens::{self, Scope};
use sibuna_console_protocol::workflows::{self, Direction};
use sibuna_console_protocol::{CredentialKind, Role, Text, users};
use sibuna_console_storage::bound::WorkBound;
use sibuna_console_storage::policy::{self, HistoryKind, Import, PolicyRead};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_policy::Action;
use sibuna_policy::candidate::Options;
use sibuna_storage::{Database, Dialect, Param, Sql, Transaction};

use crate::common::{
    NOW, audit_rows, bootstrap_admin, cookie, create_account, digest, for_each_backend, join,
    scalar, sign_in, summaries,
};

/// The composition options of the tests: no policy file, the WAF on.
pub(crate) fn base() -> Options<'static> {
    Options { default_difficulty: 16, waf: true, file: None }
}

/// Creates the bootstrap administrator and returns its id and cookie (byte 10).
pub(crate) async fn admin(tx: &mut Transaction) -> (u64, Credential) {
    let id = bootstrap_admin(tx).await;
    (id, sign_in(tx, id, 1, 10).await)
}

/// Returns the policy revision.
pub(crate) async fn revision(tx: &mut Transaction) -> u64 {
    let value = scalar(tx, "SELECT revision FROM policy_revision WHERE id = 1").await;
    u64::try_from(value).expect("revision")
}

/// Returns an edit of `document` at `expected`.
pub(crate) fn edit(document: &str, expected: u64) -> policies::Edit {
    policies::Edit {
        expected_revision: expected,
        document: Text::new(document).expect("document"),
        ..policies::Edit::default()
    }
}

/// Edits `document` as the administrator's cookie at the current revision.
pub(crate) async fn save(tx: &mut Transaction, document: &str) -> u64 {
    let expected = revision(tx).await;
    policy::edit_rule(tx, &cookie(10), &base(), &edit(document, expected), NOW)
        .await
        .expect("edit rule")
}

/// Inserts a rule directly, as an operator writing SQL would.
async fn insert_rule(tx: &mut Transaction, id: &str, priority: i64, enabled: bool) {
    let sql = Sql::both(
        "INSERT INTO policies (id, name, priority, action, enabled, created_at, updated_at) \
         VALUES ($1, $1, $2, 'deny', ($3 <> 0), 0, 0)",
    );
    let params: [Param<'_>; 3] = [id.into(), priority.into(), i64::from(enabled).into()];
    tx.execute(sql, &params).await.expect("insert rule");
}

/// Returns the history rows of rule `id` as (revision, kind, actor), oldest first.
async fn history(tx: &mut Transaction, id: &str) -> Vec<(i64, String, Option<i64>)> {
    let sql = Sql::both(
        "SELECT revision, kind, actor FROM console_policy_history WHERE policy_id = $1 \
         ORDER BY revision",
    );
    let rows = tx.fetch_all(sql, &[id.into()]).await.expect("history");
    rows.iter()
        .map(|row| {
            (row[0].as_i64().expect("revision"), row[1].as_str().expect("kind").to_owned(), {
                row[2].as_i64()
            })
        })
        .collect()
}

fn invalid(outcome: Result<u64, ConsoleStorageError>) -> &'static str {
    match outcome {
        Err(ConsoleStorageError::InvalidInput(rule)) => rule,
        other => panic!("expected invalid input, got {other:?}"),
    }
}

#[test]
fn rule_edit_writes_history_audit_and_one_revision() {
    for_each_backend("policy_edit", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (admin, credential) = admin(&mut tx).await;
        let start = revision(&mut tx).await;
        let first = r#"{"id":"a","name":"private-name","action":"deny","path":"/private-path",
            "headers":{"X-Api-Key":"private-key"}}"#;
        let committed =
            policy::edit_rule(&mut tx, &credential, &base(), &edit(first, start), NOW).await;
        assert_eq!(committed.expect("edit"), start + 1);
        assert_eq!(revision(&mut tx).await, start + 1);
        let admin_id = i64::try_from(admin).expect("id");
        let edit_row = |revision: u64| (revision as i64, "edit".to_owned(), Some(admin_id));
        assert_eq!(history(&mut tx, "a").await, [edit_row(start + 1)]);
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "policy.edit");
        assert_eq!(row.subject, Some(start as i64 + 1));
        assert_eq!(row.target.as_deref(), Some("a"));
        assert_eq!(row.actor_role.as_deref(), Some("admin"));
        assert_eq!(row.client_ip.as_deref(), Some("192.0.2.1"));
        let (before, after) = summaries(&mut tx, row.id).await;
        let after = after.expect("after");
        assert!(before.is_none());
        assert!(
            after.contains("\"action\":\"deny\"") && after.contains("\"selectors_redacted\":1")
        );
        assert!(!after.contains("private"));

        let second = r#"{"id":"a","name":"private-other","action":"challenge","enabled":false,
            "priority":7,"algorithm":"posw","difficulty":16,
            "limits":{"rate":2,"window_seconds":60,"ban_seconds":5}}"#;
        let committed =
            policy::edit_rule(&mut tx, &credential, &base(), &edit(second, start + 1), NOW).await;
        assert_eq!(committed.expect("second edit"), start + 2);
        assert_eq!(history(&mut tx, "a").await, [edit_row(start + 1), edit_row(start + 2)]);
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        let (before, after) = summaries(&mut tx, row.id).await;
        let (before, after) = (before.expect("before"), after.expect("after"));
        assert!(before.contains("\"enabled\":1") && after.contains("\"enabled\":0"));
        assert!(after.contains("\"rate\":2") && after.contains("\"algorithm\":\"posw\""));
        assert!(!before.contains("private") && !after.contains("private"));

        // A stale revision changes nothing.
        let stale =
            policy::edit_rule(&mut tx, &credential, &base(), &edit(first, start + 1), NOW).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)), "{stale:?}");
        assert_eq!(revision(&mut tx).await, start + 2);
        let enabled = "SELECT CAST(COUNT(*) AS BIGINT) FROM policies WHERE id = 'a' AND enabled";
        assert_eq!(scalar(&mut tx, enabled).await, 0);
        tx.commit().await.expect("commit");
    });
}

#[test]
fn first_console_edit_records_a_baseline() {
    for_each_backend("policy_baseline", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (admin, _) = admin(&mut tx).await;
        insert_rule(&mut tx, "b", 50, true).await;
        let current = revision(&mut tx).await;
        let document = r#"{"id":"b","name":"B","action":"allow","priority":5}"#;
        assert_eq!(save(&mut tx, document).await, current + 1);
        let admin_id = i64::try_from(admin).expect("id");
        assert_eq!(
            history(&mut tx, "b").await,
            [
                (current as i64, "baseline".to_owned(), None),
                (current as i64 + 1, "edit".to_owned(), Some(admin_id))
            ]
        );
        let read = policies::Read {
            session_digest: [0; 32],
            require_totp: false,
            committed: None,
            selection: Selection::Document {
                id: Text::new("b").expect("id"),
                revision: Some(current),
                previous: false,
            },
        };
        let PolicyRead::Document(baseline) =
            policy::read_policy(&mut tx, &cookie(10), &read, NOW).await.expect("read")
        else {
            panic!("a document")
        };
        let parsed = sibuna_policy::management::parse(baseline.document.as_bytes()).expect("doc");
        assert_eq!((parsed.priority, parsed.rule.action), (50, Action::Deny));
        // A later edit adds no second baseline.
        save(&mut tx, r#"{"id":"b","name":"B","action":"deny"}"#).await;
        assert_eq!(history(&mut tx, "b").await.len(), 3);
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        let (before, _) = summaries(&mut tx, row.id).await;
        assert!(before.expect("before").contains("\"action\":\"allow\""));
    });
}

async fn try_edit(
    tx: &mut Transaction,
    credential: &Credential,
    document: &str,
    expected: u64,
) -> Result<u64, ConsoleStorageError> {
    policy::edit_rule(tx, credential, &base(), &edit(document, expected), NOW).await
}

#[test]
fn edits_are_validated_as_a_whole_candidate() {
    for_each_backend("policy_candidate", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        let start = revision(&mut tx).await;
        let bad_cidr = r#"{"id":"c","name":"C","action":"deny","cidrs":["999.0.0.0/8"]}"#;
        assert_eq!(invalid(try_edit(&mut tx, &credential, bad_cidr, start).await), "InvalidCidr");
        let bad_id = r#"{"id":"c d","name":"C","action":"deny"}"#;
        assert_eq!(invalid(try_edit(&mut tx, &credential, bad_id, start).await), "InvalidId");
        assert!(!invalid(try_edit(&mut tx, &credential, "{", start).await).is_empty());
        for index in 0..121 {
            insert_rule(&mut tx, &format!("r{index:03}"), 100, true).await;
        }
        let current = revision(&mut tx).await;
        let enabled = r#"{"id":"z","name":"Z","action":"deny"}"#;
        assert_eq!(
            invalid(try_edit(&mut tx, &credential, enabled, current).await),
            "TooManyRules"
        );
        let disabled = r#"{"id":"z","name":"Z","action":"deny","enabled":false}"#;
        let saved = try_edit(&mut tx, &credential, disabled, current).await.expect("disabled");
        assert_eq!(saved, current + 1);
        let actions = crate::common::audit_actions(&mut tx).await;
        assert_eq!(actions.iter().filter(|action| *action == "policy.edit").count(), 1);
    });
}

#[test]
fn policy_writes_follow_the_credential() {
    for_each_backend("policy_credential", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (admin, credential) = admin(&mut tx).await;
        let viewer = create_account(&mut tx, &credential, "viewer", Role::Viewer).await;
        let viewer = sign_in(&mut tx, viewer, 1, 20).await;
        let operator = create_account(&mut tx, &credential, "ops", Role::Operator).await;
        let operator = sign_in(&mut tx, operator, 1, 30).await;
        let document = r#"{"id":"a","name":"A","action":"deny"}"#;
        let start = revision(&mut tx).await;
        let forbidden = |outcome: Result<u64, ConsoleStorageError>| {
            assert!(matches!(outcome, Err(ConsoleStorageError::Forbidden)), "{outcome:?}");
        };
        let input = edit(document, start);
        forbidden(policy::edit_rule(&mut tx, &viewer, &base(), &input, NOW).await);
        let wrong_csrf = Credential { csrf_digest: digest(99), ..operator.clone() };
        forbidden(policy::edit_rule(&mut tx, &wrong_csrf, &base(), &input, NOW).await);
        // Required second factors apply to administrators; operators may still edit.
        let required = Credential { require_totp: true, ..credential.clone() };
        forbidden(policy::edit_rule(&mut tx, &required, &base(), &input, NOW).await);
        let required = Credential { require_totp: true, ..operator.clone() };
        assert_eq!(
            policy::edit_rule(&mut tx, &required, &base(), &input, NOW).await.expect("operator"),
            start + 1
        );
        assert_eq!(
            audit_rows(&mut tx).await.pop().expect("audit").actor_role.as_deref(),
            Some("operator")
        );
        // Tokens need `policy_write`; the audit names the token's attenuated role.
        for (byte, scopes) in [(40, Scope::StatsRead.bit()), (41, Scope::PolicyWrite.bit())] {
            let create = tokens::Create {
                auth: users::Auth::default(),
                label: Text::new("automation").expect("label"),
                role: Role::Operator,
                scopes,
                expires: None,
                digest: digest(byte),
            };
            sibuna_console_storage::tokens::create_token(&mut tx, &credential, &create, NOW)
                .await
                .expect("token");
        }
        let bearer = |byte| Credential {
            kind: CredentialKind::Bearer,
            digest: digest(byte),
            ..Credential::default()
        };
        let input = edit(document, start + 1);
        forbidden(policy::edit_rule(&mut tx, &bearer(40), &base(), &input, NOW).await);
        assert_eq!(
            policy::edit_rule(&mut tx, &bearer(41), &base(), &input, NOW).await.expect("token"),
            start + 2
        );
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!((row.actor, row.actor_role.as_deref()), (Some(admin as i64), Some("operator")));
    });
}

#[test]
fn inspection_edit_writes_history_and_audit() {
    for_each_backend("policy_inspection", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (admin, credential) = admin(&mut tx).await;
        let start = revision(&mut tx).await;
        let modes =
            r#"{"path_traversal":"enforce","sqli":"audit","xss":"disabled","rce":"enforce"}"#;
        let input = edit(modes, start);
        let committed = policy::edit_inspection(&mut tx, &credential, &base(), &input, NOW).await;
        assert_eq!(committed.expect("inspection"), start + 1);
        assert_eq!(revision(&mut tx).await, start + 1);
        let stored = Sql::both("SELECT path_traversal, sqli, xss, rce FROM policy_inspection");
        let rows = tx.fetch_all(stored, &[]).await.expect("modes");
        let names: Vec<&str> = rows[0].iter().map(|cell| cell.as_str().expect("mode")).collect();
        assert_eq!(names, ["enforce", "audit", "disabled", "enforce"]);
        let history = Sql::both(
            "SELECT revision, actor, sqli, xss, previous_sqli, previous_xss \
             FROM console_inspection_history",
        );
        let rows = tx.fetch_all(history, &[]).await.expect("history");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0].as_i64(), Some(start as i64 + 1));
        assert_eq!(rows[0][1].as_i64(), Some(admin as i64));
        let modes_of = |index: usize| rows[0][index].as_str().expect("mode").to_owned();
        assert_eq!(
            [modes_of(2), modes_of(3), modes_of(4), modes_of(5)],
            ["audit", "disabled", "enforce", "enforce"]
        );
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(
            (row.action.as_str(), row.target.as_deref()),
            ("inspection.edit", Some("inspection"))
        );
        assert_eq!(row.subject, Some(start as i64 + 1));
        let (before, after) = summaries(&mut tx, row.id).await;
        assert!(before.expect("before").contains("\"sqli\":\"enforce\""));
        let after = after.expect("after");
        assert!(after.contains("\"sqli\":\"audit\"") && after.contains("\"xss\":\"disabled\""));
        // A stale revision, a partial document and a wrong CSRF digest change nothing.
        let stale = policy::edit_inspection(&mut tx, &credential, &base(), &input, NOW).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
        for document in [r#"{"sqli":"ignore"}"#, "{}"] {
            let outcome = policy::edit_inspection(
                &mut tx,
                &credential,
                &base(),
                &edit(document, start + 1),
                NOW,
            )
            .await;
            assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
        }
        let wrong = Credential { csrf_digest: digest(3), ..credential.clone() };
        let outcome =
            policy::edit_inspection(&mut tx, &wrong, &base(), &edit(modes, start + 1), NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Forbidden)));
        // The next edit records the stored modes as the previous ones.
        let all =
            r#"{"path_traversal":"disabled","sqli":"disabled","xss":"disabled","rce":"disabled"}"#;
        policy::edit_inspection(&mut tx, &credential, &base(), &edit(all, start + 1), NOW)
            .await
            .expect("second");
        let previous = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_inspection_history \
                        WHERE previous_sqli = 'audit' AND sqli = 'disabled'";
        assert_eq!(scalar(&mut tx, previous).await, 1);
        assert_eq!(revision(&mut tx).await, start + 2);
    });
}

/// Returns the priorities of the stored rules by id.
async fn priorities(tx: &mut Transaction) -> Vec<(String, i64)> {
    let sql = Sql::both("SELECT id, priority FROM policies ORDER BY id");
    let rows = tx.fetch_all(sql, &[]).await.expect("priorities");
    rows.iter()
        .map(|row| (row[0].as_str().expect("id").to_owned(), row[1].as_i64().expect("priority")))
        .collect()
}

fn order(id: &str, direction: Direction, expected: u64) -> workflows::Order {
    workflows::Order {
        auth: users::Auth::default(),
        expected_revision: expected,
        id: Text::new(id).expect("id"),
        direction,
    }
}

#[test]
fn ordering_swaps_two_rules_in_one_revision() {
    for_each_backend("policy_order", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        save(&mut tx, r#"{"id":"a","name":"A","action":"deny","priority":10}"#).await;
        save(&mut tx, r#"{"id":"b","name":"B","action":"deny","priority":20}"#).await;
        save(&mut tx, r#"{"id":"c","name":"C","action":"deny","priority":30,"enabled":false}"#)
            .await;
        let start = revision(&mut tx).await;
        let committed =
            policy::order_rules(&mut tx, &credential, &order("c", Direction::Up, start), NOW)
                .await;
        assert_eq!(committed.expect("order"), start + 1);
        assert_eq!(revision(&mut tx).await, start + 1);
        let expected = [("a".to_owned(), 10), ("b".to_owned(), 30), ("c".to_owned(), 20)];
        assert_eq!(priorities(&mut tx).await, expected);
        for id in ["b", "c"] {
            let last = history(&mut tx, id).await.pop().expect("history");
            assert_eq!(last.0, start as i64 + 1);
        }
        let at = Selection::Document {
            id: Text::new("c").expect("id"),
            revision: Some(start + 1),
            previous: false,
        };
        let document = read(&mut tx, &credential, at, None).await;
        let Ok(PolicyRead::Document(document)) = document else { panic!("{document:?}") };
        let parsed = sibuna_policy::management::parse(document.document.as_bytes()).expect("doc");
        assert_eq!((parsed.priority, parsed.enabled), (20, false));
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!((row.action.as_str(), row.target.as_deref()), ("policy.order", Some("c")));
        let (_, after) = summaries(&mut tx, row.id).await;
        assert_eq!(after.as_deref(), Some("{\"priority\":20}"));
    });
}

#[test]
fn history_documents_are_bounded_before_the_insert() {
    for_each_backend("policy_history_bound", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        // A rule written directly with SQL renders to more than 4,096 bytes; moving it
        // would record that rendering, which storage refuses before the insert on both
        // backends rather than leaving it to a CHECK that measures differently.
        let sql = Sql::both(
            "INSERT INTO policies (id, name, priority, action, enabled, created_at, updated_at) \
             VALUES ($1, $2, $3, 'deny', TRUE, 0, 0)",
        );
        let long = "n".repeat(4100);
        for (id, name, priority) in [("long", long.as_str(), 1_i64), ("short", "S", 2)] {
            let params: [Param<'_>; 3] = [id.into(), name.into(), priority.into()];
            tx.execute(sql, &params).await.expect("insert rule");
        }
        let start = revision(&mut tx).await;
        let moved =
            policy::order_rules(&mut tx, &credential, &order("long", Direction::Down, start), NOW)
                .await;
        assert_eq!(invalid(moved), "history document size");
        assert!(history(&mut tx, "long").await.is_empty());
    });
}

#[test]
fn ordering_nudges_equal_priorities_and_refuses_edges() {
    for_each_backend("policy_order_edges", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        save(&mut tx, r#"{"id":"a","name":"A","action":"deny","priority":10}"#).await;
        save(&mut tx, r#"{"id":"b","name":"B","action":"deny","priority":30}"#).await;
        save(&mut tx, r#"{"id":"d","name":"D","action":"deny","priority":30}"#).await;
        // Equal priorities: the moved rule passes its neighbour by one.
        let current = revision(&mut tx).await;
        policy::order_rules(&mut tx, &credential, &order("d", Direction::Up, current), NOW)
            .await
            .expect("nudge");
        let expected = [("a".to_owned(), 10), ("b".to_owned(), 30), ("d".to_owned(), 29)];
        assert_eq!(priorities(&mut tx).await, expected);
        // No neighbour, an unknown rule and a stale revision change nothing.
        let current = revision(&mut tx).await;
        for (id, direction) in [("a", Direction::Up), ("b", Direction::Down), ("x", Direction::Up)]
        {
            let input = order(id, direction, current);
            let outcome = policy::order_rules(&mut tx, &credential, &input, NOW).await;
            assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{id}");
        }
        let input = order("b", Direction::Up, current - 1);
        let stale = policy::order_rules(&mut tx, &credential, &input, NOW).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
        assert_eq!(revision(&mut tx).await, current);
    });
}

#[test]
fn import_replaces_all_rules_in_one_revision() {
    for_each_backend("policy_import", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        save(&mut tx, r#"{"id":"old","name":"Old","action":"deny"}"#).await;
        let documents: Vec<String> = ["x", "y", "z"]
            .iter()
            .map(|id| format!(r#"{{"id":"{id}","name":"{id}","action":"allow"}}"#))
            .collect();
        let start = revision(&mut tx).await;
        let duplicate =
            Import { expected_revision: start, documents: vec![documents[0].clone(); 2] };
        assert_eq!(
            invalid(policy::import_rules(&mut tx, &credential, &base(), &duplicate, NOW).await),
            "DuplicateId"
        );
        let broken = Import { expected_revision: start, documents: vec!["{".to_owned()] };
        assert!(matches!(
            policy::import_rules(&mut tx, &credential, &base(), &broken, NOW).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        let import = Import { expected_revision: start, documents: documents.clone() };
        let committed = policy::import_rules(&mut tx, &credential, &base(), &import, NOW).await;
        assert_eq!(committed.expect("import"), start + 1);
        assert_eq!(revision(&mut tx).await, start + 1);
        let ids: Vec<String> = priorities(&mut tx).await.into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, ["x", "y", "z"]);
        for id in ["x", "y", "z"] {
            assert_eq!(history(&mut tx, id).await.len(), 1);
        }
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        let digest = policy::import_digest(&documents);
        assert_eq!(
            (row.action.as_str(), row.target.as_deref()),
            ("policy.import", Some(digest.as_str()))
        );
        let (_, after) = summaries(&mut tx, row.id).await;
        let after = after.expect("after");
        assert!(after.contains("\"count\":3") && after.contains(&digest));
        let stale = policy::import_rules(&mut tx, &credential, &base(), &import, NOW).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
    });
}

/// Reads `selection` as `credential`, expecting `committed` when given.
async fn read(
    tx: &mut Transaction,
    credential: &Credential,
    selection: Selection,
    committed: Option<u64>,
) -> Result<PolicyRead, ConsoleStorageError> {
    let input =
        policies::Read { session_digest: [0; 32], require_totp: false, committed, selection };
    policy::read_policy(tx, credential, &input, NOW).await
}

/// Saves rules r0 to r9 with descending priorities (every third disabled) and returns a
/// viewer's cookie.
async fn ten_rules(tx: &mut Transaction, admin: &Credential) -> Credential {
    for index in 0..10 {
        let document = format!(
            r#"{{"id":"r{index}","name":"R","action":"deny","priority":{},"enabled":{}}}"#,
            100 - index,
            index % 3 != 0
        );
        save(tx, &document).await;
    }
    let viewer = create_account(tx, admin, "viewer", Role::Viewer).await;
    sign_in(tx, viewer, 1, 20).await
}

#[test]
fn rules_and_the_catalogue_page_in_their_orders() {
    for_each_backend("policy_rule_pages", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        let viewer = ten_rules(&mut tx, &credential).await;
        let committed = revision(&mut tx).await;
        let query = policies::Query::default();
        let page = policy::rule_page(&mut tx, &viewer, &query, NOW).await.expect("rules");
        let ids: Vec<&str> = page.rows.iter().map(|rule| rule.id.as_str()).collect();
        assert_eq!(ids, ["r9", "r8", "r7", "r6", "r5", "r4", "r3", "r2"]);
        assert_eq!((page.committed, page.next), (committed, Some(8)));
        assert!(!page.rows[0].enabled && page.rows[1].enabled);
        let rest = policies::Query { offset: 8, ..query.clone() };
        let page = policy::rule_page(&mut tx, &viewer, &rest, NOW).await.expect("rules");
        assert_eq!((page.rows.len(), page.next), (2, None));
        let catalog = |after: &str| Selection::Catalog(Text::new(after).expect("after"));
        let first = read(&mut tx, &viewer, catalog(""), Some(committed)).await;
        let Ok(PolicyRead::Catalog(first)) = first else { panic!("catalog: {first:?}") };
        assert_eq!((first.rows.len(), first.next.as_deref()), (8, Some("r7")));
        let second = read(&mut tx, &viewer, catalog("r7"), Some(committed)).await;
        let Ok(PolicyRead::Catalog(second)) = second else { panic!("catalog: {second:?}") };
        assert_eq!((second.rows.len(), second.next), (2, None));
        let stale = read(&mut tx, &viewer, catalog(""), Some(committed - 1)).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
        // A token needs `policy_read`.
        let create = tokens::Create {
            auth: users::Auth::default(),
            label: Text::new("stats").expect("label"),
            role: Role::Viewer,
            scopes: Scope::StatsRead.bit(),
            expires: None,
            digest: digest(50),
        };
        sibuna_console_storage::tokens::create_token(&mut tx, &credential, &create, NOW)
            .await
            .expect("token");
        let bearer = Credential {
            kind: CredentialKind::Bearer,
            digest: digest(50),
            ..Credential::default()
        };
        let outcome = policy::rule_page(&mut tx, &bearer, &query, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Forbidden)));
    });
}

#[test]
fn history_and_documents_page_newest_first() {
    for_each_backend("policy_history_pages", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        let viewer = ten_rules(&mut tx, &credential).await;
        // Ten edits of one rule page their history eight at a time, newest first.
        for _ in 0..9 {
            save(&mut tx, r#"{"id":"r1","name":"R","action":"allow"}"#).await;
        }
        let committed = revision(&mut tx).await;
        let history = |before| Selection::History { id: Text::new("r1").expect("id"), before };
        let page = read(&mut tx, &viewer, history(None), None).await;
        let Ok(PolicyRead::History(page)) = page else { panic!("history: {page:?}") };
        assert_eq!((page.rows.len(), page.rows[0].revision), (8, committed));
        assert!(page.rows.iter().all(|row| row.kind == HistoryKind::Edit && row.actor.is_some()));
        let rest = read(&mut tx, &viewer, history(page.next), None).await;
        let Ok(PolicyRead::History(rest)) = rest else { panic!("history: {rest:?}") };
        assert_eq!((rest.rows.len(), rest.next), (2, None));
        // The document before the second revision is the first one.
        let document = |revision, previous| Selection::Document {
            id: Text::new("r1").expect("id"),
            revision,
            previous,
        };
        let first = Some(rest.rows[1].revision + 1);
        let previous = read(&mut tx, &viewer, document(first, true), None).await;
        let Ok(PolicyRead::Document(previous)) = previous else { panic!("{previous:?}") };
        assert!(previous.document.as_str().contains("\"deny\""));
        let current = read(&mut tx, &viewer, document(None, false), None).await;
        let Ok(PolicyRead::Document(current)) = current else { panic!("{current:?}") };
        assert_eq!(current.revision, committed);
        assert!(current.document.as_str().contains("\"allow\""));
        let missing = read(&mut tx, &viewer, document(Some(1), false), None).await;
        assert!(matches!(missing, Err(ConsoleStorageError::InvalidInput(_))));
        let stale = read(&mut tx, &viewer, history(None), Some(committed - 1)).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
    });
}

fn test_input(path: &str, draft: Option<&str>, committed: Option<u64>) -> policies::Test {
    policies::Test {
        path: Text::new(path).expect("path"),
        ip: Text::new("192.0.2.7").expect("ip"),
        user_agent: Text::new("curl/8").expect("agent"),
        draft: draft.map(|draft| Text::new(draft).expect("draft")),
        committed,
        ..policies::Test::default()
    }
}

#[test]
fn private_tests_evaluate_the_committed_policy_or_a_draft() {
    for_each_backend("policy_test", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        save(&mut tx, r#"{"id":"p","name":"Private","action":"deny","path":"/private"}"#).await;
        let committed = revision(&mut tx).await;
        let result = policy::test_request(
            &mut tx,
            &credential,
            &base(),
            &test_input("/private", None, None),
            NOW,
        )
        .await
        .expect("test");
        assert_eq!(
            (result.action, result.rule.as_str(), result.preview),
            (Action::Deny, "Private", false)
        );
        assert_eq!(result.committed, committed);
        let draft = r#"{"id":"p","name":"Open","action":"allow","path":"/private"}"#;
        let result = policy::test_request(
            &mut tx,
            &credential,
            &base(),
            &test_input("/private", Some(draft), Some(committed)),
            NOW,
        )
        .await
        .expect("draft");
        assert_eq!(
            (result.action, result.rule.as_str(), result.preview),
            (Action::Allow, "Open", true)
        );
        // Nothing was written.
        assert_eq!(revision(&mut tx).await, committed);
        let stale = policy::test_request(
            &mut tx,
            &credential,
            &base(),
            &test_input("/private", Some(draft), Some(committed - 1)),
            NOW,
        )
        .await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
        let bad = policies::Test {
            ip: Text::new("not-an-address").expect("ip"),
            ..test_input("/", None, None)
        };
        assert!(matches!(
            policy::test_request(&mut tx, &credential, &base(), &bad, NOW).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
    });
}

/// Inserts incident `sequence` of node 1, with evidence when `evidence` names its query
/// bytes, body bytes and truncation bits.
async fn incident(
    tx: &mut Transaction,
    sequence: i64,
    path: &[u8],
    recorded_at: u64,
    evidence: Option<(i64, i64, i64)>,
) {
    let receipt = Sql::both(
        "INSERT INTO incident_receipts (node_id, next_sequence) VALUES (1, $1) \
         ON CONFLICT (node_id) DO UPDATE SET next_sequence = excluded.next_sequence",
    );
    tx.execute(receipt, &[(sequence + 1).into()]).await.expect("receipt");
    // The search column of PostgreSQL is a `tsvector` that Rust writes (SID 0013); while
    // the core schema still derives it from `search_text`, that column is set instead.
    let search_text = tx.dialect() == Dialect::Postgres
        && !tx
            .fetch_all(
                Sql::both(
                    "SELECT 1 FROM information_schema.columns WHERE table_schema = \
                     current_schema() AND table_name = 'security_incidents' \
                     AND column_name = 'search_text'",
                ),
                &[],
            )
            .await
            .expect("columns")
            .is_empty();
    let sql = match (tx.dialect(), search_text) {
        (Dialect::Sqlite, _) => Sql::both(
            "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding) \
             VALUES ($1, 1, '192.0.2.9', $2, 'GET', $3, 'sqli', $2, 0, $4, $5)",
        ),
        (Dialect::Postgres, true) => Sql::both(
            "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding, \
             search_text) VALUES ($1, 1, '192.0.2.9', $2, 'GET', $3, 'sqli', $2, 0, $4, $5, '')",
        ),
        (Dialect::Postgres, false) => Sql::both(
            "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding, \
             search) VALUES ($1, 1, '192.0.2.9', $2, 'GET', $3, 'sqli', $2, 0, $4, $5, \
             CAST('' AS tsvector))",
        ),
    };
    let id = (1i64 << 40) | sequence;
    let embedding = [0u8; 256];
    let params: [Param<'_>; 5] = [
        id.into(),
        b"curl/8".as_slice().into(),
        path.into(),
        i64::try_from(recorded_at).expect("time").into(),
        embedding.as_slice().into(),
    ];
    tx.execute(sql, &params).await.expect("incident");
    if let Some((query, body, truncated)) = evidence {
        let sql = Sql::both(
            "INSERT INTO console_incident_evidence (incident_id, selected_status, query_bytes, \
             body_bytes, declared_body_bytes, truncated) VALUES ($1, 403, $2, $3, 0, $4)",
        );
        let params: [Param<'_>; 4] = [id.into(), query.into(), body.into(), truncated.into()];
        tx.execute(sql, &params).await.expect("evidence");
    }
}

#[test]
fn replay_judges_retained_incidents_without_writing() {
    for_each_backend("policy_replay", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        save(&mut tx, r#"{"id":"p","name":"Private","action":"deny","path":"/private"}"#).await;
        incident(&mut tx, 1, b"/private", NOW - 60, Some((0, 0, 0))).await;
        incident(&mut tx, 2, b"/private", NOW - 120, Some((5, 0, 0))).await;
        incident(&mut tx, 3, b"/robots.txt", NOW - 180, None).await;
        incident(&mut tx, 4, b"/private", NOW - 30 * 3600, Some((0, 0, 0))).await;
        let committed = revision(&mut tx).await;
        let replay = workflows::Replay {
            rule: Text::new("Private").expect("rule"),
            hours: 24,
            ..workflows::Replay::default()
        };
        let summary =
            policy::replay(&mut tx, &credential, &base(), &replay, WorkBound::default(), NOW)
                .await
                .expect("replay");
        assert_eq!((summary.total, summary.matched, summary.inconclusive), (3, 2, 2));
        assert_eq!((summary.committed, summary.preview), (committed, false));
        assert_eq!(summary.rows.len(), 3);
        assert!(summary.rows[0].conclusive && summary.rows[0].matched);
        assert_eq!(summary.rows[0].action.as_str(), "deny");
        let draft = r#"{"id":"p","name":"Private","action":"allow","path":"/nothing"}"#;
        let preview = workflows::Replay {
            draft: Some(Text::new(draft).expect("draft")),
            committed: Some(committed),
            rule: Text::default(),
            ..replay
        };
        let summary =
            policy::replay(&mut tx, &credential, &base(), &preview, WorkBound::default(), NOW)
                .await
                .expect("preview");
        assert!(summary.preview);
        assert!(summary.rows.iter().all(|row| row.rule.as_str() != "Private"));
        assert_eq!(revision(&mut tx).await, committed);
    });
}

async fn edit_and_commit(
    db: &Database,
    document: &str,
    expected: u64,
) -> Result<u64, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let revision =
        policy::edit_rule(&mut tx, &cookie(10), &base(), &edit(document, expected), NOW).await?;
    tx.commit().await?;
    Ok(revision)
}

#[test]
fn two_nodes_editing_at_one_revision_one_wins() {
    for_each_backend("policy_race", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let start = revision(&mut tx).await;
        tx.commit().await.expect("commit");
        let first = r#"{"id":"a","name":"A","action":"deny"}"#;
        let second = r#"{"id":"b","name":"B","action":"deny"}"#;
        let (one, two) =
            join(edit_and_commit(&db, first, start), edit_and_commit(&db, second, start)).await;
        let conflict = |outcome: &Result<u64, ConsoleStorageError>| {
            matches!(outcome, Err(ConsoleStorageError::Conflict))
        };
        assert!(
            one.as_ref().is_ok_and(|r| *r == start + 1) && conflict(&two)
                || two.as_ref().is_ok_and(|r| *r == start + 1) && conflict(&one),
            "{one:?} {two:?}"
        );
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(revision(&mut tx).await, start + 1);
        assert_eq!(scalar(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM policies").await, 1);
        assert_eq!(
            scalar(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM console_policy_history").await,
            1
        );
    });
}

// Ported from `console_policy_auth_test.zig` "queued policy and inspection edits refuse
// expired or incomplete MFA authority".
#[test]
fn rule_and_inspection_edits_refuse_expired_sessions_and_missing_required_factors() {
    for_each_backend("policy_expired_mfa", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        let rule = r#"{"id":"edit","name":"Deny","action":"deny","path":"/edit"}"#;
        let modes =
            r#"{"path_traversal":"enforce","sqli":"audit","xss":"enforce","rce":"disabled"}"#;
        let start = revision(&mut tx).await;
        // Each edit is made at the revision current when it reaches storage.
        let both = async |tx: &mut Transaction, credential: &Credential, now: u64| {
            let expected = revision(tx).await;
            let rule =
                policy::edit_rule(tx, credential, &base(), &edit(rule, expected), now).await;
            let modes = edit(modes, revision(tx).await);
            let inspection = policy::edit_inspection(tx, credential, &base(), &modes, now).await;
            (rule, inspection)
        };
        // The cookie has been idle for 30 minutes when the edits reach storage.
        let (rule_edit, inspection_edit) = both(&mut tx, &credential, NOW + 1800).await;
        assert!(matches!(rule_edit, Err(ConsoleStorageError::Unauthorized)), "{rule_edit:?}");
        assert!(matches!(inspection_edit, Err(ConsoleStorageError::Unauthorized)));
        // An administrator without the required second factor is refused.
        let required = Credential { require_totp: true, ..credential.clone() };
        let (rule_edit, inspection_edit) = both(&mut tx, &required, NOW).await;
        assert!(matches!(rule_edit, Err(ConsoleStorageError::Forbidden)), "{rule_edit:?}");
        assert!(matches!(inspection_edit, Err(ConsoleStorageError::Forbidden)));
        assert_eq!(revision(&mut tx).await, start);
        // Required factors apply to administrators; an operator still edits policy.
        let operator = create_account(&mut tx, &credential, "ops", Role::Operator).await;
        let operator = sign_in(&mut tx, operator, 1, 30).await;
        let operator = Credential { require_totp: true, ..operator };
        let (rule_edit, inspection_edit) = both(&mut tx, &operator, NOW).await;
        assert_eq!(rule_edit.expect("operator rule edit"), start + 1);
        assert_eq!(inspection_edit.expect("operator inspection edit"), start + 2);
        let audited = crate::common::audit_actions(&mut tx).await;
        let edits = audited
            .iter()
            .filter(|action| matches!(action.as_str(), "policy.edit" | "inspection.edit"));
        assert_eq!(edits.count(), 2);
    });
}

// Ported from `console_policy_audit_test.zig` "audit records preserve the full supported
// policy identifier and bounded page encoding".
#[test]
fn audit_rows_keep_the_full_policy_identifier_and_pages_stay_bounded() {
    use sibuna_console_protocol::audit::{self, LAST_ID, PAGE_ROWS};
    for_each_backend("policy_long_identifier", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        let id = "a".repeat(128);
        let committed =
            save(&mut tx, &format!(r#"{{"id":"{id}","name":"A","action":"deny"}}"#)).await;
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.target.as_deref(), Some(id.as_str()));
        let read =
            audit::Read { id: u64::try_from(row.id).expect("id"), ..audit::Read::default() };
        let detail = sibuna_console_storage::audit::read_audit(&mut tx, &credential, &read, NOW)
            .await
            .expect("detail");
        let target = detail.row.policy_revision().expect("a navigable policy revision");
        assert_eq!((target.id.as_str(), target.revision), (id.as_str(), committed));
        // A full page of such rows, every number at its largest, keeps the Zig 4 KiB bound.
        let rows = (0..PAGE_ROWS as u64)
            .map(|index| audit::Row {
                id: LAST_ID - index,
                actor: LAST_ID,
                subject: LAST_ID,
                recorded_at: LAST_ID,
                ..detail.row.clone()
            })
            .collect();
        let page = audit::Page { rows, next: None };
        let encoded = sibuna_console_protocol::codec::to_json(&page);
        assert!(encoded.len() <= 4096, "{} bytes", encoded.len());
    });
}
