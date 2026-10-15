//! S30 and S31: node commands, and the membership rows of the nodes page.

use sibuna_console_protocol::nodes::{self, Command, Kind, State};
use sibuna_console_protocol::{CredentialKind, Role};
use sibuna_console_storage::nodes::{
    self as store, Announcement, CommandState, Completed, Completion, Requested,
};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::{Database, Sql, Transaction};

use crate::common::{
    NOW, audit_rows, bootstrap_admin, bytes, create_account, for_each_backend, join, scalar,
    sign_in, summaries,
};
use crate::notifications::same;

const BOOT: [u8; 16] = [0x11; 16];

fn announcement(node: u32, boot: [u8; 16]) -> Announcement<'static> {
    Announcement {
        node,
        address: "local",
        version: "0.1.0",
        boot,
        applied_revision: 1,
        ..Announcement::default()
    }
}

/// Creates the administrator (cookie 10) and an operator (cookie 20), announces node 1 and
/// returns the operator's credential.
async fn operator(tx: &mut Transaction) -> Credential {
    let admin = bootstrap_admin(tx).await;
    let admin = sign_in(tx, admin, 1, 10).await;
    let operator = create_account(tx, &admin, "operator", Role::Operator).await;
    store::announce(tx, &announcement(1, BOOT), NOW).await.expect("announce");
    sign_in(tx, operator, 1, 20).await
}

fn command(byte: u8, kind: Kind) -> Command {
    Command {
        id: [byte; 16],
        boot: BOOT,
        node: 1,
        expected_revision: 0,
        expires: NOW + nodes::COMMAND_SECONDS,
        kind,
        ..Command::default()
    }
}

fn completion(byte: u8, state: CommandState) -> Completion {
    Completion {
        id: [byte; 16],
        boot: BOOT,
        state,
        completed_at: NOW + 1,
        applied_revision: Some(1),
        cleared_entries: None,
    }
}

fn expect_error<T: std::fmt::Debug>(
    outcome: Result<T, ConsoleStorageError>,
    expected: fn(&ConsoleStorageError) -> bool,
) {
    assert!(outcome.as_ref().is_err_and(expected), "{outcome:?}");
}

fn is_conflict(error: &ConsoleStorageError) -> bool {
    matches!(error, ConsoleStorageError::Conflict)
}

fn is_forbidden(error: &ConsoleStorageError) -> bool {
    matches!(error, ConsoleStorageError::Forbidden)
}

fn is_invalid(error: &ConsoleStorageError) -> bool {
    matches!(error, ConsoleStorageError::InvalidInput(_))
}

#[test]
fn membership_rows_keep_first_seen_and_show_safe_links_only() {
    for_each_backend("membership", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let operator = operator(&mut tx).await;
        let restarted = Announcement {
            console_url: "https://console.example:9443",
            applied_revision: 4,
            control_revision: 2,
            draining: true,
            ..announcement(1, [0x22; 16])
        };
        store::announce(&mut tx, &restarted, NOW + 60).await.expect("heartbeat");
        store::announce(&mut tx, &announcement(2, [0x33; 16]), NOW).await.expect("second node");
        let page = store::query_members(&mut tx, &operator, NOW).await.expect("members");
        assert_eq!(page.committed, 0);
        assert_eq!(page.members.len(), 2);
        let first = &page.members[0];
        assert_eq!((first.node, first.first_seen, first.last_seen), (1, NOW, NOW + 60));
        assert_eq!(first.boot.as_str(), "22".repeat(16));
        assert_eq!(first.console_url.as_str(), "https://console.example:9443");
        assert_eq!((first.applied_revision, first.control_revision), (4, 2));
        assert!(first.draining && !page.members[1].draining);
        assert_eq!((first.applied_slot, first.decided_slot), (0, 0));
        // A clock stepped back never moves last_seen below first_seen.
        store::announce(&mut tx, &announcement(2, [0x33; 16]), NOW - 50).await.expect("back");
        let second = &store::load_members(&mut tx).await.expect("members").members[1];
        assert_eq!((second.first_seen, second.last_seen), (NOW, NOW));
        // A link written directly is shown only when it is a plain origin.
        let unsafe_link = Sql::both(
            "UPDATE console_nodes SET console_url = 'javascript:alert(1)' WHERE node = 1",
        );
        tx.execute(unsafe_link, &[]).await.expect("direct write");
        let page = store::load_members(&mut tx).await.expect("members");
        assert_eq!(page.members[0].console_url.as_str(), "");
        let invalid = Announcement { address: "", ..announcement(3, BOOT) };
        expect_error(store::announce(&mut tx, &invalid, NOW).await, is_invalid);
        let bearer = Credential { kind: CredentialKind::Bearer, ..operator };
        expect_error(store::query_members(&mut tx, &bearer, NOW).await, |error| {
            matches!(error, ConsoleStorageError::Unauthorized)
        });
    });
}

#[test]
fn command_intent_is_audited_and_bounded() {
    for_each_backend("command_intent", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let operator = operator(&mut tx).await;
        let input = command(1, Kind::Drain);
        let Requested::Recorded(receipt) =
            store::request_command(&mut tx, &operator, &input, NOW).await.expect("request")
        else {
            panic!("a new command is recorded");
        };
        assert_eq!((receipt.state, receipt.completion_persisted), (State::Intent, false));
        assert_eq!(receipt.id.as_str(), "01".repeat(16));
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "node.command.intent");
        assert_eq!((row.actor, row.actor_role.as_deref()), (Some(2), Some("operator")));
        assert_eq!(
            (row.subject, row.target.as_deref()),
            (Some(1), Some("01".repeat(16).as_str()))
        );
        assert_eq!(row.client_ip.as_deref(), Some("192.0.2.1"));
        let (_, after) = summaries(&mut tx, row.id).await;
        same(after, "{\"command\":\"drain\",\"revision\":0,\"state\":\"intent\"}");
        // A retry returns the stored receipt; another command under the same id conflicts.
        let retry = store::request_command(&mut tx, &operator, &input, NOW + 5).await;
        let Ok(Requested::Existing(stored)) = retry else { panic!("{retry:?}") };
        assert_eq!((stored.state, stored.completion_persisted), (State::Uncertain, false));
        let other = Command { kind: Kind::Resume, ..input.clone() };
        expect_error(store::request_command(&mut tx, &operator, &other, NOW).await, is_conflict);
        let stale = Command { expires: NOW, ..command(2, Kind::Drain) };
        expect_error(store::request_command(&mut tx, &operator, &stale, NOW).await, is_invalid);
        let far = Command { expires: NOW + 31, ..command(2, Kind::Drain) };
        expect_error(store::request_command(&mut tx, &operator, &far, NOW).await, is_invalid);
        let unknown = Command { node: 5, ..command(2, Kind::Drain) };
        expect_error(store::request_command(&mut tx, &operator, &unknown, NOW).await, is_conflict);
        let wrong = Credential { csrf_digest: [9; 32], ..operator.clone() };
        let next = command(2, Kind::Drain);
        expect_error(store::request_command(&mut tx, &wrong, &next, NOW).await, is_forbidden);
        let demote = Sql::both("UPDATE console_users SET role = 'viewer' WHERE id = 2");
        tx.execute(demote, &[]).await.expect("demote");
        expect_error(store::request_command(&mut tx, &operator, &next, NOW).await, is_forbidden);
        let intents = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_commands";
        assert_eq!(scalar(&mut tx, intents).await, 1);
    });
}

/// Inserts `count` drain intents of node 1 at `requested_at` directly.
async fn commands(db: &Database, count: u32, requested_at: u64, boot: u8) {
    let boot = bytes(db.dialect(), 16, boot);
    let id = match db.dialect() {
        sibuna_storage::Dialect::Sqlite => "CAST(printf('%016x', x) AS BLOB)",
        sibuna_storage::Dialect::Postgres => "convert_to(lpad(to_hex(x), 16, '0'), 'UTF8')",
    };
    let script = format!(
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < {count}) \
         INSERT INTO console_commands (id, node, boot, kind, actor, actor_role, \
         expected_revision, requested_at) SELECT {id}, 1, {boot}, 'drain', 1, 'admin', 0, \
         {requested_at} FROM n"
    );
    db.execute_script(&script).await.expect("commands");
}

// Port of console_nodes_test.zig "command capacity fails closed and expired receipts prune
// only a bounded batch".
#[test]
fn command_capacity_fails_closed_and_prunes_a_bounded_batch() {
    for_each_backend("command_capacity", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let operator = operator(&mut tx).await;
        tx.commit().await.expect("commit");
        commands(&db, 4096, NOW, 0x44).await;
        let mut tx = db.begin().await.expect("begin");
        let input = command(0x77, Kind::Drain);
        let outcome = store::request_command(&mut tx, &operator, &input, NOW).await;
        expect_error(outcome, |error| matches!(error, ConsoleStorageError::Capacity));
        let old = Sql::both("UPDATE console_commands SET requested_at = 0");
        tx.execute(old, &[]).await.expect("age the receipts");
        let recorded = store::request_command(&mut tx, &operator, &input, NOW).await;
        assert!(matches!(recorded, Ok(Requested::Recorded(_))), "{recorded:?}");
        let count = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_commands";
        assert_eq!(scalar(&mut tx, count).await, 4081);
    });
}

#[test]
fn command_completes_once() {
    for_each_backend("command_completion", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let operator = operator(&mut tx).await;
        store::request_command(&mut tx, &operator, &command(1, Kind::Drain), NOW)
            .await
            .expect("1");
        let clear = command(2, Kind::ClearLocalBans);
        store::request_command(&mut tx, &operator, &clear, NOW).await.expect("2");
        let intent = store::load_command(&mut tx, &[2; 16]).await.expect("load").expect("row");
        assert_eq!(intent.state, State::Uncertain);
        let done = completion(1, CommandState::Applied);
        assert_eq!(
            store::complete_command(&mut tx, &done).await.expect("done"),
            Completed::Recorded
        );
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "node.command.applied");
        assert_eq!((row.actor, row.actor_role), (None, None));
        assert_eq!(row.subject, Some(1));
        let (_, after) = summaries(&mut tx, row.id).await;
        same(
            after,
            "{\"command\":\"drain\",\"state\":\"applied\",\"revision\":1,\
             \"cleared_entries\":null}",
        );
        // An acknowledgment lost after commit is replayed without a second audit row.
        let again = store::complete_command(&mut tx, &done).await.expect("again");
        assert_eq!(again, Completed::Unchanged);
        let different = Completion { state: CommandState::Rejected, ..done };
        expect_error(store::complete_command(&mut tx, &different).await, is_conflict);
        let wrong_boot = Completion { boot: [0x99; 16], ..completion(2, CommandState::Applied) };
        expect_error(store::complete_command(&mut tx, &wrong_boot).await, is_conflict);
        let cleared = Completion { cleared_entries: Some(3), ..done };
        expect_error(store::complete_command(&mut tx, &cleared).await, is_invalid);
        let intent = completion(2, CommandState::Intent);
        expect_error(store::complete_command(&mut tx, &intent).await, is_invalid);
        let early = Completion { completed_at: NOW - 1, ..completion(2, CommandState::Applied) };
        expect_error(store::complete_command(&mut tx, &early).await, is_invalid);
        let rejected = Completion {
            applied_revision: None,
            cleared_entries: Some(3),
            ..completion(2, CommandState::Rejected)
        };
        store::complete_command(&mut tx, &rejected).await.expect("rejected");
        let read = nodes::Read { id: [2; 16], ..nodes::Read::default() };
        let receipt = store::read_command(&mut tx, &operator, &read, NOW).await.expect("read");
        assert_eq!((receipt.state, receipt.cleared_entries), (State::Rejected, Some(3)));
        assert!(receipt.completion_persisted);
        let missing = nodes::Read { id: [3; 16], ..read };
        expect_error(store::read_command(&mut tx, &operator, &missing, NOW).await, is_conflict);
        let actions = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_audit \
                       WHERE action LIKE 'node.command.%'";
        assert_eq!(scalar(&mut tx, actions).await, 4);
    });
}

#[test]
fn pruning_keeps_intents_of_the_current_boot() {
    for_each_backend("command_pruning", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let operator = operator(&mut tx).await;
        store::request_command(&mut tx, &operator, &command(1, Kind::Drain), NOW)
            .await
            .expect("1");
        store::request_command(&mut tx, &operator, &command(2, Kind::Drain), NOW)
            .await
            .expect("2");
        store::complete_command(&mut tx, &completion(2, CommandState::Applied)).await.expect("2");
        tx.commit().await.expect("commit");
        commands(&db, 3, NOW, 0x55).await;
        let mut tx = db.begin().await.expect("begin");
        let before = NOW + store::RECEIPT_SECONDS;
        let pruned = store::prune_commands(&mut tx, before, 2).await.expect("prune");
        assert_eq!(pruned, 2, "a bounded batch");
        let pruned = store::prune_commands(&mut tx, before, 16).await.expect("prune");
        assert_eq!(pruned, 2, "the rest but the current boot's intent");
        let left = store::load_command(&mut tx, &[1; 16]).await.expect("load");
        assert_eq!(left.expect("kept").state, State::Uncertain);
        assert_eq!(store::prune_commands(&mut tx, NOW, 16).await.expect("prune"), 0);
    });
}

async fn request_and_commit(db: &Database, byte: u8) -> Result<Requested, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let requested = store::request_command(
        &mut tx,
        &crate::common::cookie(20),
        &command(byte, Kind::Drain),
        NOW,
    )
    .await?;
    tx.commit().await?;
    Ok(requested)
}

#[test]
fn racing_commands_do_not_exceed_the_capacity() {
    for_each_backend("race_commands", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        operator(&mut tx).await;
        tx.commit().await.expect("commit");
        commands(&db, 4095, NOW, 0x44).await;
        let (first, second) =
            join(request_and_commit(&db, 0xa1), request_and_commit(&db, 0xa2)).await;
        let capacity = |outcome: &Result<Requested, ConsoleStorageError>| {
            matches!(outcome, Err(ConsoleStorageError::Capacity))
        };
        assert!(
            first.is_ok() && capacity(&second) || second.is_ok() && capacity(&first),
            "{first:?} {second:?}"
        );
        let mut tx = db.begin().await.expect("begin");
        let count = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_commands";
        assert_eq!(scalar(&mut tx, count).await, 4096);
    });
}
