//! Local node commands and the nodes pages through a running console: commands fenced by
//! boot and control revision with durable, idempotent receipts; a completion kept in memory
//! when it cannot be recorded, so a clear never runs twice; an effect refused when the
//! authority ends during its intent; old-boot intents that stay uncertain; capacity; and the
//! membership page with its storage snapshot (Zig's `console_nodes_test.zig` and the route
//! half of `tools/console_nodes_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::atomic::Ordering;

use sibuna_console_protocol::codec::from_json;
use sibuna_console_protocol::nodes::{Command, Kind, Receipt, State, Status};
use sibuna_console_protocol::{CredentialKind, Role, Text, users};
use sibuna_console_storage::Credential;
use sibuna_console_storage::nodes::{Announcement, announce, request_command};
use sibuna_crypto::sha256::Sha256;
use sibuna_storage::Sql;
use support::{Harness, Response, Session};

const BOOT: &str = "07070707070707070707070707070707";

fn post(harness: &Harness, session: &Session, path: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(path, &headers, body)
}

fn scalar(harness: &Harness, sql: &'static str) -> i64 {
    harness.transact(move |tx| {
        Box::pin(
            async move { Ok(tx.fetch_all(Sql::both(sql), &[]).await?[0][0].as_i64().unwrap()) },
        )
    })
}

fn execute(harness: &Harness, sql: &'static str) {
    harness.transact(move |tx| {
        Box::pin(async move {
            tx.execute_script(sql).await?;
            Ok(())
        })
    });
}

/// Starts a console whose node has announced itself, with an operator signed in.
fn start(name: &str) -> (Harness, Session) {
    let harness = Harness::start(name);
    let now = support::unix_now();
    harness.transact(move |tx| {
        Box::pin(async move {
            let row = Announcement {
                node: 1,
                address: "local",
                version: "0.2.0-test",
                boot: [7; 16],
                ..Announcement::default()
            };
            announce(tx, &row, now).await
        })
    });
    let operator = harness.create_user("operator", Role::Operator, false);
    let session = harness.sign_in(operator, 1);
    (harness, session)
}

fn command(
    harness: &Harness,
    session: &Session,
    id: u8,
    kind: &str,
    revision: u64,
    boot: &str,
) -> Response {
    let id = format!("{id:02x}").repeat(16);
    let body = format!(
        "{{\"id\":\"{id}\",\"boot\":\"{boot}\",\"node\":1,\
         \"expected_revision\":\"{revision}\",\"kind\":\"{kind}\"}}"
    );
    post(harness, session, "/console/api/nodes/command", &body)
}

fn receipt(response: &Response) -> Receipt {
    assert_eq!(response.status, 200, "{}", response.text());
    from_json(&response.body).unwrap()
}

fn status(harness: &Harness, session: &Session) -> Status {
    let reply = harness.get("/console/api/nodes/local", &[("Cookie", &session.cookie)]);
    assert_eq!(reply.status, 200, "{}", reply.text());
    from_json(&reply.body).unwrap()
}

// console_nodes_test.zig: "local drain commands fence boot and revision and retain durable
// idempotent receipts".
#[test]
fn drain_commands_fence_boot_and_revision_with_idempotent_receipts() {
    let (harness, session) = start("nodes-drain");
    let local = status(&harness, &session);
    assert_eq!((local.node, local.boot.as_str(), local.control_revision), (1, BOOT, 0));
    assert_eq!(local.operation_id.len(), 32);
    let first = command(&harness, &session, 1, "drain", 0, BOOT);
    let applied = receipt(&first);
    assert_eq!((applied.state, applied.completion_persisted), (State::Applied, true));
    assert_eq!(applied.applied_revision, Some(1));
    assert!(harness.node.draining.load(Ordering::SeqCst));
    assert_eq!(receipt(&command(&harness, &session, 1, "drain", 0, BOOT)), applied);
    let stale = command(&harness, &session, 2, "resume", 0, BOOT);
    assert_eq!((stale.status, stale.code().as_str()), (409, "CONSOLENODE"));
    let other_boot = command(&harness, &session, 2, "resume", 1, &"77".repeat(16));
    assert_eq!(other_boot.status, 409);
    let other_kind = command(&harness, &session, 1, "resume", 0, BOOT);
    assert_eq!(other_kind.status, 409);
    let elsewhere = post(
        &harness,
        &session,
        "/console/api/nodes/command",
        &format!(
            r#"{{"id":"{}","boot":"{BOOT}","node":2,"expected_revision":"1","kind":"drain"}}"#,
            "09".repeat(16)
        ),
    );
    assert_eq!((elsewhere.status, elsewhere.code().as_str()), (400, "CONSOLENODE"));
    receipt(&command(&harness, &session, 3, "resume", 1, BOOT));
    let local = status(&harness, &session);
    assert!(!local.draining && local.control_revision == 2 && !local.completion_pending);
    let read = post(
        &harness,
        &session,
        "/console/api/nodes/command/read",
        &format!(r#"{{"id":"{}"}}"#, "01".repeat(16)),
    );
    assert_eq!(receipt(&read), applied);
    let unknown = post(
        &harness,
        &session,
        "/console/api/nodes/command/read",
        &format!(r#"{{"id":"{}"}}"#, "0f".repeat(16)),
    );
    assert_eq!(unknown.status, 409);
    harness.stop();
}

// console_nodes_test.zig: "a failed completion retains the clear result and cannot clear a
// later ban on retry".
#[test]
fn a_failed_completion_is_retained_and_a_clear_never_runs_twice() {
    let (harness, session) = start("nodes-clear");
    harness.node.bans.store(1, Ordering::SeqCst);
    execute(
        &harness,
        "CREATE TRIGGER reject_completion BEFORE UPDATE ON console_commands \
         BEGIN SELECT RAISE(ABORT, 'test completion failure'); END;",
    );
    let cleared = receipt(&command(&harness, &session, 1, "clear_local_bans", 0, BOOT));
    assert_eq!((cleared.state, cleared.completion_persisted), (State::Applied, false));
    assert_eq!(cleared.cleared_entries, Some(1));
    assert!(status(&harness, &session).completion_pending);
    harness.node.bans.store(1, Ordering::SeqCst);
    assert_eq!(receipt(&command(&harness, &session, 1, "clear_local_bans", 0, BOOT)), cleared);
    let blocked = command(&harness, &session, 2, "drain", 1, BOOT);
    assert_eq!((blocked.status, blocked.code().as_str()), (503, "CONSOLENODE"));
    execute(&harness, "DROP TRIGGER reject_completion;");
    let recorded = receipt(&command(&harness, &session, 1, "clear_local_bans", 0, BOOT));
    assert!(recorded.completion_persisted);
    assert_eq!(Receipt { completion_persisted: false, ..recorded }, cleared);
    assert_eq!(harness.node.clears.load(Ordering::SeqCst), 1);
    assert_eq!(harness.node.bans.load(Ordering::SeqCst), 1);
    let audited = "SELECT COUNT(*) FROM console_audit WHERE action LIKE 'node.command.%'";
    assert_eq!(scalar(&harness, audited), 2);
    harness.stop();
}

// console_nodes_test.zig: "intent failure and revocation during its commit cannot cause a
// local effect".
#[test]
fn no_effect_without_a_recorded_intent_and_current_authority() {
    let (harness, session) = start("nodes-intent");
    execute(
        &harness,
        "CREATE TRIGGER reject_intent BEFORE INSERT ON console_audit \
         WHEN NEW.action = 'node.command.intent' \
         BEGIN SELECT RAISE(ABORT, 'test intent failure'); END;",
    );
    let failed = command(&harness, &session, 1, "drain", 0, BOOT);
    assert_eq!(failed.status, 503, "{}", failed.text());
    assert!(!harness.node.draining.load(Ordering::SeqCst));
    execute(&harness, "DROP TRIGGER reject_intent;");
    execute(
        &harness,
        "CREATE TRIGGER revoke_after_intent AFTER INSERT ON console_commands BEGIN \
         UPDATE console_sessions SET created_at = 0, expires_at = 1, idle_expires_at = 1; END;",
    );
    let rejected = receipt(&command(&harness, &session, 1, "drain", 0, BOOT));
    assert_eq!((rejected.state, rejected.completion_persisted), (State::Rejected, true));
    assert_eq!(rejected.applied_revision, None);
    assert!(!harness.node.draining.load(Ordering::SeqCst));
    harness.stop();
}

// console_nodes_test.zig: "unresolved old-boot intents stay uncertain across restart and
// are never replayed".
#[test]
fn old_boot_intents_stay_uncertain_and_are_never_replayed() {
    let (harness, session) = start("nodes-restart");
    // An intent a previous boot recorded and never completed.
    let old_boot = [9u8; 16];
    let auth = users::Auth {
        session_digest: Sha256::digest(&raw(&session.cookie["__sibuna_console=".len()..])),
        csrf_digest: Sha256::digest(&raw(&session.csrf)),
        require_totp: false,
        client: Text::new("127.0.0.1").unwrap(),
    };
    let now = support::unix_now();
    let intent = Command {
        auth: auth.clone(),
        id: [1; 16],
        boot: old_boot,
        node: 1,
        expected_revision: 0,
        expires: now + 30,
        kind: Kind::Drain,
    };
    harness.transact(move |tx| {
        Box::pin(async move {
            let credential = Credential::new(CredentialKind::Session, &auth);
            request_command(tx, &credential, &intent, now).await.map(|_| ())
        })
    });
    let retried = receipt(&command(&harness, &session, 1, "drain", 0, &"09".repeat(16)));
    assert_eq!((retried.state, retried.completion_persisted), (State::Uncertain, false));
    assert_eq!((retried.completed_at, retried.applied_revision), (None, None));
    assert!(!harness.node.draining.load(Ordering::SeqCst));
    assert!(receipt(&command(&harness, &session, 2, "drain", 0, BOOT)).completion_persisted);
    harness.stop();
}

// console_nodes_test.zig: "queued commands recheck expiry and viewers cannot control the
// local node".
#[test]
fn viewers_and_bad_credentials_cannot_control_the_node() {
    let (harness, session) = start("nodes-access");
    let forged = Session { csrf: "09".repeat(32), ..session.clone() };
    let refused = command(&harness, &forged, 1, "drain", 0, BOOT);
    assert_eq!((refused.status, refused.code().as_str()), (400, "CONSOLE002"));
    let viewer = harness.create_user("viewer", Role::Viewer, false);
    let viewing = harness.sign_in(viewer, 1);
    let refused = command(&harness, &viewing, 1, "drain", 0, BOOT);
    assert_eq!((refused.status, refused.code().as_str()), (403, "CONSOLE403"));
    assert_eq!(status(&harness, &viewing).node, 1);
    execute(
        &harness,
        "UPDATE console_sessions SET created_at = 0, expires_at = 1, idle_expires_at = 1;",
    );
    let expired = command(&harness, &session, 1, "drain", 0, BOOT);
    assert_eq!((expired.status, expired.code().as_str()), (401, "CONSOLE401"));
    assert!(!harness.node.draining.load(Ordering::SeqCst));
    harness.stop();
}

// console_nodes_test.zig: "command capacity fails closed and expired receipts prune only a
// bounded batch".
#[test]
fn command_capacity_fails_closed_and_pruning_is_bounded() {
    let (harness, session) = start("nodes-capacity");
    execute(
        &harness,
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 4096) \
         INSERT INTO console_commands (id, node, boot, kind, actor, actor_role, \
         expected_revision, requested_at) SELECT CAST(printf('%016x', x) AS BLOB), 1, \
         X'11111111111111111111111111111111', 'drain', 1, 'operator', 0, \
         CAST(strftime('%s', 'now') AS INTEGER) FROM n;",
    );
    let full = command(&harness, &session, 0x77, "drain", 0, BOOT);
    assert_eq!((full.status, full.code().as_str()), (503, "CONSOLENODE"));
    assert!(!harness.node.draining.load(Ordering::SeqCst));
    execute(&harness, "UPDATE console_commands SET requested_at = 0;");
    assert!(receipt(&command(&harness, &session, 0x77, "drain", 0, BOOT)).completion_persisted);
    assert_eq!(scalar(&harness, "SELECT COUNT(*) FROM console_commands"), 4081);
    harness.stop();
}

#[test]
fn the_membership_page_reports_a_single_sqlite_leader() {
    let (harness, session) = start("nodes-members");
    let reply = harness.get("/console/api/nodes", &[("Cookie", &session.cookie)]);
    assert_eq!(reply.status, 200, "{}", reply.text());
    let text = reply.text();
    assert!(
        text.starts_with(
            "{\"page\":{\"self\":1,\"committed\":0,\"storage\":{\"role\":\"single\",\"leader\":1,\
             \"term\":0,\"decided\":0,\"applied\":0,\"durable\":0,\"quorum\":true,"
        ),
        "{text}"
    );
    assert!(text.contains("\"members\":[{\"node\":1,\"address\":\"local\""), "{text}");
    assert!(text.contains("\"probes\":[],\"peers\":[],\"observed_at\":"), "{text}");
    assert!(harness.get("/console/api/nodes", &[]).status == 401);
    harness.stop();
}

fn raw(hex: &str) -> Vec<u8> {
    sibuna_encoding::hex::decode(hex.as_bytes()).unwrap()
}
