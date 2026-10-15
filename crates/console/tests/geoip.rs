//! GeoIP through a running console (unit U6): imports of inline CSV, the status reply the
//! interface and the CLI decode, refused requests, a failed import that keeps the previous
//! generation, the embedded snapshot, restoring the durable generation at start, and the
//! storage steps that recheck the credential on every call (Zig's `console_geoip.py`,
//! `console_geo_cli_test.py` (live half) and `console_geo_auth_test.zig`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod signin;
mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use sibuna_console::{Config, GeoSlot};
use sibuna_console_protocol::geo::{Activate, Batch, Begin};
use sibuna_console_protocol::{Role, Text};
use sibuna_console_storage::geoip::{
    activate_generation, begin_generation, metadata, store_chunk,
};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_geoip::{Database, Provider, snapshot, wire};
use sibuna_storage::Sql;
use signin::{attempt, count, exec, fixture_session, json, text};
use support::{Harness, Response, Session};

const CSV: &str = "1.1.1.0,1.1.1.255,AU\\n8.8.8.0,8.8.8.255,US\\n";
const SECOND: &str = "8.8.8.0,8.8.8.255,DE\\n";

/// Starts a console and signs in an administrator; returns the console's GeoIP slot too.
fn start(name: &str, embedded: Option<&'static [u8]>) -> (Harness, Arc<GeoSlot>, Session) {
    let mut slot = None;
    let harness = Harness::start_with(name, Config::default(), |inputs| {
        inputs.geoip_embedded = embedded;
        slot = Some(Arc::clone(&inputs.geo));
    });
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    (harness, slot.unwrap(), session)
}

fn headers(session: &Session) -> [(&str, &str); 2] {
    [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())]
}

fn status(harness: &Harness, session: &Session) -> Response {
    let reply = harness.get("/console/api/geoip", &headers(session));
    assert_eq!(reply.status, 200, "{}", reply.text());
    reply
}

fn import(harness: &Harness, session: &Session, body: &str) -> Response {
    harness.post("/console/api/geoip", &headers(session), body)
}

/// Waits until the import has ended and returns the final status reply.
fn finished(harness: &Harness, session: &Session) -> Response {
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        let reply = status(harness, session);
        let state = text(&json(&reply), "status");
        if state == "applied" || state == "failed" || Instant::now() > end {
            return reply;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn csv_body(provider: &str, version: &str, revision: u64, checksum: &str, csv: &str) -> String {
    format!(
        "{{\"provider\":\"{provider}\",\"source_version\":\"{version}\",\
         \"expected_revision\":{revision},\"checksum\":\"{checksum}\",\"csv\":\"{csv}\"}}"
    )
}

#[test]
fn inline_imports_activate_and_failures_keep_the_previous_generation() {
    let (harness, slot, admin) = start("geoip-import", None);
    let empty = status(&harness, &admin);
    let reply = json(&empty);
    assert_eq!((text(&reply, "revision"), text(&reply, "status")), ("0".into(), "idle".into()));
    assert_eq!(text(&reply, "provider"), "user-country");
    assert_eq!(text(&reply, "source"), "ip-location-db user-country");
    assert_eq!(text(&reply, "attribution"), "");

    let accepted = import(&harness, &admin, &csv_body("dbip", "2026-09", 0, "", CSV));
    assert_eq!(accepted.text(), "{\"accepted\":true}");
    let done = finished(&harness, &admin);
    let reply = json(&done);
    assert_eq!(text(&reply, "status"), "applied", "{}", done.text());
    assert_eq!((text(&reply, "revision"), text(&reply, "ranges")), ("1".into(), "2".into()));
    assert_eq!(text(&reply, "processed_ranges"), "2");
    assert_eq!(text(&reply, "source"), "DB-IP IP to Country Lite");
    assert_eq!(text(&reply, "license"), "CC BY 4.0");
    assert_eq!(text(&reply, "attribution"), "https://db-ip.com");
    assert_ne!(text(&reply, "loaded_at"), "0");
    let digest = text(&reply, "digest");
    assert_eq!(digest.len(), 64);
    assert_eq!(slot.lookup("8.8.8.8").unwrap().country, Some(*b"US"));
    assert_eq!(slot.revision(), 1);

    // A wrong operator checksum fails the import; the generation stays.
    let wrong = "0".repeat(64);
    import(&harness, &admin, &csv_body("user-country", "2026-09-09", 1, &wrong, SECOND));
    assert_eq!(text(&json(&finished(&harness, &admin)), "status"), "failed");
    // So does a stale revision, refused by storage.
    import(&harness, &admin, &csv_body("user-country", "2026-09-09", 0, "", SECOND));
    assert_eq!(text(&json(&finished(&harness, &admin)), "status"), "failed");
    assert_eq!(slot.lookup("8.8.8.8").unwrap().country, Some(*b"US"));
    let kept = json(&status(&harness, &admin)).to_string();
    assert!(kept.contains(&digest) && kept.contains("\"revision\":1"), "{kept}");

    // The matching checksum, in upper case, imports the second generation.
    let expected =
        Database::from_csv(Provider::UserCountry, "2026-09-09", b"8.8.8.0,8.8.8.255,DE\n");
    let checksum = sibuna_encoding::hex::encode(expected.unwrap().digest()).to_ascii_uppercase();
    import(&harness, &admin, &csv_body("user-country", "2026-09-09", 1, &checksum, SECOND));
    let reply = finished(&harness, &admin);
    let reply = json(&reply);
    assert_eq!((text(&reply, "status"), text(&reply, "revision")), ("applied".into(), "2".into()));
    assert_eq!(text(&reply, "attribution"), "");
    assert_eq!(slot.lookup("8.8.8.8").unwrap().country, Some(*b"DE"));
    assert_eq!(
        count(
            &harness,
            Sql::both("SELECT COUNT(*) FROM console_audit WHERE action = 'geoip.activate'")
        ),
        2
    );
}

#[test]
fn malformed_and_concurrent_imports_are_refused() {
    let (harness, slot, admin) = start("geoip-refused", None);
    for body in [
        csv_body("maxmind", "2026-09", 0, "", CSV),
        csv_body("dbip", "2026-09-09", 0, "", CSV),
        csv_body("user-country", "2026-09", 0, "", CSV),
        csv_body("dbip", "2026-09", 0, "abc", CSV),
        csv_body("dbip", "2026-09", 9_223_372_036_854_775_807, "", CSV),
        csv_body("dbip", "2026-09", 0, "", &"8.8.8.0,8.8.8.255,US\\n".repeat(400)),
        "{\"source_version\":\"2026-09-09\"}".to_owned(),
        "{\"source_version\":\"2026-09-09\",\"expected_revision\":0,\"url\":\"https://x\"}"
            .to_owned(),
    ] {
        let reply = import(&harness, &admin, &body);
        assert_eq!((reply.status, reply.code()), (400, "CONSOLE002".into()), "{body}");
    }
    // While another import holds the slot's claim, a request is busy.
    let claim = slot.begin_import().unwrap();
    let reply = import(&harness, &admin, &csv_body("dbip", "2026-09", 0, "", CSV));
    assert_eq!((reply.status, reply.code()), (429, "CONSOLE003".into()));
    drop(claim);
    // Without a session the routes are closed; without the CSRF token a POST is refused.
    assert_eq!(harness.get("/console/api/geoip", &[]).status, 401);
    let cookie = [("Cookie", admin.cookie.as_str())];
    assert_eq!(
        harness
            .post("/console/api/geoip", &cookie, &csv_body("dbip", "2026-09", 0, "", CSV))
            .status,
        400
    );
    assert_eq!(text(&json(&status(&harness, &admin)), "status"), "idle");
}

#[test]
fn the_embedded_snapshot_serves_until_the_first_import_and_restarts_restore_storage() {
    let database =
        Database::from_csv(Provider::Dbip, "2026-08", b"9.9.9.0,9.9.9.255,CH\n").unwrap();
    let bytes: &'static [u8] = Box::leak(snapshot::encode(&database).unwrap().into_boxed_slice());
    let (mut harness, slot, admin) = start("geoip-embedded", Some(bytes));
    let reply = status(&harness, &admin);
    let reply = json(&reply);
    assert_eq!(text(&reply, "source"), "embedded snapshot");
    assert_eq!((text(&reply, "revision"), text(&reply, "loaded_at")), ("0".into(), "0".into()));
    assert_eq!(
        (text(&reply, "ranges"), text(&reply, "source_version")),
        ("1".into(), "2026-08".into())
    );
    assert!(slot.is_embedded());
    assert_eq!(slot.lookup("9.9.9.9").unwrap().country, Some(*b"CH"));

    import(&harness, &admin, &csv_body("dbip", "2026-09", 0, "", CSV));
    let reply = finished(&harness, &admin);
    assert_eq!(text(&json(&reply), "source"), "DB-IP IP to Country Lite");
    assert!(!slot.is_embedded());
    assert_eq!(slot.lookup("9.9.9.9").map(|mapping| mapping.country), Some(None));

    // A restart restores the durable generation, not the snapshot.
    signin::restart(&mut harness, Config::default(), false);
    let session = harness.sign_in(1, 1);
    let restored = status(&harness, &session);
    let restored = json(&restored);
    assert_eq!((text(&restored, "revision"), text(&restored, "ranges")), ("1".into(), "2".into()));
    assert_eq!(text(&restored, "source"), "DB-IP IP to Country Lite");
    assert_ne!(text(&restored, "loaded_at"), "0");
}

/// Sets the fixture session's lifetime: valid until `now + 1000`, or expired at `now`.
fn expires(harness: &Harness, now: u64, valid: bool) {
    let until = if valid { now + 1000 } else { now };
    let sql = Sql::both(
        "UPDATE console_sessions SET created_at = $1, expires_at = $2, idle_expires_at = $2",
    );
    exec(harness, sql, vec![i64::try_from(now - 100).unwrap(), i64::try_from(until).unwrap()]);
}

fn run<T: Send + 'static>(
    harness: &Harness,
    job: impl for<'a> FnOnce(
        &'a mut sibuna_storage::Transaction,
    ) -> sibuna_storage::BorrowedFuture<'a, Result<T, ConsoleStorageError>>
    + Send
    + 'static,
) -> Result<T, ConsoleStorageError> {
    attempt(harness, job)
}

// console_geo_auth_test.zig: "queued GeoIP writes and immutable replays recheck expiry and
// mandatory MFA".
#[test]
fn geoip_writes_and_replays_recheck_expiry_and_mandatory_mfa() {
    let harness = Harness::start("geoip-auth");
    let credential = fixture_session(&harness);
    let now = support::unix_now();
    let digest = Text::new(&"a".repeat(64)).unwrap();
    let begin = Begin {
        expected_revision: 0,
        digest: digest.clone(),
        provider: Text::new("dbip").unwrap(),
        source_version: Text::new("2026-09").unwrap(),
        ranges: 1,
        ..Begin::default()
    };
    let range = Database::from_csv(Provider::Dbip, "2026-09", b"8.8.8.0,8.8.8.255,US\n").unwrap();
    let mut bytes = [0u8; wire::BATCH_BYTES];
    let length = wire::encode_batch(&range.ranges().collect::<Vec<_>>(), &mut bytes).unwrap();
    let batch = Batch {
        digest: digest.clone(),
        ordinal: 0,
        bytes: bytes[..length].to_vec(),
        ..Batch::default()
    };
    let activate = Activate { expected_revision: 0, digest, ..Activate::default() };
    let step = |credential: &Credential, which: u8| {
        let (credential, begin, batch, activate) =
            (credential.clone(), begin.clone(), batch.clone(), activate.clone());
        run(&harness, move |tx| {
            Box::pin(async move {
                match which {
                    0 => begin_generation(tx, &credential, &begin, now).await.map(|()| 0),
                    1 => store_chunk(tx, &credential, &batch, now).await.map(|()| 0),
                    _ => activate_generation(tx, &credential, &activate, now).await,
                }
            })
        })
    };
    expires(&harness, now, false);
    assert!(step(&credential, 0).is_err());
    expires(&harness, now, true);
    assert!(step(&credential, 0).is_ok());
    expires(&harness, now, false);
    assert!(step(&credential, 1).is_err());
    assert!(step(&credential, 0).is_err());
    expires(&harness, now, true);
    assert!(step(&credential, 1).is_ok());
    expires(&harness, now, false);
    assert!(step(&credential, 1).is_err());
    assert!(step(&credential, 2).is_err());
    expires(&harness, now, true);
    let mandatory = Credential { require_totp: true, ..credential.clone() };
    for which in 0..3 {
        assert!(step(&mandatory, which).is_err(), "{which}");
    }
    let revision =
        run(&harness, |tx| Box::pin(async move { metadata(tx).await })).unwrap().revision;
    assert_eq!(revision, 0);
    let acknowledged = step(&credential, 2).unwrap();
    let active = run(&harness, |tx| Box::pin(async move { metadata(tx).await })).unwrap();
    assert_eq!(active.loaded_at, acknowledged);
    assert_eq!(
        count(
            &harness,
            Sql::both("SELECT COUNT(*) FROM console_audit WHERE action = 'geoip.activate'")
        ),
        1
    );
}
