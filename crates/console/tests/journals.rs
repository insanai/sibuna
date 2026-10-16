//! The collector's journals through a running console and its storage thread: traffic and
//! challenge minutes, challenge records and difficulty transitions, ranking archives, rule
//! hits across an engine publication, membership, and retention (the server halves of
//! Zig's `console_membership_test.zig`, `console_retention_test.zig` #4 and the journal
//! scripts). Telemetry and rule-hit samples are injected; time is the system clock or,
//! where a minute must roll, a manual clock.

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use sibuna_console::{Clock, Config, ManualClock, RuleHitSample};
use sibuna_console_protocol::codec::from_json;
use sibuna_console_protocol::rule_hits::{self, Generation, Identity, Key, Name};
use sibuna_console_protocol::{StatsSnapshot, rankings_archive};
use sibuna_core::incident_heads::ResponseState;
use sibuna_core::{Evidence, Incident};
use sibuna_storage::{Cell, Sql};
use sibuna_store::challenge_metrics::{Algorithm, Cause};
use sibuna_store::rule_hits::{Counters, Matches};
use sibuna_store::telemetry::{
    ChallengeOutcome, ChallengeRecord, ConsoleTelemetry, Outcome, Sample,
};
use support::Harness;

/// Reads the rows of `sql` in a transaction of its own.
fn rows(harness: &Harness, sql: &'static str) -> Vec<Vec<Cell>> {
    harness
        .transact(move |tx| Box::pin(async move { Ok(tx.fetch_all(Sql::both(sql), &[]).await?) }))
}

/// Polls `check` every 100 ms for at most `seconds` until it holds.
fn until(what: &str, seconds: u64, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while !check() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A console whose telemetry the test holds; `clock` replaces the system clock when given.
fn start(name: &str, clock: Option<Arc<ManualClock>>) -> (Harness, Arc<ConsoleTelemetry>) {
    let telemetry = Arc::new(ConsoleTelemetry::new());
    let shared = Arc::clone(&telemetry);
    let harness = Harness::start_with(name, Config::default(), move |inputs| {
        inputs.telemetry = shared;
        if let Some(clock) = clock {
            let clock: Arc<dyn Clock> = clock;
            inputs.clock = clock;
        }
    });
    (harness, telemetry)
}

// minute_journal_test.zig, challenge_journal.zig and challenge_records_journal.zig against
// storage: every journal reaches its table without a subscriber or a route.
#[test]
fn minutes_challenge_minutes_records_and_transitions_reach_storage() {
    let (harness, telemetry) = start("journals", None);
    for _ in 0..5 {
        telemetry.count(Outcome::Admitted);
    }
    telemetry.challenges.issue(Algorithm::Posw, 13, 16);
    telemetry.challenges.submitted.fetch_add(1, Ordering::Relaxed);
    telemetry.challenges.reject(Cause::MissingId);
    let mut record = ChallengeRecord::default();
    record.second = support::unix_now();
    record.outcome = ChallengeOutcome::Rejected;
    record.cause = Some(Cause::MissingId);
    record.set_ip(b"8.8.12.1");
    telemetry.challenge_event(record);
    // The journal saw bump 0 at its first second; a later second sees the change.
    std::thread::sleep(Duration::from_millis(1100));
    telemetry.adaptive_bits.store(2, Ordering::Relaxed);
    telemetry.adaptive_rate_256.store(300 * 256, Ordering::Relaxed);
    until("no record row", 5, || {
        !rows(&harness, "SELECT ip, outcome, cause FROM console_challenge_records").is_empty()
    });
    let record = &rows(&harness, "SELECT ip, outcome, cause FROM console_challenge_records")[0];
    assert_eq!(record[0].as_str(), Some("8.8.12.1"));
    assert_eq!((record[1].as_str(), record[2].as_i64()), (Some("rejected"), Some(2)));
    until("no transition row", 5, || {
        !rows(&harness, "SELECT bits FROM console_challenge_difficulty").is_empty()
    });
    let change =
        &rows(&harness, "SELECT previous_bits, bits, rate_256 FROM console_challenge_difficulty")
            [0];
    assert_eq!(
        (change[0].as_i64(), change[1].as_i64(), change[2].as_i64()),
        (Some(0), Some(2), Some(300 * 256))
    );
    // The open minutes are offered every five seconds.
    until("no traffic minute", 10, || {
        !rows(&harness, "SELECT node FROM console_minutes WHERE node = 1").is_empty()
    });
    until("no challenge minute", 10, || {
        !rows(&harness, "SELECT node FROM console_challenge_minutes WHERE node = 1").is_empty()
    });
    harness.stop();
}

// rankings_journal_test.zig against storage: a sealed minute's archive round-trips.
#[test]
fn ranking_archives_round_trip_through_storage() {
    let start_second = support::unix_now() / 60 * 60 + 10;
    let clock = Arc::new(ManualClock::new(start_second, 1000));
    let (harness, telemetry) = start("archives", Some(Arc::clone(&clock)));
    for _ in 0..3 {
        telemetry.push(
            Outcome::Admitted,
            &Sample {
                second: start_second,
                ip: b"9.0.0.1",
                path: b"/archived",
                ..Sample::default()
            },
        );
    }
    std::thread::sleep(Duration::from_millis(600));
    // Two minutes later the whole late-sample horizon has passed and the minute is sealed.
    for _ in 0..26 {
        clock.advance_ms(5_000);
        std::thread::sleep(Duration::from_millis(60));
    }
    const ARCHIVES: &str = "SELECT bytes, node, minute FROM console_rank_archives";
    until("no archive stored", 10, || !rows(&harness, ARCHIVES).is_empty());
    let stored = &rows(&harness, ARCHIVES)[0];
    let archive = rankings_archive::decode(stored[0].as_bytes().unwrap()).unwrap();
    assert_eq!((archive.identity.node, archive.identity.boot), (1, [7; 16]));
    assert_eq!(archive.minute.minute, Some(start_second / 60));
    let counters = archive.minute.paths.counters();
    assert_eq!(counters[0].key.as_bytes(), b"/archived");
    assert_eq!(counters[0].estimate, 3);
    assert_eq!(stored[2].as_i64(), Some((start_second / 60) as i64));
    harness.stop();
}

fn generation(number: u64, born: rule_hits::Clock) -> Generation {
    let identity = Identity { key: Key::new("m:hits").unwrap(), name: Name::new("Hits").unwrap() };
    Generation { node: 1, boot: [7; 16], number, revision: number, born, rules: vec![identity] }
}

fn sample(generation: Generation, counters: &Counters<{ rule_hits::MAX_RULES }>) -> RuleHitSample {
    let mut sample = RuleHitSample { generation, ..RuleHitSample::default() };
    counters.read(&mut sample.counts);
    sample
}

// rule_hit_journal_test.zig against storage: a publication changes the generation without
// resetting either generation's counters; the old frame is recorded as a cutover.
#[test]
fn rule_hits_change_generation_on_publication() {
    let start_second = support::unix_now() / 60 * 60 + 5;
    let clock = Arc::new(ManualClock::new(start_second, 1000));
    let (harness, _) = start("rule-hits", Some(Arc::clone(&clock)));
    let born = rule_hits::Clock { utc: clock.unix_seconds(), ms: clock.monotonic_ms() };
    let mut matches = Matches::new();
    matches.set(0);
    let first = Counters::new(NonZeroU64::new(1).unwrap());
    for _ in 0..5 {
        first.record(&matches);
    }
    *harness.node.sample.lock().unwrap() = Some(sample(generation(1, born), &first));
    clock.advance_ms(1000);
    std::thread::sleep(Duration::from_millis(1300));
    let born = rule_hits::Clock { utc: clock.unix_seconds(), ms: clock.monotonic_ms() };
    let second = Counters::new(NonZeroU64::new(2).unwrap());
    second.record(&matches);
    *harness.node.sample.lock().unwrap() = Some(sample(generation(2, born), &second));
    clock.advance_ms(1000);
    const HITS: &str =
        "SELECT generation, hits, complete FROM console_rule_hits ORDER BY generation";
    until("the retired generation was not recorded", 10, || !rows(&harness, HITS).is_empty());
    let cutover = &rows(&harness, HITS)[0];
    assert_eq!((cutover[0].as_i64(), cutover[1].as_i64()), (Some(1), Some(5)));
    // The new generation keeps counting from its publication into the next minute.
    second.record(&matches);
    *harness.node.sample.lock().unwrap() = Some(sample(generation(2, born), &second));
    for _ in 0..14 {
        clock.advance_ms(5_000);
        std::thread::sleep(Duration::from_millis(80));
    }
    until("the new generation was not recorded", 10, || rows(&harness, HITS).len() >= 2);
    let next = &rows(&harness, HITS)[1];
    assert_eq!((next[0].as_i64(), next[1].as_i64()), (Some(2), Some(2)));
    harness.stop();
}

// console_membership_test.zig: the row announces the writer, keeps first_seen and follows
// the applied revision.
#[test]
fn membership_follows_the_applied_revision_and_keeps_first_seen() {
    let (harness, _) = start("membership", None);
    const MEMBER: &str = "SELECT first_seen, last_seen, applied_revision, address, version \
                          FROM console_nodes WHERE node = 1";
    until("no membership row", 5, || !rows(&harness, MEMBER).is_empty());
    let first = rows(&harness, MEMBER).remove(0);
    assert_eq!((first[2].as_i64(), first[3].as_str()), (Some(0), Some("local")));
    assert_eq!(first[4].as_str(), Some("0.2.0-test"));
    harness.node.revision.store(5, Ordering::SeqCst);
    until("the applied revision was not announced", 8, || {
        rows(&harness, MEMBER)[0][2].as_i64() == Some(5)
    });
    assert_eq!(rows(&harness, MEMBER)[0][0].as_i64(), first[0].as_i64());
    harness.stop();
}

// console_retention_test.zig #4: the collector's retention schedule removes expired
// findings and audit rows without changing lifetime counters.
#[test]
fn collector_retention_removes_expired_history() {
    let (harness, _) = start("retention", None);
    harness.storage.record_incident(&Incident {
        client_ip: "198.51.100.1",
        user_agent: b"test",
        ja4: None,
        method: "GET",
        path: b"/trap",
        category: "honeypot",
        payload: b"retainedneedle",
        now: 1,
        evidence: Evidence { version: 1, selected_status: 403, ..Evidence::default() },
        request_head: b"",
        response_head: b"",
        request_truncated: false,
        response_truncated: false,
        response_state: ResponseState::default(),
    });
    harness.transact(|tx| {
        Box::pin(async move {
            const AUDIT: Sql = Sql::both(
                "INSERT INTO console_audit (id, recorded_at, actor, action, subject) \
                 VALUES (999999, 0, 1, 'audit.export', 1)",
            );
            tx.execute(AUDIT, &[]).await?;
            Ok(())
        })
    });
    // The finding was committed: the collector counted it, already expired, from the feed.
    let user = harness.create_user("admin", sibuna_console_protocol::Role::Admin, false);
    let cookie = harness.sign_in(user, 1).cookie;
    until("the finding was not committed", 5, || {
        let reply = harness.get("/console/api/stats", &[("Cookie", &cookie)]);
        let stats: StatsSnapshot = from_json(&reply.body).unwrap();
        stats.incident_geo.is_some_and(|geo| geo.expired == 1)
    });
    const OLD: &str = "SELECT (SELECT COUNT(*) FROM security_incidents) + \
                       (SELECT COUNT(*) FROM console_audit WHERE recorded_at = 0)";
    until("expired rows were not removed", 15, || rows(&harness, OLD)[0][0].as_i64() == Some(0));
    harness.stop();
}
