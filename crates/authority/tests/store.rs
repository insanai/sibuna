//! The store of SID 0028 on every backend: in memory, SQLite and, when PostgreSQL is
//! installed and the feature `postgres` is built, a PostgreSQL server of our own.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sibuna_authority::{
    Access, Draft, Error, Head, Location, MemoryStore, NodeReport, Origin, Settings, SqlStore,
    Store, Woken, commit_settled, digest,
};

fn draft(document: &str) -> Draft<'_> {
    Draft {
        document,
        source: b"fn edge() {}",
        source_name: "edge.jlv",
        origin: Origin::Apply,
        author: "op@host",
        note: "a note",
        now: 1_795_608_000,
    }
}

fn settings(location: Location) -> Settings {
    Settings {
        location,
        node: "n1".into(),
        node_stated: true,
        poll: Duration::from_secs(5),
        cache: None,
    }
}

/// An empty directory for one test.
fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir()
        .join(format!("sibuna-authority-{}-{serial}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What every store must do: the invariants 1 and 2 of SID 0028 and the reports.
fn exercise(store: &mut impl Store) {
    assert_eq!(store.head().unwrap(), Head::default());
    assert_eq!(store.revision(1).unwrap_err(), Error::Unknown(1));
    assert!(store.history(10).unwrap().is_empty());
    // A commit must name the head, also the first one.
    assert_eq!(
        store.commit(1, &draft("{}")).unwrap_err(),
        Error::Conflict { expected: 1, found: 0 }
    );
    assert_eq!(store.commit(0, &draft(r#"{"a":1}"#)), Ok(1));
    assert_eq!(store.commit(1, &draft(r#"{"a":2}"#)), Ok(2));
    // A stale expected revision changes nothing.
    let stale = store.commit(1, &draft(r#"{"a":3}"#)).unwrap_err();
    assert_eq!(stale, Error::Conflict { expected: 1, found: 2 });
    let head = store.head().unwrap();
    assert_eq!(head, Head { revision: 2, digest: digest(br#"{"a":2}"#) });
    // A rollback is a commit of an earlier document.
    let first = store.revision(1).unwrap();
    assert_eq!(first.document, r#"{"a":1}"#);
    assert_eq!(first.source, b"fn edge() {}");
    assert_eq!(first.entry.source_digest, digest(b"fn edge() {}"));
    let back = Draft { origin: Origin::Rollback(1), ..draft(&first.document) };
    assert_eq!(commit_settled(store, 2, &back), Ok(3));
    let third = store.revision(3).unwrap();
    assert_eq!((third.document.as_str(), third.entry.origin), (r#"{"a":1}"#, Origin::Rollback(1)));
    assert_eq!(third.entry.digest, first.entry.digest);
    // The earlier revisions read as before.
    assert_eq!(store.revision(2).unwrap().document, r#"{"a":2}"#);
    let history = store.history(2).unwrap();
    assert_eq!(history.iter().map(|entry| entry.number).collect::<Vec<_>>(), [3, 2]);
    assert_eq!(history[1].author, "op@host");
    assert_eq!(history[1].note, "a note");
    assert_eq!(history[1].committed_at, 1_795_608_000);
    assert_eq!(store.history(100).unwrap().len(), 3);
    // A draft beyond its bounds reaches no store.
    let long = "x".repeat(201);
    assert_eq!(
        store.commit(3, &Draft { note: &long, ..draft("{}") }).unwrap_err().code(),
        "DBA001"
    );
    let report = |node: &str, applied, refused, detail: &str| NodeReport {
        node: node.into(),
        applied,
        digest: "d".repeat(64),
        refused,
        detail: detail.into(),
        seen_at: 42,
    };
    store.report(&report("b", 2, 0, "")).unwrap();
    store.report(&report("a", 1, 2, "refused")).unwrap();
    store.report(&report("b", 3, 0, "")).unwrap();
    assert_eq!(store.nodes().unwrap(), [report("a", 1, 2, "refused"), report("b", 3, 0, "")]);
}

#[test]
fn the_store_in_memory_keeps_the_invariants() {
    exercise(&mut MemoryStore::new());
}

#[test]
fn sqlite_keeps_the_invariants_and_never_announces() {
    let dir = scratch("sqlite");
    let location = Location::Sqlite(dir.join("authority.db"));
    let mut store = SqlStore::new(&settings(location.clone()), Access::Operator).unwrap();
    exercise(&mut store);
    assert_eq!(store.is_postgres(), Some(false));
    // A second process of the host sees the same revisions.
    let mut node = SqlStore::new(&settings(location), Access::Node).unwrap();
    assert_eq!(node.head().unwrap().revision, 3);
    assert_eq!(node.wait(Duration::from_millis(30)), Woken::TimedOut);
    // Another thread ends a wait at once.
    let waker = node.waker();
    let started = Instant::now();
    std::thread::spawn(move || waker.wake());
    assert_eq!(node.wait(Duration::from_secs(20)), Woken::Notified);
    assert!(started.elapsed() < Duration::from_secs(10));
    drop((store, node));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_node_does_not_create_the_tables() {
    let dir = scratch("node");
    let location = Location::Sqlite(dir.join("authority.db"));
    let mut node = SqlStore::new(&settings(location.clone()), Access::Node).unwrap();
    assert_eq!(node.head().unwrap_err(), Error::Empty);
    let mut operator = SqlStore::new(&settings(location), Access::Operator).unwrap();
    assert_eq!(operator.head().unwrap().revision, 0);
    assert_eq!(node.head().unwrap().revision, 0, "the node connects again and finds the tables");
    drop((node, operator));
    std::fs::remove_dir_all(dir).unwrap();
}

/// Starts `writers` threads that each commit on the same expected head, each through a
/// connection of its own. Returns how many succeeded and how many met a conflict.
fn race(location: &Location, expected: u64, writers: usize) -> (usize, usize) {
    let outcomes: Vec<Result<u64, Error>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..writers)
            .map(|index| {
                scope.spawn(move || {
                    let mut store =
                        SqlStore::new(&settings(location.clone()), Access::Node).unwrap();
                    let document = format!(r#"{{"writer":{index}}}"#);
                    store.commit(expected, &draft(&document))
                })
            })
            .collect();
        handles.into_iter().map(|handle| handle.join().unwrap()).collect()
    });
    let won = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    let is_conflict = |outcome: &&Result<u64, Error>| match outcome {
        Err(Error::Conflict { expected: named, .. }) => *named == expected,
        _ => false,
    };
    let conflicts = outcomes.iter().filter(is_conflict).count();
    assert_eq!(won + conflicts, writers, "{outcomes:?}");
    (won, conflicts)
}

#[test]
fn of_eight_sqlite_writers_on_one_head_one_wins() {
    let dir = scratch("race");
    let location = Location::Sqlite(dir.join("authority.db"));
    let mut store = SqlStore::new(&settings(location.clone()), Access::Operator).unwrap();
    store.commit(0, &draft("{}")).unwrap();
    assert_eq!(race(&location, 1, 8), (1, 7));
    assert_eq!(store.head().unwrap().revision, 2);
    assert_eq!(store.history(10).unwrap().len(), 2);
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_document_changed_in_the_table_is_refused() {
    let dir = scratch("damaged");
    let path = dir.join("authority.db");
    let mut store = SqlStore::new(&settings(Location::Sqlite(path.clone())), Access::Operator);
    let store = store.as_mut().unwrap();
    store.commit(0, &draft(r#"{"a":1}"#)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let db = sibuna_storage::Database::open(&sibuna_storage::Target::Sqlite(path)).await;
        let db = db.unwrap();
        db.execute_script(r#"UPDATE edge_revisions SET document = '{"a":9}'"#).await.unwrap();
        db.close().await;
    });
    assert_eq!(store.revision(1).unwrap_err().code(), "DBA008");
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(not(feature = "postgres"))]
#[test]
fn postgresql_needs_the_feature() {
    eprintln!(
        "skipped: PostgreSQL is tested with `cargo test -p sibuna-authority --features postgres`"
    );
    let location = Location::PostgresUrlFile("/nonexistent/sibuna/url".into());
    let mut store = SqlStore::new(&settings(location), Access::Node).unwrap();
    assert_eq!(store.head().unwrap_err().code(), "DBA005", "the URL file is read first");
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use sibuna_authority::testing::{PASSWORD, Postgres, ROLE};

    fn location(server: &Postgres) -> Location {
        Location::PostgresUrlFile(server.url_file("operator.url", ROLE, PASSWORD, "postgres"))
    }

    #[test]
    fn postgresql_keeps_the_invariants_and_one_of_eight_writers_wins() {
        let Some(server) = Postgres::start("store") else { return };
        let location = location(&server);
        let mut store = SqlStore::new(&settings(location.clone()), Access::Operator).unwrap();
        exercise(&mut store);
        assert_eq!(store.is_postgres(), Some(true));
        assert_eq!(race(&location, 3, 8), (1, 7));
        assert_eq!(store.head().unwrap().revision, 4);
    }

    #[test]
    fn a_commit_notifies_a_waiting_node() {
        let Some(server) = Postgres::start("notify") else { return };
        let location = location(&server);
        let mut operator = SqlStore::new(&settings(location.clone()), Access::Operator).unwrap();
        operator.commit(0, &draft("{}")).unwrap();
        let mut node = SqlStore::new(&settings(location), Access::Node).unwrap();
        assert_eq!(node.head().unwrap().revision, 1);
        // The listening session starts with the connection. Let it settle, then drain.
        while node.wait(Duration::from_millis(300)) == Woken::Notified {}
        let started = Instant::now();
        let commit = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            operator.commit(1, &draft(r#"{"a":1}"#))
        });
        assert_eq!(node.wait(Duration::from_secs(30)), Woken::Notified);
        let waited = started.elapsed();
        assert!(waited < Duration::from_secs(5), "notified after {waited:?}");
        eprintln!("PostgreSQL notification reached the node {waited:?} after the wait began");
        assert_eq!(commit.join().unwrap(), Ok(2));
        assert_eq!(node.head().unwrap().revision, 2);
    }

    #[test]
    fn a_node_role_reads_and_reports_and_cannot_commit() {
        let Some(server) = Postgres::start("roles") else { return };
        let mut operator = SqlStore::new(&settings(location(&server)), Access::Operator).unwrap();
        operator.commit(0, &draft("{}")).unwrap();
        server.execute(
            "postgres",
            "CREATE ROLE edge_node LOGIN PASSWORD 'node-secret';
             GRANT SELECT ON edge_head, edge_revisions, edge_nodes, sibuna_schema TO edge_node;
             GRANT INSERT, UPDATE ON edge_nodes TO edge_node;",
        );
        let url = server.url_file("node.url", "edge_node", "node-secret", "postgres");
        let mut node = SqlStore::new(&settings(Location::PostgresUrlFile(url)), Access::Node);
        let node = node.as_mut().unwrap();
        assert_eq!(node.head().unwrap().revision, 1);
        assert_eq!(node.revision(1).unwrap().document, "{}");
        let report = NodeReport { node: "n1".into(), applied: 1, ..NodeReport::default() };
        node.report(&report).unwrap();
        assert_eq!(operator.nodes().unwrap(), [report]);
        let refused = node.commit(1, &draft(r#"{"a":1}"#)).unwrap_err();
        assert!(refused.is_unavailable(), "{refused}");
        assert!(refused.to_string().contains("permission denied"), "{refused}");
        assert_eq!(operator.head().unwrap().revision, 1);
    }

    #[test]
    fn a_store_survives_an_outage_and_a_new_password() {
        let Some(mut server) = Postgres::start("outage") else { return };
        let url_file = server.url_file("node.url", ROLE, PASSWORD, "postgres");
        let located = settings(Location::PostgresUrlFile(url_file.clone()));
        let mut store = SqlStore::new(&located, Access::Operator).unwrap();
        store.commit(0, &draft("{}")).unwrap();
        server.stop();
        let down = store.head().unwrap_err();
        assert!(down.is_unavailable(), "{down}");
        assert!(!down.to_string().contains(PASSWORD), "{down}");
        assert!(server.resume());
        assert_eq!(store.head().unwrap().revision, 1, "the store connects again");
        // A wrong password is refused, and the message does not hold it.
        std::fs::write(&url_file, server.url(ROLE, "wrong-password", "postgres")).unwrap();
        let mut other = SqlStore::new(&located, Access::Node).unwrap();
        let refused = other.head().unwrap_err();
        assert!(refused.is_unavailable(), "{refused}");
        assert!(!refused.to_string().contains("wrong-password"), "{refused}");
        // The file is read again at the next connection.
        std::fs::write(&url_file, server.url(ROLE, PASSWORD, "postgres")).unwrap();
        assert_eq!(other.head().unwrap().revision, 1);
        // A URL file that others can read is refused before any connection.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut exposed = SqlStore::new(&located, Access::Node).unwrap();
            assert_eq!(exposed.head().unwrap_err().code(), "DBA005");
        }
    }
}
