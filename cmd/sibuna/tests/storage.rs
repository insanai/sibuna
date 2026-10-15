//! The daemon with persistent storage (SID 0011): policy reloaded from the database, honeypot
//! bans that survive a restart, and incidents recorded with their forensic payload.
//!
//! Every test runs against SQLite in a fresh directory, and against PostgreSQL as well when
//! the build has the `postgres` feature and `SIBUNA_TEST_DATABASE_URL` names a test database.
//! Paths, addresses and node ids are unique per run, so tests sharing one PostgreSQL database
//! do not see each other's rows.

#![cfg(feature = "storage")]
#![allow(clippy::unwrap_used)]

mod support;

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sibuna::{Daemon, DaemonOptions, Hooks, Recipe};
use sibuna_challenge::Seed;
use sibuna_core::Config;
use sibuna_storage::{Cell, Param, Sql, Storage, StorageError};

use support::*;

/// One storage configuration under test.
struct Backend {
    label: &'static str,
    config: Config,
    dir: Option<PathBuf>,
}

impl Drop for Backend {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A value unique to this process and call, for paths, addresses, ids and nodes.
fn unique() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    (std::process::id() % 4000) * 64 + NEXT.fetch_add(1, Ordering::Relaxed)
}

fn base_config() -> Config {
    Config {
        upstream_port: origin_port(),
        trust_forwarded: Some(true),
        workers: 1,
        idle_timeout_seconds: 5,
        storage_poll_ms: 50,
        ..Config::default()
    }
}

fn backends() -> Vec<Backend> {
    let dir = std::env::temp_dir().join(format!("sibuna-storage-{}", unique()));
    std::fs::create_dir_all(&dir).unwrap();
    let sqlite = Config { data_dir: Some(dir.to_str().unwrap().to_owned()), ..base_config() };
    let mut backends = vec![Backend { label: "sqlite", config: sqlite, dir: Some(dir) }];
    if cfg!(feature = "postgres")
        && let Ok(url) = std::env::var("SIBUNA_TEST_DATABASE_URL")
        && !url.is_empty()
    {
        let config = Config {
            database_url: Some(url),
            cluster_node: Some(1000 + unique()),
            ..base_config()
        };
        backends.push(Backend { label: "postgres", config, dir: None });
    }
    backends
}

fn start(config: &Config) -> Daemon {
    let options = DaemonOptions {
        config: config.clone(),
        recipe: Recipe::new(config, None),
        seed: Seed::new([7; 32]),
        hooks: Hooks::default(),
    };
    Daemon::start(options, TcpListener::bind("127.0.0.1:0").unwrap()).unwrap()
}

fn port_of(daemon: &Daemon) -> u16 {
    daemon.address().unwrap().port()
}

/// Repeats `probe` until it returns true or five seconds pass.
fn eventually(what: &str, mut probe: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !probe() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Runs one statement with text parameters on the storage thread.
fn execute(storage: &Storage, sql: &'static str, params: Vec<String>) {
    storage
        .with_database(move |db| async move {
            let params: Vec<Param<'_>> =
                params.iter().map(|value| value.as_str().into()).collect();
            db.execute(Sql::both(sql), &params).await
        })
        .unwrap();
}

/// Fetches rows of text cells with text parameters.
fn fetch(storage: &Storage, sql: &'static str, params: Vec<String>) -> Vec<Vec<String>> {
    storage
        .with_database(move |db| async move {
            let params: Vec<Param<'_>> =
                params.iter().map(|value| value.as_str().into()).collect();
            let rows = db.fetch_all(Sql::both(sql), &params).await?;
            Ok::<_, StorageError>(
                rows.iter().map(|row| row.iter().map(cell_text).collect()).collect(),
            )
        })
        .unwrap()
}

fn cell_text(cell: &Cell) -> String {
    match (cell.as_str(), cell.as_i64(), cell.as_bytes()) {
        (Some(text), _, _) => text.to_owned(),
        (None, Some(number), _) => number.to_string(),
        (None, None, Some(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

#[test]
fn policies_written_to_the_database_are_enforced_on_the_next_tick() {
    for backend in backends() {
        let daemon = start(&backend.config);
        let port = port_of(&daemon);
        let id = format!("reload-{}", unique());
        let path = format!("/{id}");
        let ip = "198.18.0.1";
        assert_eq!(get(port, &path, ip, "curl/8", "").status(), 401, "{}", backend.label);
        let storage = daemon.storage().unwrap();
        execute(
            storage,
            "INSERT INTO policies (id, name, priority, path_pattern, action, created_at, \
             updated_at) VALUES ($1, $1, 0, $2, 'deny', 1, 1)",
            vec![id.clone(), path.clone()],
        );
        eventually("the stored denial", || get(port, &path, ip, "curl/8", "").status() == 403);
        let response = get(port, &path, ip, "curl/8", "Accept: text/html\r\n");
        assert!(response.contains(&format!("Sibuna refused this request (403): {id}.")));
        execute(storage, "DELETE FROM policies WHERE id = $1", vec![id.clone()]);
        eventually("the removal", || get(port, &path, ip, "curl/8", "").status() == 401);
        assert!(daemon.stop(), "{}", backend.label);
    }
}

#[test]
fn honeypot_bans_persist_across_a_restart() {
    for backend in backends() {
        let n = unique();
        let ip = format!("198.19.{}.{}", n / 250 % 250, n % 250 + 1);
        let daemon = start(&backend.config);
        let port = port_of(&daemon);
        assert_eq!(get(port, "/__sibuna/honeypot", &ip, "Scrapy/2.0", "").status(), 403);
        let storage = daemon.storage().unwrap();
        let query = "SELECT reputation_score, banned_until, trigger_rule FROM ip_reputation \
                     WHERE ip_or_cidr = $1";
        eventually("the persisted ban", || !fetch(storage, query, vec![ip.clone()]).is_empty());
        let row = fetch(storage, query, vec![ip.clone()]).remove(0);
        assert_eq!((row[0].as_str(), row[2].as_str()), ("-100", "honeypot"), "{}", backend.label);
        assert!(row[1].parse::<u64>().unwrap() > 1_700_000_000);
        assert!(daemon.stop());
        // A new process has an empty ban table; the stored reputation still bans the address.
        let restarted = start(&backend.config);
        let port = port_of(&restarted);
        let response = get(port, "/robots.txt", &ip, "curl/8", "Accept: text/html\r\n");
        assert_eq!(response.status(), 403, "{}", backend.label);
        assert!(response.contains("ip/cidr-trie"));
        assert_eq!(get(port, "/robots.txt", "198.18.1.1", "curl/8", "").status(), 200);
        let storage = restarted.storage().unwrap();
        execute(storage, "DELETE FROM ip_reputation WHERE ip_or_cidr = $1", vec![ip.clone()]);
        eventually("the lifted ban", || {
            get(port, "/robots.txt", &ip, "curl/8", "").status() == 200
        });
        assert!(restarted.stop());
    }
}

#[test]
fn waf_denials_are_recorded_as_searchable_incidents() {
    for backend in backends() {
        let n = unique();
        let ip = format!("198.18.{}.{}", 2 + n / 250 % 200, n % 250 + 1);
        let daemon = start(&backend.config);
        let port = port_of(&daemon);
        let attack = format!("/search{n}?q=1%27%20union%20select%20null--");
        assert_eq!(get(port, &attack, &ip, "curl/8", "").status(), 403);
        let storage = daemon.storage().unwrap();
        let query = "SELECT violation_category, path, offending_payload, method, user_agent \
                     FROM security_incidents WHERE client_ip = $1";
        eventually("the incident", || !fetch(storage, query, vec![ip.clone()]).is_empty());
        let row = fetch(storage, query, vec![ip.clone()]).remove(0);
        assert_eq!(row[0], "waf:sqli", "{}", backend.label);
        assert_eq!(row[1], format!("/search{n}"));
        assert_eq!(row[2], "q=1%27%20union%20select%20null--");
        assert_eq!((row[3].as_str(), row[4].as_str()), ("GET", "curl/8"));
        // FTS5 reads the word inside the path; PostgreSQL's parser keeps the path as one token.
        let term =
            if backend.label == "postgres" { format!("/search{n}") } else { format!("search{n}") };
        let hits = storage.search_incidents(&term, 10).unwrap();
        assert!(hits.iter().any(|hit| hit.client_ip == ip), "{}: {hits:?}", backend.label);
        let server = daemon.server().unwrap();
        assert!(server.metrics().incidents_persisted.value() >= 1);
        assert!(daemon.stop());
    }
}
