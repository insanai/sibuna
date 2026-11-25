//! Learned source affinity with a disk tier (SID 0027) at the routing interface.
#![allow(clippy::unwrap_used)]

mod free;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge, HttpRoutes, Query, ServerState};
use sibuna_spill::Outcome;

/// The clients of every test.
const CLIENTS: u16 = 300;

/// A directory of its own for one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-lb-hints-{}-{serial}", std::process::id());
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("hints.spill")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A topology with one HTTP frontend on `vip` and a pool that is sticky by source.
/// `weights` gives the weight of each server, on ports from 9500. `spill` is the whole
/// `spill` member with its comma, or nothing.
fn topology(vip: SocketAddr, weights: &[u32], spill: &str) -> Config {
    let rows: Vec<String> = weights
        .iter()
        .enumerate()
        .map(|(i, weight)| {
            format!(r#"{{"name":"s{i}","addr":"127.0.0.1:{}","weight":{weight}}}"#, 9500 + i)
        })
        .collect();
    let source = format!(
        r#"{{{spill}"frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","sticky":"source","servers":[{}]}}}}}}"#,
        rows.join(",")
    );
    Config::parse(source.as_bytes()).unwrap()
}

fn spill(path: &Path) -> String {
    format!(r#""spill":{{"path":"{}","size":"1m","memory":"64k"}},"#, path.display())
}

/// The port of the server that serves client number `client` now.
fn serve(routes: &HttpRoutes, vip: SocketAddr, client: u16) -> u16 {
    serve_at(routes, vip, client, 1)
}

/// [`serve`] for a request that was decided under revision `revision` of the routes.
fn serve_at(routes: &HttpRoutes, vip: SocketAddr, client: u16, revision: u64) -> u16 {
    let peer = SocketAddr::from(([198, 18, (client >> 8) as u8, client as u8], 40_000));
    let query = Query {
        vip,
        peer,
        host: b"app.example",
        path: b"/",
        policy_revision: revision,
        ..Query::default()
    };
    routes.choose(&query).unwrap().address().port()
}

/// Serves every client twice and returns the server of each. The second request makes
/// the hint definite, which sends it to the disk.
fn settle(routes: &HttpRoutes, vip: SocketAddr) -> Vec<u16> {
    let homes: Vec<u16> = (0..CLIENTS).map(|client| serve(routes, vip, client)).collect();
    for client in 0..CLIENTS {
        assert_eq!(serve(routes, vip, client), homes[usize::from(client)]);
    }
    homes
}

/// Waits until the disk has answered `count` questions with a hint.
fn promoted(edge: &Edge, count: u64) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while edge.spill_status().unwrap().promoted < count {
        assert!(Instant::now() < deadline, "{:?}", edge.spill_status());
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_client_keeps_its_server_when_a_heavy_server_joins() {
    let scratch = Scratch::new();
    let vip = free::tcp();
    let section = spill(&scratch.file());
    let mut edge = Edge::bind(topology(vip, &[1, 1], &section)).unwrap();
    let routes = edge.http_routes();
    let status = edge.spill_status().unwrap();
    assert_eq!(status.outcome, Some(Outcome::Created));
    assert!(status.slots > 15_000 && status.entries == 4096);
    let homes = settle(&routes, vip);
    assert!(homes.contains(&9500) && homes.contains(&9501));
    // A server with almost all the weight joins. The ranking would move nearly every
    // client to it. The clients that were served stay.
    edge.reload(topology(vip, &[1, 1, 200], &section)).unwrap();
    for client in 0..CLIENTS {
        assert_eq!(serve_at(&routes, vip, client, 2), homes[usize::from(client)], "{client}");
    }
    // Clients that were never served follow the ranking.
    let moved = (1000..1300).filter(|&client| serve_at(&routes, vip, client, 2) == 9502).count();
    assert!(moved > 270, "{moved}");
    // A server that is drained gives up its clients, and they keep their new server
    // when it returns: the hint follows the choice.
    edge.set_server_state("app", "s0", ServerState::Drain).unwrap();
    let refuges: Vec<u16> = (0..CLIENTS).map(|client| serve_at(&routes, vip, client, 2)).collect();
    for (home, refuge) in homes.iter().zip(&refuges) {
        assert_eq!(home == refuge, *home != 9500);
        assert_ne!(*refuge, 9500);
    }
    edge.set_server_state("app", "s0", ServerState::Ready).unwrap();
    for client in 0..CLIENTS {
        assert_eq!(serve_at(&routes, vip, client, 2), refuges[usize::from(client)], "{client}");
    }
    let status = edge.spill_status().unwrap();
    assert!(status.hits >= 4 * u64::from(CLIENTS) && status.misses >= u64::from(CLIENTS));
}

#[test]
fn hints_survive_a_restart_of_the_edge() {
    let scratch = Scratch::new();
    let section = spill(&scratch.file());
    let vip = free::tcp();
    let edge = Edge::bind(topology(vip, &[1, 1], &section)).unwrap();
    let homes = settle(&edge.http_routes(), vip);
    // The edge ends. Its storage thread writes what is queued and flushes the file.
    drop(edge);

    // A new edge on the same file, with a heavy server that the old one did not have.
    let vip = free::tcp();
    let edge = Edge::bind(topology(vip, &[1, 1, 200], &section)).unwrap();
    let routes = edge.http_routes();
    assert_eq!(edge.spill_status().unwrap().outcome, Some(Outcome::Reused));
    // The first flow of a client finds the table in memory empty and goes on without a
    // hint. The disk answers, and the answer replaces that choice.
    let first: Vec<u16> = (0..CLIENTS).map(|client| serve(&routes, vip, client)).collect();
    assert!(first.iter().filter(|&&port| port == 9502).count() > 270);
    promoted(&edge, u64::from(CLIENTS));
    for client in 0..CLIENTS {
        assert_eq!(serve(&routes, vip, client), homes[usize::from(client)], "{client}");
    }
    let status = edge.spill_status().unwrap();
    assert_eq!(status.disk.cache.hits, u64::from(CLIENTS));
    assert_eq!(status.disk.shed, 0);
    drop((routes, edge));

    // Without the file the same clients follow the ranking to the heavy server.
    std::fs::remove_file(scratch.file()).unwrap();
    let vip = free::tcp();
    let edge = Edge::bind(topology(vip, &[1, 1, 200], &section)).unwrap();
    assert_eq!(edge.spill_status().unwrap().outcome, Some(Outcome::Created));
    let fresh = settle(&edge.http_routes(), vip);
    assert!(fresh.iter().filter(|&&port| port == 9502).count() > 270);
}

#[test]
fn a_damaged_file_costs_the_hints_and_the_edge_serves_on() {
    let scratch = Scratch::new();
    let section = spill(&scratch.file());
    let vip = free::tcp();
    let edge = Edge::bind(topology(vip, &[1, 1], &section)).unwrap();
    let homes = settle(&edge.http_routes(), vip);
    drop(edge);
    // Noise over every slot of the file. The header stays, so the file is reused.
    let mut bytes = std::fs::read(scratch.file()).unwrap();
    for (at, byte) in bytes.iter_mut().enumerate().skip(8192) {
        *byte = (at * 131 % 251) as u8 | 1;
    }
    std::fs::write(scratch.file(), &bytes).unwrap();
    let vip = free::tcp();
    let edge = Edge::bind(topology(vip, &[1, 1, 200], &section)).unwrap();
    let routes = edge.http_routes();
    assert_eq!(edge.spill_status().unwrap().outcome, Some(Outcome::Reused));
    let first: Vec<u16> = (0..CLIENTS).map(|client| serve(&routes, vip, client)).collect();
    // No hint comes back, so every client keeps the server the ranking gave it.
    for client in 0..CLIENTS {
        assert_eq!(serve(&routes, vip, client), first[usize::from(client)]);
    }
    assert!(first.iter().filter(|&&port| port == 9502).count() > 270);
    assert_ne!(first, homes);
    let deadline = Instant::now() + Duration::from_secs(20);
    while edge.spill_status().unwrap().disk.cache.lookups < u64::from(CLIENTS) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let status = edge.spill_status().unwrap();
    assert_eq!((status.promoted, status.disk.cache.hits), (0, 0));
    assert!(status.disk.cache.corrupt > 0);
}

#[test]
fn a_file_that_is_not_a_cache_stops_the_edge_and_stays_as_it_is() {
    let scratch = Scratch::new();
    std::fs::write(scratch.file(), b"the notes of somebody").unwrap();
    let config = topology(free::tcp(), &[1, 1], &spill(&scratch.file()));
    let error = Edge::bind(config).err().unwrap().to_string();
    assert!(error.contains("SPILL002") && error.contains("Hint:"), "{error}");
    assert_eq!(std::fs::read(scratch.file()).unwrap(), b"the notes of somebody");
}

#[test]
fn a_second_edge_on_the_file_runs_with_the_table_in_memory() {
    let scratch = Scratch::new();
    let section = spill(&scratch.file());
    let first = Edge::bind(topology(free::tcp(), &[1, 1], &section)).unwrap();
    let vip = free::tcp();
    let second = Edge::bind(topology(vip, &[1, 1], &section)).unwrap();
    let status = second.spill_status().unwrap();
    assert_eq!((status.outcome, status.persistent, status.slots), (None, false, 0));
    // The table in memory still keeps every client on its server.
    let routes = second.http_routes();
    let homes = settle(&routes, vip);
    second_reload(second, vip, &section, &homes);
    drop(first);
}

/// Reloads `edge` with a heavy third server and checks that the clients stay.
fn second_reload(mut edge: Edge, vip: SocketAddr, section: &str, homes: &[u16]) {
    edge.reload(topology(vip, &[1, 1, 200], section)).unwrap();
    let routes = edge.http_routes();
    for client in 0..CLIENTS {
        assert_eq!(serve_at(&routes, vip, client, 2), homes[usize::from(client)], "{client}");
    }
}

#[test]
fn the_spill_section_changes_only_with_a_restart_and_is_off_without_it() {
    let scratch = Scratch::new();
    let vip = free::tcp();
    let mut edge = Edge::bind(topology(vip, &[1, 1], &spill(&scratch.file()))).unwrap();
    let other = format!(r#""spill":{{"path":"{}","size":"2m"}},"#, scratch.file().display());
    for changed in [other.as_str(), ""] {
        let error = edge.reload(topology(vip, &[1, 1], changed)).err().unwrap().to_string();
        assert!(error.contains("spill section requires a restart"), "{error}");
    }
    // An edge without the section keeps no table and follows the ranking.
    let vip = free::tcp();
    let mut plain = Edge::bind(topology(vip, &[1, 1], "")).unwrap();
    assert!(plain.spill_status().is_none());
    let routes = plain.http_routes();
    settle(&routes, vip);
    plain.reload(topology(vip, &[1, 1, 200], "")).unwrap();
    let moved = (0..CLIENTS).filter(|&client| serve_at(&routes, vip, client, 2) == 9502).count();
    assert!(moved > 270, "{moved}");
}
