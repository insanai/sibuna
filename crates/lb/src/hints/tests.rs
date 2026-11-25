#![allow(clippy::unwrap_used)]

#[cfg(all(unix, target_pointer_width = "64"))]
mod scale;

use super::*;
use crate::Config;

/// The life of a choice in these tests, in milliseconds.
const TTL: u64 = 600_000;

fn spill(source: &str) -> io::Result<Option<SpillOptions>> {
    let text = format!(
        r#"{{{source}"frontends":{{"web":{{"binds":["127.0.0.1:1"],"default_backend":"app"}}}},
        "backends":{{"app":{{"servers":[{{"name":"a","addr":"127.0.0.1:2"}}]}}}}}}"#
    );
    Config::parse(text.as_bytes()).map(|config| config.spill().cloned())
}

#[test]
fn the_spill_section_is_off_by_default_and_has_bounds() {
    assert_eq!(spill("").unwrap(), None);
    let least = spill(r#""spill":{"path":"/tmp/h","size":"64k"},"#).unwrap().unwrap();
    assert_eq!((least.path, least.size), (PathBuf::from("/tmp/h"), 64 << 10));
    let most = spill(r#""spill":{"path":"h","size":"64g"},"#).unwrap().unwrap();
    assert_eq!(most.size, 64 << 30);
    for (bad, word) in [
        (r#""spill":{"size":"1m"},"#, "path"),
        (r#""spill":{"path":"","size":"1m"},"#, "spill.path"),
        (r#""spill":{"path":"h"},"#, "size"),
        (r#""spill":{"path":"h","size":"1k"},"#, "spill.size"),
        (r#""spill":{"path":"h","size":"65g"},"#, "spill.size"),
        (r#""spill":{"path":"h","size":"lots"},"#, "spill.size"),
        (r#""spill":{"path":"h","size":"1m","shards":8},"#, "shards"),
    ] {
        let error = spill(bad).unwrap_err().to_string();
        assert!(error.contains(word), "{bad}: {error}");
    }
}

/// The options of a tier on a file of its own in the temporary directory, or in the
/// directory that `SIBUNA_SPILL_DIR` names.
fn on_disk(name: &str, size: u64) -> SpillOptions {
    let directory =
        std::env::var_os("SIBUNA_SPILL_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let path = directory.join(format!("sibuna-hints-{}-{name}.spill", std::process::id()));
    std::fs::File::create_new(&path).expect("the measurement needs a fresh path");
    SpillOptions { path, size }
}

/// Opens the tier with a table of `slots` in front. Returns its owner and the store.
fn open(options: &SpillOptions, slots: usize) -> (Spill, Arc<dyn AffinityStore>) {
    let cluster = ClusterState::new(slots);
    let spill = Spill::open(Some(options), slots, &cluster).unwrap();
    let store = Arc::clone(cluster.store());
    (spill, store)
}

/// Waits until the storage thread has served everything that was queued.
fn drained(spill: &Spill) {
    loop {
        let disk = spill.status().unwrap().disk;
        let cache = disk.cache;
        let served = cache.lookups
            + cache.stored
            + cache.updated
            + cache.kept
            + cache.replaced
            + cache.rejected
            + cache.refused;
        if served >= disk.queued {
            return;
        }
        std::thread::yield_now();
    }
}

/// The key of client number `client`: bytes that look like a keyed hash.
fn key(client: u64) -> AffinityKey {
    let low = client.wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let high = low.rotate_left(29).wrapping_mul(0xff51_afd7_ed55_8ccd);
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&low.to_le_bytes());
    bytes[8..].copy_from_slice(&high.to_le_bytes());
    AffinityKey(bytes)
}

/// Serves client number `client` once, as a pool does: a lookup, and a choice when the
/// lookup found nothing. Returns the server that the lookup found.
fn flow(store: &dyn AffinityStore, client: u64, server: u64) -> Option<u64> {
    let now = unix_ms();
    let found = store.find(&key(client), now);
    if found.is_none() {
        store.keep(&key(client), Affinity { server, ends: now + TTL }, now);
    }
    found.map(|entry| entry.server)
}

#[test]
fn a_choice_is_encoded_in_the_value_of_a_hint() {
    let entry = Affinity { server: 0x0102_0304_0506_0708, ends: 1_800_000_000_123 };
    assert_eq!(decode(&encode(entry)), Some(entry));
    assert_eq!(decode(&encode(entry)[..15]), None);
    assert_eq!(decode(&[0; 17]), None);
}

#[test]
fn a_choice_is_found_again_after_the_file_was_closed_and_opened() {
    let options = on_disk("again", 1 << 20);
    let (spill, store) = open(&options, 1024);
    assert_eq!(spill.status().unwrap().outcome, Some(Outcome::Created));
    for client in 0..200 {
        assert_eq!(flow(&*store, client, 1_000 + client), None);
        drained(&spill);
    }
    drop((spill, store));

    let (spill, store) = open(&options, 1024);
    assert_eq!(spill.status().unwrap().outcome, Some(Outcome::Reused));
    let now = unix_ms();
    for client in 0..200 {
        // The first lookup finds memory empty and asks. The next one has the answer.
        assert_eq!(store.find(&key(client), now), None);
        drained(&spill);
        assert_eq!(store.find(&key(client), now).map(|e| e.server), Some(1_000 + client));
    }
    let status = spill.status().unwrap();
    assert_eq!((status.asked, status.promoted, status.preferred), (200, 200, 0));
    assert_eq!(status.table_slots, 1024);
    // An unknown client is asked for and stays unknown.
    assert_eq!(store.find(&key(900), now), None);
    drained(&spill);
    assert_eq!(store.find(&key(900), now), None);
    drop((spill, store));
    let _ = std::fs::remove_file(&options.path);
}

#[test]
fn a_guess_made_while_the_disk_is_asked_gives_way_to_what_the_disk_knows() {
    let options = on_disk("guess", 1 << 20);
    let (spill, store) = open(&options, 1024);
    for client in 0..100 {
        flow(&*store, client, 21);
        drained(&spill);
    }
    drop((spill, store));

    // After a restart the ranking would choose another server. Whether the answer of
    // the disk comes before or after that choice is stored, the disk wins.
    let (spill, store) = open(&options, 1024);
    for client in 0..100 {
        assert_eq!(flow(&*store, client, 11), None);
        if client % 2 == 0 {
            drained(&spill);
        }
        // A second flow that comes at once may still see the guess. It does not make
        // the guess definite: the lookup found an entry, so nothing is stored.
        let seen = flow(&*store, client, 11);
        assert!(seen == Some(11) || seen == Some(21), "{seen:?}");
    }
    drained(&spill);
    let now = unix_ms();
    for client in 0..100 {
        assert_eq!(store.find(&key(client), now).map(|entry| entry.server), Some(21));
    }
    let status = spill.status().unwrap();
    assert_eq!(status.preferred, 100, "{status:?}");
    assert_eq!(status.disk.cache.updated + status.disk.cache.replaced, 0);
    drop((spill, store));

    // The disk still holds what it knew.
    let (spill, store) = open(&options, 1024);
    for client in 0..100 {
        store.find(&key(client), now);
    }
    drained(&spill);
    for client in 0..100 {
        assert_eq!(store.find(&key(client), now).map(|entry| entry.server), Some(21));
    }
    drop((spill, store));
    let _ = std::fs::remove_file(&options.path);
}

#[test]
fn a_change_of_a_known_choice_replaces_the_hint_on_disk() {
    let options = on_disk("change", 1 << 20);
    let (spill, store) = open(&options, 1024);
    let now = unix_ms();
    assert_eq!(flow(&*store, 7, 21), None);
    drained(&spill);
    // The server of the client could not serve and another did: the later end wins in
    // memory, and the disk follows.
    let moved = Affinity { server: 22, ends: now + TTL + 1 };
    assert_eq!(store.keep(&key(7), moved, now), Kept::Stored);
    drained(&spill);
    assert_eq!(spill.status().unwrap().disk.cache.updated, 1);
    drop((spill, store));
    let (spill, store) = open(&options, 1024);
    store.find(&key(7), now);
    drained(&spill);
    assert_eq!(store.find(&key(7), now), Some(moved));
    drop((spill, store));
    let _ = std::fs::remove_file(&options.path);
}

/// How many of the clients `0..count` have a hint on the disk of `options`.
fn on_disk_count(options: &SpillOptions, count: u64) -> u64 {
    let (spill, store) = open(options, 1024);
    for client in 0..count {
        store.find(&key(client), unix_ms());
        drained(&spill);
    }
    spill.status().unwrap().disk.cache.hits
}

#[test]
fn a_flood_of_clients_seen_once_displaces_no_hint_on_disk() {
    const RESIDENTS: u64 = 300;
    // 768 slots on disk and 1,024 in memory.
    let options = on_disk("flood", 64 << 10);
    let (spill, store) = open(&options, 1024);
    for client in 0..RESIDENTS {
        flow(&*store, client, 21);
        drained(&spill);
    }
    drop((spill, store));
    let before = on_disk_count(&options, RESIDENTS);
    assert!(before > RESIDENTS * 3 / 4, "{before}");

    // Twenty-six clients for every slot come once each. Each asks the disk and
    // guesses, and leaves memory when later ones need its slot.
    let (spill, store) = open(&options, 1024);
    for client in 1_000..21_000 {
        flow(&*store, client, 11);
        if client % 500 == 0 {
            drained(&spill);
        }
    }
    drained(&spill);
    let cache = spill.status().unwrap().disk.cache;
    assert_eq!(cache.replaced + cache.updated, 0, "{cache:?}");
    drop((spill, store));
    assert_eq!(on_disk_count(&options, RESIDENTS), before);
    let _ = std::fs::remove_file(&options.path);
}

#[test]
fn a_file_in_use_leaves_the_table_in_memory_and_a_second_store_is_refused() {
    let options = on_disk("busy", 1 << 20);
    let (first, _store) = open(&options, 1025);
    let (second, store) = open(&options, 1025);
    assert_eq!(first.status().unwrap().table_slots, 2048);
    assert_eq!(second.status().unwrap().table_slots, 2048);
    assert_eq!(second.status().unwrap().budget.memory_bytes(), (PENDING * 8) as u64);
    let status = second.status().unwrap();
    assert_eq!((status.outcome, status.slots), (None, 0));
    assert_eq!(flow(&*store, 1, 21), None);
    assert_eq!(flow(&*store, 1, 22), Some(21));
    assert_eq!(second.status().unwrap().asked, 0);
    // A cluster state that has a store cannot take the tier.
    let cluster = ClusterState::new(1024);
    assert!(cluster.use_store(Arc::new(AffinityTable::new(1024))));
    drop(second);
    drop(first);
    let error = Spill::open(Some(&options), 1024, &cluster).err().unwrap().to_string();
    assert!(error.contains("has a store"), "{error}");
    assert!(Spill::open(None, 1024, &cluster).unwrap().status().is_none());
    let _ = std::fs::remove_file(&options.path);
}

/// The resident memory of this process in KiB: all of it, the anonymous part and the
/// part that maps files.
fn resident() -> [u64; 3] {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    ["VmRSS:", "RssAnon:", "RssFile:"].map(|name| {
        let line = status.lines().find_map(|line| line.strip_prefix(name));
        line.and_then(|rest| rest.split_whitespace().next()?.parse().ok()).unwrap_or(0)
    })
}

fn measured(phase: &str, operations: u64, started: std::time::Instant) {
    let seconds = started.elapsed().as_secs_f64();
    let [all, anonymous, file] = resident();
    eprintln!(
        "{phase:<40} {operations:>9} ops {seconds:>6.2} s {:>6.2} M ops/s  rss {all} KiB \
         (anonymous {anonymous}, file {file})",
        operations as f64 / seconds / 1e6
    );
}

/// Four threads serve flows of the clients below `span` without a pause.
fn measured_threads(name: &str, spill: &Spill, store: &dyn AffinityStore, span: u64) {
    let started = std::time::Instant::now();
    std::thread::scope(|scope| {
        for worker in 0..4u64 {
            scope.spawn(move || {
                for round in 0..1_000_000u64 {
                    let client = (round * 4 + worker).wrapping_mul(2_654_435_761) % span;
                    flow(store, client, client);
                }
            });
        }
    });
    measured(name, 4_000_000, started);
    let status = spill.status().unwrap();
    eprintln!("  asked {}, shed {}", status.asked, status.disk.shed);
}

/// Measures both tiers with a working set of thirty times the table in memory.
///
/// ```sh
/// SIBUNA_SPILL_DIR=/var/tmp cargo test --release -p sibuna-lb --lib measure_two_tiers \
///     -- --ignored --nocapture
/// ```
#[test]
#[ignore = "a measurement, not a check"]
fn measure_two_tiers() {
    const CLIENTS: u64 = 2_000_000;
    const BATCH: u64 = 1_000;
    let options = on_disk("measure", 256 << 20);
    let (spill, store) = open(&options, 65_536);
    let status = spill.status().unwrap();
    eprintln!("table {} slots, disk {} slots", status.table_slots, status.slots);
    eprintln!("{:?}", status.budget);

    // Every client is served once: a miss, a choice, a guess for the disk.
    let started = std::time::Instant::now();
    for first in (0..CLIENTS).step_by(BATCH as usize) {
        for client in first..first + BATCH {
            flow(&*store, client, client);
        }
        drained(&spill);
    }
    measured("first flow of 2,000,000 clients", CLIENTS, started);

    // Every client returns. Its first flow finds memory empty, the second its choice.
    let started = std::time::Instant::now();
    let (mut in_memory, mut retained) = (0u64, 0u64);
    for first in (0..CLIENTS).step_by(BATCH as usize) {
        let now = unix_ms();
        for client in first..first + BATCH {
            in_memory += u64::from(store.find(&key(client), now).is_some());
        }
        drained(&spill);
        for client in first..first + BATCH {
            let found = store.find(&key(client), now).map(|entry| entry.server);
            retained += u64::from(found == Some(client));
        }
    }
    measured("return of 2,000,000 clients, 2 lookups", 2 * CLIENTS, started);
    eprintln!("  still in memory {in_memory}, found at the second lookup {retained} of {CLIENTS}");
    let status = spill.status().unwrap();
    eprintln!("  promoted {}, {:?}", status.promoted, status.disk);

    // What a worker pays: four threads on clients that fit in memory, then on all.
    measured_threads("4 threads, 16,000 clients (hits)", &spill, &*store, 16_000);
    measured_threads("4 threads, all (misses)", &spill, &*store, CLIENTS);
    drop((spill, store));
    let _ = std::fs::remove_file(&options.path);
}
