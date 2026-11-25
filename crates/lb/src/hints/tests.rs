#![allow(clippy::unwrap_used)]

use super::*;
use crate::Config;

const NOW: u32 = 1_800_000_000;
const TTL: u32 = 600;

impl Hints {
    /// Hints with the table in memory alone, as when another process holds the file.
    fn without_disk(memory: u64) -> Self {
        let options = SpillOptions {
            path: PathBuf::from("unused"),
            size: 1 << 20,
            memory,
            ttl: Duration::from_secs(u64::from(TTL)),
        };
        let table = Arc::new(Table::new(memory, TTL));
        let status = SpillStatus {
            path: options.path,
            outcome: None,
            persistent: false,
            slots: 0,
            entries: table.entries.len() as u64,
            budget: Budget::default(),
            table_bytes: table.entries.len() as u64 * ENTRY_LEN,
            disk: ServiceCounters::default(),
            hits: 0,
            misses: 0,
            promoted: 0,
        };
        Self { table, service: None, status, ttl: TTL, counters: Arc::default() }
    }
}

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
    assert_eq!(least.path, PathBuf::from("/tmp/h"));
    assert_eq!((least.size, least.memory), (64 << 10, 1 << 20));
    assert_eq!(least.ttl, Duration::from_secs(3600));
    let all = r#""spill":{"path":"h","size":"2g","memory":"8m","ttl":"30m"},"#;
    let all = spill(all).unwrap().unwrap();
    assert_eq!((all.size, all.memory, all.ttl), (2 << 30, 8 << 20, Duration::from_secs(1800)));
    for (bad, word) in [
        (r#""spill":{"size":"1m"},"#, "path"),
        (r#""spill":{"path":"","size":"1m"},"#, "spill.path"),
        (r#""spill":{"path":"h"},"#, "size"),
        (r#""spill":{"path":"h","size":"1k"},"#, "spill.size"),
        (r#""spill":{"path":"h","size":"65g"},"#, "spill.size"),
        (r#""spill":{"path":"h","size":"lots"},"#, "spill.size"),
        (r#""spill":{"path":"h","size":"1m","memory":"1k"},"#, "spill.memory"),
        (r#""spill":{"path":"h","size":"1m","memory":"2g"},"#, "spill.memory"),
        (r#""spill":{"path":"h","size":"1m","ttl":"30s"},"#, "spill.ttl"),
        (r#""spill":{"path":"h","size":"1m","ttl":"721h"},"#, "spill.ttl"),
        (r#""spill":{"path":"h","size":"1m","shards":8},"#, "shards"),
    ] {
        let error = spill(bad).unwrap_err().to_string();
        assert!(error.contains(word), "{bad}: {error}");
    }
}

#[test]
fn without_a_disk_every_choice_is_definite_and_follows_the_server() {
    let hints = Hints::without_disk(4 << 10);
    assert_eq!(hints.status().entries, 256);
    assert_eq!(hints.recall(7, NOW), Recall::Miss);
    hints.learn(7, 11, true, NOW);
    let (_, held) = hints.table.find(7, NOW).unwrap();
    assert_eq!(held, Found { tag: 11, tentative: false, expires: NOW + TTL });
    assert_eq!(hints.recall(7, NOW), Recall::Hit(11));
    hints.learn(7, 11, false, NOW + 1);
    let (_, held) = hints.table.find(7, NOW + 1).unwrap();
    assert_eq!(held, Found { tag: 11, tentative: false, expires: NOW + TTL });
    // A second miss of the same client leaves what is there.
    hints.learn(7, 12, true, NOW + 2);
    assert_eq!(hints.recall(7, NOW + 2), Recall::Hit(11));
    // The hinted server could not serve and another did: the hint follows.
    hints.learn(7, 12, false, NOW + 3);
    assert_eq!(hints.recall(7, NOW + 3), Recall::Hit(12));
    let status = hints.status();
    assert_eq!((status.hits, status.misses), (3, 1));
}

#[test]
fn a_hint_expires_and_is_renewed_in_the_second_half_of_its_life() {
    let hints = Hints::without_disk(4 << 10);
    hints.learn(7, 11, false, NOW);
    let expiry = |at| hints.table.find(7, at).map(|(_, held)| held.expires);
    // In the first half a use writes nothing.
    hints.learn(7, 11, false, NOW + TTL / 2);
    assert_eq!(expiry(NOW + TTL / 2), Some(NOW + TTL));
    hints.learn(7, 11, false, NOW + TTL / 2 + 1);
    assert_eq!(expiry(NOW + TTL / 2 + 1), Some(NOW + TTL / 2 + 1 + TTL));
    assert_eq!(hints.recall(7, NOW + TTL / 2 + TTL), Recall::Hit(11));
    assert_eq!(hints.recall(7, NOW + TTL / 2 + 1 + TTL), Recall::Miss);
    // An entry from a future that no hint can have, as a clock set back leaves it.
    assert_eq!(hints.recall(7, NOW - 1), Recall::Miss);
}

#[test]
fn the_halves_of_two_writes_do_not_make_a_hint() {
    let table = Table::new(4 << 10, TTL);
    let mut wrong = 0;
    for key in 1..=50_000u64 {
        let key = key.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let other = key.rotate_left(17) | 1;
        let entry = Entry::default();
        Table::write(&entry, other, Found { tag: 5, tentative: false, expires: NOW + 60 });
        // A reader catches the key of one write and the rest of another.
        entry.key.store(key, Ordering::Relaxed);
        wrong += usize::from(table.read(&entry, key, NOW).is_some());
        entry.key.store(other, Ordering::Relaxed);
        assert!(table.read(&entry, other, NOW).is_some());
    }
    // Noise passes the expiry check with a chance of 600 in 2^32 for each try.
    assert_eq!(wrong, 0);
}

#[test]
fn a_full_set_gives_up_a_tentative_hint_first_and_reports_a_definite_one() {
    // One set of four entries.
    let table = Table::new(64, TTL);
    assert_eq!(table.entries.len(), 4);
    let hint = |tag, tentative| Found { tag, tentative, expires: NOW + TTL };
    for key in 1..=3 {
        assert_eq!(table.insert(key, hint(key as u32, false), NOW), None);
    }
    assert_eq!(table.insert(4, hint(4, true), NOW), None);
    // The tentative hint leaves without a word.
    assert_eq!(table.insert(5, hint(5, false), NOW), None);
    assert!(table.find(4, NOW).is_none());
    // Now a definite hint must leave, and the caller hears which.
    let (old_key, old) = table.insert(6, hint(6, false), NOW).unwrap();
    assert!([1, 2, 3, 5].contains(&old_key) && old.tag == old_key as u32);
    assert!(table.find(old_key, NOW).is_none());
    assert_eq!(table.find(6, NOW).map(|(_, held)| held.tag), Some(6));
    // An expired hint is free space.
    let later = Found { tag: 7, tentative: false, expires: NOW + 2 * TTL };
    assert_eq!(table.insert(7, later, NOW + TTL), None);
    // The same key is written in place.
    assert_eq!(table.insert(7, Found { tag: 8, ..later }, NOW + TTL), None);
    assert_eq!(table.find(7, NOW + TTL).map(|(_, held)| held.tag), Some(8));
}

#[test]
fn the_answer_of_the_disk_replaces_a_tentative_hint_and_no_definite_one() {
    let mut cache =
        sibuna_spill::load_memory_cache(&sibuna_spill::Options { size: 1 << 20, max_ttl: 600 })
            .unwrap();
    let wall = sibuna_spill::unix_seconds();
    let stored = |cache: &mut sibuna_spill::Cache, key: u64, tag: u32| {
        cache.put(&key.to_le_bytes(), &tag.to_le_bytes(), wall + 300, wall);
        cache.get(&key.to_le_bytes(), wall).unwrap()
    };
    let (table, counters) = (Table::new(4 << 10, TTL), Counters::default());
    let clock = now();
    let hint = |tag, tentative| Found { tag, tentative, expires: clock + TTL };
    // Nothing in memory: the answer fills it.
    promote(&table, &counters, &1u64.to_le_bytes(), &stored(&mut cache, 1, 21));
    let (_, held) = table.find(1, clock).unwrap();
    assert_eq!((held.tag, held.tentative), (21, false));
    assert!(u64::from(held.expires) <= wall + 300);
    // A choice made without a hint gives way to the hint.
    table.insert(2, hint(9, true), clock);
    promote(&table, &counters, &2u64.to_le_bytes(), &stored(&mut cache, 2, 22));
    assert_eq!(
        table.find(2, clock).map(|(_, held)| (held.tag, held.tentative)),
        Some((22, false))
    );
    // A definite hint in memory is newer than the disk.
    table.insert(3, hint(9, false), clock);
    promote(&table, &counters, &3u64.to_le_bytes(), &stored(&mut cache, 3, 23));
    assert_eq!(table.find(3, clock).map(|(_, held)| held.tag), Some(9));
    assert_eq!(counters.promoted.load(Ordering::Relaxed), 2);
    // An answer that is not a hint of ours is ignored.
    cache.put(b"short", b"x", wall + 300, wall);
    let foreign = cache.get(b"short", wall).unwrap();
    promote(&table, &counters, b"short", &foreign);
    promote(&table, &counters, &0u64.to_le_bytes(), &stored(&mut cache, 4, 24));
    assert_eq!(counters.promoted.load(Ordering::Relaxed), 2);
}

#[test]
fn workers_that_learn_and_recall_at_once_read_only_hints_that_were_written() {
    // 64 entries for 512 keys: the workers overwrite each other all the time.
    let hints = Hints::without_disk(1 << 10);
    let tag_of =
        |key: u64, worker: u32| (key as u32).wrapping_mul(31).wrapping_add(worker) & !TENTATIVE;
    std::thread::scope(|scope| {
        for worker in 0..8u32 {
            let hints = &hints;
            scope.spawn(move || {
                let mut state = u64::from(worker) + 1;
                for _ in 0..200_000 {
                    state =
                        state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let key = (state >> 33) % 512 + 1;
                    match hints.recall(key, NOW) {
                        Recall::Miss => hints.learn(key, tag_of(key, worker), true, NOW),
                        Recall::Hit(tag) => {
                            let writer = tag.wrapping_sub((key as u32).wrapping_mul(31));
                            assert!(writer < 8, "key {key} read the tag {tag}");
                            hints.learn(key, tag_of(key, worker), false, NOW);
                        }
                    }
                }
            });
        }
    });
    let status = hints.status();
    assert_eq!(status.hits + status.misses, 8 * 200_000);
    assert!(status.hits > 0 && status.misses > 0);
}

#[test]
fn keys_and_tags_are_stable_and_never_zero() {
    let client = crate::sticky::client_bytes("192.0.2.9".parse().unwrap());
    let other = crate::sticky::client_bytes("192.0.2.10".parse().unwrap());
    let seed = pool_seed("app");
    assert_eq!(key(seed, &client), key(pool_seed("app"), &client));
    assert_ne!(key(seed, &client), key(seed, &other));
    assert_ne!(key(seed, &client), key(pool_seed("api"), &client));
    assert_ne!(key(seed, &client), 0);
    assert_eq!(tag(u64::MAX), 0x7fff_ffff);
    assert_eq!(tag(0x1_8000_0001), 1);
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

/// Waits until the storage thread has served everything that was queued.
fn drained(hints: &Hints) {
    loop {
        let disk = hints.status().disk;
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

fn measured(phase: &str, operations: u64, started: std::time::Instant) {
    let seconds = started.elapsed().as_secs_f64();
    let [all, anonymous, file] = resident();
    eprintln!(
        "{phase:<40} {operations:>9} ops {seconds:>6.2} s {:>6.2} M ops/s  rss {all} KiB \
         (anonymous {anonymous}, file {file})",
        operations as f64 / seconds / 1e6
    );
}

/// The key and the tag of client number `client` of the measurement.
fn measured_client(client: u64) -> (u64, u32) {
    let name = (u128::from(client) + 1).to_le_bytes();
    (key(pool_seed("app"), &name), (client as u32).wrapping_mul(7).wrapping_add(1) & !TENTATIVE)
}

/// Serves client number `client` once, as a pool does: recall, then learn.
fn measured_flow(hints: &Hints, client: u64) {
    let (key, tag) = measured_client(client);
    let missed = hints.recall(key, now()) == Recall::Miss;
    hints.learn(key, tag, missed, now());
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
    let directory =
        std::env::var_os("SIBUNA_SPILL_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let path = directory.join(format!("sibuna-lb-measure-{}.spill", std::process::id()));
    let ttl = Duration::from_secs(3600);
    let options = SpillOptions { path: path.clone(), size: 256 << 20, memory: 1 << 20, ttl };
    let (hints, disk) = Hints::open(Some(&options)).unwrap();
    let hints = hints.unwrap();
    let status = hints.status();
    eprintln!("table {} entries, disk {} slots", status.entries, status.slots);
    eprintln!("{:?}", status.budget);

    // Every client is served once: a miss, a choice, a guess for the disk.
    let started = std::time::Instant::now();
    for first in (0..CLIENTS).step_by(BATCH as usize) {
        (first..first + BATCH).for_each(|client| measured_flow(&hints, client));
        drained(&hints);
    }
    measured("first flow of 2,000,000 clients", CLIENTS, started);

    // Every client returns. Its first flow finds memory empty, the second its hint.
    let started = std::time::Instant::now();
    let (mut in_memory, mut retained) = (0u64, 0u64);
    for first in (0..CLIENTS).step_by(BATCH as usize) {
        for client in first..first + BATCH {
            let (key, _) = measured_client(client);
            in_memory += u64::from(hints.recall(key, now()) != Recall::Miss);
        }
        drained(&hints);
        for client in first..first + BATCH {
            let (key, tag) = measured_client(client);
            retained += u64::from(hints.recall(key, now()) == Recall::Hit(tag));
        }
    }
    measured("return of 2,000,000 clients, 2 flows", 2 * CLIENTS, started);
    eprintln!("  still in memory {in_memory}, hint on the second flow {retained} of {CLIENTS}");
    let status = hints.status();
    eprintln!("  promoted {}, {:?}", status.promoted, status.disk);

    // What a worker pays: four threads on clients that fit in memory, then on all.
    let spans =
        [("4 threads, 16,000 clients (hits)", 16_000), ("4 threads, all (misses)", CLIENTS)];
    for (name, span) in spans {
        let started = std::time::Instant::now();
        std::thread::scope(|scope| {
            for worker in 0..4u64 {
                let hints = &hints;
                scope.spawn(move || {
                    for round in 0..1_000_000u64 {
                        let client = (round * 4 + worker).wrapping_mul(2_654_435_761) % span;
                        measured_flow(hints, client);
                    }
                });
            }
        });
        measured(name, 4_000_000, started);
        let status = hints.status();
        eprintln!("  hits {}, misses {}, shed {}", status.hits, status.misses, status.disk.shed);
    }
    drop(disk);
    let _ = std::fs::remove_file(&path);
}

/// The options of hints on a file of their own in the temporary directory.
fn on_disk(name: &str, size: u64) -> SpillOptions {
    let file = format!("sibuna-hints-{}-{name}.spill", std::process::id());
    let path = std::env::temp_dir().join(file);
    let _ = std::fs::remove_file(&path);
    SpillOptions { path, size, memory: 64 << 10, ttl: Duration::from_secs(u64::from(TTL)) }
}

fn open(options: &SpillOptions) -> (Arc<Hints>, Disk) {
    let (hints, disk) = Hints::open(Some(options)).unwrap();
    (hints.unwrap(), disk)
}

#[test]
fn a_guess_never_becomes_definite_before_the_disk_has_answered() {
    let options = on_disk("guess", 1 << 20);
    let (hints, disk) = open(&options);
    let at = now();
    let ((known, _), (unknown, _)) = (measured_client(7), measured_client(8));
    // The disk knows the server of one client and nothing of the other.
    hints.learn(known, 21, false, at);
    drained(&hints);
    // Memory lost both, and each got a choice without a hint. Then a second flow of
    // each uses the guess, before any answer of the disk.
    let guess = Found { tag: 11, tentative: true, expires: at + TTL };
    for key in [known, unknown] {
        hints.table.insert(key, guess, at);
        assert_eq!(hints.recall(key, at), Recall::Hit(11));
        hints.learn(key, 11, false, at);
        let (_, held) = hints.table.find(key, at).unwrap();
        assert!(held.tentative || held != Found { tentative: false, ..guess } || key == unknown);
    }
    // The use asked the disk again. Its hint wins, and its silence confirms the guess.
    drained(&hints);
    let held = |key| hints.table.find(key, at).map(|(_, held)| (held.tag, held.tentative));
    assert_eq!(held(known), Some((21, false)));
    assert_eq!(held(unknown), Some((11, false)));
    // The disk still holds what it knew.
    drop(disk);
    let (hints, disk) = open(&options);
    assert_eq!(hints.recall(known, at), Recall::Miss);
    drained(&hints);
    assert_eq!(hints.table.find(known, at).map(|(_, held)| held.tag), Some(21));
    drop(disk);
    let _ = std::fs::remove_file(&options.path);
}

/// How many of the clients `0..count` have a hint on the disk of `options`.
fn on_disk_count(options: &SpillOptions, count: u64) -> u64 {
    let (hints, disk) = open(options);
    for client in 0..count {
        hints.recall(measured_client(client).0, now());
        drained(&hints);
    }
    let hits = hints.status().disk.cache.hits;
    drop(disk);
    hits
}

#[test]
fn a_flood_of_clients_seen_once_displaces_no_hint_on_disk() {
    const RESIDENTS: u64 = 300;
    // 768 slots on disk and 4,096 entries in memory.
    let options = on_disk("flood", 64 << 10);
    let (hints, disk) = open(&options);
    for client in 0..RESIDENTS {
        let (key, tag) = measured_client(client);
        hints.learn(key, tag, false, now());
        drained(&hints);
    }
    drop(disk);
    let before = on_disk_count(&options, RESIDENTS);
    assert!(before > RESIDENTS * 3 / 4, "{before}");

    // Twenty-six clients for every slot come once each. Each asks the disk, guesses,
    // is confirmed, and leaves memory when later ones need its entry.
    let (hints, disk) = open(&options);
    for client in 1_000..21_000 {
        measured_flow(&hints, client);
        if client % 500 == 0 {
            drained(&hints);
        }
    }
    drained(&hints);
    let cache = hints.status().disk.cache;
    assert_eq!(cache.replaced, 0, "{cache:?}");
    drop(disk);
    assert_eq!(on_disk_count(&options, RESIDENTS), before);
    let _ = std::fs::remove_file(&options.path);
}
