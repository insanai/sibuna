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
fn a_choice_after_a_miss_is_tentative_and_becomes_definite_when_it_is_used() {
    let hints = Hints::without_disk(4 << 10);
    assert_eq!(hints.status().entries, 256);
    assert_eq!(hints.recall(7, NOW), Recall::Miss);
    hints.learn(7, 11, true, NOW);
    let (_, held) = hints.table.find(7, NOW).unwrap();
    assert_eq!(held, Found { tag: 11, tentative: true, expires: NOW + TTL });
    assert_eq!(hints.recall(7, NOW), Recall::Hit(11));
    hints.learn(7, 11, false, NOW + 1);
    let (_, held) = hints.table.find(7, NOW + 1).unwrap();
    assert_eq!(held, Found { tag: 11, tentative: false, expires: NOW + 1 + TTL });
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
