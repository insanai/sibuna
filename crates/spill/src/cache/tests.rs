#![allow(clippy::unwrap_used)]

use super::*;
use crate::format::{DATA_START, Geometry};

const NOW: u64 = 1_000_000;
const TTL: u64 = 3_600;
const LATER: u64 = NOW + 600;

/// A cache of about 4 MiB in memory with a fixed salt, so that every run places the
/// keys alike: 255 buckets and 1,020 slots in each shard.
fn cache() -> Cache {
    let geometry = Geometry::for_size(4 << 20).unwrap();
    let store = Store::memory(geometry.file_len()).unwrap();
    Cache::new(store, geometry, 0x5eed, TTL).unwrap()
}

fn key(number: u32) -> [u8; 8] {
    let mut bytes = *b"key-0000";
    bytes[4..].copy_from_slice(&number.to_le_bytes());
    bytes
}

fn place(cache: &Cache, key: &[u8]) -> (usize, u64) {
    cache.geometry.place(cache.hash(key))
}

/// The first `count` keys, from `start` on, that belong to the bucket of `key(0)`.
fn bucket_mates(cache: &Cache, start: u32, count: usize) -> Vec<[u8; 8]> {
    let home = place(cache, &key(0));
    (start..).map(key).filter(|key| place(cache, key) == home).take(count).collect()
}

/// The first `count` keys of the shard of `key(0)` that lie in other buckets.
fn shard_mates(cache: &Cache, count: usize) -> Vec<[u8; 8]> {
    let home = place(cache, &key(0));
    let mate = |key: &[u8; 8]| {
        let (shard, bucket) = place(cache, key);
        shard == home.0 && bucket != home.1
    };
    (1_000_000..).map(key).filter(mate).take(count).collect()
}

fn value_of(cache: &mut Cache, key: &[u8]) -> Option<Vec<u8>> {
    cache.get(key, NOW).map(|hint| hint.value().to_vec())
}

/// Changes one byte of the slot `way` of the bucket of `key(0)`.
fn damage(cache: &mut Cache, way: usize, byte: u64) {
    let (shard, bucket) = place(cache, &key(0));
    let offset = Geometry::slot_offset(cache.geometry.slot_index(shard, bucket, way)) + byte;
    let mut one = [0];
    assert!(cache.store.read(offset, &mut one));
    assert!(cache.store.write(offset, &[one[0] ^ 0x40]));
}

#[test]
fn a_hint_is_stored_read_updated_and_removed() {
    let mut cache = cache();
    assert_eq!(cache.slot_count(), 64 * 255 * 4);
    assert_eq!(cache.get(b"client", NOW), None);
    assert_eq!(cache.put(b"client", b"server-a", LATER, NOW), Put::Stored);
    let hint = cache.get(b"client", NOW).unwrap();
    assert_eq!((hint.value(), hint.expires), (&b"server-a"[..], LATER));
    assert_eq!(cache.put(b"client", b"server-b", LATER + 1, NOW), Put::Updated);
    assert_eq!(value_of(&mut cache, b"client"), Some(b"server-b".to_vec()));
    // The longest key and value, and the empty value.
    assert_eq!(cache.put(&[1; MAX_KEY], &[2; MAX_VALUE], LATER, NOW), Put::Stored);
    assert_eq!(value_of(&mut cache, &[1; MAX_KEY]), Some(vec![2; MAX_VALUE]));
    assert_eq!(cache.put(b"bare", b"", LATER, NOW), Put::Stored);
    assert_eq!(value_of(&mut cache, b"bare"), Some(Vec::new()));
    assert!(cache.remove(b"client", NOW));
    assert!(!cache.remove(b"client", NOW));
    assert_eq!(cache.get(b"client", NOW), None);
    let counters = cache.counters();
    assert_eq!((counters.stored, counters.updated, counters.removed), (3, 1, 1));
    assert_eq!((counters.lookups, counters.hits), (6, 4));
}

#[test]
fn a_hint_that_cannot_be_stored_is_refused_and_changes_nothing() {
    let mut cache = cache();
    assert_eq!(cache.put(b"", b"v", LATER, NOW), Put::Refused);
    assert_eq!(cache.put(&[1; MAX_KEY + 1], b"v", LATER, NOW), Put::Refused);
    assert_eq!(cache.put(b"k", &[1; MAX_VALUE + 1], LATER, NOW), Put::Refused);
    assert_eq!(cache.put(b"k", b"v", NOW, NOW), Put::Refused);
    assert_eq!(cache.put(b"k", b"v", NOW + TTL + 1, NOW), Put::Refused);
    assert_eq!(cache.put(b"k", b"v", u64::MAX, u64::MAX - 1), Put::Stored);
    assert_eq!(cache.put(b"k", b"v", NOW + TTL, NOW), Put::Stored);
    assert_eq!(cache.get(b"", NOW), None);
    assert_eq!(cache.get(&[1; MAX_KEY + 1], NOW), None);
    assert!(!cache.remove(b"", NOW));
    assert_eq!(cache.counters().refused, 5);
}

#[test]
fn a_hint_expires_and_its_slot_is_reused() {
    let mut cache = cache();
    let mates = bucket_mates(&cache, 0, 5);
    for mate in &mates[..4] {
        assert_eq!(cache.put(mate, b"old", NOW + 10, NOW), Put::Stored);
    }
    assert!(cache.get(&mates[0], NOW + 9).is_some());
    assert!(cache.get(&mates[0], NOW + 10).is_none());
    // The bucket is full of expired entries: a new key needs no admission.
    assert_eq!(cache.put(&mates[4], b"new", NOW + 700, NOW + 10), Put::Stored);
    assert_eq!(cache.counters().expired, 1);
    assert_eq!(cache.counters().rejected, 0);
}

#[test]
fn a_full_bucket_rejects_a_key_seen_once_and_admits_a_key_that_returns() {
    let mut cache = cache();
    let mates = bucket_mates(&cache, 0, 6);
    for mate in &mates[..4] {
        assert_eq!(cache.put(mate, b"first", LATER, NOW), Put::Stored);
    }
    let (shard, _) = place(&cache, &mates[0]);
    assert!(mates[..4].iter().all(|mate| cache.estimate(shard, mate) == 1));
    // Seen once against entries seen once: the estimates are equal, so it stays out,
    // and the bucket is as it was.
    assert_eq!(cache.put(&mates[4], b"late", LATER, NOW), Put::Rejected);
    assert_eq!(cache.get(&mates[4], NOW), None);
    for mate in &mates[..4] {
        assert_eq!(value_of(&mut cache, mate), Some(b"first".to_vec()));
    }
    // That lookup and the offer below make three sightings against two.
    assert_eq!(cache.put(&mates[4], b"late", LATER, NOW), Put::Replaced);
    assert_eq!(value_of(&mut cache, &mates[4]), Some(b"late".to_vec()));
    // Among entries of equal estimate the one written first gave way.
    assert_eq!(cache.get(&mates[0], NOW), None);
    for mate in &mates[1..4] {
        assert_eq!(value_of(&mut cache, mate), Some(b"first".to_vec()));
    }
    let counters = cache.counters();
    assert_eq!((counters.stored, counters.rejected, counters.replaced), (4, 1, 1));
}

#[test]
fn the_victim_is_the_least_frequent_entry_not_the_oldest() {
    let mut cache = cache();
    let mates = bucket_mates(&cache, 0, 5);
    for mate in &mates[..4] {
        assert_eq!(cache.put(mate, b"v", LATER, NOW), Put::Stored);
    }
    // Every entry but the third is read often. The first is the oldest.
    for _ in 0..6 {
        for index in [0, 1, 3] {
            assert!(cache.get(&mates[index], NOW).is_some());
        }
    }
    for _ in 0..3 {
        assert!(cache.get(&mates[4], NOW).is_none());
    }
    assert_eq!(cache.put(&mates[4], b"v", LATER, NOW), Put::Replaced);
    assert!(cache.get(&mates[2], NOW).is_none());
    for index in [0, 1, 3, 4] {
        assert!(cache.get(&mates[index], NOW).is_some(), "{index}");
    }
}

#[test]
fn aging_lets_a_new_key_displace_entries_that_were_popular_long_ago() {
    let mut cache = cache();
    let mates = bucket_mates(&cache, 0, 6);
    let (shard, _) = place(&cache, &mates[0]);
    for mate in &mates[..4] {
        assert_eq!(cache.put(mate, b"hot", LATER, NOW), Put::Stored);
        for _ in 0..20 {
            assert!(cache.get(mate, NOW).is_some());
        }
        assert_eq!(cache.estimate(shard, mate), 15);
    }
    for _ in 0..4 {
        cache.put(&mates[4], b"new", LATER, NOW);
    }
    assert_eq!(cache.counters().rejected, 4);
    // Other clients of the shard come and go. The sketch ages once for every 4,080.
    let before = cache.counters().agings;
    for other in shard_mates(&cache, 4_080 * 6) {
        assert!(cache.get(&other, NOW).is_none());
    }
    assert!(cache.counters().agings >= before + 6);
    let faded = mates[..4].iter().map(|mate| cache.estimate(shard, mate)).max().unwrap();
    assert!(faded <= 3, "{faded}");
    // A key that returns a few times now wins a slot.
    let admitted = (0..6).any(|_| cache.put(&mates[5], b"new", LATER, NOW) == Put::Replaced);
    assert!(admitted);
    assert_eq!(value_of(&mut cache, &mates[5]), Some(b"new".to_vec()));
}

#[test]
fn ages_are_right_across_a_wrap_of_the_write_counter() {
    let mut cache = cache();
    let mates = bucket_mates(&cache, 0, 7);
    let (shard, _) = place(&cache, &mates[0]);
    // Two writes before the counter of 32 bits wraps.
    cache.set_write_count(shard, u32::MAX - 2);
    for mate in &mates[..4] {
        assert_eq!(cache.put(mate, b"v", LATER, NOW), Put::Stored);
    }
    // The stamps are MAX-1, MAX, 0 and 1: the counter wrapped between the entries.
    assert_eq!(cache.write_count(shard), 1);
    // Each newcomer is seen three times and displaces the entry written longest ago,
    // which is the first, then the second, then the third: not the smallest stamp.
    for (round, newcomer) in mates[4..].iter().enumerate() {
        assert!(cache.get(newcomer, NOW).is_none());
        assert!(cache.get(newcomer, NOW).is_none());
        assert_eq!(cache.put(newcomer, b"v", LATER, NOW), Put::Replaced);
        assert!(cache.get(&mates[round], NOW).is_none(), "round {round}");
        for mate in &mates[round + 1..4] {
            // A lookup would raise the estimate, so look at the slots only.
            let (shard, bucket) = place(&cache, mate);
            let found = (0..WAYS).any(|way| {
                let index = cache.geometry.slot_index(shard, bucket, way);
                matches!(cache.slot(index, NOW), SlotState::Live(entry) if entry.key() == mate)
            });
            assert!(found, "round {round}");
        }
    }
    // A counter that lost its value, as a loss of power can do, harms nothing.
    cache.set_write_count(shard, 0x8000_0000);
    assert!(cache.get(&mates[4], NOW).is_some());
    assert_eq!(cache.put(&mates[4], b"w", LATER, NOW), Put::Updated);
}

#[test]
fn a_damaged_slot_is_free_space_and_is_counted_once() {
    let mut cache = cache();
    let mates = bucket_mates(&cache, 0, 4);
    for mate in &mates {
        assert_eq!(cache.put(mate, b"v", LATER, NOW), Put::Stored);
    }
    // One flipped bit in the value of the second slot and in the key of the third.
    damage(&mut cache, 1, 50);
    damage(&mut cache, 2, 30);
    assert!(cache.get(&mates[0], NOW).is_some());
    assert_eq!(cache.get(&mates[1], NOW), None);
    assert_eq!(cache.get(&mates[2], NOW), None);
    assert!(cache.get(&mates[3], NOW).is_some());
    // The first lookup found both, cleared them and counted each once.
    assert_eq!(cache.counters().corrupt, 2);
    assert_eq!(cache.put(&mates[1], b"again", LATER, NOW), Put::Stored);
    assert_eq!(value_of(&mut cache, &mates[1]), Some(b"again".to_vec()));
    assert_eq!(cache.counters().corrupt, 2);
}

#[test]
fn a_slot_copied_to_another_place_is_not_trusted() {
    let mut cache = cache();
    let mates = bucket_mates(&cache, 0, 2);
    assert_eq!(cache.put(&mates[0], b"v", LATER, NOW), Put::Stored);
    let (shard, bucket) = place(&cache, &mates[0]);
    let from = Geometry::slot_offset(cache.geometry.slot_index(shard, bucket, 0));
    let mut bytes = [0; SLOT_LEN];
    assert!(cache.store.read(from, &mut bytes));
    // The same bytes in the next slot of the bucket.
    assert!(cache.store.write(from + SLOT_LEN as u64, &bytes));
    assert!(cache.get(&mates[0], NOW).is_some());
    assert_eq!(cache.counters().corrupt, 1);
}

#[test]
fn two_copies_of_a_key_read_as_the_newer_and_an_offer_leaves_one() {
    let mut cache = cache();
    let (shard, bucket) = place(&cache, &key(0));
    // What a loss of power can leave: the key in two slots, each valid in its place.
    for (way, value, stamp) in [(0, b"old", 5u32), (2, b"new", 9u32)] {
        let index = cache.geometry.slot_index(shard, bucket, way);
        let bytes = write_slot(&key(0), value, LATER, stamp, cache.salt, index);
        assert!(cache.store.write(Geometry::slot_offset(index), &bytes));
    }
    cache.set_write_count(shard, 9);
    assert_eq!(value_of(&mut cache, &key(0)), Some(b"new".to_vec()));
    assert_eq!(cache.put(&key(0), b"now", LATER, NOW), Put::Updated);
    let live = (0..WAYS)
        .filter(|&way| {
            let index = cache.geometry.slot_index(shard, bucket, way);
            matches!(cache.slot(index, NOW), SlotState::Live(_))
        })
        .count();
    assert_eq!(live, 1);
    assert_eq!(value_of(&mut cache, &key(0)), Some(b"now".to_vec()));
}

#[test]
fn a_cache_of_noise_yields_nothing_and_does_not_panic() {
    let mut cache = cache();
    let len = cache.geometry.file_len();
    let mut state = 0x9e37_79b9_u64;
    let mut offset = DATA_START - 4096;
    while offset < len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        assert!(cache.store.write(offset, &(state ^ (state >> 31)).to_le_bytes()));
        offset += 8;
    }
    for number in 0..20_000 {
        assert_eq!(cache.get(&key(number), NOW), None);
    }
    assert!(cache.counters().corrupt > 20_000);
    // The cache works on: every slot it looked at is free again. A few buckets get more
    // than four of these keys, and the fifth is rejected as in any cache.
    for number in 0..20_000 {
        assert_ne!(cache.put(&key(number), b"v", LATER, NOW), Put::Refused, "{number}");
    }
    let kept = (0..20_000).filter(|&number| cache.get(&key(number), NOW).is_some()).count();
    assert!(kept > 19_800, "{kept}");
    assert_eq!(kept as u64, cache.counters().stored);
}

#[test]
fn the_budget_names_every_part() {
    let cache = cache();
    let budget = cache.budget();
    assert_eq!(budget.file_bytes, 8192 + 255 * 16384);
    assert_eq!(budget.index_bytes, 8192);
    assert_eq!(budget.slot_bytes, 65_280 * 64);
    // 1,020 slots in a shard: 4,096 counters of four bits, in each of 64 shards.
    assert_eq!(budget.sketch_bytes, 64 * 2048);
    assert_eq!(budget.queue_bytes, 0);
    assert!(budget.scratch_bytes > 0 && budget.scratch_bytes < 8192);
    assert_eq!(budget.memory_bytes(), budget.sketch_bytes + budget.scratch_bytes);
}

#[test]
fn a_working_set_in_use_is_kept_under_a_flood_of_new_keys() {
    let mut cache = cache();
    // 20,000 hints in 65,280 slots.
    for number in 0..20_000 {
        cache.put(&key(number), b"home", LATER, NOW);
    }
    let stored = (0..20_000).filter(|&number| cache.get(&key(number), NOW).is_some()).count();
    assert!(stored > 19_800, "{stored}");
    // Ten new keys for every slot of the cache. Between two of them, three lookups of
    // the working set, so each of its hints is used once for every 6,700 new keys.
    let mut next = 0;
    for flood in 0..650_000u32 {
        cache.put(&key(5_000_000 + flood), b"away", LATER, NOW);
        for _ in 0..3 {
            cache.get(&key(next % 20_000), NOW);
            next += 1;
        }
    }
    let kept = (0..20_000).filter(|&number| cache.get(&key(number), NOW).is_some()).count();
    // Without admission, ten new keys for every slot would leave almost none.
    assert!(kept > 19_000, "{kept} of 20000");
}
