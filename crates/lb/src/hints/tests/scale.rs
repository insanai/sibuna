//! SID 0015 affinity measurements with healthy, stalled and busy storage.

use super::*;
use std::time::{Duration, Instant};

const CANDIDATES: u64 = 50_000_000;
const HOT: u64 = 262_144;
const TABLE_SLOTS: usize = 1 << 20;

/// SplitMix64's permutation spreads sequential identifiers over the table's buckets.
fn client(mut id: u64) -> u64 {
    id = (id ^ (id >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    id = (id ^ (id >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    id ^ (id >> 31)
}

fn probe(store: &dyn AffinityStore, id: u64) -> bool {
    store.find(&key(client(id)), unix_ms()).is_some_and(|entry| entry.server == 1)
}

fn exercise(store: &dyn AffinityStore, n: u64, hot: u64) {
    // Only the seed phase assigns server 1. A lost affinity falls back to server 2.
    flow(store, client(hot + n), 2);
    for offset in 0..3 {
        flow(store, client((3 * n + offset) % hot), 2);
    }
}

/// Runs the same four-flow operation for every candidate and samples the caller's latency.
fn flood(store: &dyn AffinityStore, candidates: u64, hot: u64, period: Option<Duration>) {
    let mut samples = Vec::new();
    let start = Instant::now();
    let mut batch = start;
    for n in 0..candidates {
        if n % 4093 == 0 {
            let sample = Instant::now();
            exercise(store, n, hot);
            samples.push(sample.elapsed().as_nanos());
        } else {
            exercise(store, n, hot);
        }
        if let Some(period) = period
            && (n + 1).is_multiple_of(128)
        {
            if let Some(wait) = period.checked_sub(batch.elapsed()) {
                std::thread::sleep(wait);
            }
            batch = Instant::now();
        }
    }
    let elapsed = start.elapsed();
    samples.sort_unstable();
    let p99 = samples[(samples.len() * 99).div_ceil(100) - 1];
    eprintln!("{candidates} cold candidates and {} hot flows in {elapsed:?}", 3 * candidates);
    eprintln!("{} four-flow latency samples, p99 {p99} ns", samples.len());
}

#[test]
#[ignore = "SID 0015 capacity measurement, requires 512 MiB of disk"]
fn measure_fifty_million_candidates() {
    let _ = retention("fifty-million", HOT, TABLE_SLOTS, None);
}

/// Checks the specified cohort under the SID 0015 traffic mix and a chosen table budget.
#[test]
#[ignore = "99% first-lookup affinity qualification, requires 512 MiB of disk"]
fn qualify_ninety_nine_percent_affinity() {
    let hot = std::env::var("SIBUNA_AFFINITY_HOT_KEYS").map_or(HOT, |text| {
        text.parse().expect("SIBUNA_AFFINITY_HOT_KEYS must be a positive integer")
    });
    let slots = std::env::var("SIBUNA_AFFINITY_TABLE_SLOTS").map_or(TABLE_SLOTS, |text| {
        text.parse::<usize>().expect("table capacity must be an integer")
    });
    assert!(slots.is_power_of_two() && AffinityTable::accepts(slots as u64));
    assert!((1..=slots as u64).contains(&hot), "cohort must fit the selected table capacity");
    let period = std::env::var("SIBUNA_AFFINITY_COLD_PER_SECOND").ok().map(|text| {
        let rate: u32 =
            text.parse().expect("cold candidates per second must be a positive integer");
        assert!(rate > 0);
        eprintln!("offering at most {rate} cold candidates per second in batches of 128");
        Duration::from_secs(128) / rate
    });
    let (retained, seeded) = retention("qualify-affinity", hot, slots, period);
    assert!(seeded > 0 && retained * 100 >= seeded * 99, "below 99%: {retained}/{seeded}");
}

fn retention(name: &str, hot: u64, slots: usize, period: Option<Duration>) -> (usize, usize) {
    let options = on_disk(name, 512 << 20);
    let (spill, store) = open(&options, slots);
    let status = spill.status().unwrap();
    assert!(status.persistent);
    eprintln!("{} table slots, {:?}", status.table_slots, status.budget);
    let start = Instant::now();
    for id in 0..hot {
        flow(&*store, client(id), 1);
        if id % 1024 == 1023 {
            drained(&spill);
        }
    }
    drained(&spill);
    let seeded: Vec<bool> = (0..hot).map(|id| probe(&*store, id)).collect();
    drained(&spill);
    let before = spill.status().unwrap().disk;
    flood(&*store, CANDIDATES, hot, period);
    drained(&spill);
    let after = spill.status().unwrap().disk;
    eprintln!(
        "flood queue accepted {}, shed {}",
        after.queued - before.queued,
        after.shed - before.shed
    );
    let retained =
        seeded.iter().enumerate().filter(|&(i, &live)| live && probe(&*store, i as u64)).count();
    let seed_count = seeded.iter().filter(|&&live| live).count();
    let elapsed = start.elapsed();
    eprintln!(
        "first lookup retained {retained} of {seed_count} seeded choices from {hot} offered"
    );
    drop((spill, store));
    std::fs::remove_file(&options.path).unwrap();
    assert!(elapsed.as_millis() < u128::from(TTL), "seed TTL expired during the run");
    (retained, seed_count)
}

/// Measures caller latency when the storage thread cannot finish a lookup, then when
/// another process holds the file at startup. Each mode starts with empty RAM.
#[test]
#[ignore = "SID 0015 storage availability measurement, requires 512 MiB of disk"]
fn measure_storage_unavailability() {
    use std::sync::mpsc::sync_channel;

    let options = on_disk("unavailable", 512 << 20);
    let disk = sibuna_spill::Options { size: options.size, max_ttl: LONGEST_TTL + CLOCK_SLACK };
    let (cache, report) =
        sibuna_spill::load_cache(&options.path, &disk, unix_ms() / 1000).unwrap();
    assert!(report.persistent);
    let front = Arc::new(Front::new(TABLE_SLOTS));
    let sink = Arc::clone(&front);
    let (entered, waiting) = sync_channel(1);
    let (resume, release) = sync_channel(1);
    let mut first = true;
    let service =
        sibuna_spill::start_service(cache, ServiceOptions::default(), move |key, hint| {
            if first {
                first = false;
                entered.send(()).unwrap();
                release
                    .recv_timeout(Duration::from_secs(180))
                    .expect("measurement did not resume storage");
            }
            sink.answer(key, hint);
        })
        .unwrap();
    let store = SpillStore { front, service: Some(service.handle()) };
    store.find(&key(client(HOT * 16)), unix_ms());
    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
    eprintln!("storage thread stalled during first lookup");
    flood(&store, 4_000_000, HOT, None);
    let counters = service.counters();
    eprintln!("queued {}, shed {}", counters.queued, counters.shed);
    resume.send(()).unwrap();
    assert!(counters.shed > 0);
    drop(store);

    // The service still owns the mapped file. Startup must take the memory-only path.
    let (busy, local) = open(&options, TABLE_SLOTS);
    assert!(busy.status().unwrap().outcome.is_none());
    eprintln!("file busy at startup, memory only");
    flood(&*local, 4_000_000, HOT, None);
    assert_eq!(busy.status().unwrap().disk.queued, 0);
    drop((busy, local, service));
    std::fs::remove_file(&options.path).unwrap();
}
