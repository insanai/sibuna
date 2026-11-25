//! Measures a spill cache on a mapped file: operations in a second and resident memory.
//!
//! ```sh
//! cargo run --release -p sibuna-spill --example spill_measure -- 256 /var/tmp
//! ```
//!
//! The first argument is the size of the file in MiB (default 64). The second is the
//! directory of the file (default: the temporary directory). The program offers twice
//! as many distinct keys as the cache has slots, then keeps a working set of a quarter
//! of the slots in use under a flood of new keys, then closes the file and reads the
//! working set from a new mapping, then offers through the storage thread. A third
//! argument N flushes the file after every N offers of the first phase, to see what
//! a bound on the dirty pages costs. A fourth argument sets the number of distinct
//! flood keys (default: four per slot).
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use sibuna_spill::{Cache, Options, ServiceOptions, load_cache, start_service, unix_seconds};

const TTL: u64 = 3_600;
/// The first number of the keys of the working set.
const BASE: u64 = 1 << 40;

fn key(number: u64) -> [u8; 8] {
    // A fixed permutation, so that the keys look like hashes and not like a counter.
    number.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes()
}

/// The resident memory of this process in KiB: all of it, the anonymous part and the
/// part that maps files. Zeros where `/proc` does not say.
fn resident() -> [u64; 3] {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    ["VmRSS:", "RssAnon:", "RssFile:"].map(|name| {
        let line = status.lines().find_map(|line| line.strip_prefix(name));
        line.and_then(|rest| rest.split_whitespace().next()?.parse().ok()).unwrap_or(0)
    })
}

fn report(phase: &str, operations: u64, started: Instant) {
    let seconds = started.elapsed().as_secs_f64();
    let [all, anonymous, file] = resident();
    println!(
        "{phase:<34} {operations:>10} ops {:>7.2} s {:>6.2} M ops/s   rss {all} KiB \
         (anonymous {anonymous}, file {file})",
        seconds,
        operations as f64 / seconds / 1e6
    );
}

/// The clock of one run: now, and when its hints expire.
#[derive(Clone, Copy)]
struct Clock {
    now: u64,
    later: u64,
}

/// Offers twice as many distinct keys as slots: the cache cannot hold them all.
fn fill(cache: &mut Cache, clock: Clock, flush_every: u64) {
    let slots = cache.slot_count();
    let started = Instant::now();
    for number in 0..2 * slots {
        cache.put(&key(number), b"server", clock.later, clock.now);
        if flush_every != 0 && number % flush_every == flush_every - 1 {
            cache.flush().unwrap();
        }
    }
    report("offer 2 x slots distinct keys", 2 * slots, started);
    println!("  {:?}", cache.counters());
}

/// Reads the hint of member `number` of the working set and offers it again when it
/// is missing, as a table in memory does when it has to ask.
fn use_hint(cache: &mut Cache, clock: Clock, number: u64) {
    if cache.get(&key(BASE + number), clock.now).is_none() {
        cache.put(&key(BASE + number), b"home", clock.later, clock.now);
    }
}

/// How many of the first `working` members of the working set the cache holds.
fn held(cache: &mut Cache, clock: Clock, working: u64) -> u64 {
    (0..working).filter(|&n| cache.get(&key(BASE + n), clock.now).is_some()).count() as u64
}

/// Keeps a working set of a quarter of the slots in use, first alone and then under a
/// flood of distinct keys, with three working-set accesses per candidate.
/// Returns how many members the cache holds at the end.
fn work(cache: &mut Cache, clock: Clock, flood_keys: u64) -> u64 {
    let working = cache.slot_count() / 4;
    let started = Instant::now();
    for _ in 0..4 {
        for number in 0..working {
            use_hint(cache, clock, number);
        }
    }
    report("working set: 4 x read or offer", 4 * working, started);
    let seeded: Vec<bool> =
        (0..working).map(|n| cache.get(&key(BASE + n), clock.now).is_some()).collect();
    let initial = seeded.iter().filter(|&&present| present).count();
    println!("  working set held: {initial} of {working}");

    let started = Instant::now();
    let mut next = 0;
    for flood in 0..flood_keys {
        cache.put(&key((1 << 41) + flood), b"away", clock.later, clock.now);
        for _ in 0..3 {
            use_hint(cache, clock, next % working);
            next += 1;
        }
    }
    report("flood, 3 working-set uses per key", 4 * flood_keys, started);
    let mut kept = 0;
    let mut retained = 0;
    for (n, seeded) in seeded.into_iter().enumerate() {
        if cache.get(&key(BASE + n as u64), clock.now).is_some() {
            kept += 1;
            retained += u64::from(seeded);
        }
    }
    println!(
        "  seeded keys present after {flood_keys} distinct candidates: {retained} of {initial}"
    );
    println!("  working set held after the flood: {kept} of {working}");
    println!("  {:?}", cache.counters());
    kept
}

/// Maps the file again and reads the working set: what a restart finds.
fn reopen(path: &Path, options: &Options, clock: Clock, kept: u64) -> Cache {
    let started = Instant::now();
    let (mut cache, opened) = load_cache(path, options, clock.now).unwrap();
    let working = cache.slot_count() / 4;
    let found = held(&mut cache, clock, working);
    report("reopen, read the working set", working, started);
    println!("  {:?}: {found} of {working} hints found, {kept} were held", opened.outcome);
    cache
}

/// Puts the cache behind its storage thread: what four threads can offer, and what
/// the queue sheds when they do not pause.
fn offer_through_service(cache: Cache, clock: Clock) {
    let each = cache.slot_count() / 4;
    let service = start_service(cache, ServiceOptions::default(), |_, _| {}).unwrap();
    let started = Instant::now();
    std::thread::scope(|scope| {
        for worker in 0..4u64 {
            let handle = service.handle();
            scope.spawn(move || {
                for number in 0..each {
                    handle.offer(&key((worker << 44) + number), b"s", clock.later);
                }
            });
        }
    });
    report("4 threads offer, no pause", 4 * each, started);
    let counters = service.counters();
    println!("  queued {}, shed {}", counters.queued, counters.shed);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let mebibytes: u64 = arguments.next().map(|n| n.parse()).transpose()?.unwrap_or(64);
    let directory = arguments.next().map_or_else(std::env::temp_dir, PathBuf::from);
    let flush_every: u64 = arguments.next().map(|n| n.parse()).transpose()?.unwrap_or(0);
    let flood_keys: Option<u64> = arguments.next().map(|n| n.parse()).transpose()?;
    if arguments.next().is_some() || flood_keys.is_some_and(|n| n == 0 || n > BASE) {
        return Err(
            "expected MiB [directory [flush_every [distinct_flood_keys in 1..=2^40]]]".into()
        );
    }
    let size = mebibytes.checked_mul(1 << 20).ok_or("file size overflow")?;
    if !(sibuna_spill::MIN_SIZE..=sibuna_spill::MAX_SIZE).contains(&size) {
        return Err("file size must be in 1..=65536 MiB".into());
    }
    let scratch = directory.join(format!("sibuna-spill-measure-{}", std::process::id()));
    std::fs::create_dir(&scratch)?;
    let path = scratch.join("hints.spill");
    let options = Options { size, max_ttl: TTL };
    let now = unix_seconds();
    let clock = Clock { now, later: now + TTL / 2 };

    let started = Instant::now();
    let (mut cache, opened) = load_cache(&path, &options, now).unwrap();
    let slots = cache.slot_count();
    println!("file {} ({mebibytes} MiB), {slots} slots, {:?}", path.display(), opened.outcome);
    println!("budget {:?}", cache.budget());
    report("create and map", 1, started);

    fill(&mut cache, clock, flush_every);
    let kept = work(&mut cache, clock, flood_keys.unwrap_or(4 * slots));
    let started = Instant::now();
    cache.flush().unwrap();
    drop(cache);
    report("flush and close", 1, started);
    let cache = reopen(&path, &options, clock, kept);
    offer_through_service(cache, clock);
    if opened.persistent {
        std::fs::remove_file(&path)?;
    }
    std::fs::remove_dir(scratch)?;
    Ok(())
}
