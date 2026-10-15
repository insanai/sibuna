//! Publication of policy engine snapshots (read-copy-update with `Arc`).
//!
//! The storage thread (or startup) builds a complete [`Engine`] off the request path and
//! publishes it with [`EngineSlot::publish`]. Request threads read through an
//! [`EngineCache`]: one acquire load of the slot's generation per request, and a clone of the
//! published `Arc` only when the generation moved. An old engine is freed when the last
//! cache holding it refreshes or is dropped; nothing ever waits for readers to drain.
//!
//! With the console, an engine may be published with its rule-hit counters and their
//! generation identity ([`EngineSlot::publish_observed`]); the pair is one publication, so
//! a request always records its matches in the counters of the engine that evaluated it
//! (SID 0007, "Rule observations"). Without counters, requests evaluate without collecting
//! matches. The console samples the counters once a second ([`EngineSlot::sample_hits`]);
//! when a publication retires the generation the last sample read, the slot keeps that
//! generation's counters until the next sample has read their final values, so the hits
//! counted between the last sample and the publication are not lost.
//!
//! # Why a generation-checked cache
//!
//! SID 0010 asks us to measure the read cost with 16 threads and choose between
//! `RwLock<Arc<Engine>>` and a lock-free alternative in safe Rust. Reading through the lock
//! takes the lock word and the reference count, two cache lines every core writes. On the
//! development machine (Ryzen 9 5950X, 16 threads reading in a loop; the ignored test
//! `read_cost_under_contention` below) a read took:
//!
//! | reader                                   | 1 thread | 16 threads |
//! |------------------------------------------|----------|------------|
//! | `RwLock` read guard only                  | 4.2 ns   | 752 ns     |
//! | `RwLock` read and `Arc` clone             | 7.6 ns   | 833 ns     |
//! | generation check with a cached `Arc`      | 0.8 ns   | 1.8 ns     |
//!
//! The cache keeps reads off every shared written line: the generation is written once per
//! publication and otherwise only read, so each core keeps its copy. We therefore use the
//! cache, with the `RwLock` only on the slow path of a refresh.

#[cfg(feature = "console")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use sibuna_policy::Engine;

#[cfg(feature = "console")]
pub use crate::console::hits::RuleHits;

/// What the console's sampler last read, and the counters a publication retired since.
#[cfg(feature = "console")]
#[derive(Debug, Default)]
struct Sampled {
    /// The generation number the last sample read; 0 before the first.
    last: u64,
    /// The counters of generation `last`, kept after a publication retired them until the
    /// next sample reads their final values.
    retired: Option<Arc<RuleHits>>,
}

/// One publication: the engine and, with the console, its rule-hit counters.
#[derive(Clone, Debug)]
struct Published {
    engine: Arc<Engine>,
    #[cfg(feature = "console")]
    hits: Option<Arc<RuleHits>>,
}

impl Published {
    fn plain(engine: Engine) -> Published {
        Published {
            engine: Arc::new(engine),
            #[cfg(feature = "console")]
            hits: None,
        }
    }
}

/// The published engine and its generation.
#[derive(Debug)]
pub struct EngineSlot {
    current: RwLock<Published>,
    /// Advanced after every publication. Release on publish and acquire on read: a reader
    /// that sees a new generation also sees the engine stored before it.
    generation: AtomicU64,
    /// The console sampler's state. Publications and samples take it before `current`, so
    /// a retirement is decided against the sample before or after it, never between. Request
    /// threads never take it.
    #[cfg(feature = "console")]
    sampled: Mutex<Sampled>,
}

impl EngineSlot {
    /// Returns a slot publishing `engine` as generation 1.
    pub fn new(engine: Engine) -> EngineSlot {
        EngineSlot {
            current: RwLock::new(Published::plain(engine)),
            generation: AtomicU64::new(1),
            #[cfg(feature = "console")]
            sampled: Mutex::default(),
        }
    }

    /// Publishes `engine`: later requests evaluate with it. The previous engine is freed once
    /// no request or connection cache holds it. Never blocks on readers beyond the short
    /// write lock.
    pub fn publish(&self, engine: Engine) {
        self.replace(Published::plain(engine));
    }

    /// Publishes `engine` with the rule-hit counters its requests record into, as one
    /// publication.
    #[cfg(feature = "console")]
    pub fn publish_observed(&self, engine: Engine, hits: RuleHits) {
        self.replace(Published { engine: Arc::new(engine), hits: Some(Arc::new(hits)) });
    }

    fn replace(&self, fresh: Published) {
        #[cfg(feature = "console")]
        let mut sampled = self.sampled.lock().unwrap_or_else(PoisonError::into_inner);
        let previous = {
            let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
            std::mem::replace(&mut *current, fresh)
        };
        self.generation.fetch_add(1, Ordering::Release);
        // Keep the counters the last sample read until the next sample reads their final
        // values. An earlier retirement that was not read yet stays: it is the generation
        // the console follows.
        #[cfg(feature = "console")]
        if let Some(hits) = &previous.hits
            && hits.generation().number == sampled.last
        {
            sampled.retired = Some(Arc::clone(hits));
        }
        // The old engine is dropped outside the lock (when this was its last holder).
        drop(previous);
    }

    /// Returns the current engine, cloning its `Arc` (the slow path; use an [`EngineCache`]
    /// on the request path).
    pub fn load(&self) -> Arc<Engine> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner).engine)
    }

    /// Returns the rule-hit counters of the current engine, or `None` when it was published
    /// without them.
    #[cfg(feature = "console")]
    pub fn load_hits(&self) -> Option<Arc<RuleHits>> {
        self.current.read().unwrap_or_else(PoisonError::into_inner).hits.clone()
    }

    /// Fills `sample` with the current engine's rule-hit counters and, once, the final
    /// counters of the generation the previous sample read when a publication has retired
    /// it since (`sample.retired`). Returns false when the current engine has no counters.
    /// The console's collector calls it once a second; it never runs on the request path.
    #[cfg(feature = "console")]
    pub fn sample_hits(&self, sample: &mut sibuna_console::RuleHitSample) -> bool {
        let mut sampled = self.sampled.lock().unwrap_or_else(PoisonError::into_inner);
        match sampled.retired.take() {
            Some(retired) => retired.read(sample.retired.get_or_insert_with(Default::default)),
            None => sample.retired = None,
        }
        let Some(hits) = self.load_hits() else { return false };
        hits.sample(sample);
        sampled.last = hits.generation().number;
        true
    }

    fn load_published(&self) -> Published {
        self.current.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Returns the current generation; it starts at 1 and grows with every publication.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

/// One connection's view of the published engine.
#[derive(Debug, Default)]
pub struct EngineCache {
    generation: u64,
    published: Option<Published>,
}

impl EngineCache {
    /// Returns an empty cache; the first [`EngineCache::refresh`] fills it.
    pub fn new() -> EngineCache {
        EngineCache::default()
    }

    /// Brings the cache up to the slot's current engine and returns it. Costs one acquire
    /// load when nothing was published since the last refresh. Each use on the request path
    /// refreshes, so a request sees the engine current at that step, as Zig pinned a slot
    /// per evaluation.
    #[inline]
    pub fn refresh(&mut self, slot: &EngineSlot) -> &Engine {
        &self.refreshed(slot).engine
    }

    /// As [`EngineCache::refresh`], and also returns the engine's rule-hit counters, when it
    /// was published with them.
    #[cfg(feature = "console")]
    #[inline]
    pub fn refresh_observed(&mut self, slot: &EngineSlot) -> (&Engine, Option<&RuleHits>) {
        let published = self.refreshed(slot);
        (&published.engine, published.hits.as_deref())
    }

    #[inline]
    fn refreshed(&mut self, slot: &EngineSlot) -> &Published {
        let generation = slot.generation();
        if self.generation != generation {
            // A publication between the load above and this clone labels a newer engine
            // with an older generation; the next refresh simply loads again.
            self.generation = generation;
            self.published = None;
        }
        self.published.get_or_insert_with(|| slot.load_published())
    }

    /// Releases the cached engine, so a long-lived exchange (an upgraded connection) does
    /// not keep an old snapshot alive. The next refresh loads the current one.
    pub fn release(&mut self) {
        self.published = None;
    }
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::time::Instant;

    use super::*;
    use sibuna_policy::Action;

    #[test]
    fn caches_follow_publications_and_old_engines_are_freed() {
        let slot = EngineSlot::new(Engine::new(8));
        let mut cache = EngineCache::new();
        assert_eq!(cache.refresh(&slot).default_difficulty, 8);
        let first = slot.load();
        assert_eq!(Arc::strong_count(&first), 3);
        let mut next = Engine::new(9);
        next.default_action = Action::Allow;
        slot.publish(next);
        // The slot dropped its handle; the cache and `first` still hold the old engine.
        assert_eq!(Arc::strong_count(&first), 2);
        assert_eq!(cache.refresh(&slot).default_difficulty, 9);
        assert_eq!(Arc::strong_count(&first), 1);
        assert_eq!(slot.generation(), 2);
        cache.release();
        assert_eq!(cache.refresh(&slot).default_action, Action::Allow);
    }

    #[test]
    fn concurrent_readers_see_only_published_engines() {
        let slot = EngineSlot::new(Engine::new(1));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    let mut cache = EngineCache::new();
                    let mut last = 0;
                    for _ in 0..20_000 {
                        let seen = cache.refresh(&slot).default_difficulty;
                        assert!(seen >= last, "a reader went back in time");
                        last = seen;
                    }
                });
            }
            for difficulty in 2..50 {
                slot.publish(Engine::new(difficulty));
            }
        });
        assert_eq!(EngineCache::new().refresh(&slot).default_difficulty, 49);
    }

    // No hit is lost across a publication: the counters the last sample read stay until
    // the next sample has read their final values, even across two quick publications.
    #[cfg(feature = "console")]
    #[test]
    fn retired_counters_are_kept_until_a_sample_reads_them() {
        use sibuna_console::{ManualClock, RuleHitSample};
        use sibuna_policy::{PolicyRule, RuleMatches};

        use crate::console::hits::Generations;

        let mut generations = Generations::new(1, [1; 16], Arc::new(ManualClock::new(100, 1)));
        let slot = EngineSlot::new(Engine::new(8));
        let mut publish = || {
            let mut engine = Engine::new(8);
            engine.insert_rule(0, PolicyRule::new("Counted", Action::Deny)).unwrap();
            let hits = generations.next(&engine, 1, &[]).unwrap();
            slot.publish_observed(engine, hits);
        };
        let mut matches = RuleMatches::new();
        matches.set(0);
        let hit = |times: usize| {
            let hits = slot.load_hits().unwrap();
            (0..times).for_each(|_| hits.record(&matches, 1));
        };
        let mut sample = RuleHitSample::default();
        publish();
        hit(1);
        assert!(slot.sample_hits(&mut sample));
        assert_eq!((sample.counts.generation, sample.counts.values[0]), (1, 1));
        assert!(sample.retired.is_none());
        // Two hits after the sample, then a publication: the next sample carries them.
        hit(2);
        publish();
        assert!(slot.sample_hits(&mut sample));
        let retired = sample.retired.unwrap();
        assert_eq!((retired.generation, retired.values[0]), (1, 3));
        assert_eq!((sample.counts.generation, sample.counts.values[0]), (2, 0));
        assert!(slot.sample_hits(&mut sample) && sample.retired.is_none());
        // Two publications between samples: the sampled generation is the one kept.
        hit(1);
        publish();
        publish();
        assert!(slot.sample_hits(&mut sample));
        let retired = sample.retired.unwrap();
        assert_eq!((retired.generation, retired.values[0]), (2, 1));
        assert_eq!(sample.counts.generation, 4);
        // A plain publication has no counters to sample.
        slot.publish(Engine::new(8));
        assert!(!slot.sample_hits(&mut sample));
    }

    fn time_reads(threads: usize, read: impl Fn() -> u32 + Sync) -> f64 {
        let reads = 2_000_000u32;
        let started = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    let mut sum = 0u32;
                    for _ in 0..reads {
                        sum = sum.wrapping_add(read());
                    }
                    black_box(sum);
                });
            }
        });
        started.elapsed().as_nanos() as f64 / f64::from(reads)
    }

    /// The measurement behind the module's table. Run with
    /// `cargo test --release -p sibuna slot -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing measurement"]
    fn read_cost_under_contention() {
        let slot = EngineSlot::new(Engine::new(16));
        for threads in [1, 16] {
            let guard = time_reads(threads, || {
                let current = slot.current.read().unwrap_or_else(PoisonError::into_inner);
                current.engine.default_difficulty
            });
            let clone = time_reads(threads, || slot.load().default_difficulty);
            let cached = time_reads(threads, || {
                thread_local! {
                    static CACHE: std::cell::RefCell<EngineCache> =
                        std::cell::RefCell::new(EngineCache::new());
                }
                CACHE.with(|cache| cache.borrow_mut().refresh(&slot).default_difficulty)
            });
            println!(
                "{threads:2} threads: guard {guard:.1} ns, guard+clone {clone:.1} ns, \
                 cache {cached:.1} ns per read"
            );
        }
    }
}
