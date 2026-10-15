//! Publication of policy engine snapshots (read-copy-update with `Arc`).
//!
//! The storage thread (or startup) builds a complete [`Engine`] off the request path and
//! publishes it with [`EngineSlot::publish`]. Request threads read through an
//! [`EngineCache`]: one acquire load of the slot's generation per request, and a clone of the
//! published `Arc` only when the generation moved. An old engine is freed when the last
//! cache holding it refreshes or is dropped; nothing ever waits for readers to drain.
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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use sibuna_policy::Engine;

/// The published engine and its generation.
#[derive(Debug)]
pub struct EngineSlot {
    current: RwLock<Arc<Engine>>,
    /// Advanced after every publication. Release on publish and acquire on read: a reader
    /// that sees a new generation also sees the engine stored before it.
    generation: AtomicU64,
}

impl EngineSlot {
    /// Returns a slot publishing `engine` as generation 1.
    pub fn new(engine: Engine) -> EngineSlot {
        EngineSlot { current: RwLock::new(Arc::new(engine)), generation: AtomicU64::new(1) }
    }

    /// Publishes `engine`: later requests evaluate with it. The previous engine is freed once
    /// no request or connection cache holds it. Never blocks on readers beyond the short
    /// write lock.
    pub fn publish(&self, engine: Engine) {
        let fresh = Arc::new(engine);
        let previous = {
            let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
            std::mem::replace(&mut *current, fresh)
        };
        self.generation.fetch_add(1, Ordering::Release);
        // The old engine is dropped outside the lock (when this was its last holder).
        drop(previous);
    }

    /// Returns the current engine, cloning its `Arc` (the slow path; use an [`EngineCache`]
    /// on the request path).
    pub fn load(&self) -> Arc<Engine> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
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
    engine: Option<Arc<Engine>>,
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
        let generation = slot.generation();
        if self.generation != generation {
            // A publication between the load above and this clone labels a newer engine
            // with an older generation; the next refresh simply loads again.
            self.generation = generation;
            self.engine = None;
        }
        self.engine.get_or_insert_with(|| slot.load())
    }

    /// Releases the cached engine, so a long-lived exchange (an upgraded connection) does
    /// not keep an old snapshot alive. The next refresh loads the current one.
    pub fn release(&mut self) {
        self.engine = None;
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
                current.default_difficulty
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
