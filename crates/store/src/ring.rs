//! A bounded multi-producer, single-consumer queue (Vyukov's sequence-stamped ring).
//!
//! Every slot carries a sequence number that tells producers whether the slot is free and
//! the consumer whether it is full, so neither side takes a lock. Worker threads push
//! records from the request path; one collector thread drains them. A full ring refuses the
//! newest value instead of blocking, which is the right trade for sampled or forensic data
//! under a flood.
//!
//! Single consumption is enforced by types: [`BoundedQueue::pop`] needs `&mut self`, and the
//! shared path hands out at most one [`Consumer`] at a time through
//! [`BoundedQueue::consumer`].

// A lock-free MPSC ring cannot be written in safe Rust: producers and the consumer access
// different slots of one array concurrently, and only the sequence protocol (not the type
// system) proves which thread may touch which slot. Each slot therefore holds its value in
// an `UnsafeCell<MaybeUninit<T>>`, and every access is justified by that protocol below.
#![allow(unsafe_code)]

use std::cell::UnsafeCell;
use std::fmt;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// One ring slot: a sequence stamp and possibly a value.
///
/// For a slot at index `i` and a position `p` with `p % N == i`:
/// - `sequence == p` means the slot is empty and the producer that claims position `p` may
///   write it;
/// - `sequence == p + 1` means the slot holds the value pushed at position `p`, which the
///   consumer at position `p` may read;
/// - `sequence == p + N` means the consumer has taken that value and the slot is empty for
///   position `p + N`.
struct Slot<T> {
    sequence: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
}

/// Keeps a hot counter on a cache line of its own, so producers advancing `tail` do not
/// invalidate the consumer's `head`.
#[repr(align(64))]
struct Padded(AtomicUsize);

/// A bounded MPSC queue of `N` values of type `T`; `N` is a power of two, at least 2.
///
/// The slots are allocated once, on the heap, by [`BoundedQueue::new`]; `push` and `pop`
/// never allocate. Values still queued when the queue is dropped are dropped with it.
pub struct BoundedQueue<T, const N: usize> {
    slots: Box<[Slot<T>; N]>,
    head: Padded,
    tail: Padded,
    consumer_claimed: AtomicBool,
}

// SAFETY: values move into the queue on one thread and out on another, but are never shared
// by reference between threads, exactly like a channel. `T: Send` is therefore sufficient,
// and all slot accesses are serialised by the sequence protocol documented on `Slot`.
unsafe impl<T: Send, const N: usize> Sync for BoundedQueue<T, N> {}

impl<T, const N: usize> BoundedQueue<T, N> {
    /// Fails the build unless `N` is a power of two of at least 2.
    const VALID_CAPACITY: () = assert!(N >= 2 && N.is_power_of_two());
    const MASK: usize = N - 1;

    /// The number of values the queue holds when full.
    pub const CAPACITY: usize = N;

    /// Returns an empty queue; allocates the `N` slots on the heap.
    pub fn new() -> Self {
        let () = Self::VALID_CAPACITY;
        let slots: Vec<Slot<T>> = (0..N)
            .map(|i| Slot {
                sequence: AtomicUsize::new(i),
                value: UnsafeCell::new(MaybeUninit::uninit()),
            })
            .collect();
        let Ok(slots) = Box::<[Slot<T>; N]>::try_from(slots.into_boxed_slice()) else {
            unreachable!("the slot vector has exactly N elements");
        };
        Self {
            slots,
            head: Padded(AtomicUsize::new(0)),
            tail: Padded(AtomicUsize::new(0)),
            consumer_claimed: AtomicBool::new(false),
        }
    }

    /// Appends `value`; any number of threads may push concurrently.
    ///
    /// Returns `Err(value)` without storing it when the queue is full, so the caller keeps
    /// ownership and may count or drop it.
    pub fn push(&self, value: T) -> Result<(), T> {
        // Relaxed: `tail` only hands out positions; the slot's sequence carries the
        // synchronisation.
        let mut pos = self.tail.0.load(Ordering::Relaxed);
        loop {
            let slot = &self.slots[pos & Self::MASK];
            // Acquire: pairs with the consumer's Release store of `pos`, so the consumer's
            // read of the previous value in this slot happens before our write.
            let seq = slot.sequence.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(pos) as isize;
            if diff == 0 {
                // Relaxed: the CAS only arbitrates which producer owns position `pos`.
                match self.tail.0.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: the CAS gave this thread position `pos`, and
                        // `sequence == pos` says the slot is empty; no other producer can
                        // claim `pos` and the consumer does not read it before the Release
                        // store below.
                        unsafe { (*slot.value.get()).write(value) };
                        // Release: publishes the written value to the consumer.
                        slot.sequence.store(pos.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(current) => pos = current,
                }
            } else if diff < 0 {
                return Err(value);
            } else {
                pos = self.tail.0.load(Ordering::Relaxed);
            }
        }
    }

    /// Removes the oldest value through exclusive access; returns `None` when empty.
    ///
    /// `&mut self` proves there is no concurrent consumer (and no concurrent producer).
    pub fn pop(&mut self) -> Option<T> {
        self.take()
    }

    /// Claims the single consumer role for shared use; returns `None` while another
    /// [`Consumer`] for this queue is alive.
    pub fn consumer(&self) -> Option<Consumer<'_, T, N>> {
        // Acquire: pairs with the Release in `Consumer::drop`, so the previous consumer's
        // `head` updates are visible to the new one.
        if self.consumer_claimed.swap(true, Ordering::Acquire) {
            return None;
        }
        Some(Consumer { queue: self })
    }

    /// The consumer step. Callers guarantee there is at most one consumer: either `&mut
    /// self` or the unique `Consumer` claim.
    fn take(&self) -> Option<T> {
        // Relaxed: only the single consumer writes `head`.
        let pos = self.head.0.load(Ordering::Relaxed);
        let slot = &self.slots[pos & Self::MASK];
        // Acquire: pairs with the producer's Release store of `pos + 1`, so the value
        // written at position `pos` is visible.
        let seq = slot.sequence.load(Ordering::Acquire);
        if (seq.wrapping_sub(pos.wrapping_add(1)) as isize) < 0 {
            return None;
        }
        // SAFETY: `sequence == pos + 1` says the producer of position `pos` finished writing
        // this slot, and the single-consumer guarantee says nobody else reads it. The value
        // is moved out exactly once, because the sequence advances to `pos + N` below.
        let value = unsafe { (*slot.value.get()).assume_init_read() };
        self.head.0.store(pos.wrapping_add(1), Ordering::Relaxed);
        // Release: the slot is empty again; producers may reuse it at position `pos + N`.
        slot.sequence.store(pos.wrapping_add(N), Ordering::Release);
        Some(value)
    }
}

impl<T, const N: usize> Default for BoundedQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for BoundedQueue<T, N> {
    fn drop(&mut self) {
        while self.take().is_some() {}
    }
}

impl<T, const N: usize> fmt::Debug for BoundedQueue<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedQueue")
            .field("capacity", &N)
            .field("head", &self.head.0.load(Ordering::Relaxed))
            .field("tail", &self.tail.0.load(Ordering::Relaxed))
            .finish()
    }
}

/// The unique consumer of a [`BoundedQueue`], borrowed from it by
/// [`BoundedQueue::consumer`]; dropping it releases the role.
pub struct Consumer<'a, T, const N: usize> {
    queue: &'a BoundedQueue<T, N>,
}

impl<T, const N: usize> Consumer<'_, T, N> {
    /// Removes the oldest value; returns `None` when the queue is empty.
    ///
    /// A producer that has claimed a position but not finished writing it makes the queue
    /// look empty until it finishes; later values wait behind it, so order is preserved.
    pub fn pop(&mut self) -> Option<T> {
        self.queue.take()
    }
}

impl<T, const N: usize> Drop for Consumer<'_, T, N> {
    fn drop(&mut self) {
        // Release: publishes this consumer's `head` updates to the next claimant.
        self.queue.consumer_claimed.store(false, Ordering::Release);
    }
}

impl<T, const N: usize> fmt::Debug for Consumer<'_, T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Consumer").field("queue", self.queue).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::Barrier;
    use std::thread;

    impl<T, const N: usize> BoundedQueue<T, N> {
        /// An empty queue whose positions start at `start`, to exercise counter wrap.
        fn starting_at(start: usize) -> Self {
            let queue = Self::new();
            for (i, slot) in queue.slots.iter().enumerate() {
                let offset = i.wrapping_sub(start) & Self::MASK;
                slot.sequence.store(start.wrapping_add(offset), Ordering::Relaxed);
            }
            queue.head.0.store(start, Ordering::Relaxed);
            queue.tail.0.store(start, Ordering::Relaxed);
            queue
        }
    }

    #[test]
    fn bounded_queue_preserves_order_reports_full_and_wraps() {
        let mut q = BoundedQueue::<u32, 8>::new();
        assert_eq!(q.pop(), None);
        for i in 0..8 {
            assert!(q.push(i).is_ok());
        }
        assert_eq!(q.push(99), Err(99));
        for i in 0..8 {
            assert_eq!(q.pop(), Some(i));
        }
        assert_eq!(q.pop(), None);
        for round in 0..100 {
            assert!(q.push(round).is_ok());
            assert!(q.push(round + 1000).is_ok());
            assert_eq!(q.pop(), Some(round));
            assert_eq!(q.pop(), Some(round + 1000));
        }
    }

    #[test]
    fn bounded_queue_accepts_concurrent_producers() {
        let q = BoundedQueue::<u64, 1024>::new();
        let sum = thread::scope(|s| {
            for idx in 0..4u64 {
                let q = &q;
                s.spawn(move || {
                    for n in 0..200 {
                        let mut value = idx * 1000 + n;
                        while let Err(back) = q.push(value) {
                            value = back;
                            std::hint::spin_loop();
                        }
                    }
                });
            }
            let mut consumer = q.consumer().expect("first claim");
            let (mut seen, mut sum) = (0, 0u64);
            while seen < 800 {
                match consumer.pop() {
                    Some(v) => {
                        seen += 1;
                        sum += v;
                    }
                    None => std::hint::spin_loop(),
                }
            }
            sum
        });
        let expected: u64 = (0..4u64).flat_map(|idx| (0..200).map(move |n| idx * 1000 + n)).sum();
        assert_eq!(sum, expected);
    }

    /// Several producers race on a small ring so it is often full; the consumer must see
    /// every value exactly once and each producer's values in the order it pushed them.
    #[test]
    fn stress_preserves_per_producer_order_and_counts() {
        const PRODUCERS: usize = 8;
        const PER_PRODUCER: u64 = 20_000;
        let q = BoundedQueue::<(usize, u64), 16>::new();
        let barrier = Barrier::new(PRODUCERS + 1);
        let refused = AtomicUsize::new(0);
        let next = thread::scope(|s| {
            for producer in 0..PRODUCERS {
                let (q, barrier, refused) = (&q, &barrier, &refused);
                s.spawn(move || {
                    barrier.wait();
                    for n in 0..PER_PRODUCER {
                        let mut value = (producer, n);
                        while let Err(back) = q.push(value) {
                            refused.fetch_add(1, Ordering::Relaxed);
                            value = back;
                            thread::yield_now();
                        }
                    }
                });
            }
            let mut consumer = q.consumer().expect("first claim");
            let mut next = [0u64; PRODUCERS];
            barrier.wait();
            let mut remaining = PRODUCERS as u64 * PER_PRODUCER;
            while remaining > 0 {
                if let Some((producer, n)) = consumer.pop() {
                    assert_eq!(n, next[producer], "producer {producer} out of order");
                    next[producer] += 1;
                    remaining -= 1;
                } else {
                    std::hint::spin_loop();
                }
            }
            next
        });
        assert_eq!(next, [PER_PRODUCER; PRODUCERS]);
        assert!(refused.load(Ordering::Relaxed) > 0, "the ring never filled");
        let mut q = q;
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn full_queue_refuses_and_returns_the_value() {
        let q = BoundedQueue::<String, 2>::new();
        assert!(q.push("a".to_owned()).is_ok());
        assert!(q.push("b".to_owned()).is_ok());
        assert_eq!(q.push("c".to_owned()), Err("c".to_owned()));
        let mut consumer = q.consumer().expect("first claim");
        assert_eq!(consumer.pop().as_deref(), Some("a"));
        assert!(q.push("c".to_owned()).is_ok());
        assert_eq!(consumer.pop().as_deref(), Some("b"));
        assert_eq!(consumer.pop().as_deref(), Some("c"));
        assert_eq!(consumer.pop(), None);
    }

    #[test]
    fn only_one_consumer_at_a_time() {
        let q = BoundedQueue::<u8, 4>::new();
        let first = q.consumer();
        assert!(first.is_some());
        assert!(q.consumer().is_none());
        drop(first);
        assert!(q.consumer().is_some());
    }

    #[test]
    fn drop_releases_queued_values() {
        struct Counted(Rc<Cell<u32>>);
        impl Drop for Counted {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Rc::new(Cell::new(0));
        let mut q = BoundedQueue::<Counted, 8>::new();
        for _ in 0..5 {
            assert!(q.push(Counted(Rc::clone(&drops))).is_ok());
        }
        drop(q.pop());
        assert_eq!(drops.get(), 1);
        drop(q);
        assert_eq!(drops.get(), 5);
    }

    #[test]
    fn positions_wrap_around_usize_max() {
        let mut q = BoundedQueue::<usize, 4>::starting_at(usize::MAX - 5);
        for round in 0..40 {
            for k in 0..3 {
                assert!(q.push(round * 10 + k).is_ok());
            }
            for k in 0..3 {
                assert_eq!(q.pop(), Some(round * 10 + k));
            }
            assert_eq!(q.pop(), None);
        }
        for k in 0..4 {
            assert!(q.push(k).is_ok());
        }
        assert_eq!(q.push(9), Err(9));
    }

    #[test]
    fn queue_is_send_and_sync_for_send_values() {
        fn check<Q: Send + Sync>() {}
        check::<BoundedQueue<String, 8>>();
        check::<BoundedQueue<std::sync::mpsc::Sender<u8>, 8>>();
    }
}
