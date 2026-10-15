//! Joinable connection threads in a fixed table of slots.
//!
//! Each accepted connection runs on a thread of its own. A finished thread still owns its
//! stack until it is joined, so a slot is joined when it is taken again, and a new task takes
//! the lowest finished slot rather than advancing a cursor: a cursor would reach a finished
//! slot again only after a full lap of the table, leaving thousands of finished threads
//! resident, and memory would grow with the connections served instead of those open.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

/// The stack of a connection thread, as in the Zig daemon. The connection buffers live on
/// the heap, so this leaves ample room for evaluation.
const STACK_SIZE: usize = 1024 * 1024;

/// Why a task could not start.
#[derive(Debug)]
pub enum LaunchError {
    /// Every slot holds a running thread.
    Capacity,
    /// The operating system refused the thread.
    Spawn(io::Error),
}

#[derive(Debug)]
struct Slot {
    thread: Option<JoinHandle<()>>,
    /// True while no thread runs in the slot. Release when the thread finishes and acquire
    /// when the slot is chosen, so the join below sees a completed thread.
    done: Arc<AtomicBool>,
}

impl Slot {
    fn new() -> Slot {
        Slot { thread: None, done: Arc::new(AtomicBool::new(true)) }
    }
}

/// A fixed table of joinable task slots.
#[derive(Debug)]
pub struct TaskPool {
    slots: Mutex<Vec<Slot>>,
}

impl TaskPool {
    /// Returns a pool of `capacity` slots (at least one).
    pub fn new(capacity: usize) -> TaskPool {
        let slots = (0..capacity.max(1)).map(|_| Slot::new()).collect();
        TaskPool { slots: Mutex::new(slots) }
    }

    /// Runs `task` on a new thread in the lowest finished slot, joining that slot's previous
    /// thread first so its stack is reclaimed before a new one is allocated.
    ///
    /// Fails with [`LaunchError::Capacity`] when every slot is busy and with
    /// [`LaunchError::Spawn`] when the thread cannot be created; `task` is then dropped.
    pub fn launch(&self, task: impl FnOnce() + Send + 'static) -> Result<(), LaunchError> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let index = free_slot(&slots).ok_or(LaunchError::Capacity)?;
        let slot = &mut slots[index];
        if let Some(thread) = slot.thread.take() {
            // The slot is free, so its thread has run to completion; join reclaims it.
            let _ = thread.join();
        }
        slot.done.store(false, Ordering::Release);
        let done = Arc::clone(&slot.done);
        let spawned = std::thread::Builder::new().stack_size(STACK_SIZE).spawn(move || {
            // Marks the slot free even if the task panics.
            let _finished = Finished(done);
            task();
        });
        match spawned {
            Ok(thread) => {
                slot.thread = Some(thread);
                Ok(())
            }
            Err(error) => {
                slot.done.store(true, Ordering::Release);
                Err(LaunchError::Spawn(error))
            }
        }
    }

    /// Joins every thread. The caller has stopped every launcher first.
    pub fn join(&self) {
        let threads: Vec<JoinHandle<()>> = {
            let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
            slots.iter_mut().filter_map(|slot| slot.thread.take()).collect()
        };
        for thread in threads {
            let _ = thread.join();
        }
    }

    /// Returns the number of threads still running.
    pub fn running_count(&self) -> usize {
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.iter().filter(|slot| !slot.done.load(Ordering::Acquire)).count()
    }
}

/// Sets the slot's `done` flag when the task ends, however it ends.
struct Finished(Arc<AtomicBool>);

impl Drop for Finished {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The slot a new task takes: the lowest whose previous thread has finished. Kept apart
/// from `launch` so the reuse policy can be tested without threads.
fn free_slot(slots: &[Slot]) -> Option<usize> {
    slots.iter().position(|slot| slot.done.load(Ordering::Acquire))
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn a_task_takes_the_lowest_finished_slot_instead_of_walking_the_table() {
        // The reuse policy is what bounds memory: a finished thread keeps its stack until it
        // is joined, and a slot is joined only when it is taken again.
        let slots: Vec<Slot> = (0..8).map(|_| Slot::new()).collect();
        assert_eq!(free_slot(&slots), Some(0));
        slots[0].done.store(false, Ordering::Release);
        assert_eq!(free_slot(&slots), Some(1));
        // Once the first task finishes it is chosen again, so its thread is joined promptly.
        slots[1].done.store(false, Ordering::Release);
        slots[0].done.store(true, Ordering::Release);
        assert_eq!(free_slot(&slots), Some(0));
        // A full table reports exhaustion so the caller answers 503 instead of overcommitting.
        for slot in &slots {
            slot.done.store(false, Ordering::Release);
        }
        assert_eq!(free_slot(&slots), None);
    }

    #[test]
    fn launched_tasks_run_and_slots_are_reused_after_join() {
        let pool = TaskPool::new(2);
        let (sender, receiver) = mpsc::channel();
        for value in 0..10 {
            let sender = sender.clone();
            loop {
                let sender = sender.clone();
                match pool.launch(move || sender.send(value).unwrap()) {
                    Ok(()) => break,
                    Err(LaunchError::Capacity) => std::thread::yield_now(),
                    Err(LaunchError::Spawn(error)) => panic!("{error}"),
                }
            }
        }
        drop(sender);
        let mut seen: Vec<i32> = receiver.iter().collect();
        seen.sort_unstable();
        assert_eq!(seen, (0..10).collect::<Vec<_>>());
        pool.join();
        assert_eq!(pool.running_count(), 0);
    }

    #[test]
    fn a_panicking_task_frees_its_slot() {
        let pool = TaskPool::new(1);
        pool.launch(|| panic!("task failure")).unwrap();
        while pool.running_count() != 0 {
            std::thread::yield_now();
        }
        pool.launch(|| {}).unwrap();
        pool.join();
    }
}
