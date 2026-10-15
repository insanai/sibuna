//! Connection threads, reused from one connection to the next.
//!
//! Each accepted connection runs on a thread of its own, at most `capacity` at once. A thread
//! that finishes its connection parks and takes the next one, so a steady stream of new
//! connections creates no threads. Creating and ending a thread maps and unmaps its signal
//! stack and returns its stack pages; those address-space changes stall the daemon's other
//! threads. With a thread per connection, the 99.9th percentile at 100,000 requests per
//! second (64 connections, each closed after 4,096 requests) was 0.3 to 2 ms; with reuse it
//! is 60 us, below the Zig daemon's.
//!
//! A parked thread that gets no connection for [`IDLE_EXPIRY`] ends; the next launch, or the
//! next thread to finish a task, joins it, so a burst of connections does not leave its
//! threads and their stacks resident.
//! A thread whose task panics ends instead of parking, so no thread-local state survives a
//! failed connection.

use std::collections::VecDeque;
use std::io;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The stack of a connection thread, as in the Zig daemon. It holds the 64 KiB read buffer
/// and the 16 KiB write buffer (80 KiB) and leaves ample room for evaluation; the proxy's
/// 40 KiB workspace lives on the heap.
const STACK_SIZE: usize = 1024 * 1024;

/// How long a parked thread waits for a connection before it ends.
pub const IDLE_EXPIRY: Duration = Duration::from_secs(10);

/// One connection's work.
type Task = Box<dyn FnOnce() + Send + 'static>;

/// Why a task could not start.
#[derive(Debug)]
pub enum LaunchError {
    /// `capacity` tasks are running.
    Capacity,
    /// The operating system refused the thread.
    Spawn(io::Error),
}

/// The pool's bookkeeping, under one lock. Every parked thread is either counted in `idle`
/// or has a task waiting for it in `queue`: a launch takes an idle thread by moving one count
/// from `idle` to `busy` and queueing the task.
struct State {
    /// Tasks handed to parked threads, at most one per parked thread.
    queue: VecDeque<Task>,
    /// Parked threads without a task.
    idle: usize,
    /// Tasks running or queued.
    busy: usize,
    /// The handle of each thread, by entry; `None` for a free entry.
    threads: Vec<Option<JoinHandle<()>>>,
    /// Entries whose thread has ended and waits to be joined.
    ended: Vec<usize>,
    /// Set by [`TaskPool::join`]: parked threads end.
    stopping: bool,
}

impl State {
    /// Takes the handles of the ended threads, freeing their entries.
    fn take_ended(&mut self) -> Vec<JoinHandle<()>> {
        let ended = std::mem::take(&mut self.ended);
        ended.into_iter().filter_map(|index| self.threads.get_mut(index)?.take()).collect()
    }

    /// Returns a free entry for a new thread's handle.
    fn free_entry(&mut self) -> usize {
        self.threads.iter().position(Option::is_none).unwrap_or_else(|| {
            self.threads.push(None);
            self.threads.len() - 1
        })
    }
}

struct Shared {
    state: Mutex<State>,
    /// Wakes parked threads: a task was queued, or the pool is stopping.
    wake: Condvar,
    capacity: usize,
    idle_expiry: Duration,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Connection threads, at most `capacity` running at once, reused across connections.
pub struct TaskPool {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for TaskPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.shared.lock();
        f.debug_struct("TaskPool")
            .field("capacity", &self.shared.capacity)
            .field("busy", &state.busy)
            .field("idle", &state.idle)
            .finish()
    }
}

impl TaskPool {
    /// Returns a pool for at most `capacity` tasks at once (at least one). No thread starts
    /// until the first launch.
    pub fn new(capacity: usize) -> TaskPool {
        TaskPool::with_idle_expiry(capacity, IDLE_EXPIRY)
    }

    /// Returns a pool like [`TaskPool::new`] whose parked threads end after `idle_expiry`.
    pub fn with_idle_expiry(capacity: usize, idle_expiry: Duration) -> TaskPool {
        let state = State {
            queue: VecDeque::new(),
            idle: 0,
            busy: 0,
            threads: Vec::new(),
            ended: Vec::new(),
            stopping: false,
        };
        let shared = Shared {
            state: Mutex::new(state),
            wake: Condvar::new(),
            capacity: capacity.max(1),
            idle_expiry,
        };
        TaskPool { shared: Arc::new(shared) }
    }

    /// Runs `task` on a parked thread, or on a new one when none is parked. Threads that
    /// ended since the last launch are joined first, outside the lock.
    ///
    /// Fails with [`LaunchError::Capacity`] when `capacity` tasks are running and with
    /// [`LaunchError::Spawn`] when a needed thread cannot be created; `task` is then dropped.
    pub fn launch(&self, task: impl FnOnce() + Send + 'static) -> Result<(), LaunchError> {
        let task: Task = Box::new(task);
        let (ended, outcome) = {
            let mut state = self.shared.lock();
            let ended = state.take_ended();
            let outcome = if state.busy >= self.shared.capacity {
                Err(LaunchError::Capacity)
            } else if state.idle > 0 {
                state.idle -= 1;
                state.busy += 1;
                state.queue.push_back(task);
                self.shared.wake.notify_one();
                Ok(())
            } else {
                spawn(&self.shared, &mut state, task)
            };
            (ended, outcome)
        };
        for thread in ended {
            let _ = thread.join();
        }
        outcome
    }

    /// Ends every parked thread and joins every thread, after the running ones finish their
    /// tasks. The caller has stopped every launcher first.
    pub fn join(&self) {
        let threads: Vec<JoinHandle<()>> = {
            let mut state = self.shared.lock();
            state.stopping = true;
            self.shared.wake.notify_all();
            state.threads.iter_mut().filter_map(Option::take).collect()
        };
        for thread in threads {
            let _ = thread.join();
        }
    }

    /// Returns the number of tasks running or about to run.
    pub fn running_count(&self) -> usize {
        self.shared.lock().busy
    }

    /// Returns the number of threads that have not ended: running and parked.
    pub fn thread_count(&self) -> usize {
        let state = self.shared.lock();
        state.busy + state.idle
    }
}

/// Starts a thread for `task` and counts it busy. The lock is held, so the new thread cannot
/// park before it is counted.
fn spawn(shared: &Arc<Shared>, state: &mut State, task: Task) -> Result<(), LaunchError> {
    let index = state.free_entry();
    let worker = Arc::clone(shared);
    let spawned = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || work(&worker, index, task));
    match spawned {
        Ok(thread) => {
            state.threads[index] = Some(thread);
            state.busy += 1;
            Ok(())
        }
        Err(error) => Err(LaunchError::Spawn(error)),
    }
}

/// A connection thread: runs its task, then the tasks it is given while parked, until it
/// expires, the pool stops, or a task panics.
fn work(shared: &Shared, index: usize, first: Task) {
    let mut next = Some(first);
    while let Some(task) = next.take() {
        // The panic hook has reported the panic; the task's guards ran while unwinding.
        if std::panic::catch_unwind(AssertUnwindSafe(task)).is_err() {
            let mut state = shared.lock();
            state.busy -= 1;
            state.ended.push(index);
            return;
        }
        join_ended(shared);
        next = park(shared, index);
    }
}

/// Joins the threads that have ended, outside the lock, so that after a burst their stacks
/// are returned without waiting for the next launch.
fn join_ended(shared: &Shared) {
    let ended = shared.lock().take_ended();
    for thread in ended {
        let _ = thread.join();
    }
}

/// Counts the calling thread idle and waits for a task. Returns `None`, with the thread
/// recorded as ended, when the pool stops or no task comes within the idle expiry.
fn park(shared: &Shared, index: usize) -> Option<Task> {
    let mut state = shared.lock();
    state.busy -= 1;
    state.idle += 1;
    let deadline = Instant::now() + shared.idle_expiry;
    loop {
        // A queued task was counted out of `idle` by its launcher, for this thread or another
        // parked one; any of them may take it.
        if let Some(task) = state.queue.pop_front() {
            return Some(task);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if state.stopping || left.is_zero() {
            state.idle -= 1;
            state.ended.push(index);
            return None;
        }
        state = shared.wake.wait_timeout(state, left).unwrap_or_else(PoisonError::into_inner).0;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread::ThreadId;

    use super::*;

    fn launch_until_accepted(pool: &TaskPool, task: impl FnOnce() + Send + Clone + 'static) {
        loop {
            match pool.launch(task.clone()) {
                Ok(()) => return,
                Err(LaunchError::Capacity) => std::thread::yield_now(),
                Err(LaunchError::Spawn(error)) => panic!("{error}"),
            }
        }
    }

    fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn launched_tasks_run_within_the_capacity() {
        let pool = TaskPool::new(2);
        let (sender, receiver) = mpsc::channel();
        for value in 0..10 {
            let sender = sender.clone();
            launch_until_accepted(&pool, move || sender.send(value).unwrap());
        }
        drop(sender);
        let mut seen: Vec<i32> = receiver.iter().collect();
        seen.sort_unstable();
        assert_eq!(seen, (0..10).collect::<Vec<_>>());
        assert!(pool.thread_count() <= 2);
        pool.join();
        assert_eq!(pool.running_count(), 0);
    }

    // The point of the pool: one connection after another runs on one thread.
    #[test]
    fn a_finished_thread_takes_the_next_task() {
        let pool = TaskPool::new(4);
        let (sender, receiver) = mpsc::channel::<ThreadId>();
        for _ in 0..20 {
            let sender = sender.clone();
            pool.launch(move || sender.send(std::thread::current().id()).unwrap()).unwrap();
            receiver.recv().unwrap();
            wait_until(|| pool.running_count() == 0);
        }
        assert_eq!(pool.thread_count(), 1);
        pool.join();
        assert_eq!(pool.thread_count(), 0);
    }

    #[test]
    fn a_full_pool_refuses_and_frees_places_as_tasks_end() {
        let pool = TaskPool::new(2);
        let (release, wait) = mpsc::channel::<()>();
        let wait = Arc::new(Mutex::new(wait));
        for _ in 0..2 {
            let wait = Arc::clone(&wait);
            pool.launch(move || wait.lock().unwrap().recv().unwrap()).unwrap();
        }
        assert!(matches!(pool.launch(|| {}), Err(LaunchError::Capacity)));
        release.send(()).unwrap();
        wait_until(|| pool.running_count() == 1);
        pool.launch(|| {}).unwrap();
        release.send(()).unwrap();
        pool.join();
    }

    #[test]
    fn a_panicking_task_ends_its_thread_and_frees_its_place() {
        let pool = TaskPool::new(1);
        pool.launch(|| panic!("task failure")).unwrap();
        wait_until(|| pool.thread_count() == 0);
        let (sender, receiver) = mpsc::channel();
        pool.launch(move || sender.send(7).unwrap()).unwrap();
        assert_eq!(receiver.recv().unwrap(), 7);
        pool.join();
    }

    #[test]
    fn idle_threads_expire_and_the_next_launch_joins_them() {
        let pool = TaskPool::with_idle_expiry(4, Duration::from_millis(20));
        let (sender, receiver) = mpsc::channel();
        pool.launch(move || sender.send(()).unwrap()).unwrap();
        receiver.recv().unwrap();
        wait_until(|| pool.thread_count() == 0);
        assert_eq!(pool.shared.lock().ended.len(), 1);
        pool.launch(|| {}).unwrap();
        assert!(pool.shared.lock().ended.is_empty());
        pool.join();
    }
}
