//! The storage thread: the one owner of a cache, behind a bounded queue.
//!
//! Threads that serve traffic must not wait for a disk. They offer hints and ask for
//! hints through a [`Handle`]. Both calls return at once. When the queue is full the
//! work is dropped and counted: a hint is never worth a stall.
//!
//! The [`Service`] owns the thread. Handles are copies of the way in. When the service
//! is dropped the thread ends and the file is closed, whoever still holds a handle.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cache::{Budget, Cache, Counters, Hint};
use crate::format::{MAX_KEY, MAX_VALUE};

/// The smallest and the largest queue.
const QUEUE_BOUNDS: (usize, usize) = (16, 65_536);
/// The requests the thread serves between two publications of its counters.
const BATCH: usize = 256;

/// How to run a [`Service`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceOptions {
    /// The requests the queue holds, kept within 16 and 65,536.
    pub queue: usize,
}

impl Default for ServiceOptions {
    /// 4,096 requests.
    fn default() -> Self {
        Self { queue: 4096 }
    }
}

/// The current Unix second, the time that hints carry. Zero for a clock before 1970.
pub fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// One piece of work for the storage thread, of a fixed size.
#[derive(Clone, Copy)]
enum Request {
    Offer {
        key: Bytes<MAX_KEY>,
        value: Bytes<MAX_VALUE>,
        expires: u64,
        overwrite: bool,
    },
    Ask {
        key: Bytes<MAX_KEY>,
    },
    Remove {
        key: Bytes<MAX_KEY>,
    },
    /// The service was dropped: end the thread.
    Stop,
}

/// A short byte string of at most `N` bytes, held in place.
#[derive(Clone, Copy)]
struct Bytes<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> Bytes<N> {
    fn new(source: &[u8]) -> Option<Self> {
        let mut bytes = [0; N];
        bytes.get_mut(..source.len())?.copy_from_slice(source);
        Some(Self { bytes, len: u8::try_from(source.len()).ok()? })
    }

    fn get(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// What a service has done, beside the counters of its cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceCounters {
    /// The counters of the cache, as of the last batch the thread finished.
    pub cache: Counters,
    /// Offers, questions and removals dropped because the queue was full.
    pub shed: u64,
    /// Requests that were put on the queue.
    pub queued: u64,
}

struct Shared {
    shed: AtomicU64,
    queued: AtomicU64,
    /// Written by the storage thread after a batch and read by whoever asks. No thread
    /// that serves traffic takes this lock.
    cache: Mutex<Counters>,
}

/// The way into a [`Service`] for the threads that serve traffic. Cheap to clone, and
/// every method takes `&self`.
///
/// A handle that outlives its service drops all work and counts it as shed.
#[derive(Clone)]
pub struct Handle {
    sender: SyncSender<Request>,
    shared: Arc<Shared>,
}

/// A cache on a thread of its own.
///
/// Dropping the service ends the thread after the work queued before, flushes the file,
/// closes it and waits for all three.
pub struct Service {
    handle: Handle,
    thread: Option<JoinHandle<()>>,
    budget: Budget,
}

/// Moves `cache` to a new storage thread behind a bounded queue.
///
/// `found` runs on the storage thread for every question that was served, with the key
/// and the live hint, or `None` when the cache holds none. So the one who asked can
/// tell "nothing there" from "not answered yet". A question that was shed has no
/// answer.
///
/// # Errors
///
/// The error of the system when the thread cannot be started.
pub fn start_service(
    cache: Cache,
    options: ServiceOptions,
    found: impl FnMut(&[u8], Option<&Hint>) + Send + 'static,
) -> io::Result<Service> {
    let queue = options.queue.clamp(QUEUE_BOUNDS.0, QUEUE_BOUNDS.1);
    let (sender, receiver) = sync_channel(queue);
    let shared = Arc::new(Shared {
        shed: AtomicU64::new(0),
        queued: AtomicU64::new(0),
        cache: Mutex::new(cache.counters()),
    });
    let queue_bytes = (queue * size_of::<Request>()) as u64;
    let budget = Budget { queue_bytes, ..cache.budget() };
    let published = Arc::clone(&shared);
    let thread = std::thread::Builder::new()
        .name("sibuna-spill".to_owned())
        .spawn(move || serve(cache, &receiver, &published, found))?;
    Ok(Service { handle: Handle { sender, shared }, thread: Some(thread), budget })
}

/// The loop of the storage thread. It ends when the service is dropped. The cache is
/// dropped with it, which closes the file and gives up its lock.
fn serve(
    mut cache: Cache,
    receiver: &Receiver<Request>,
    shared: &Shared,
    mut found: impl FnMut(&[u8], Option<&Hint>),
) {
    let mut stopped = false;
    while !stopped && let Ok(first) = receiver.recv() {
        let now = unix_seconds();
        let more = std::iter::from_fn(|| receiver.try_recv().ok()).take(BATCH - 1);
        for request in std::iter::once(first).chain(more) {
            match request {
                Request::Offer { key, value, expires, overwrite: true } => {
                    cache.put(key.get(), value.get(), expires, now);
                }
                Request::Offer { key, value, expires, overwrite: false } => {
                    cache.put_new(key.get(), value.get(), expires, now);
                }
                Request::Ask { key } => {
                    found(key.get(), cache.get(key.get(), now).as_ref());
                }
                Request::Remove { key } => {
                    cache.remove(key.get(), now);
                }
                Request::Stop => {
                    stopped = true;
                    break;
                }
            }
        }
        *shared.cache.lock().unwrap_or_else(PoisonError::into_inner) = cache.counters();
    }
    // A failed flush loses nothing the cache promised: the kernel still holds the pages.
    let _ = cache.flush();
}

impl Handle {
    fn send(&self, request: Option<Request>) -> bool {
        let Some(request) = request else { return false };
        match self.sender.try_send(request) {
            Ok(()) => {
                self.shared.queued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.shared.shed.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Offers the hint `key` to `value` that expires at the Unix second `expires`.
    /// Returns at once. `false` means the hint was dropped: the queue was full, or the
    /// key or the value is too long.
    pub fn offer(&self, key: &[u8], value: &[u8], expires: u64) -> bool {
        self.send(Self::offer_request(key, value, expires, true))
    }

    /// Offers a hint that must not replace a live hint of the same key: a guess. See
    /// [`Cache::put_new`]. Returns at once, as [`Handle::offer`] does.
    pub fn offer_new(&self, key: &[u8], value: &[u8], expires: u64) -> bool {
        self.send(Self::offer_request(key, value, expires, false))
    }

    fn offer_request(key: &[u8], value: &[u8], expires: u64, overwrite: bool) -> Option<Request> {
        let (key, value) = Bytes::new(key).zip(Bytes::new(value))?;
        Some(Request::Offer { key, value, expires, overwrite })
    }

    /// Asks for the hint of `key`. Returns at once. The answer, if there is a live hint,
    /// goes to the function given to [`start_service`]. `false` means the question was
    /// dropped.
    pub fn ask(&self, key: &[u8]) -> bool {
        self.send(Bytes::new(key).map(|key| Request::Ask { key }))
    }

    /// Asks to remove the hint of `key`. Returns at once. `false` means the request was
    /// dropped and the hint stays until it expires.
    pub fn remove(&self, key: &[u8]) -> bool {
        self.send(Bytes::new(key).map(|key| Request::Remove { key }))
    }

    /// What the service and its cache have done.
    pub fn counters(&self) -> ServiceCounters {
        ServiceCounters {
            cache: *self.shared.cache.lock().unwrap_or_else(PoisonError::into_inner),
            shed: self.shared.shed.load(Ordering::Relaxed),
            queued: self.shared.queued.load(Ordering::Relaxed),
        }
    }
}

impl Service {
    /// A way into the service for another owner. See [`Handle`].
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }

    /// [`Handle::offer`] through the service's own handle.
    pub fn offer(&self, key: &[u8], value: &[u8], expires: u64) -> bool {
        self.handle.offer(key, value, expires)
    }

    /// [`Handle::ask`] through the service's own handle.
    pub fn ask(&self, key: &[u8]) -> bool {
        self.handle.ask(key)
    }

    /// [`Handle::remove`] through the service's own handle.
    pub fn remove(&self, key: &[u8]) -> bool {
        self.handle.remove(key)
    }

    /// [`Handle::counters`] through the service's own handle.
    pub fn counters(&self) -> ServiceCounters {
        self.handle.counters()
    }

    /// Where the bytes of the cache and the queue go.
    pub fn budget(&self) -> Budget {
        self.budget
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        // The request to stop waits for room in the queue, behind the work queued
        // before. A thread that is gone already makes the send fail, which is as well.
        let _ = self.handle.sender.send(Request::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;
    use crate::open::{Options, load_memory_cache};

    fn cache() -> Cache {
        load_memory_cache(&Options { size: 1 << 20, max_ttl: 3600 }).unwrap()
    }

    #[test]
    fn an_offer_is_stored_and_a_question_is_answered_on_the_storage_thread() {
        let (answers, heard) = mpsc::channel();
        let service = start_service(cache(), ServiceOptions::default(), move |key, hint| {
            let value = hint.map_or_else(|| b"nothing".to_vec(), |hint| hint.value().to_vec());
            let _ = answers.send((key.to_vec(), value));
        })
        .unwrap();
        let later = unix_seconds() + 600;
        assert!(service.offer(b"client-1", b"srv-a", later));
        assert!(service.ask(b"client-1"));
        assert!(service.ask(b"client-2"));
        let answer = heard.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(answer, (b"client-1".to_vec(), b"srv-a".to_vec()));
        // The cache holds nothing for the second key, and says so.
        let answer = heard.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(answer, (b"client-2".to_vec(), b"nothing".to_vec()));
        // A guess does not replace what is known, and it fills what is not.
        assert!(service.handle().offer_new(b"client-1", b"srv-b", later));
        assert!(service.handle().offer_new(b"client-4", b"srv-b", later));
        assert!(service.ask(b"client-1"));
        assert!(service.ask(b"client-4"));
        let answer = heard.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(answer, (b"client-1".to_vec(), b"srv-a".to_vec()));
        let answer = heard.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(answer, (b"client-4".to_vec(), b"srv-b".to_vec()));
        assert!(service.remove(b"client-1"));
        assert!(service.ask(b"client-1"));
        // Too long for a slot: dropped here, never queued.
        assert!(!service.offer(&[1; MAX_KEY + 1], b"v", later));
        assert!(!service.offer(b"k", &[1; MAX_VALUE + 1], later));
        let budget = service.budget();
        assert_eq!(budget.queue_bytes, 4096 * size_of::<Request>() as u64);
        assert!(budget.memory_bytes() > budget.queue_bytes);
        let handle = service.handle();
        drop(service);
        // The thread has ended. The removed key was answered with nothing.
        assert_eq!(heard.try_recv().unwrap(), (b"client-1".to_vec(), b"nothing".to_vec()));
        assert!(heard.try_recv().is_err());
        // A handle that outlives the service drops its work and counts it.
        assert!(!handle.offer(b"client-3", b"srv-a", later));
        assert!(!handle.ask(b"client-1"));
        assert_eq!(handle.counters().shed, 2);
    }

    #[test]
    fn a_full_queue_sheds_work_and_never_blocks() {
        let (gate, wait) = mpsc::channel::<()>();
        let (entered, inside) = mpsc::channel();
        let mut first = true;
        let service = start_service(cache(), ServiceOptions { queue: 1 }, move |_, _| {
            // The first answer holds the storage thread until the test lets it go.
            if std::mem::take(&mut first) {
                let _ = entered.send(());
                let _ = wait.recv();
            }
        })
        .unwrap();
        let later = unix_seconds() + 600;
        assert!(service.offer(b"a", b"1", later));
        assert!(service.ask(b"a"));
        inside.recv_timeout(Duration::from_secs(10)).unwrap();
        // The thread is held. The queue of sixteen fills, and the rest is shed at once.
        let sent = (0..100).filter(|_| service.offer(b"b", b"2", later)).count();
        assert_eq!(sent, 16);
        let counters = service.counters();
        assert_eq!((counters.queued, counters.shed), (18, 84));
        gate.send(()).unwrap();
        drop(service);
    }

    #[test]
    fn the_counters_of_the_cache_are_published_after_a_batch() {
        let service = start_service(cache(), ServiceOptions::default(), |_, _| {}).unwrap();
        let later = unix_seconds() + 600;
        for client in 0..50u32 {
            assert!(service.offer(&client.to_le_bytes(), b"s", later));
        }
        for client in 0..60u32 {
            assert!(service.ask(&client.to_le_bytes()));
        }
        for _ in 0..500 {
            if service.counters().cache.lookups == 60 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let counters = service.counters().cache;
        assert_eq!((counters.stored, counters.lookups, counters.hits), (50, 60, 50));
    }
}
