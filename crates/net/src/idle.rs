//! Activity-based deadlines: the connection registry the idle reaper walks.
//!
//! Every client connection registers its socket in an [`IdleTable`] and receives a [`Lease`].
//! The lease's [`Activity`] holds the time bytes last moved on the connection. The proxy
//! refreshes it on every origin read and per 16 KiB of upload, and attaches the origin socket
//! of the exchange in flight. A reaper thread ([`IdleTable::run_reaper`]) shuts down every
//! connection silent for longer than its timeout, together with the attached origin socket,
//! so the worker blocked on either side sees end of stream and releases its thread.
//!
//! The registry holds its own handle of each socket: a `try_clone` of the client socket and
//! a shared [`Arc`] of the origin socket. A descriptor therefore stays open, and cannot be
//! reused for another connection, while the reaper can still reach it.
//!
//! ```
//! use std::net::{TcpListener, TcpStream};
//! use sibuna_net::idle::IdleTable;
//!
//! let listener = TcpListener::bind("127.0.0.1:0").unwrap();
//! let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
//! let (stream, _) = listener.accept().unwrap();
//! let table = IdleTable::with_capacity(4);
//! let lease = table.register(&stream).unwrap();
//! lease.activity().touch();
//! assert_eq!(table.active_count(), 1);
//! drop(lease);
//! assert_eq!(table.active_count(), 0);
//! ```

use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// The number of slots in the daemon's registry, shared with the connection limit.
pub const CAPACITY: usize = 8192;

/// Milliseconds on a monotonic clock that starts at the first call in the process.
///
/// Every stamp in this module uses this clock, so stamps compare across threads. The origin
/// instant is the only process-wide state; it never changes once set.
pub fn now_ms() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let elapsed = ORIGIN.get_or_init(Instant::now).elapsed();
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Locks `mutex`, ignoring poisoning: every critical section here leaves its data valid.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The liveness of one client connection as the reaper sees it.
///
/// The stamp advances whenever bytes move on the exchange in flight, so a deadline measures
/// silence rather than response length. The origin socket of the exchange is attached so a
/// stall is cut on both sides.
#[derive(Debug, Default)]
pub struct Activity {
    /// The last [`now_ms`] at which bytes moved. Relaxed ordering: the stamp is a standalone
    /// value, and a reaper that reads a slightly older one only reaps a moment later.
    at_ms: AtomicU64,
    /// An idle bound of the current phase in milliseconds; zero uses the reaper's default.
    /// Relaxed for the same reason as `at_ms`.
    timeout_ms: AtomicU64,
    /// The origin socket of the exchange in flight. The lock orders attach, detach and the
    /// reaper's shutdown: the owner detaches before it closes or pools the socket.
    peer: Mutex<Peer>,
}

#[derive(Debug, Default)]
struct Peer {
    stream: Option<Arc<TcpStream>>,
    /// Set by [`IdleTable::shutdown`]: a socket attached afterwards is shut down at once.
    stopped: bool,
}

impl Activity {
    /// A fresh activity stamped now, for an exchange that has no [`IdleTable`] lease.
    pub fn new() -> Activity {
        let activity = Activity::default();
        activity.touch();
        activity
    }

    /// Records that bytes moved now.
    #[inline]
    pub fn touch(&self) {
        self.at_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// The [`now_ms`] stamp of the last movement.
    pub fn last_ms(&self) -> u64 {
        self.at_ms.load(Ordering::Relaxed)
    }

    /// Sets the idle bound of the current phase; zero restores the reaper's default and
    /// `u64::MAX` disables the deadline.
    pub fn set_timeout_ms(&self, timeout_ms: u64) {
        self.timeout_ms.store(timeout_ms, Ordering::Relaxed);
    }

    /// Attaches the origin socket of the exchange in flight, so a reap cuts it too. After
    /// [`IdleTable::shutdown`] the socket is shut down at once instead.
    pub fn attach_peer(&self, stream: &Arc<TcpStream>) {
        let mut peer = lock(&self.peer);
        if peer.stopped {
            let _ = stream.shutdown(Shutdown::Both);
        }
        peer.stream = Some(Arc::clone(stream));
    }

    /// Detaches the origin socket; call it before the socket is closed or pooled.
    pub fn detach_peer(&self) {
        lock(&self.peer).stream = None;
    }

    /// Interrupts the attached origin socket; its owner still closes it.
    pub fn shutdown_peer(&self) {
        if let Some(stream) = &lock(&self.peer).stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Shuts down the attached origin socket and every one attached later.
    fn stop(&self) {
        let mut peer = lock(&self.peer);
        peer.stopped = true;
        if let Some(stream) = &peer.stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Clears the state of a previous connection for a new registration.
    fn reset(&self, now_ms: u64) {
        self.at_ms.store(now_ms, Ordering::Relaxed);
        self.timeout_ms.store(0, Ordering::Relaxed);
        let mut peer = lock(&self.peer);
        peer.stream = None;
        peer.stopped = false;
    }
}

#[derive(Debug, Default)]
struct Slot {
    /// The registered client socket (a clone of the owner's handle); `None` when free. The
    /// reaper shuts it down under this lock, and the owner unregisters under it.
    stream: Mutex<Option<TcpStream>>,
    activity: Activity,
}

/// The registry of open connections for the idle reaper.
///
/// Each slot pairs a socket with its [`Activity`] under a small lock of its own; there is no
/// table-wide lock. A slot stays owned by its [`Lease`] until the lease is dropped, even after
/// a reap, so an old connection can never release a slot a new one took.
#[derive(Debug)]
pub struct IdleTable {
    slots: Box<[Slot]>,
    /// Where the next registration starts probing. Relaxed: it only spreads registrations.
    cursor: AtomicUsize,
    /// Set by [`IdleTable::shutdown`]; later registrations fail. Release and acquire pair the
    /// flag with the slot scan that follows it.
    stopping: AtomicBool,
}

impl Default for IdleTable {
    fn default() -> IdleTable {
        IdleTable::new()
    }
}

/// A connection's registration in an [`IdleTable`]; dropping it unregisters the connection.
#[derive(Debug)]
pub struct Lease<'t> {
    table: &'t IdleTable,
    index: usize,
}

impl<'t> Lease<'t> {
    /// The connection's activity, valid for the life of the lease.
    pub fn activity(&self) -> &'t Activity {
        // `index` came from a successful registration, so it is in bounds.
        &self.table.slots[self.index].activity
    }

    /// Records activity now; the daemon calls it after each request served.
    pub fn touch(&self) {
        self.activity().touch();
    }

    /// The slot number, unique among the live leases of the table.
    pub fn index(&self) -> usize {
        self.index
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.table.slots.get(self.index) {
            slot.activity.detach_peer();
            *lock(&slot.stream) = None;
        }
    }
}

impl IdleTable {
    /// A registry of [`CAPACITY`] slots, allocated once.
    pub fn new() -> IdleTable {
        IdleTable::with_capacity(CAPACITY)
    }

    /// A registry of `capacity` slots (at least one), allocated once.
    pub fn with_capacity(capacity: usize) -> IdleTable {
        let slots = (0..capacity.max(1)).map(|_| Slot::default()).collect();
        IdleTable { slots, cursor: AtomicUsize::new(0), stopping: AtomicBool::new(false) }
    }

    /// The number of slots.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Registers `stream`, stamped now. See [`IdleTable::register_at`].
    pub fn register(&self, stream: &TcpStream) -> Option<Lease<'_>> {
        self.register_at(stream, now_ms())
    }

    /// Registers `stream` with its activity stamped `now_ms`, holding a clone of the socket
    /// handle so the reaper can shut it down.
    ///
    /// Returns `None` when every slot is taken, when the handle cannot be cloned (the process
    /// is out of descriptors), or after [`IdleTable::shutdown`]; the caller then closes the
    /// connection.
    pub fn register_at(&self, stream: &TcpStream, now_ms: u64) -> Option<Lease<'_>> {
        if self.stopping.load(Ordering::Acquire) {
            return None;
        }
        let capacity = self.slots.len();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % capacity;
        for probe in 0..capacity {
            let index = (start + probe) % capacity;
            let slot = self.slots.get(index)?;
            let mut registered = lock(&slot.stream);
            if registered.is_some() {
                continue;
            }
            *registered = Some(stream.try_clone().ok()?);
            slot.activity.reset(now_ms);
            return Some(Lease { table: self, index });
        }
        None
    }

    /// The number of registered connections.
    pub fn active_count(&self) -> usize {
        self.slots.iter().filter(|slot| lock(&slot.stream).is_some()).count()
    }

    /// Shuts down every registered socket and its attached origin socket, and refuses later
    /// registrations: the first step of stopping the daemon. Owners still release their
    /// leases.
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::Release);
        for slot in self.slots.iter() {
            if let Some(stream) = lock(&slot.stream).as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
            slot.activity.stop();
        }
    }

    /// Shuts down every connection idle for longer than its timeout at `now_ms`, together
    /// with the origin socket its exchange holds. A slot's own timeout (set by an upgraded
    /// connection) overrides `timeout_ms`; a timeout of zero never reaps. Returns the number
    /// of connections cut. A reaped slot stays owned by its lease.
    pub fn reap(&self, now_ms: u64, timeout_ms: u64) -> usize {
        let mut reaped = 0;
        for slot in self.slots.iter() {
            let registered = lock(&slot.stream);
            let Some(stream) = registered.as_ref() else { continue };
            let override_ms = slot.activity.timeout_ms.load(Ordering::Relaxed);
            let timeout = if override_ms == 0 { timeout_ms } else { override_ms };
            if timeout != 0 && now_ms.saturating_sub(slot.activity.last_ms()) > timeout {
                let _ = stream.shutdown(Shutdown::Both);
                slot.activity.shutdown_peer();
                reaped += 1;
            }
        }
        reaped
    }

    /// Runs the idle reaper until `stop` is set: every [`reaper_interval`] it reaps with the
    /// HTTP timeout `http_timeout_seconds`. Returns at once when both timeouts are disabled.
    /// It checks `stop` every 200 ms; run it on a thread of its own.
    pub fn run_reaper(
        &self,
        http_timeout_seconds: u32,
        websocket_timeout_seconds: u32,
        stop: &AtomicBool,
    ) {
        let Some(interval) = reaper_interval(http_timeout_seconds, websocket_timeout_seconds)
        else {
            return;
        };
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        let timeout_ms = u64::from(http_timeout_seconds) * 1000;
        let mut next_reap = now_ms().saturating_add(interval_ms);
        // Acquire pairs with the daemon's release store when it asks the reaper to stop.
        while !stop.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(200));
            let now = now_ms();
            if now < next_reap {
                continue;
            }
            self.reap(now, timeout_ms);
            next_reap = now.saturating_add(interval_ms);
        }
    }
}

/// How often the reaper runs: a quarter of the shortest enabled timeout, clamped to 200 ms
/// to 1 s. A disabled or very long HTTP timeout does not disable an independent upgrade
/// deadline. `None` when both are disabled (zero).
pub fn reaper_interval(http_seconds: u32, websocket_seconds: u32) -> Option<Duration> {
    let shortest = match (http_seconds, websocket_seconds) {
        (0, 0) => return None,
        (0, seconds) | (seconds, 0) => seconds,
        (http, websocket) => http.min(websocket),
    };
    Some(Duration::from_millis((u64::from(shortest) * 250).clamp(200, 1000)))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn reaped_idle_slots_remain_owned_until_the_original_connection_unregisters() {
        let table = IdleTable::with_capacity(16);
        let (_client, stream) = pair();
        let old = table.register_at(&stream, 0).unwrap();
        assert_eq!(table.reap(200, 0), 0);
        old.activity().set_timeout_ms(100);
        assert_eq!(table.reap(200, 0), 1);
        table.cursor.store(old.index(), Ordering::Relaxed);
        // The same socket is sufficient to check registry ownership.
        let fresh = table.register_at(&stream, 200).unwrap();
        assert_ne!(old.index(), fresh.index());
        let fresh_index = fresh.index();
        drop(old);
        assert!(lock(&table.slots[fresh_index].stream).is_some());
        drop(fresh);
        assert_eq!(table.active_count(), 0);
    }

    #[test]
    fn reaping_cuts_the_client_and_the_attached_origin() {
        use std::io::Read;
        let table = IdleTable::with_capacity(2);
        let (mut client, stream) = pair();
        let (mut origin_peer, origin) = pair();
        let origin = Arc::new(origin);
        let lease = table.register_at(&stream, 0).unwrap();
        lease.activity().attach_peer(&origin);
        assert_eq!(table.reap(1_000, 2_000), 0);
        assert_eq!(table.reap(5_000, 2_000), 1);
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        assert_eq!(origin_peer.read(&mut byte).unwrap(), 0);
        lease.activity().detach_peer();
        // A detached origin is out of reach.
        assert_eq!(table.reap(9_000, 2_000), 1);
        assert_eq!(Arc::strong_count(&origin), 1);
    }

    #[test]
    fn shutdown_refuses_registrations_and_cuts_later_attachments() {
        use std::io::Read;
        let table = IdleTable::with_capacity(2);
        let (_client, stream) = pair();
        let lease = table.register(&stream).unwrap();
        table.shutdown();
        assert!(table.register(&stream).is_none());
        let (mut origin_peer, origin) = pair();
        lease.activity().attach_peer(&Arc::new(origin));
        let mut byte = [0u8; 1];
        assert_eq!(origin_peer.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn a_full_table_refuses_registration() {
        let table = IdleTable::with_capacity(1);
        let (_client, stream) = pair();
        let lease = table.register(&stream).unwrap();
        assert!(table.register(&stream).is_none());
        drop(lease);
        assert!(table.register(&stream).is_some());
    }

    #[test]
    fn websocket_deadlines_remain_scheduled_with_disabled_or_longer_http_deadlines() {
        assert_eq!(reaper_interval(0, 3), Some(Duration::from_millis(750)));
        assert_eq!(reaper_interval(3600, 3), Some(Duration::from_millis(750)));
        assert_eq!(reaper_interval(0, 0), None);
        assert_eq!(reaper_interval(15, 300), Some(Duration::from_millis(1000)));
        assert_eq!(reaper_interval(0, 0), None);
        assert_eq!(reaper_interval(u32::MAX, 0), Some(Duration::from_millis(1000)));
    }

    #[test]
    fn the_reaper_stops_when_asked() {
        let table = IdleTable::with_capacity(1);
        let stop = AtomicBool::new(true);
        table.run_reaper(1, 0, &stop);
        table.run_reaper(0, 0, &AtomicBool::new(false));
    }
}
