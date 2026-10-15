//! Idle keep-alive connections to the origin, shared by every connection thread.
//!
//! A socket returns to the pool only after a response whose end was framed by a length or a
//! chunked body, read to its end with no byte left over, that the origin is willing to keep
//! (see `relay::relay_response`). A socket is also checked when it is taken: one that has
//! bytes waiting or has reached end of stream is closed instead of reused, because those
//! bytes would be read as the next request's response. The pool holds at most
//! [`Pool::CAPACITY`] sockets in stripes with a lock each: a thread gives to and takes from
//! its home stripe first, so threads rarely meet on one lock, and looks into the other
//! stripes before it connects afresh.

use std::cell::Cell;
use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};

/// Stripes of the pool; a power of two.
const STRIPES: usize = 16;
/// Sockets per stripe.
const STRIPE_CAPACITY: usize = Pool::CAPACITY / STRIPES;

/// One stripe on a cache line of its own, so threads on different stripes do not contend.
#[repr(align(128))]
#[derive(Debug, Default)]
struct Stripe {
    sockets: Mutex<Vec<Arc<TcpStream>>>,
}

/// A fixed-capacity pool of idle origin sockets.
#[derive(Debug)]
pub struct Pool {
    stripes: Box<[Stripe]>,
    /// Set by [`Pool::shutdown`]: nothing is taken, given or connected afterwards. Release
    /// and acquire order it with the sockets the stopping thread then drains.
    stopping: AtomicBool,
}

impl Default for Pool {
    fn default() -> Pool {
        Pool::new()
    }
}

thread_local! {
    /// The calling thread's home stripe, assigned round robin on first use.
    static HOME: Cell<Option<usize>> = const { Cell::new(None) };
}

/// The next home stripe to hand out. Relaxed: it only spreads threads over stripes.
static NEXT_HOME: AtomicUsize = AtomicUsize::new(0);

fn home_stripe() -> usize {
    HOME.with(|home| match home.get() {
        Some(index) => index,
        None => {
            let index = NEXT_HOME.fetch_add(1, Ordering::Relaxed) % STRIPES;
            home.set(Some(index));
            index
        }
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Locks `mutex` unless another thread holds it.
fn try_lock<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

impl Pool {
    /// The most idle sockets the pool keeps, as in the Zig daemon.
    pub const CAPACITY: usize = 256;

    /// An empty pool with its storage allocated.
    pub fn new() -> Pool {
        let stripes = (0..STRIPES)
            .map(|_| Stripe { sockets: Mutex::new(Vec::with_capacity(STRIPE_CAPACITY)) })
            .collect();
        Pool { stripes, stopping: AtomicBool::new(false) }
    }

    /// Takes an idle origin socket if one is pooled: from the home stripe, else from any
    /// other stripe not locked at the moment. A pooled socket that is no longer idle (it has
    /// bytes waiting or has reached end of stream, seen with a non-blocking peek) is closed
    /// and the next one is tried; each is looked at once, so the work is bounded by
    /// [`Pool::CAPACITY`].
    pub fn take(&self) -> Option<Arc<TcpStream>> {
        if self.is_stopping() {
            return None;
        }
        let home = home_stripe();
        while let Some(socket) = self.pop(home) {
            if is_idle(&socket) {
                return Some(socket);
            }
            // Dropping the only handle closes the socket.
        }
        None
    }

    /// Removes a pooled socket: from the home stripe, else from any other stripe not locked
    /// at the moment.
    fn pop(&self, home: usize) -> Option<Arc<TcpStream>> {
        if let Some(socket) = self.stripe(home).and_then(|stripe| lock(&stripe.sockets).pop()) {
            return Some(socket);
        }
        (1..STRIPES).find_map(|offset| {
            let stripe = self.stripe((home + offset) % STRIPES)?;
            try_lock(&stripe.sockets)?.pop()
        })
    }

    /// Returns a reusable origin socket. It is closed instead when the pool is full or
    /// stopping.
    pub fn give(&self, socket: Arc<TcpStream>) {
        if self.is_stopping() {
            return;
        }
        let home = home_stripe();
        let mut socket = Some(socket);
        for offset in 0..STRIPES {
            let Some(stripe) = self.stripe((home + offset) % STRIPES) else { continue };
            let guard =
                if offset == 0 { Some(lock(&stripe.sockets)) } else { try_lock(&stripe.sockets) };
            let Some(mut sockets) = guard else { continue };
            if sockets.len() < STRIPE_CAPACITY {
                sockets.extend(socket.take());
                return;
            }
        }
        // Dropping the last handle closes the socket.
    }

    /// The number of idle sockets pooled now.
    pub fn idle_count(&self) -> usize {
        self.stripes.iter().map(|stripe| lock(&stripe.sockets).len()).sum()
    }

    /// True after [`Pool::shutdown`].
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// Stops pooling: later takes find nothing, later gives close, and the proxy connects no
    /// more. Exchanges in flight are interrupted through their [`crate::idle::Activity`]
    /// ([`crate::idle::IdleTable::shutdown`]).
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::Release);
    }

    /// Closes every pooled socket.
    pub fn drain(&self) {
        for stripe in self.stripes.iter() {
            lock(&stripe.sockets).clear();
        }
    }

    fn stripe(&self, index: usize) -> Option<&Stripe> {
        self.stripes.get(index)
    }
}

/// True when `socket` is idle: open, with no byte waiting. It peeks without blocking and
/// then restores blocking mode. Data waiting on an idle pooled socket can only be a stray
/// response (a body after a bodyless reply, or the answer to a request smuggled in a body),
/// and end of stream means the origin closed it; either way it must not be reused. A socket
/// whose mode cannot be set is not idle either.
fn is_idle(socket: &TcpStream) -> bool {
    if socket.set_nonblocking(true).is_err() {
        return false;
    }
    let mut byte = [0u8; 1];
    let quiet =
        matches!(socket.peek(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock);
    socket.set_nonblocking(false).is_ok() && quiet
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    /// A connected socket; the accepted end is kept open in `peers`.
    fn socket(listener: &TcpListener, peers: &mut Vec<TcpStream>) -> Arc<TcpStream> {
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peers.push(listener.accept().unwrap().0);
        Arc::new(stream)
    }

    #[test]
    fn pooled_sockets_come_back_and_capacity_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peers = Vec::new();
        let pool = Pool::new();
        assert!(pool.take().is_none());
        let first = socket(&listener, &mut peers);
        pool.give(Arc::clone(&first));
        let taken = pool.take().unwrap();
        assert!(Arc::ptr_eq(&first, &taken));
        for _ in 0..Pool::CAPACITY + 3 {
            pool.give(socket(&listener, &mut peers));
        }
        assert_eq!(pool.idle_count(), Pool::CAPACITY);
        let mut count = 0;
        while pool.take().is_some() {
            count += 1;
        }
        assert_eq!(count, Pool::CAPACITY);
    }

    #[test]
    fn a_stopping_pool_neither_takes_nor_keeps() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peers = Vec::new();
        let pool = Pool::new();
        pool.give(socket(&listener, &mut peers));
        pool.shutdown();
        assert!(pool.take().is_none());
        let kept = socket(&listener, &mut peers);
        pool.give(Arc::clone(&kept));
        assert_eq!(Arc::strong_count(&kept), 1);
        pool.drain();
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn sockets_with_waiting_bytes_or_a_closed_peer_are_closed_instead_of_reused() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peers = Vec::new();
        let pool = Pool::new();
        let stray = socket(&listener, &mut peers);
        let closed = socket(&listener, &mut peers);
        let idle = socket(&listener, &mut peers);
        // A stray response after the exchange, and an origin that closed.
        peers[0].write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nPOISONED!").unwrap();
        peers[1].shutdown(std::net::Shutdown::Write).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        pool.give(Arc::clone(&idle));
        pool.give(Arc::clone(&closed));
        pool.give(Arc::clone(&stray));
        drop((stray, closed));
        let taken = pool.take().unwrap();
        assert!(Arc::ptr_eq(&taken, &idle));
        assert!(pool.take().is_none());
        // The taken socket blocks again: a read waits for its timeout.
        let mut byte = [0u8; 1];
        let wait = std::time::Duration::from_millis(30);
        taken.set_read_timeout(Some(wait)).unwrap();
        let started = std::time::Instant::now();
        assert!((&*taken).read(&mut byte).is_err());
        assert!(started.elapsed() >= wait / 2);
        // The discarded sockets were closed (a reset, since a stray byte was unread).
        assert!(!matches!(peers[0].read(&mut [0u8; 64]), Ok(count) if count > 0));
    }

    #[test]
    fn threads_share_sockets_across_stripes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peers = Vec::new();
        let pool = Pool::new();
        let given = socket(&listener, &mut peers);
        std::thread::scope(|scope| {
            scope.spawn(|| pool.give(Arc::clone(&given)));
        });
        let taken = std::thread::scope(|scope| scope.spawn(|| pool.take()).join().unwrap());
        assert!(taken.is_some_and(|taken| Arc::ptr_eq(&taken, &given)));
    }
}
