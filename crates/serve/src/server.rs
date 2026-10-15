//! The bounded listener: one acceptor, one watchdog and a fixed table of joinable workers.
//!
//! The acceptor admits each connection as HTTP, gives it a free slot and starts a worker
//! thread for it; a full table is answered with 503. The worker reads one head into its
//! 16 KiB buffer (431 when it does not fit), parses it, runs the handler and closes the
//! connection. The watchdog shuts down every socket whose deadline has passed, which wakes
//! a worker blocked on it; this is how slow clients are bounded, since a blocking socket has
//! no per-read deadline here either. [`Server::stop`] wakes the acceptor by connecting to
//! it, shuts down every open socket and joins every thread it started.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::admission::{Admission, Capacity, Class};
use crate::context::{Context, Lent};
use crate::deadline::{self, Clock, Deadline};
use crate::error::{ServeError, StartError};
use crate::head::{HeadError, MAX_HEAD, parse_head, read_head};
use crate::response::{HEAD_TOO_LARGE, UNAVAILABLE};
use crate::stack;

/// The application's request handler, shared by every worker thread.
///
/// Closures implement it; annotate the argument (`|context: &mut Context<'_>| ...`) so the
/// closure accepts every context lifetime.
pub trait Handler: Send + Sync + 'static {
    /// Handles the one request of a connection. The listener closes the connection when
    /// this returns.
    ///
    /// # Errors
    ///
    /// Any [`ServeError`]; the listener counts those that are not I/O failures in
    /// [`Counters::failed`] and otherwise only closes the connection.
    fn handle(&self, context: &mut Context<'_>) -> Result<(), ServeError>;
}

impl<F> Handler for F
where
    F: Fn(&mut Context<'_>) -> Result<(), ServeError> + Send + Sync + 'static,
{
    fn handle(&self, context: &mut Context<'_>) -> Result<(), ServeError> {
        self(context)
    }
}

/// How a [`Server`] runs. The defaults are the console's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Slots and per-class quotas.
    pub capacity: Capacity,
    /// From accept until the head has arrived and the handler has started.
    pub head_timeout: Duration,
    /// Set when the handler reads the body.
    pub body_timeout: Duration,
    /// Set when the handler writes a response.
    pub respond_timeout: Duration,
    /// How often the watchdog looks for passed deadlines.
    pub watchdog_interval: Duration,
    /// The stack of every listener thread.
    pub stack_size: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            capacity: Capacity::default(),
            head_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
            respond_timeout: Duration::from_secs(30),
            watchdog_interval: Duration::from_millis(100),
            stack_size: stack::bytes(stack::USABLE),
        }
    }
}

/// What the listener has done since it started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Connections given a slot.
    pub accepted: u64,
    /// Connections answered with 503 because no slot was free.
    pub refused: u64,
    /// Heads answered with 431.
    pub oversized: u64,
    /// Heads refused by closing the connection.
    pub malformed: u64,
    /// Sockets the watchdog shut down because their deadline passed.
    pub expired: u64,
    /// Handlers that returned an error other than an I/O failure.
    pub failed: u64,
    /// Failed calls to `accept`.
    pub accept_errors: u64,
}

/// Statistics only: every counter is updated and read with relaxed ordering.
#[derive(Debug, Default)]
struct Tally {
    accepted: AtomicU64,
    refused: AtomicU64,
    oversized: AtomicU64,
    malformed: AtomicU64,
    expired: AtomicU64,
    failed: AtomicU64,
    accept_errors: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// One entry of the slot table.
#[derive(Debug, Default)]
struct Slot {
    /// A second handle on the connection's socket, kept so the watchdog and `stop` can shut
    /// it down. `None` when the slot is free.
    stream: Option<TcpStream>,
    /// The worker that served the slot last; joined before the slot is reused.
    worker: Option<JoinHandle<()>>,
}

/// State shared by the listener's threads.
struct Shared {
    handler: Box<dyn Handler>,
    options: Options,
    clock: Clock,
    /// Set once by `stop`. Release on store and acquire on load, as in Zig; the flag itself
    /// publishes no other memory.
    stopping: AtomicBool,
    admission: Mutex<Admission>,
    slots: Mutex<Box<[Slot]>>,
    /// One deadline per slot, outside the lock so connections move theirs freely.
    deadlines: Box<[AtomicU64]>,
    tally: Tally,
}

impl Shared {
    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    fn admission(&self) -> MutexGuard<'_, Admission> {
        // A panicking handler cannot leave the counts half-updated: every update is one
        // statement under the lock.
        self.admission.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn slots(&self) -> MutexGuard<'_, Box<[Slot]>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A running listener. Dropping it stops it as [`Server::stop`] does.
pub struct Server {
    shared: Arc<Shared>,
    address: SocketAddr,
    acceptor: Option<JoinHandle<()>>,
    watchdog: Option<JoinHandle<()>>,
}

impl Server {
    /// Binds `address` (with `SO_REUSEADDR`) and starts the acceptor and the watchdog;
    /// every connection is then served by `handler` on a thread of its own.
    ///
    /// # Errors
    ///
    /// [`StartError::Capacity`] for invalid `options.capacity`, [`StartError::Bind`] when
    /// the address cannot be bound, and [`StartError::Spawn`] when a thread cannot start.
    pub fn start<H: Handler>(
        address: SocketAddr,
        handler: H,
        options: Options,
    ) -> Result<Server, StartError> {
        let admission = Admission::new(options.capacity).map_err(StartError::Capacity)?;
        let listener = TcpListener::bind(address).map_err(StartError::Bind)?;
        let address = listener.local_addr().map_err(StartError::Bind)?;
        let slots = usize::from(options.capacity.max_slots);
        let shared = Arc::new(Shared {
            handler: Box::new(handler),
            options,
            clock: Clock::new(),
            stopping: AtomicBool::new(false),
            admission: Mutex::new(admission),
            slots: Mutex::new((0..slots).map(|_| Slot::default()).collect()),
            deadlines: (0..slots).map(|_| AtomicU64::new(deadline::SPENT)).collect(),
            tally: Tally::default(),
        });
        let mut server =
            Server { shared: Arc::clone(&shared), address, acceptor: None, watchdog: None };
        let watched = Arc::clone(&shared);
        server.watchdog = Some(spawn(options.stack_size, move || watch(&watched))?);
        server.acceptor = Some(spawn(options.stack_size, move || accept(&shared, &listener))?);
        Ok(server)
    }

    /// The address the listener is bound to (with the port chosen for port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// The listener's counters so far.
    pub fn counters(&self) -> Counters {
        let tally = &self.shared.tally;
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Counters {
            accepted: read(&tally.accepted),
            refused: read(&tally.refused),
            oversized: read(&tally.oversized),
            malformed: read(&tally.malformed),
            expired: read(&tally.expired),
            failed: read(&tally.failed),
            accept_errors: read(&tally.accept_errors),
        }
    }

    /// A snapshot of the admitted connections by class.
    pub fn admission(&self) -> Admission {
        *self.shared.admission()
    }

    /// Stops the listener and returns once every thread it started has ended: it refuses
    /// new admissions, wakes and joins the acceptor and the watchdog, shuts down every open
    /// socket and joins every worker. A worker whose handler is busy without touching its
    /// socket is waited for; handlers should check [`Context::is_stopping`] in long waits.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        let Some(acceptor) = self.acceptor.take() else { return };
        // Release pairs with the acquire loads of the acceptor, workers and watchdog.
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.admission().stop();
        wake(self.address, &acceptor);
        let _ = acceptor.join();
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.thread().unpark();
            let _ = watchdog.join();
        }
        let workers: Vec<JoinHandle<()>> = {
            let mut slots = self.shared.slots();
            for stream in slots.iter().filter_map(|slot| slot.stream.as_ref()) {
                let _ = stream.shutdown(Shutdown::Both);
            }
            slots.iter_mut().filter_map(|slot| slot.worker.take()).collect()
        };
        // The workers' exit path takes the slot lock, so join them after releasing it.
        for worker in workers {
            let _ = worker.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.halt();
    }
}

fn spawn(
    stack: usize,
    body: impl FnOnce() + Send + 'static,
) -> Result<JoinHandle<()>, StartError> {
    thread::Builder::new().stack_size(stack).spawn(body).map_err(StartError::Spawn)
}

/// Wakes an acceptor blocked in `accept` by connecting to it: closing a listening socket
/// does not wake a blocked `accept` on Linux. A wildcard address is reached over loopback.
fn wake(address: SocketAddr, acceptor: &JoinHandle<()>) {
    let mut target = address;
    if target.ip().is_unspecified() {
        target.set_ip(match target {
            SocketAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
            SocketAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
        });
    }
    // A full accept backlog can delay the connection; retry for up to ten seconds, then
    // join regardless.
    for _ in 0..40 {
        if acceptor.is_finished() {
            return;
        }
        if TcpStream::connect_timeout(&target, Duration::from_millis(250)).is_ok() {
            return;
        }
    }
}

fn accept(shared: &Arc<Shared>, listener: &TcpListener) {
    loop {
        let accepted = listener.accept();
        if shared.is_stopping() {
            return;
        }
        match accepted {
            Ok((stream, peer)) => admit(shared, stream, peer),
            Err(_) => {
                bump(&shared.tally.accept_errors);
                // Out of descriptors, for example: do not spin while the condition lasts.
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Gives the connection a slot and a worker, or answers 503.
fn admit(shared: &Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    if shared.admission().acquire(Class::Http).is_err() {
        return refuse(shared, stream);
    }
    match occupy(shared, stream, peer) {
        Ok(()) => bump(&shared.tally.accepted),
        Err(stream) => {
            shared.admission().release(Class::Http);
            if let Some(stream) = stream {
                refuse(shared, stream);
            }
        }
    }
}

/// Puts the connection in a free slot and starts its worker. On failure a handle on the
/// connection is handed back for a 503 when one is left.
fn occupy(
    shared: &Arc<Shared>,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<(), Option<TcpStream>> {
    let mut slots = shared.slots();
    let Some(index) = slots.iter().position(|slot| slot.stream.is_none()) else {
        // Admission and the table count the same connections, and a worker frees its slot
        // before its admission, so this is a transient overlap at most.
        return Err(Some(stream));
    };
    let Ok(watched) = stream.try_clone() else { return Err(Some(stream)) };
    let slot = slots.get_mut(index).ok_or(None)?;
    if let Some(previous) = slot.worker.take() {
        // The previous worker has freed the slot and only releases its admission now,
        // which does not need this lock.
        let _ = previous.join();
    }
    slot.stream = Some(watched);
    let head_deadline = shared.clock.after(shared.options.head_timeout);
    if let Some(at) = shared.deadlines.get(index) {
        // Relaxed: see `Deadline::set`.
        at.store(head_deadline, Ordering::Relaxed);
    }
    let worker = Arc::clone(shared);
    let spawned = thread::Builder::new()
        .stack_size(shared.options.stack_size)
        .spawn(move || run(&worker, index, stream, peer));
    match spawned {
        Ok(handle) => {
            slot.worker = Some(handle);
            Ok(())
        }
        // The closure took the stream with it; answer on the watchdog's handle instead.
        Err(_) => Err(slot.stream.take()),
    }
}

fn refuse(shared: &Shared, stream: TcpStream) {
    bump(&shared.tally.refused);
    // A fresh socket's send buffer is empty, so this short write does not block.
    let _ = (&stream).write_all(UNAVAILABLE);
}

/// Frees the slot and then the admission of a finished connection, also when its handler
/// panics.
struct Exit<'a> {
    shared: &'a Shared,
    index: usize,
    class: Class,
}

impl Drop for Exit<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.shared.slots().get_mut(self.index) {
            slot.stream = None;
        }
        self.shared.admission().release(self.class);
    }
}

/// A worker: serves the one request of the connection in slot `index`.
fn run(shared: &Shared, index: usize, stream: TcpStream, peer: SocketAddr) {
    let mut exit = Exit { shared, index, class: Class::Http };
    // Declared after `exit`, so the socket closes before the slot and admission are freed.
    let stream = stream;
    let Some(at) = shared.deadlines.get(index) else { return };
    let mut receive = [0u8; MAX_HEAD];
    let (length, received) = match read_head(&mut &stream, &mut receive) {
        Ok(read) => read,
        Err(HeadError::TooLarge) => {
            bump(&shared.tally.oversized);
            let _ = (&stream).write_all(HEAD_TOO_LARGE);
            return;
        }
        Err(HeadError::Closed | HeadError::Failed) => return,
    };
    let (head, rest) = receive.split_at(length);
    let Some(head) = parse_head(head) else {
        bump(&shared.tally.malformed);
        return;
    };
    let lent = Lent {
        stream: &stream,
        peer,
        deadline: Deadline::new(at, &shared.clock),
        admission: &shared.admission,
        stopping: &shared.stopping,
        body_timeout: shared.options.body_timeout,
        respond_timeout: shared.options.respond_timeout,
    };
    let received = rest.get(..received - length).unwrap_or_default();
    let mut context = Context::new(head, received, lent, &mut exit.class);
    if let Err(error) = shared.handler.handle(&mut context)
        && !error.is_io()
    {
        bump(&shared.tally.failed);
    }
}

/// The watchdog: every interval, shuts down the sockets whose deadline has passed.
fn watch(shared: &Shared) {
    while !shared.is_stopping() {
        thread::park_timeout(shared.options.watchdog_interval);
        let now = shared.clock.now();
        let slots = shared.slots();
        for (slot, at) in slots.iter().zip(shared.deadlines.iter()) {
            if let Some(stream) = &slot.stream
                && deadline::expire(at, now)
            {
                bump(&shared.tally.expired);
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}
