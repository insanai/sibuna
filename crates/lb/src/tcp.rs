//! Bounded connect work outside the packet worker and full-duplex nonblocking relay.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::pool::Ticket;
use sibuna_reactor::{Poller, READ, WRITE, Wake, Waker, handle};

type Job = (u64, SocketAddr, Instant);

/// The result of one queued connect.
pub(crate) enum Connect {
    /// The origin accepted the connection.
    Ready(TcpStream),
    /// The origin refused or did not answer in time.
    Failed,
    /// The deadline passed in the queue. Nothing is known about the origin.
    Expired,
}

/// Blocking connects run on these threads so the packet worker never waits for an origin.
pub(crate) struct Connectors {
    tx: mpsc::SyncSender<Job>,
    pub done: mpsc::Receiver<(u64, Connect)>,
}

impl Connectors {
    const THREADS: usize = 16;
    const QUEUE: usize = 4096;

    pub fn start(wake: &Wake) -> io::Result<Self> {
        let (tx, jobs) = mpsc::sync_channel::<Job>(Self::QUEUE);
        let (completed, done) = mpsc::channel();
        let jobs = Arc::new(Mutex::new(jobs));
        for _ in 0..Self::THREADS {
            let jobs = Arc::clone(&jobs);
            let completed = completed.clone();
            let wake = wake.clone();
            std::thread::Builder::new().name("edge-connect".into()).spawn(move || {
                loop {
                    let job =
                        jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).recv();
                    let Ok((id, addr, deadline)) = job else { break };
                    let result = match deadline.checked_duration_since(Instant::now()) {
                        Some(left) if !left.is_zero() => {
                            match TcpStream::connect_timeout(&addr, left) {
                                Ok(stream) => Connect::Ready(stream),
                                Err(_) => Connect::Failed,
                            }
                        }
                        _ => Connect::Expired,
                    };
                    if completed.send((id, result)).is_err() {
                        break;
                    }
                    wake.wake();
                }
            })?;
        }
        Ok(Self { tx, done })
    }

    pub fn submit(&self, id: u64, addr: SocketAddr, deadline: Instant) -> bool {
        self.tx.try_send((id, addr, deadline)).is_ok()
    }
}

#[derive(Default)]
struct Direction {
    eof: bool,
    pending: Vec<u8>,
    sent: usize,
    stalled: Option<Instant>,
}

impl Direction {
    fn pump(
        &mut self,
        mut src: &TcpStream,
        mut dst: &TcpStream,
        buf: &mut [u8],
    ) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        if !self.pending.is_empty() {
            let n = write(&mut dst, &self.pending[self.sent..])?;
            self.sent += n;
            if self.sent == self.pending.len() {
                self.pending = Vec::new();
                self.sent = 0;
                self.stalled = None;
            } else if n > 0 {
                self.stalled = Some(Instant::now());
            }
            return Ok(n > 0);
        }
        let n = match src.read(buf) {
            Ok(0) => {
                self.eof = true;
                dst.shutdown(Shutdown::Write)?;
                return Ok(true);
            }
            Ok(n) => n,
            Err(error) if transient(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        let written = write(&mut dst, &buf[..n])?;
        if written < n {
            self.pending.extend_from_slice(&buf[written..n]);
            self.stalled = Some(Instant::now());
        }
        Ok(true)
    }
}

fn write(dst: &mut &TcpStream, bytes: &[u8]) -> io::Result<usize> {
    match dst.write(bytes) {
        Ok(0) => Err(io::ErrorKind::WriteZero.into()),
        Err(error) if transient(&error) => Ok(0),
        result => result,
    }
}

pub(crate) fn transient(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
}

pub(crate) struct Stream {
    _permit: crate::FlowPermit,
    pub client: TcpStream,
    pub origin: TcpStream,
    _ticket: Ticket,
    up: Direction,
    down: Direction,
    timeout: Duration,
    last: Instant,
}

impl Stream {
    pub fn new(
        permit: crate::FlowPermit,
        client: TcpStream,
        origin: TcpStream,
        ticket: Ticket,
        timeout: Duration,
        pending: Vec<u8>,
    ) -> io::Result<Self> {
        client.set_nonblocking(true)?;
        origin.set_nonblocking(true)?;
        let stalled = (!pending.is_empty()).then(Instant::now);
        Ok(Self {
            _permit: permit,
            client,
            origin,
            _ticket: ticket,
            timeout,
            up: Direction { pending, stalled, ..Default::default() },
            down: Direction::default(),
            last: Instant::now(),
        })
    }

    /// Registers both sockets for the events this stream can use now.
    fn sync(&self, poll: &mut Poller<u64>, key: u64) -> io::Result<()> {
        let (client, origin) = self.interests();
        poll.set(handle(&self.client), client, key)?;
        poll.set(handle(&self.origin), origin, key)
    }

    fn forget(&self, poll: &mut Poller<u64>) {
        poll.remove(handle(&self.client));
        poll.remove(handle(&self.origin));
    }

    fn interests(&self) -> (i16, i16) {
        let interest = |out: &Direction, incoming: &Direction| {
            let read = !out.eof && out.pending.is_empty();
            (i16::from(read) * READ) | (i16::from(!incoming.pending.is_empty()) * WRITE)
        };
        (interest(&self.up, &self.down), interest(&self.down, &self.up))
    }

    pub fn expired(&self, now: Instant) -> bool {
        [Some(self.last), self.up.stalled, self.down.stalled]
            .into_iter()
            .flatten()
            .any(|last| now.saturating_duration_since(last) >= self.timeout)
    }

    pub fn relay(&mut self, scratch: &mut [u8]) -> io::Result<bool> {
        let up = self.up.pump(&self.client, &self.origin, scratch)?;
        let down = self.down.pump(&self.origin, &self.client, scratch)?;
        if up || down {
            self.last = Instant::now();
        }
        Ok(!(self.up.eof && self.down.eof))
    }
}

struct Worker {
    tx: Option<mpsc::Sender<Stream>>,
    wake: Wake,
    load: Arc<AtomicUsize>,
    thread: Option<JoinHandle<()>>,
}

/// Relay threads. Each owns a poller and the established streams assigned to it.
pub(crate) struct Relays {
    workers: Vec<Worker>,
}

impl Relays {
    /// Starts `count` relay threads.
    pub fn start(count: usize) -> io::Result<Self> {
        let mut workers = Vec::with_capacity(count);
        for index in 0..count.max(1) {
            let (tx, rx) = mpsc::channel();
            let (waker, wake) = Waker::new()?;
            let load = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&load);
            let mut poll = Poller::new()?;
            poll.set(handle(waker.socket()), READ, WAKE)?;
            let thread = std::thread::Builder::new()
                .name(format!("edge-relay-{index}"))
                .spawn(move || relay_loop(poll, &waker, &rx, &counter))?;
            workers.push(Worker { tx: Some(tx), wake, load, thread: Some(thread) });
        }
        Ok(Self { workers })
    }

    /// Hands an established stream to the least loaded relay thread.
    pub fn submit(&self, stream: Stream) {
        let Some(worker) = self.workers.iter().min_by_key(|w| w.load.load(Ordering::Relaxed))
        else {
            return;
        };
        worker.load.fetch_add(1, Ordering::Relaxed);
        if let Some(tx) = &worker.tx
            && tx.send(stream).is_ok()
        {
            worker.wake.wake();
        }
    }
}

impl Drop for Relays {
    fn drop(&mut self) {
        for worker in &mut self.workers {
            worker.tx = None;
            worker.wake.wake();
        }
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

const WAKE: u64 = 0;
const SWEEP: Duration = Duration::from_millis(100);

fn relay_loop(
    mut poll: Poller<u64>,
    waker: &Waker,
    incoming: &mpsc::Receiver<Stream>,
    load: &AtomicUsize,
) {
    let mut streams: HashMap<u64, Stream> = HashMap::new();
    let mut ready = Vec::new();
    let mut scratch = vec![0u8; 65536].into_boxed_slice();
    let mut next_id = WAKE;
    let mut swept = Instant::now();
    loop {
        ready.clear();
        if poll.wait(SWEEP.as_millis() as i32, &mut ready).is_err() {
            // Without readiness the thread cannot serve its streams. Back off and retry.
            std::thread::sleep(SWEEP);
        }
        for &key in &ready {
            if key != WAKE {
                advance(&mut streams, &mut poll, key, &mut scratch, load);
                continue;
            }
            waker.drain();
            loop {
                match incoming.try_recv() {
                    Ok(stream) => {
                        next_id = next_id.wrapping_add(1).max(1);
                        streams.insert(next_id, stream);
                        // The prefix or early client bytes may already be writable.
                        advance(&mut streams, &mut poll, next_id, &mut scratch, load);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return,
                }
            }
        }
        let now = Instant::now();
        if now.saturating_duration_since(swept) >= SWEEP {
            swept = now;
            streams.retain(|_, stream| {
                let keep = !stream.expired(now);
                if !keep {
                    stream.forget(&mut poll);
                    load.fetch_sub(1, Ordering::Relaxed);
                }
                keep
            });
        }
    }
}

fn advance(
    streams: &mut HashMap<u64, Stream>,
    poll: &mut Poller<u64>,
    key: u64,
    scratch: &mut [u8],
    load: &AtomicUsize,
) {
    let Some(stream) = streams.get_mut(&key) else { return };
    let open = stream.relay(scratch).unwrap_or(false) && stream.sync(poll, key).is_ok();
    if !open && let Some(stream) = streams.remove(&key) {
        stream.forget(poll);
        load.fetch_sub(1, Ordering::Relaxed);
    }
}
