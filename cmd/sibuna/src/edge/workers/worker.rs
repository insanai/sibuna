//! One worker: its poller, its tables and the client side of each connection.

use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use sibuna_net::CONNECT_TIMEOUT;
use sibuna_reactor::{
    Io, Poller, READ, Slab, WRITE, Waker, Wheel, handle, read_once as read, write_once as write,
};

use super::conn::{BUFFER, Buffer, Conn, HIGH_WATER, Origin, Reading};
use super::request::{self, Scratch, Step};
use super::{Incoming, Shared, Timeouts};
use crate::connection::{MAX_REQUESTS_PER_CONNECTION, PeerText};
use crate::server::{Server, admit_handoff, admit_within};

const KIND_WAKE: u64 = 0;
pub(super) const KIND_CLIENT: u64 = 1;
pub(super) const KIND_ORIGIN: u64 = 2;

/// Spare request buffers a worker keeps.
const SPARE_BUFFERS: usize = 128;
/// Body bytes that extend a request's deadline.
const BODY_CREDIT: usize = 16 * 1024;
/// Rounds of work one event may cause, so that one connection cannot hold the worker.
const ROUNDS: usize = 8;
/// A vector that grew beyond this is released when it empties, so that a connection
/// between two bursts holds no memory for the last one.
pub(super) const KEPT_CAPACITY: usize = 16 * 1024;

/// The key a socket is registered by: its kind, the generation and index of its record.
pub(super) fn key(kind: u64, index: u32, generation: u32) -> u64 {
    (kind << 62) | (u64::from(generation & 0x3fff_ffff) << 32) | u64::from(index)
}

/// Which socket of a connection reported an event.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    Client,
    Origin,
    /// A deadline or the worker itself.
    Neither,
}

pub(super) struct Worker {
    pub server: Arc<Server>,
    pub poll: Poller<u64>,
    pub conns: Slab<Conn>,
    pub origins: Slab<Origin>,
    /// Idle server sockets by address, as indices of `origins`.
    pub idle: HashMap<SocketAddr, Vec<u32>>,
    pub idle_count: usize,
    pub buffers: Vec<Buffer>,
    pub wires: Vec<Vec<u8>>,
    pub wheel: Wheel,
    pub scratch: Scratch,
    /// Where a socket is read before the bytes have an owner.
    pub block: Box<[u8]>,
    pub load: Arc<AtomicUsize>,
    pub shared: Arc<Shared>,
    pub timeouts: Timeouts,
    pub now: Instant,
    pub draining: bool,
    swept: Instant,
}

impl Worker {
    pub fn new(
        server: Arc<Server>,
        shared: Arc<Shared>,
        load: Arc<AtomicUsize>,
        timeouts: Timeouts,
        waker: &Waker,
    ) -> io::Result<Self> {
        let mut poll = Poller::new()?;
        poll.set(handle(waker.socket()), READ, key(KIND_WAKE, 0, 0))?;
        let now = Instant::now();
        Ok(Self {
            server,
            poll,
            conns: Slab::new(),
            origins: Slab::new(),
            idle: HashMap::new(),
            idle_count: 0,
            buffers: Vec::new(),
            wires: Vec::new(),
            wheel: Wheel::new(now),
            scratch: Scratch::new(),
            block: vec![0; BUFFER].into_boxed_slice(),
            load,
            shared,
            timeouts,
            now,
            draining: false,
            swept: now,
        })
    }

    /// Serves until the workers are stopped.
    pub fn run(mut self, waker: &Waker, incoming: &mpsc::Receiver<Incoming>) {
        let (mut ready, mut due) = (Vec::new(), Vec::new());
        loop {
            ready.clear();
            if self.poll.wait(250, &mut ready).is_err() {
                // Without readiness the worker cannot serve. Back off and try again.
                std::thread::sleep(Duration::from_millis(50));
            }
            self.now = Instant::now();
            for &key in &ready {
                let (index, generation) = (key as u32, (key >> 32) as u32 & 0x3fff_ffff);
                match key >> 62 {
                    KIND_WAKE => {
                        waker.drain();
                        self.receive(incoming);
                    }
                    KIND_CLIENT => {
                        if self.conns.generation(index) & 0x3fff_ffff == generation {
                            self.guarded(index, Side::Client);
                        }
                    }
                    _ => self.origin_event(index, generation),
                }
            }
            if self.shared.stopping.load(Ordering::Acquire) {
                for index in self.conns.indices() {
                    self.close(index);
                }
                return;
            }
            self.tick(&mut due);
        }
    }

    fn receive(&mut self, incoming: &mpsc::Receiver<Incoming>) {
        while let Ok(incoming) = incoming.try_recv() {
            if !self.adopt(incoming) {
                self.load.fetch_sub(1, Ordering::Relaxed);
            }
        }
        if !self.draining && self.shared.draining.load(Ordering::Acquire) {
            self.draining = true;
            for index in self.conns.indices() {
                self.guarded(index, Side::Neither);
            }
        }
    }

    /// Takes a connection under the connection limits and registers it.
    fn adopt(&mut self, incoming: Incoming) -> bool {
        let Incoming { stream, ingress, permit } = incoming;
        if self.draining || stream.set_nonblocking(true).is_err() {
            return false;
        }
        let admission = if ingress.secure {
            admit_handoff(&self.server)
        } else {
            let bound = ingress.connection_bound(&self.server);
            let peer = ingress.peer.ip();
            let Some(admission) = admit_within(&self.server, &stream, peer, bound) else {
                return false;
            };
            admission
        };
        // A socket pair from the TLS front refuses this option. It needs none.
        let _ = stream.set_nodelay(true);
        let mut peer = PeerText::default();
        peer.format(Some(ingress.peer));
        let conn = Conn {
            stream,
            ingress,
            peer,
            _permit: permit,
            admission: Some(admission),
            input: None,
            output: Vec::new(),
            sent: 0,
            reading: Reading::default(),
            exchange: None,
            served: 0,
            activity: self.now,
            deadline: self.now,
            armed: self.now,
            read_closed: false,
            closing: false,
            trace: None,
        };
        let (index, _) = self.conns.insert(conn);
        self.sync(index);
        true
    }

    /// Runs the work of one connection. A panic closes that connection only.
    pub fn guarded(&mut self, index: u32, side: Side) {
        let result = catch_unwind(AssertUnwindSafe(|| self.drive(index, side)));
        if result.is_err() {
            self.server.metrics.worker_faults.bump();
            let _ = catch_unwind(AssertUnwindSafe(|| self.close(index)));
        }
    }

    /// Does everything a connection can do without waiting.
    fn drive(&mut self, index: u32, side: Side) {
        if side == Side::Client && !self.read_client(index) {
            return;
        }
        for round in 0..ROUNDS {
            self.requests(index);
            let side = if round == 0 { side } else { Side::Neither };
            let again = self.pump(index, side);
            if !self.flush_client(index) {
                return;
            }
            if !again {
                break;
            }
        }
        self.trim(index);
        self.sync(index);
    }

    /// Reads the client once. Returns false when the connection was closed.
    fn read_client(&mut self, index: u32) -> bool {
        let Some(conn) = self.conns.at(index) else { return false };
        if conn.read_closed || conn.closing {
            return true;
        }
        let was_empty = !conn.has_input();
        let result = match conn.input.as_mut() {
            Some(buffer) => {
                let result =
                    read(&conn.stream, buffer.data.get_mut(buffer.len..).unwrap_or_default());
                if let Io::Bytes(count) = result {
                    buffer.len += count;
                }
                result
            }
            None => {
                let result = read(&conn.stream, &mut self.block);
                if let Io::Bytes(count) = result {
                    let mut buffer = self.buffers.pop().unwrap_or_else(Buffer::new);
                    buffer.data[..count].copy_from_slice(&self.block[..count]);
                    buffer.len = count;
                    conn.input = Some(buffer);
                }
                result
            }
        };
        match result {
            Io::Bytes(count) => {
                let tunnel = conn.exchange.as_ref().is_some_and(|exchange| exchange.tunnel);
                conn.reading.credit += count;
                // A head has one deadline from its first byte. A body earns more time.
                let body = conn.reading.head_len != 0 || conn.exchange.is_some();
                let earned = body && conn.reading.credit >= BODY_CREDIT;
                if tunnel || earned || (was_empty && conn.exchange.is_none()) {
                    conn.activity = self.now;
                    conn.reading.credit = 0;
                }
            }
            Io::Blocked => {}
            Io::Closed => conn.read_closed = true,
            Io::Failed => {
                self.close(index);
                return false;
            }
        }
        true
    }

    /// Decides the buffered requests until one needs a server or more bytes.
    fn requests(&mut self, index: u32) {
        loop {
            let Some(conn) = self.conns.at(index) else { return };
            if conn.exchange.is_some() || conn.closing {
                return;
            }
            if !conn.has_input() || conn.backlog() >= HIGH_WATER {
                break;
            }
            match request::advance(&self.server, conn, &mut self.scratch) {
                Step::Wait => {
                    if conn.read_closed {
                        request::truncated(&self.server, conn, &mut self.scratch);
                        conn.closing = true;
                    }
                    break;
                }
                Step::Answered { keep, used } => {
                    Self::next_request(conn, used, self.now);
                    conn.closing |= !keep || self.draining;
                }
                Step::Admitted { plan, used } => {
                    conn.trace = self.scratch.trace.entry.take();
                    Self::next_request(conn, used, self.now);
                    let wire = std::mem::replace(
                        &mut self.scratch.defer.wire,
                        self.wires.pop().unwrap_or_default(),
                    );
                    self.begin(index, plan, wire);
                    return;
                }
            }
        }
        let Some(conn) = self.conns.at(index) else { return };
        if (conn.read_closed || self.draining) && !conn.has_input() {
            conn.closing = true;
        }
        if (conn.closing || !conn.has_input())
            && let Some(mut buffer) = conn.input.take()
            && self.buffers.len() < SPARE_BUFFERS
        {
            buffer.len = 0;
            self.buffers.push(buffer);
        }
    }

    /// Gives an empty request buffer back, so that a connection that waits holds none.
    fn trim(&mut self, index: u32) {
        let Some(conn) = self.conns.at(index) else { return };
        if !conn.has_input()
            && let Some(mut buffer) = conn.input.take()
            && self.buffers.len() < SPARE_BUFFERS
        {
            buffer.len = 0;
            self.buffers.push(buffer);
        }
    }

    fn next_request(conn: &mut Conn, used: usize, now: Instant) {
        if let Some(buffer) = conn.input.as_mut() {
            buffer.consume(used);
        }
        conn.reading = Reading::default();
        conn.served += 1;
        conn.activity = now;
        if conn.served >= MAX_REQUESTS_PER_CONNECTION {
            conn.closing = true;
        }
    }

    /// Writes pending response bytes. Returns false when the connection was closed.
    pub fn flush_client(&mut self, index: u32) -> bool {
        let Some(conn) = self.conns.at(index) else { return false };
        if conn.backlog() > 0 {
            match write(&conn.stream, conn.output.get(conn.sent..).unwrap_or_default()) {
                Io::Bytes(count) => {
                    conn.sent += count;
                    conn.activity = self.now;
                }
                Io::Blocked => {}
                Io::Closed | Io::Failed => {
                    self.close(index);
                    return false;
                }
            }
            if conn.backlog() == 0 {
                conn.sent = 0;
                conn.output.clear();
                if conn.output.capacity() > KEPT_CAPACITY {
                    conn.output = Vec::new();
                }
            }
        }
        if conn.closing && conn.backlog() == 0 {
            self.close(index);
            return false;
        }
        true
    }

    /// Registers the sockets of a connection for what it can use now and sets its deadline.
    pub fn sync(&mut self, index: u32) {
        let generation = self.conns.generation(index);
        let Some(conn) = self.conns.at(index) else { return };
        let full = conn.input.as_ref().is_some_and(|buffer| buffer.len == buffer.data.len());
        let exchange = conn.exchange.as_deref();
        let room = exchange.map_or(conn.backlog(), |exchange| exchange.backlog()) < HIGH_WATER;
        let reads = !conn.read_closed && !conn.closing && !full && room;
        let events = (i16::from(reads) * READ) | (i16::from(conn.backlog() > 0) * WRITE);
        let registered =
            self.poll.set(handle(&conn.stream), events, key(KIND_CLIENT, index, generation));
        let mut timeout = self.timeouts.idle;
        let mut since = conn.activity;
        let mut origin = None;
        if let Some(exchange) = exchange {
            if exchange.connecting {
                (timeout, since) = (CONNECT_TIMEOUT, exchange.connect_since);
            } else if exchange.tunnel {
                timeout = self.timeouts.tunnel;
            }
            let reads = !exchange.connecting && conn.backlog() < HIGH_WATER;
            let writes = exchange.connecting || exchange.backlog() > 0;
            origin = exchange
                .origin
                .map(|at| (at, (i16::from(reads) * READ) | (i16::from(writes) * WRITE)));
        }
        conn.deadline = since + timeout;
        if conn.deadline < conn.armed || conn.armed <= self.now {
            conn.armed = self.wheel.arm(index, generation, conn.deadline);
        }
        let mut failed = registered.is_err();
        if let Some((at, events)) = origin {
            let generation = self.origins.generation(at);
            if let Some(origin) = self.origins.at(at) {
                let key = key(KIND_ORIGIN, at, generation);
                failed |= self.poll.set(handle(&origin.stream), events, key).is_err();
            }
        }
        if failed {
            self.close(index);
        }
    }

    /// Closes a connection, the exchange it serves and that exchange's server socket.
    pub fn close(&mut self, index: u32) {
        let Some(mut conn) = self.conns.remove(index) else { return };
        self.load.fetch_sub(1, Ordering::Relaxed);
        // A tunnel, or an exchange cut short, is logged when its connection closes.
        super::trace::settle(&self.server, &mut conn.trace, self.now);
        self.poll.remove(handle(&conn.stream));
        if let Some(exchange) = conn.exchange.take() {
            if let Some(origin) = exchange.origin {
                self.drop_origin(origin);
            }
            self.recycle(exchange.wire);
        }
        // The place under the limits is free before the client can see the close.
        drop(conn.admission.take());
        let _ = conn.stream.shutdown(Shutdown::Write);
        // Closing over unread bytes resets the connection, and the reset can destroy the
        // response on its way. Take what has arrived first.
        for _ in 0..4 {
            if !matches!(read(&conn.stream, &mut self.block), Io::Bytes(_)) {
                break;
            }
        }
        if let Some(mut buffer) = conn.input.take()
            && self.buffers.len() < SPARE_BUFFERS
        {
            buffer.len = 0;
            self.buffers.push(buffer);
        }
    }

    pub fn recycle(&mut self, mut wire: Vec<u8>) {
        if wire.capacity() <= BUFFER && self.wires.len() < SPARE_BUFFERS {
            wire.clear();
            self.wires.push(wire);
        }
    }

    /// Looks at the connections whose timer fired and at the idle server sockets.
    fn tick(&mut self, due: &mut Vec<(u32, u32)>) {
        due.clear();
        self.wheel.expired(self.now, due);
        for &(index, generation) in due.iter() {
            let Some(conn) = self.conns.current(index, generation) else { continue };
            if self.now >= conn.deadline {
                self.server.metrics.deadline_closes.bump();
                self.expire(index);
            } else {
                conn.armed = self.wheel.arm(index, generation, conn.deadline);
            }
        }
        if self.now.saturating_duration_since(self.swept) >= Duration::from_secs(1) {
            self.swept = self.now;
            self.sweep_idle();
        }
    }
}
