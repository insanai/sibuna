//! Bounded connect work outside the packet worker and full-duplex nonblocking relay.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use crate::poll::{READ, WRITE};
use crate::pool::Ticket;

type Job = (u64, SocketAddr, Instant);

pub(crate) struct Connectors {
    tx: mpsc::SyncSender<Job>,
    pub done: mpsc::Receiver<(u64, io::Result<TcpStream>)>,
}

impl Connectors {
    pub fn start() -> io::Result<Self> {
        let (tx, jobs) = mpsc::sync_channel::<Job>(64);
        let (completed, done) = mpsc::channel();
        let jobs = Arc::new(Mutex::new(jobs));
        for _ in 0..4 {
            let jobs = Arc::clone(&jobs);
            let completed = completed.clone();
            std::thread::Builder::new().name("edge-connect".into()).spawn(move || {
                loop {
                    let job =
                        jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).recv();
                    let Ok((id, addr, deadline)) = job else { break };
                    let result = match deadline.checked_duration_since(Instant::now()) {
                        Some(left) if !left.is_zero() => TcpStream::connect_timeout(&addr, left),
                        _ => Err(io::ErrorKind::TimedOut.into()),
                    };
                    if completed.send((id, result)).is_err() {
                        break;
                    }
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
            client,
            origin,
            _ticket: ticket,
            timeout,
            up: Direction { pending, stalled, ..Default::default() },
            down: Direction::default(),
            last: Instant::now(),
        })
    }

    pub fn interests(&self) -> (i16, i16) {
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
