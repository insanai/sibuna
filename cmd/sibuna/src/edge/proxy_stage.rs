//! The stage that reads a PROXY header before TLS or HTTP sees a connection (SID 0020).
//!
//! ```text
//!  accept --submit--> [ stage: at most 4,096 connections, 5 s each ]
//!                        | readable: look at the first bytes without taking them
//!                        v
//!           trusted peer and a whole, valid header?
//!              yes: take exactly the header, deliver with the client address
//!              no:  close and count
//! ```
//!
//! The header must be whole in the first look. A sender writes it in one piece, and
//! HAProxy's own receiver has the same rule. So the socket stays the only buffer, and
//! the first byte of TLS or HTTP is the next one read.

use std::io::{self, Read};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_lb::{FlowPermit, MAX_PROXY_HEADER, parse_proxy_header};
use sibuna_reactor::{Poller, READ, Slab, Wake, Waker, handle};

use super::http::Dispatcher;
use crate::access::Observe;

/// The most connections that wait for their header at once.
const MAX_HELD: usize = 4096;
/// The longest wait for a header.
const PATIENCE: Duration = Duration::from_secs(5);
/// The key of the waker in the poller. No record has this index.
const WAKE: (u32, u32) = (u32::MAX, 0);

/// A connection that has not sent its header yet.
struct Held {
    bind: SocketAddr,
    stream: TcpStream,
    permit: FlowPermit,
    since: Instant,
}

/// What became of a connection that turned readable.
#[derive(Debug, PartialEq, Eq)]
enum Look {
    /// A whole header was taken. The client address is its source, when it names one.
    Header(Option<SocketAddr>),
    /// Nothing arrived yet.
    Wait,
    /// The connection is closed: it sent no valid header in one piece.
    Refuse,
}

/// The sending side of the stage. Dropping it stops the thread and closes what waits.
pub(super) struct Stage {
    sender: Mutex<mpsc::Sender<Held>>,
    wake: Wake,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Stage {
    /// Starts the stage. Connections with a header go to `dispatcher`.
    ///
    /// # Errors
    ///
    /// The error of creating the poller, the waker or the thread.
    pub fn start(dispatcher: Arc<Dispatcher>, observe: Arc<Observe>) -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let (waker, wake) = Waker::new()?;
        let mut poll = Poller::new()?;
        poll.set(handle(waker.socket()), READ, WAKE)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker = Worker { poll, held: Slab::new(), dispatcher, observe, stop: stop.clone() };
        let thread = std::thread::Builder::new()
            .name("edge-proxy-header".into())
            .spawn(move || worker.run(&waker, &receiver))?;
        Ok(Self { sender: Mutex::new(sender), wake, stop, thread: Some(thread) })
    }

    /// Gives the stage a connection accepted on the PROXY frontend at `bind`.
    pub fn submit(&self, bind: SocketAddr, stream: TcpStream, permit: FlowPermit) {
        let held = Held { bind, stream, permit, since: Instant::now() };
        let sent = self.sender.lock().unwrap_or_else(PoisonError::into_inner).send(held).is_ok();
        if sent {
            self.wake.wake();
        }
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.wake.wake();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Worker {
    poll: Poller<(u32, u32)>,
    held: Slab<Held>,
    dispatcher: Arc<Dispatcher>,
    observe: Arc<Observe>,
    stop: Arc<AtomicBool>,
}

impl Worker {
    fn run(mut self, waker: &Waker, incoming: &mpsc::Receiver<Held>) {
        let mut ready = Vec::new();
        while !self.stop.load(Ordering::Acquire) {
            ready.clear();
            if self.poll.wait(250, &mut ready).is_err() {
                std::thread::sleep(Duration::from_millis(50));
            }
            for &(index, generation) in &ready {
                if (index, generation) == WAKE {
                    waker.drain();
                    while let Ok(held) = incoming.try_recv() {
                        self.adopt(held);
                    }
                } else if self.held.current(index, generation).is_some() {
                    self.look(index);
                }
            }
            self.expire(Instant::now());
        }
    }

    /// Registers a new connection, or refuses it: the stage is full, or its socket peer
    /// is not a proxy the frontend trusts.
    fn adopt(&mut self, held: Held) {
        let trusted = held.stream.peer_addr().is_ok_and(|peer| {
            self.dispatcher.frontend(held.bind).is_some_and(|front| front.trusts(peer.ip()))
        });
        if !trusted || self.held.len() >= MAX_HELD || held.stream.set_nonblocking(true).is_err() {
            self.refuse();
            return;
        }
        let fd = handle(&held.stream);
        let key = self.held.insert(held);
        if self.poll.set(fd, READ, key).is_err() {
            self.held.remove(key.0);
            self.refuse();
        }
    }

    fn refuse(&self) {
        self.observe.proxy_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Looks at a readable connection and delivers or closes it.
    fn look(&mut self, index: u32) {
        let Some(held) = self.held.at(index) else { return };
        let outcome = take_header(&held.stream);
        if outcome == Look::Wait {
            return;
        }
        let Some(held) = self.held.remove(index) else { return };
        self.poll.remove(handle(&held.stream));
        match outcome {
            Look::Header(client) => {
                self.observe.proxy_accepted.fetch_add(1, Ordering::Relaxed);
                self.dispatcher.deliver(held.bind, held.stream, held.permit, client);
            }
            Look::Wait | Look::Refuse => self.refuse(),
        }
    }

    /// Closes the connections that waited too long.
    fn expire(&mut self, now: Instant) {
        for index in self.held.indices() {
            let late = self
                .held
                .at(index)
                .is_some_and(|held| now.saturating_duration_since(held.since) >= PATIENCE);
            if late && let Some(held) = self.held.remove(index) {
                self.poll.remove(handle(&held.stream));
                self.refuse();
            }
        }
    }
}

/// Looks at the first bytes of `stream` without taking them. When they hold a whole
/// PROXY header, takes exactly the header.
fn take_header(mut stream: &TcpStream) -> Look {
    let mut bytes = [0u8; MAX_PROXY_HEADER];
    let seen = match stream.peek(&mut bytes) {
        Ok(0) => return Look::Refuse,
        Ok(seen) => seen,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Look::Wait,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Look::Wait,
        Err(_) => return Look::Refuse,
    };
    // An incomplete header is refused too: it must arrive in one piece.
    let Ok(header) = parse_proxy_header(&bytes[..seen]) else { return Look::Refuse };
    // The bytes were just seen, so this read does not wait.
    match stream.read_exact(&mut bytes[..header.length]) {
        Ok(()) => Look::Header(header.source),
        Err(_) => Look::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;

    use super::*;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        (client, server)
    }

    fn settle(server: &TcpStream) -> Look {
        // Loopback delivery is quick but not instant.
        for _ in 0..200 {
            match take_header(server) {
                Look::Wait => std::thread::sleep(Duration::from_millis(5)),
                other => return other,
            }
        }
        Look::Wait
    }

    #[test]
    fn exactly_the_header_is_taken_and_the_rest_stays_for_http() {
        let (mut client, server) = pair();
        client
            .write_all(b"PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\r\nGET / HTTP/1.1\r\n")
            .unwrap();
        assert_eq!(settle(&server), Look::Header(Some("203.0.113.7:51234".parse().unwrap())));
        let mut rest = [0u8; 64];
        let count = (&server).read(&mut rest).unwrap();
        assert_eq!(&rest[..count], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn a_connection_without_a_whole_valid_header_is_refused() {
        let (mut client, server) = pair();
        assert_eq!(take_header(&server), Look::Wait, "nothing arrived yet");
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(settle(&server), Look::Refuse);
        let (mut client, server) = pair();
        client.write_all(b"PROXY TCP4 203.0.113.7").unwrap();
        assert_eq!(settle(&server), Look::Refuse, "a header in pieces");
        let (client, server) = pair();
        drop(client);
        assert_eq!(settle(&server), Look::Refuse, "a closed connection");
    }
}
