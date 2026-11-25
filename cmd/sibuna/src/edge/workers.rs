//! Event-driven HTTP workers (SID 0016).
//!
//! Each worker is one thread with one poller. It owns its client connections, its server
//! sockets and its buffers, so the request path takes no lock of its own. An accepted
//! connection goes to the worker with the fewest connections and stays there.

mod conn;
mod exchange;
mod linger;
mod request;
mod secure;
mod trace;
mod worker;

use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use sibuna_lb::FlowPermit;
use sibuna_reactor::{Wake, Waker};

use crate::connection::Ingress;
use crate::server::Server;

pub(super) use secure::Started;

/// A connection on its way to a worker.
pub(super) struct Incoming {
    pub stream: TcpStream,
    pub ingress: Ingress,
    /// The flow slot of a connection the edge accepted itself.
    pub permit: Option<FlowPermit>,
    /// A TLS connection whose handshake has not begun: the worker begins it (SID 0024).
    pub tls: Option<Started>,
}

/// What the workers of one server share.
pub(super) struct Shared {
    /// Finish the exchanges in flight and close every connection after its response.
    pub draining: AtomicBool,
    /// Close everything and end.
    pub stopping: AtomicBool,
    /// The most idle server connections one worker keeps. See [`idle_per_worker`].
    pub idle_limit: usize,
}

/// The most idle server connections one of `workers` workers keeps for reuse: its share
/// of `max_connections`, at least one and at most 1,024. All workers together then
/// keep at most [`idle_total`], which the descriptor check counts (SID 0020).
pub fn idle_per_worker(max_connections: u32, workers: usize) -> usize {
    (max_connections as usize / workers.max(1)).clamp(1, 1024)
}

/// The most idle server connections that `workers` workers keep together.
pub fn idle_total(max_connections: u32, workers: usize) -> usize {
    workers.max(1) * idle_per_worker(max_connections, workers)
}

/// The time limits of a worker.
#[derive(Clone, Copy)]
pub(super) struct Timeouts {
    pub idle: Duration,
    pub tunnel: Duration,
}

struct Handle {
    sender: Mutex<mpsc::Sender<Incoming>>,
    wake: Wake,
    load: Arc<AtomicUsize>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// The workers of one server.
pub(super) struct Workers {
    handles: Vec<Handle>,
    shared: Arc<Shared>,
}

impl Workers {
    /// True when this platform can run the workers.
    pub const SUPPORTED: bool = sibuna_reactor::CAN_START_CONNECT;

    /// Starts `count` workers for `server`.
    pub fn start(server: &Arc<Server>, count: usize, timeouts: Timeouts) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            draining: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            idle_limit: idle_per_worker(server.config.max_connections, count),
        });
        let mut handles = Vec::with_capacity(count);
        for index in 0..count.max(1) {
            let (sender, receiver) = mpsc::channel();
            let (waker, wake) = Waker::new()?;
            let load = Arc::new(AtomicUsize::new(0));
            let worker = worker::Worker::new(
                Arc::clone(server),
                Arc::clone(&shared),
                Arc::clone(&load),
                timeouts,
                &waker,
            )?;
            let thread = std::thread::Builder::new()
                .name(format!("edge-http-{index}"))
                .spawn(move || worker.run(&waker, &receiver))?;
            handles.push(Handle {
                sender: Mutex::new(sender),
                wake,
                load,
                thread: Mutex::new(Some(thread)),
            });
        }
        Ok(Self { handles, shared })
    }

    /// The worker count for this machine: one per processor the process may use.
    pub fn default_count() -> usize {
        std::thread::available_parallelism().map_or(1, |count| count.get().min(64))
    }

    /// Gives a connection to the worker that serves the fewest.
    pub fn submit(&self, incoming: Incoming) {
        let Some(handle) = self.handles.iter().min_by_key(|h| h.load.load(Ordering::Relaxed))
        else {
            return;
        };
        handle.load.fetch_add(1, Ordering::Relaxed);
        let sent =
            handle.sender.lock().unwrap_or_else(PoisonError::into_inner).send(incoming).is_ok();
        if sent {
            handle.wake.wake();
        } else {
            handle.load.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Lets exchanges in flight finish and closes each connection after its response.
    pub fn drain(&self) {
        self.shared.draining.store(true, Ordering::Release);
        self.wake_all();
    }

    /// Closes every connection and joins the workers.
    pub fn stop(&self) {
        self.shared.stopping.store(true, Ordering::Release);
        self.wake_all();
        for handle in &self.handles {
            let thread = handle.thread.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(thread) = thread {
                let _ = thread.join();
            }
        }
    }

    fn wake_all(&self) {
        for handle in &self.handles {
            handle.wake.wake();
        }
    }
}
