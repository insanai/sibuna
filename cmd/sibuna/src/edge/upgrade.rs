//! Replacing the process of a running edge without closing a listener (SID 0029).
//!
//! A daemon with `global.upgrade_socket` plays two parts, one after the other.
//!
//! ```text
//!  start:  begin_take --> Edge::bind_inherited --> ... --> Replacement::finish
//!          (the replacement of a running daemon, or a first start when nobody answers)
//!
//!  serve:  gate thread                              edge worker
//!          accept, authenticate  --- Lend ------->  lend_listeners
//!          give the listeners, wait for READY
//!                                --- Freeze ----->  freeze_datagrams
//!          give the mappings     --- Flows ------>  lend_flows (a piece at a time)
//!          wait for DONE         --- Release ---->  release_listeners, then the drain
//!          or, on a failure      --- Resume ----->  resume_datagrams
//! ```
//!
//! The gate thread speaks the protocol and may wait. The edge worker never waits: it
//! answers each request between two turns. The gate thread sends `Resume` only when the
//! connection of the replacement is closed, which is the proof that the replacement
//! reads no socket.

use std::io;

use sibuna_lb::{Config, Edge, Inherited};

pub(super) use imp::{Old, Replacement};

/// How long a process that has handed its listeners over serves on before it drains.
/// A drain closes a connection that has not sent a request yet, and the last
/// connections that the process accepted are in that state.
pub(super) const SETTLE: std::time::Duration = std::time::Duration::from_millis(200);

#[cfg(unix)]
mod imp {
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
    use std::time::{Duration, Instant};

    use sibuna_upgrade::{
        Done, Failure, Flow, Gate, Giving, Listener, Taking, Timeouts, UpgradeError, begin_give,
        begin_take,
    };

    use super::super::note;
    use super::{Config, Edge, Inherited, io};

    /// How long the gate thread waits for one answer of the edge worker.
    const WORKER_TIMEOUT: Duration = Duration::from_secs(5);
    /// The mappings lent in one request, so that their copies never fill the
    /// descriptor table.
    const PIECE: usize = 4096;
    /// The requests of the gate thread answered between two turns of the worker.
    const REQUESTS_PER_STEP: usize = 8;

    /// What the gate thread asks of the edge worker.
    enum Request {
        Lend(SyncSender<io::Result<Vec<(Listener, OwnedFd)>>>),
        Freeze(SyncSender<usize>),
        Flows(usize, SyncSender<io::Result<Vec<(Flow, OwnedFd)>>>),
        Resume,
        Release { pid: i32, listeners: usize, done: Done, unread: Duration },
    }

    /// The way to the edge worker: the queue of requests, and the call that ends the
    /// wait of the worker so that it looks at the queue.
    struct Worker {
        requests: Sender<Request>,
        wake: Box<dyn Fn() + Send>,
    }

    impl Worker {
        /// Leaves a request. False when the worker is gone.
        fn tell(&self, request: Request) -> bool {
            let sent = self.requests.send(request).is_ok();
            (self.wake)();
            sent
        }

        /// Asks the worker and waits for its answer.
        fn ask<T>(&self, request: impl FnOnce(SyncSender<T>) -> Request) -> Option<T> {
            let (reply, answer) = mpsc::sync_channel(1);
            if !self.tell(request(reply)) {
                return None;
            }
            answer.recv_timeout(WORKER_TIMEOUT).ok()
        }
    }

    /// The start of a process that may replace a running one.
    pub(in super::super) struct Replacement {
        taking: Option<Taking>,
        listeners: Vec<Listener>,
        inherited: Inherited,
    }

    fn other(error: UpgradeError) -> io::Error {
        io::Error::other(error)
    }

    impl Replacement {
        /// Connects to `global.upgrade_socket` of `config` and takes the listeners of
        /// the daemon that answers there. Without the key, or when nobody answers,
        /// nothing is taken and the process starts as a first one.
        ///
        /// # Errors
        ///
        /// The [`UpgradeError`] of a handoff that was refused or broke. The running
        /// daemon keeps serving.
        pub fn begin(config: &Config) -> io::Result<Self> {
            let mut replacement =
                Self { taking: None, listeners: Vec::new(), inherited: Inherited::default() };
            let Some(path) = config.upgrade_socket() else { return Ok(replacement) };
            let taking = begin_take(Path::new(path), &Timeouts::default()).map_err(other)?;
            let Some(mut taking) = taking else { return Ok(replacement) };
            for (listener, socket) in taking.listeners() {
                replacement.listeners.push(listener);
                replacement.inherited.push(listener, socket)?;
            }
            // A daemon that listens on none of our addresses is another service. Going
            // on would stop it and serve nothing of what it served.
            let lent = replacement.listeners.len();
            if lent > 0 && replacement.inherited.matching_count(config) == 0 {
                let text =
                    format!("the daemon at {path} lent {lent} listeners, none of this file");
                return Err(other(UpgradeError::new(Failure::Unrelated, text)));
            }
            replacement.taking = Some(taking);
            Ok(replacement)
        }

        /// The listening sockets that were taken, for [`Edge::bind_inherited`].
        pub fn inherited(&mut self) -> Inherited {
            std::mem::take(&mut self.inherited)
        }

        /// Completes the handoff, when there is one: says that this process is ready,
        /// adopts the UDP mappings, starts accepting, acknowledges, and starts reading
        /// UDP. The caller has built everything it serves with and turns its worker at
        /// once after this call. Returns true when a running daemon was replaced.
        ///
        /// # Errors
        ///
        /// The [`UpgradeError`] of a handoff that broke, or the error of the poller.
        /// The caller must end without another turn of its worker: the old daemon
        /// takes the service back when this process is gone.
        pub fn finish(self, edge: &mut Edge) -> io::Result<bool> {
            let Some(mut taking) = self.taking else { return Ok(false) };
            let pid = taking.peer().pid;
            let flows = taking.ready().map_err(other)?;
            let (adopted, dropped) = edge.adopt_flows(flows, &self.listeners);
            edge.arm_streams()?;
            taking.done(adopted, dropped).map_err(other)?;
            edge.arm_datagrams()?;
            note(format_args!(
                "UPG020: took {} listeners and {adopted} UDP mappings from pid {pid}, \
                 {dropped} mappings dropped",
                self.listeners.len()
            ));
            Ok(true)
        }
    }

    /// The part of a serving daemon that a replacement talks to.
    pub(in super::super) struct Old {
        gate: Option<Arc<Gate>>,
        requests: Option<Receiver<Request>>,
        handed: bool,
    }

    impl Drop for Old {
        fn drop(&mut self) {
            // The gate thread holds the gate until the process ends, so the file is
            // removed here. After a handoff the file belongs to the replacement.
            if let Some(gate) = &self.gate {
                gate.remove_file();
            }
        }
    }

    impl Old {
        /// A daemon without an upgrade socket.
        pub fn none() -> Self {
            Self { gate: None, requests: None, handed: false }
        }

        /// Binds the upgrade socket at `path` and starts the thread that serves it.
        /// Without a path nothing is started. `edge` is the edge that the thread asks.
        ///
        /// # Errors
        ///
        /// The error of binding the socket or of starting the thread.
        pub fn start(path: Option<&str>, edge: &Edge) -> io::Result<Self> {
            let Some(path) = path else { return Ok(Self::none()) };
            let gate = Gate::listen(Path::new(path)).map_err(|error| {
                io::Error::new(error.kind(), format!("upgrade socket {path}: {error}"))
            })?;
            let gate = Arc::new(gate);
            let (sender, requests) = mpsc::channel();
            let served = Arc::clone(&gate);
            let worker = Worker { requests: sender, wake: Box::new(edge.waker()) };
            std::thread::Builder::new()
                .name("edge-upgrade".into())
                .spawn(move || serve(&served, &worker))?;
            Ok(Self { gate: Some(gate), requests: Some(requests), handed: false })
        }

        /// The path of the upgrade socket, if the daemon has one.
        pub fn path(&self) -> Option<&Path> {
            self.gate.as_deref().map(Gate::path)
        }

        /// True once a replacement serves in the place of this process.
        pub fn is_handed(&self) -> bool {
            self.handed
        }

        /// Answers the requests of the gate thread, a few at a time. Returns true when
        /// the replacement has taken the service: the caller then drains and ends.
        pub fn step(&mut self, edge: &mut Edge) -> bool {
            let Some(requests) = &self.requests else { return false };
            for request in requests.try_iter().take(REQUESTS_PER_STEP) {
                match request {
                    Request::Lend(reply) => {
                        let _ = reply.send(edge.lend_listeners());
                    }
                    Request::Freeze(reply) => {
                        // A gate thread that gave up sends `Resume` after this request.
                        let _ = reply.send(edge.freeze_datagrams());
                    }
                    Request::Flows(start, reply) => {
                        let _ = reply.send(edge.lend_flows(start, PIECE));
                    }
                    Request::Resume => edge.resume_datagrams(),
                    Request::Release { pid, listeners, done, unread } => {
                        edge.release_listeners();
                        note(format_args!(
                            "UPG010: handed {listeners} listeners and {} UDP mappings to pid \
                             {pid}, {} mappings dropped, UDP unread for {} ms",
                            done.adopted,
                            done.dropped,
                            unread.as_millis()
                        ));
                        self.handed = true;
                        return true;
                    }
                }
            }
            false
        }
    }

    /// Serves the gate until a replacement has taken the service or the worker is gone.
    fn serve(gate: &Gate, requests: &Worker) {
        loop {
            let Ok(stream) = gate.accept() else {
                // A failed accept belongs to one peer. A pause keeps a persistent
                // failure from spinning.
                std::thread::sleep(Duration::from_millis(50));
                continue;
            };
            match hand_over(stream, gate, requests) {
                Ok(()) | Err(Ended::WorkerGone) => return,
                Err(Ended::Refused(error)) => {
                    note(format_args!("UPG012: refused an upgrade peer: {error}"));
                }
                Err(Ended::Failed { pid, error }) => note(format_args!(
                    "UPG011: the replacement pid {pid} failed before the cutover: {error}. \
                     Serving on."
                )),
            }
        }
    }

    /// Why a handoff ended without a cutover.
    enum Ended {
        /// The peer was not let in.
        Refused(UpgradeError),
        /// The handoff broke. Everything is as before it.
        Failed { pid: i32, error: UpgradeError },
        /// The edge worker does not answer: the daemon is stopping.
        WorkerGone,
    }

    /// One handoff, from the accepted connection to the release of the listeners.
    fn hand_over(stream: UnixStream, gate: &Gate, requests: &Worker) -> Result<(), Ended> {
        let mut giving = begin_give(stream, &Timeouts::default()).map_err(Ended::Refused)?;
        let pid = giving.peer().pid;
        let failed = |error| Ended::Failed { pid, error };
        let listeners = match requests.ask(Request::Lend) {
            Some(Ok(listeners)) => listeners,
            Some(Err(error)) => {
                giving.refuse_busy("the daemon cannot copy its descriptors");
                let text = format!("copying the listeners: {error}");
                return Err(failed(UpgradeError::new(Failure::Busy, text)));
            }
            None => {
                giving.refuse_busy("the daemon is stopping");
                return Err(Ended::WorkerGone);
            }
        };
        let lent: Vec<_> =
            listeners.iter().map(|(listener, fd)| (*listener, fd.as_fd())).collect();
        giving.give_listeners(&lent).map_err(failed)?;
        drop(lent);
        let count = listeners.len();
        drop(listeners);
        // Until READY nothing has changed here, so a failure needs no repair.
        giving.wait_ready().map_err(failed)?;
        let frozen = Instant::now();
        match cut_over(&mut giving, requests) {
            Ok(done) => {
                gate.keep_file();
                let unread = frozen.elapsed();
                requests.tell(Request::Release { pid, listeners: count, done, unread });
                Ok(())
            }
            Err(error) => {
                take_back(&mut giving, &error, requests);
                Err(Ended::Failed { pid, error })
            }
        }
    }

    /// The cutover: the worker stops reading UDP, the mappings go to the replacement,
    /// and the replacement acknowledges.
    fn cut_over(giving: &mut Giving, requests: &Worker) -> Result<Done, UpgradeError> {
        let stopping = || UpgradeError::new(Failure::Busy, "the edge worker did not answer");
        let total = requests.ask(Request::Freeze).ok_or_else(stopping)?;
        let mut start = 0;
        while start < total {
            let piece = requests.ask(|reply| Request::Flows(start, reply)).ok_or_else(stopping)?;
            let piece = piece.map_err(|error| {
                UpgradeError::new(Failure::Busy, format!("lending the UDP mappings: {error}"))
            })?;
            let lent: Vec<_> = piece.iter().map(|(flow, fd)| (*flow, fd.as_fd())).collect();
            giving.give_flows(&lent)?;
            start += PIECE;
        }
        giving.commit()?;
        giving.wait_done()
    }

    /// Takes the service back after a cutover that failed with `error`. The worker
    /// reads UDP again only when the connection of the replacement is closed. A
    /// replacement that is still there is ended first.
    fn take_back(giving: &mut Giving, error: &UpgradeError, requests: &Worker) {
        if error.failure != Failure::Closed {
            let mut waited = 0u32;
            while !giving.end_peer(Duration::from_secs(1)) {
                waited += 1;
                if waited.is_power_of_two() {
                    note(format_args!(
                        "UPG013: the replacement pid {} cannot be ended. UDP stays unread until \
                         it is gone. End it by hand.",
                        giving.peer().pid
                    ));
                }
            }
        }
        requests.tell(Request::Resume);
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{Config, Edge, Inherited, io};

    /// The start of a process. This system passes no sockets, so nothing is replaced.
    pub(in super::super) struct Replacement;

    impl Replacement {
        /// Takes nothing: `global.upgrade_socket` is refused on this system.
        pub fn begin(_config: &Config) -> io::Result<Self> {
            Ok(Self)
        }

        /// No sockets.
        pub fn inherited(&mut self) -> Inherited {
            Inherited::default()
        }

        /// Nothing to complete.
        pub fn finish(self, _edge: &mut Edge) -> io::Result<bool> {
            Ok(false)
        }
    }

    /// No upgrade socket on this system.
    pub(in super::super) struct Old;

    impl Old {
        /// A daemon without an upgrade socket.
        pub fn none() -> Self {
            Self
        }

        /// Starts nothing.
        pub fn start(_path: Option<&str>, _edge: &Edge) -> io::Result<Self> {
            Ok(Self)
        }

        /// No path.
        pub fn path(&self) -> Option<&std::path::Path> {
            None
        }

        /// Never.
        pub fn is_handed(&self) -> bool {
            false
        }

        /// Nothing to answer.
        pub fn step(&mut self, _edge: &mut Edge) -> bool {
            false
        }
    }
}
