//! The thread of the ACME server of the local authority (SID 0021).
//!
//! ```text
//!   HTTP frontend                         thread edge-acme-server
//!   -------------                         -----------------------
//!   Server::handle(request) --queues-->   next_task, at most one second of waiting
//!   (memory only, no I/O)                 perform: HTTP-01 validation, or sign a leaf
//!                                         every minute: write the revocation lists
//!                                                       when due, and load crl.der
//! ```
//!
//! The request path never waits for a network or a file: it reads and writes the
//! state of the server. All such work is on this one thread, one task after another.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sibuna_acme::local::LocalAuthority;
use sibuna_acme::schedule;
use sibuna_acme::server::{Outcome, Server, ServerOptions};
use sibuna_lb::InternalServer;

use super::supervise::{panic_text, restart_delay};
use super::{Event, Notify, Shared};

/// How long the thread waits for a task before it looks at the clock and at the flag
/// that stops it.
const IDLE: Duration = Duration::from_secs(1);
/// How often the thread looks at the revocation lists.
const CRL_PERIOD: Duration = Duration::from_secs(60);

fn now() -> u64 {
    super::now_ms() / 1000
}

/// The options of the server from the configuration.
fn server_options(config: &InternalServer, constraints: &[String]) -> ServerOptions {
    ServerOptions {
        url: config.url.clone(),
        names: config.names.clone(),
        ranges: config.ranges.clone(),
        constraints: constraints.to_vec(),
        http_port: config.http_port,
    }
}

/// Builds the server when the configuration has one. A URL that the server cannot
/// use is a defect of the configuration reader, which has checked it: there is then
/// no server.
pub(super) fn build(shared: &Shared) -> Option<Arc<Server>> {
    let internal = &shared.options.internal;
    let config = internal.server.as_ref()?;
    Server::new(server_options(config, &internal.constraints)).ok().map(Arc::new)
}

/// The work of the thread between two panics.
struct Worker<'a> {
    shared: &'a Shared,
    server: &'a Server,
    report: &'a Notify,
    authority: Option<LocalAuthority>,
    /// When the authority is opened again after a failure, in seconds since 1970.
    open_at: u64,
    crl_at: Instant,
}

impl Worker<'_> {
    fn failed(&self, error: sibuna_acme::Error, retry_at: u64) {
        self.shared.failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        (self.report)(&Event::Failed { name: None, error, retry_at });
    }

    /// Opens the local authority when it is not open and the delay has passed.
    fn open(&mut self) {
        let now = now();
        if self.authority.is_some() || now < self.open_at {
            return;
        }
        let options = &self.shared.options;
        let storage = Path::new(&options.storage);
        match LocalAuthority::open(storage, now, &options.internal.constraints) {
            Ok(authority) => self.authority = Some(authority),
            Err(error) => {
                self.open_at = now + schedule::FIRST_DELAY;
                self.failed(error, self.open_at);
            }
        }
    }

    /// Writes the revocation lists when they are due and gives the present one to
    /// the server, once a minute.
    fn publish_crl(&mut self) {
        let Some(authority) = self.authority.as_ref().filter(|_| Instant::now() >= self.crl_at)
        else {
            return;
        };
        self.crl_at = Instant::now() + CRL_PERIOD;
        let now = now();
        if let Err(error) = authority.refresh_crl(now, false) {
            self.failed(error, now + CRL_PERIOD.as_secs());
        }
        // The list is a small file: the entries are bounded by the authority.
        if let Ok(der) = std::fs::read(authority.crl_path()) {
            self.server.set_crl(der);
        }
    }

    /// Runs until the daemon stops.
    fn run(&mut self) {
        while !self.shared.stopping.load(std::sync::atomic::Ordering::Acquire) {
            self.open();
            self.publish_crl();
            let Some(authority) = &self.authority else {
                // Without the authority nothing can be signed. The tasks wait.
                std::thread::sleep(IDLE.min(Duration::from_millis(200)));
                continue;
            };
            let Some(task) = self.server.next_task(IDLE) else { continue };
            let lifetime = self.shared.options.internal.lifetime;
            match self.server.perform(task, authority, lifetime, now()) {
                Outcome::Validated { name, failure } => {
                    (self.report)(&Event::ServerValidated { name, failure });
                }
                Outcome::Issued { names } => (self.report)(&Event::ServerIssued { names }),
                Outcome::NotIssued { error, .. } => {
                    // The storage may have changed under the authority: open it again.
                    self.authority = None;
                    self.failed(error, now());
                }
            }
        }
    }
}

/// Runs the thread until the daemon stops. A panic is reported, and the work starts
/// again after the restart delay with the state of the server as it is: each change
/// of that state is one step under its lock.
pub(super) fn run(shared: &Shared, server: &Server, report: &Notify) {
    let mut panics = 0;
    loop {
        let mut worker =
            Worker { shared, server, report, authority: None, open_at: 0, crl_at: Instant::now() };
        let Err(payload) = catch_unwind(AssertUnwindSafe(|| worker.run())) else { return };
        panics += 1;
        let restart_in = restart_delay(panics);
        report(&Event::Panicked { message: panic_text(payload.as_ref()), restart_in });
        if !shared.pause(Duration::from_secs(restart_in)) {
            return;
        }
    }
}
