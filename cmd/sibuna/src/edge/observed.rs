//! What the edge observes, with or without an HTTP frontend (SID 0020): the counters,
//! the access log and the separate listener, and how a reload changes them.
//!
//! ```text
//!  reload:  plan (open the new log file, bind the new listener)  -- may fail, nothing changed
//!           reload the routes                                    -- may fail, the plan is dropped
//!           apply (switch the log, close the old listener)       -- cannot fail
//! ```

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sibuna_lb::{Edge, ObserveOptions};

use super::http::Http;
use super::probe::{Probe, Sources};
use crate::access::{Change, Observe};
use crate::server::Server;

/// The handle of everything observed.
pub(super) struct Observed {
    observe: Arc<Observe>,
    /// The HTTP server, for the process counters of the separate listener.
    server: Option<Arc<Server>>,
    probe: Option<Probe>,
}

/// What a reload does to the separate listener.
enum Listener {
    Keep,
    Close,
    /// The listener of the new address, already bound and serving.
    Open(Probe),
}

/// The changes a reload prepared. Whatever can fail has happened.
pub(super) struct Plan {
    log: Change,
    listener: Listener,
}

impl Observed {
    /// Starts the access log of a topology without an HTTP frontend, and the separate
    /// listener when the topology has one. With an HTTP frontend the log is the one of
    /// its server.
    ///
    /// # Errors
    ///
    /// The error of opening the log file or of binding the listener.
    pub fn start(http: Option<&Http>, options: &ObserveOptions, edge: &Edge) -> io::Result<Self> {
        let (observe, server) = match http {
            Some(http) => {
                let (observe, server) = http.observed();
                (observe, Some(server))
            }
            None => (super::http::start_observe(options, edge)?, None),
        };
        let mut observed = Self { observe, server, probe: None };
        observed.probe = options.listen.map(|address| observed.listen(address)).transpose()?;
        edge.log_flows(observed.observe.log().is_some());
        Ok(observed)
    }

    fn listen(&self, address: std::net::SocketAddr) -> io::Result<Probe> {
        let sources = Sources { observe: self.observe.clone(), server: self.server.clone() };
        Probe::start(address, sources)
    }

    /// Prepares the move to `next`: opens the new log destination and binds the new
    /// listener while the old one serves.
    ///
    /// # Errors
    ///
    /// The error of opening the log file or of binding the address. Nothing changed.
    pub fn plan(&self, next: &ObserveOptions) -> io::Result<Plan> {
        // The listener first: a bind that fails leaves no new log file behind.
        let listener = match next.listen {
            address if address == self.observe.listen() => Listener::Keep,
            None => Listener::Close,
            Some(address) => Listener::Open(self.listen(address)?),
        };
        let log = self.observe.plan(next)?;
        Ok(Plan { log, listener })
    }

    /// Moves to the options of a reloaded topology. The old listener closes here,
    /// after the new one has been serving since [`Observed::plan`].
    pub fn apply(&mut self, next: ObserveOptions, plan: Plan, edge: &Edge) {
        self.observe.apply(next, plan.log);
        match plan.listener {
            Listener::Keep => {}
            Listener::Close => self.probe = None,
            Listener::Open(probe) => self.probe = Some(probe),
        }
        edge.log_flows(self.observe.log().is_some());
    }

    /// Offers the lines of the flows that ended since the last call to the log.
    pub fn pass_flows(&self, edge: &mut Edge) {
        for flow in edge.ended_flows() {
            self.observe.offer_flow(flow);
        }
    }

    /// Reopens the access log file, for log rotation, when `asked` is set, and clears it.
    pub fn reopen_log_when(&self, asked: &AtomicBool) {
        if asked.swap(false, Ordering::AcqRel) {
            self.observe.reopen_log();
        }
    }

    /// The counters and the log, for the admin socket.
    /// Gives the request path and the telemetry the hooks that the edge publishes
    /// (SID 0030). Called once, before the listeners serve.
    pub fn set_hooks(&self, slot: &Arc<sibuna_plugin::Slot>) {
        let _ = self.observe.hooks.set(Arc::clone(slot));
    }

    pub fn shared(&self) -> &Arc<Observe> {
        &self.observe
    }

    /// Turns the readiness answer to 503.
    pub fn drain(&self) {
        self.observe.draining.store(true, Ordering::Release);
    }

    /// Writes the queued lines and ends the writer. Every request path has ended.
    pub fn close_log(&self) {
        self.observe.close_log();
    }
}
