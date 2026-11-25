//! Kernel listener admission of a frontend (SID 0032): `defer_accept` and `backlog`.
//!
//! Both are opt-in and need no privilege. A frontend that names neither makes no
//! system call here. An option that the platform refuses becomes a [`ListenFault`]
//! for the caller to report, and the listener serves without it.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use sibuna_json::ObjectReader;

use crate::config::{Protocol, duration, field, invalid, number};

/// The longest `defer_accept`. The kernel gives up a silent connection after its own
/// retransmissions, about a minute with default settings.
const MAX_DEFER: Duration = Duration::from_secs(60);
/// The largest `backlog`, the range of `net.core.somaxconn` on older kernels.
const MAX_BACKLOG: usize = 65535;

/// What a frontend asks of the kernel for its listeners.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ListenOptions {
    /// The length of the accept queue (`backlog`).
    pub backlog: Option<u32>,
    /// How long the kernel holds a connection without data (`defer_accept`).
    pub defer_accept: Option<Duration>,
}

/// A kernel option that a listener asked for and did not get. The listener serves
/// without it.
#[derive(Debug)]
pub struct ListenFault {
    /// The name of the frontend.
    pub frontend: Arc<str>,
    /// The address of the listener.
    pub bind: SocketAddr,
    /// The option of the file: `defer_accept` or `backlog`.
    pub option: &'static str,
    /// Why the platform refused it. `Unsupported` on a platform without the option.
    pub error: io::Error,
}

impl std::fmt::Display for ListenFault {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { frontend, bind, option, error } = self;
        write!(out, "frontend {frontend} ({bind}) serves without {option}: {error}")
    }
}

impl ListenOptions {
    /// Reads `defer_accept` and `backlog` from a frontend. Fails when a value is out
    /// of range or the frontend is a UDP frontend, which has no accept queue.
    pub fn parse(r: &mut ObjectReader<'_, '_>, proto: Protocol) -> io::Result<Self> {
        let defer_accept = match field(r.take_str("defer_accept"))? {
            None => None,
            Some(text) => Some(
                duration(text)
                    .filter(|wait| (Duration::from_secs(1)..=MAX_DEFER).contains(wait))
                    .ok_or_else(|| {
                        let path = r.field_path("defer_accept");
                        invalid(format!("{path} must be a duration from 1s to 60s"))
                    })?,
            ),
        };
        let backlog = match number(r, "backlog", 0, MAX_BACKLOG)? {
            0 => None,
            length => Some(length as u32),
        };
        let options = Self { backlog, defer_accept };
        if proto == Protocol::Udp && options != Self::default() {
            return Err(invalid(format!(
                "{}: defer_accept and backlog need a tcp or http frontend",
                r.path()
            )));
        }
        Ok(options)
    }

    /// Applies these options to `listener`, which had `previous` before. Only an
    /// option that is named, or that was named and is now removed, makes a system
    /// call. Every refusal is pushed to `faults` under `frontend`.
    pub fn apply(
        &self,
        previous: &Self,
        listener: &TcpListener,
        frontend: &Arc<str>,
        faults: &mut Vec<ListenFault>,
    ) {
        let Ok(bind) = listener.local_addr() else { return };
        let mut fault = |option, error| {
            faults.push(ListenFault { frontend: frontend.clone(), bind, option, error });
        };
        if let Some(length) = self.backlog
            && let Err(error) = sibuna_reactor::set_backlog(listener, length)
        {
            fault("backlog", error);
        }
        // A removed `defer_accept` is set to zero, so a reload can turn it off.
        let defer = match (self.defer_accept, previous.defer_accept) {
            (Some(wait), _) => Some(wait),
            (None, Some(_)) => Some(Duration::ZERO),
            (None, None) => None,
        };
        if let Some(wait) = defer
            && let Err(error) = sibuna_reactor::set_defer_accept(listener, wait)
        {
            fault("defer_accept", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").expect("bind")
    }

    #[test]
    fn options_that_are_not_named_change_nothing_and_report_nothing() {
        let listener = listener();
        let mut faults = Vec::new();
        let none = ListenOptions::default();
        none.apply(&none, &listener, &"web".into(), &mut faults);
        assert!(faults.is_empty());
        if sibuna_reactor::CAN_DEFER_ACCEPT {
            assert_eq!(sibuna_reactor::defer_accept(&listener).expect("read"), 0);
        }
    }

    #[test]
    fn named_options_reach_the_kernel_or_become_faults() {
        let listener = listener();
        let mut faults = Vec::new();
        let asked =
            ListenOptions { backlog: Some(512), defer_accept: Some(Duration::from_secs(3)) };
        asked.apply(&ListenOptions::default(), &listener, &"web".into(), &mut faults);
        if sibuna_reactor::CAN_DEFER_ACCEPT {
            assert!(faults.is_empty(), "{faults:?}");
            assert!(sibuna_reactor::defer_accept(&listener).expect("read") >= 3);
            // A reload that removes the option turns it off.
            ListenOptions::default().apply(&asked, &listener, &"web".into(), &mut faults);
            assert_eq!(sibuna_reactor::defer_accept(&listener).expect("read"), 0);
        } else {
            let options: Vec<_> = faults.iter().map(|fault| fault.option).collect();
            assert!(options.contains(&"defer_accept"));
            assert!(faults[0].to_string().contains("frontend web"));
        }
    }

    /// A socket on which the kernel refuses both options stands for a platform or a
    /// sandbox that does. The refusals are reported, and nothing else happens.
    #[cfg(unix)]
    #[test]
    fn a_refusal_of_the_kernel_is_a_fault_and_not_a_failure() {
        let datagram = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let odd = TcpListener::from(std::os::fd::OwnedFd::from(datagram));
        let mut faults = Vec::new();
        let asked =
            ListenOptions { backlog: Some(64), defer_accept: Some(Duration::from_secs(3)) };
        asked.apply(&ListenOptions::default(), &odd, &"web".into(), &mut faults);
        let options: Vec<_> = faults.iter().map(|fault| fault.option).collect();
        assert_eq!(options, ["backlog", "defer_accept"]);
        let line = faults[0].to_string();
        assert!(line.starts_with("frontend web (127.0.0.1:"), "{line}");
        assert!(line.contains("serves without backlog"), "{line}");
    }
}
