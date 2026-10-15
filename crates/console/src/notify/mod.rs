//! Notifications (unit U6; Zig's `notifier_job.zig`, `notify_delivery.zig`,
//! `notify_target.zig` and `notify_syslog.zig`).
//!
//! [`Notifier::raise`] enqueues an observed event (denial spike, ban, node unhealthy); [`run`]
//! is the notifier thread, which holds the notifier lease, claims deliveries and sends them:
//! a signed HTTPS webhook (plain HTTP only to loopback literals) or an RFC 5424 syslog line
//! over UDP or framed TCP, with targets checked again before each attempt.

use sibuna_console_protocol::notifications::{Destination, Event, Read};

use crate::shared::{Setup, Shared};

/// The outcome of one delivery attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    /// The destination accepted it (a 2xx webhook reply, or a syslog line written).
    pub delivered: bool,
    /// A redacted outcome, at most 96 bytes, never containing the secret.
    pub detail: String,
}

/// The notifier's queue of raised events and its delivery state.
#[derive(Debug, Default)]
pub struct Notifier {}

impl Notifier {
    /// Returns an idle notifier.
    pub fn new(setup: &Setup<'_>) -> Notifier {
        let _ = setup;
        Notifier {}
    }

    /// Records that `event` was observed at `second` (Unix seconds) with a short `detail`;
    /// the notifier thread enqueues it durably. Never blocks.
    pub fn raise(&self, event: Event, second: u64, detail: &str) {
        let _ = (event, second, detail);
    }

    /// Sends a test delivery to `destination`, reading its sealed secret with `read`, and
    /// returns the outcome; called by the `notifications/test` route on its own thread.
    pub fn test_destination(
        &self,
        shared: &Shared,
        destination: &Destination,
        read: &Read,
    ) -> Delivery {
        let _ = (shared, destination, read);
        Delivery { delivered: false, detail: "notifications are not available".into() }
    }
}

/// The notifier thread's body: returns when the console stops.
pub fn run(shared: &Shared) {
    let _ = shared;
}
