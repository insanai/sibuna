//! The live hub (unit U5; Zig's `topic_ring.zig`, `topic_store.zig`, `subscriber.zig`,
//! `subscription_queue.zig`, `subscription_hub.zig` and `subscription_job.zig`).
//!
//! The hub owns one bounded ring per topic and one outbox per subscriber, in two partitions:
//! 64 browser subscriptions and 16 peer streams. Stream handlers attach, send commands and
//! take frames; [`run`] is the feeder thread, which reads the topic sources (statistics,
//! events, nodes, policy, challenges, audit) and fans out once per UTC second. No socket is
//! written while a hub lock is held.

use std::fmt;
use std::time::Duration;

use sibuna_console_protocol::Topic;
use sibuna_console_protocol::subscriptions::Command;

use crate::shared::{Setup, Shared};

/// A subscriber's place in the hub; given by [`Hub::attach`] or [`Hub::attach_peer`] and
/// returned with [`Hub::detach`].
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Subscription {
    index: usize,
    generation: u64,
}

/// One frame of a subscription, ready to send as a WebSocket text message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The topic.
    pub topic: Topic,
    /// The subscription epoch it belongs to.
    pub epoch: u64,
    /// The JSON text, at most 2 KiB.
    pub text: String,
}

/// A topic's queue overflowed: the subscriber must resubscribe for a new snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Gap {
    /// The topic.
    pub topic: Topic,
    /// The invalidated epoch.
    pub epoch: u64,
    /// Frames dropped.
    pub dropped: u64,
}

/// What a subscriber takes from its outbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// A frame to send.
    Frame(Frame),
    /// A gap notice, which precedes any surviving frame.
    Gap(Gap),
}

/// Why the hub refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HubError {
    /// The partition is full (64 browsers or 16 peers).
    Full,
    /// The console is stopping.
    Stopping,
    /// The command is invalid or not allowed for this subscriber.
    InvalidCommand,
    /// The subscription was detached.
    Stale,
}

impl fmt::Display for HubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HubError::Full => "the subscriber table is full",
            HubError::Stopping => "the hub is stopping",
            HubError::InvalidCommand => "invalid subscription command",
            HubError::Stale => "the subscription has ended",
        })
    }
}

impl std::error::Error for HubError {}

/// The topic stores and the subscriber table.
#[derive(Debug, Default)]
pub struct Hub {}

impl Hub {
    /// Returns an empty hub.
    pub fn new(setup: &Setup<'_>) -> Hub {
        let _ = setup;
        Hub {}
    }

    /// Attaches a browser subscriber.
    ///
    /// Fails with [`HubError::Full`] at 64 browsers and [`HubError::Stopping`] while the
    /// console stops.
    pub fn attach(&self) -> Result<Subscription, HubError> {
        Err(HubError::Stopping)
    }

    /// Attaches a management peer stream, which may subscribe only to unfiltered local
    /// statistics.
    ///
    /// Fails like [`Hub::attach`], at 16 peers.
    pub fn attach_peer(&self) -> Result<Subscription, HubError> {
        Err(HubError::Stopping)
    }

    /// Detaches `subscription` and drops its queued frames.
    pub fn detach(&self, subscription: Subscription) {
        let _ = subscription;
    }

    /// Applies a client command (`sub`, `unsub`, `filter`; `ping` is the stream's) and
    /// starts a new epoch for its topic.
    ///
    /// Fails with [`HubError::InvalidCommand`], [`HubError::Stale`] or
    /// [`HubError::Stopping`].
    pub fn command(&self, subscription: &Subscription, command: &Command) -> Result<(), HubError> {
        let _ = (subscription, command);
        Err(HubError::Stopping)
    }

    /// Takes the next item of `subscription`'s outbox, waiting at most `wait` for one;
    /// `None` when none arrived (or the console is stopping).
    pub fn take(&self, subscription: &Subscription, wait: Duration) -> Option<Item> {
        let _ = (subscription, wait);
        None
    }

    /// Refuses new attachments and wakes every waiting [`Hub::take`]; the console calls it
    /// first when it stops.
    pub fn stop(&self) {}
}

/// The feeder thread's body: returns when the console stops.
pub fn run(shared: &Shared) {
    let _ = shared;
}
