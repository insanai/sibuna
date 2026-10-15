//! The live hub (unit U5; Zig's `topic_ring.zig`, `topic_store.zig`, `subscriber.zig`,
//! `subscription_queue.zig`, `subscription_hub.zig` and `subscription_job.zig`).
//!
//! The hub owns one bounded journal per topic and one outbox per subscriber, in two
//! partitions: 64 browser subscriptions and 16 peer streams. Stream handlers attach, send
//! commands and take frames; [`run`] is the feeder thread, which reads the topic sources
//! (statistics, events, nodes, policy, challenges, audit) and fans out once per UTC second.
//! No socket is written while a hub lock is held.
//!
//! ```text
//! feeder thread (100 ms)                     stream threads (one per WebSocket)
//!   storage tickets -> topic stores            reader: Hub::command (sub, unsub, filter)
//!   live stats, dashboard, challenges          writer: Hub::take (waits <= 100 ms)
//!   once per second: Hub::fanout                 -> frames and gap notices -> socket
//!     each subscriber: snapshot / deltas
//!     -> its outbox (64 frames), wakes the writer
//! ```
//!
//! # Locks
//!
//! The topic state (`Topics`), the subscriber table (`Table`) and each subscriber (`Member`)
//! have a mutex of their own, always taken in that order. A writer waiting for frames holds
//! only its subscriber's lock, and only while it takes an item; the fan-out holds the topic
//! and table locks while it pumps each subscriber in turn. Every lock is held for bounded
//! work: at most 64 messages per subscriber and fan-out.
//!
//! # Changes from the Zig version
//!
//! - Rings, stores and outboxes are allocated on demand within Zig's bounds (1,024 records
//!   of 2 KiB per topic, 64 frames per outbox, 64 KiB per view) instead of preallocated.
//! - A ring is guarded by the topic lock instead of a lock of its own that publishers and
//!   readers only tried to take, so no publication is lost to contention (Zig reported such
//!   a loss as a one-record gap).
//! - A stream writer waits on its subscriber's condition variable for at most 100 ms
//!   instead of sleeping 100 ms, so a frame is written as soon as the fan-out queued it.
//! - Server messages carry only the members of their operation, in the order of SID 0007's
//!   example (`snapshot_begin` has no `data`, `part`, `update` or `kind`); Zig's serializer
//!   also wrote `"data":null` and the unused members. Every client reads only the members
//!   of the operation.
//! - The fan-out runs on the first feeder tick of each new UTC second as read from the
//!   console's clock (Zig computed the time to the next boundary from the real-time clock in
//!   milliseconds).
//! - The `nodes` topic is filtered from the structured view the feeder built, instead of
//!   parsing the stored JSON again.
//! - A browser's statistics view is remembered from its first snapshot even before the
//!   dashboard exists, so the first dashboard delta always has a base.
//! - The feeder holds at most [`feeder::FEEDER_JOBS`] of the console's four background
//!   storage jobs, so the collector's journals are never starved.
//!
//! # Zig machinery that Rust deleted
//!
//! - `init`/`deinit` with `errdefer` chains and the 512 KiB parse arena and 64 KiB scratch
//!   buffers reset per publication: owned `String`s and values dropped with their scope.
//! - Handle lookups that panicked on a recycled slot ("subscription lifetime"): a
//!   [`Subscription`] owns a reference to its subscriber, and a detached one only stops
//!   receiving.
//! - Mailbox tickets abandoned explicitly at shutdown: a dropped storage ticket abandons
//!   its reply.

mod feeder;
mod outbox;
mod ring;
mod subscriber;
mod topic;
mod views;

#[cfg(test)]
mod tests;

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sibuna_console_protocol::StatsSnapshot;
use sibuna_console_protocol::Topic;
use sibuna_console_protocol::codec::{WireEnum, to_json};
use sibuna_console_protocol::subscription_feed::Page;
use sibuna_console_protocol::subscriptions::{Command, TOPIC_COUNT, validate};

use crate::collector::dashboard;
use crate::peer::Observation;
use crate::shared::Setup;
use subscriber::{Sources, Subscriber};
use topic::{Store, TopicError};
use views::NodesView;

pub use feeder::run;

/// Browser subscriptions the hub admits.
pub const BROWSERS: usize = 64;
/// Management peer streams the hub admits.
pub const PEERS: usize = 16;

/// A subscriber's place in the hub; given by [`Hub::attach`] or [`Hub::attach_peer`] and
/// returned with [`Hub::detach`]. Two subscriptions are equal when they name the same slot
/// and generation.
#[derive(Debug)]
pub struct Subscription {
    index: usize,
    generation: u64,
    member: Arc<Member>,
}

impl PartialEq for Subscription {
    fn eq(&self, other: &Subscription) -> bool {
        (self.index, self.generation) == (other.index, other.generation)
    }
}

impl Eq for Subscription {}

impl Hash for Subscription {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.index, self.generation).hash(state);
    }
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

/// A subscriber shared by the hub's table and its [`Subscription`].
#[derive(Debug)]
struct Member {
    subscriber: Mutex<Subscriber>,
    /// Signalled when the fan-out queued something, on detach and when the hub stops.
    ready: Condvar,
    /// Set by [`Hub::detach`]; read under the subscriber lock, so Relaxed suffices.
    detached: AtomicBool,
}

impl Member {
    fn lock(&self) -> MutexGuard<'_, Subscriber> {
        self.subscriber.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The topic state the feeder publishes and the fan-out reads.
#[derive(Debug, Default)]
struct Topics {
    stores: [Store; TOPIC_COUNT],
    /// The dashboard's journal: one tiny state per collection, so browser views refresh.
    dashboard_store: Store,
    dashboard: dashboard::Frame,
    /// The dashboard has been collected at least once.
    dashboard_ready: bool,
    /// The structured view behind the `nodes` store.
    nodes: Option<NodesView>,
}

impl Topics {
    fn store(&mut self, topic: Topic) -> &mut Store {
        &mut self.stores[topic.index()]
    }
}

#[derive(Debug)]
struct Slot {
    generation: u64,
    member: Arc<Member>,
}

/// The subscriber table: browsers in slots 0 to 63, peers in 64 to 79.
#[derive(Debug)]
struct Table {
    slots: Vec<Option<Slot>>,
    next_id: u64,
    next_epoch: u64,
}

/// The topic stores and the subscriber table.
#[derive(Debug)]
pub struct Hub {
    /// This console's boot as 32 hex digits, the first half of every epoch.
    boot: String,
    /// Set by [`Hub::stop`]; Release on store, Acquire on load.
    stopping: AtomicBool,
    topics: Mutex<Topics>,
    table: Mutex<Table>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Hub {
    /// Returns an empty hub for the console of `setup`.
    pub fn new(setup: &Setup<'_>) -> Hub {
        Hub::with_boot(&setup.identity.boot)
    }

    /// Returns an empty hub whose epochs start with `boot` as hex.
    fn with_boot(boot: &[u8; 16]) -> Hub {
        let mut slots = Vec::new();
        slots.resize_with(BROWSERS + PEERS, || None);
        Hub {
            boot: sibuna_encoding::hex::encode(boot),
            stopping: AtomicBool::new(false),
            topics: Mutex::new(Topics::default()),
            table: Mutex::new(Table { slots, next_id: 1, next_epoch: 1 }),
        }
    }

    /// Returns this console's boot as 32 hex digits, as every epoch begins.
    pub fn boot(&self) -> &str {
        &self.boot
    }

    /// Attaches a browser subscriber.
    ///
    /// Fails with [`HubError::Full`] at 64 browsers and [`HubError::Stopping`] while the
    /// console stops.
    pub fn attach(&self) -> Result<Subscription, HubError> {
        self.attach_range(0, BROWSERS)
    }

    /// Attaches a management peer stream, which may subscribe only to unfiltered local
    /// statistics.
    ///
    /// Fails like [`Hub::attach`], at 16 peers.
    pub fn attach_peer(&self) -> Result<Subscription, HubError> {
        self.attach_range(BROWSERS, BROWSERS + PEERS)
    }

    fn attach_range(&self, start: usize, end: usize) -> Result<Subscription, HubError> {
        let mut table = lock(&self.table);
        if self.stopping.load(Ordering::Acquire) {
            return Err(HubError::Stopping);
        }
        // 2^64 attachments cannot happen; an exhausted counter reads as a full table.
        let generation = table.next_id;
        if generation == u64::MAX {
            return Err(HubError::Full);
        }
        let free = (start..end).find(|&index| table.slots.get(index).is_some_and(Option::is_none));
        let index = free.ok_or(HubError::Full)?;
        let member = Arc::new(Member {
            subscriber: Mutex::new(Subscriber::new(index >= BROWSERS)),
            ready: Condvar::new(),
            detached: AtomicBool::new(false),
        });
        table.slots[index] = Some(Slot { generation, member: Arc::clone(&member) });
        table.next_id += 1;
        Ok(Subscription { index, generation, member })
    }

    /// Detaches `subscription` and drops its queued frames.
    pub fn detach(&self, subscription: Subscription) {
        let mut table = lock(&self.table);
        if let Some(slot) = table.slots.get_mut(subscription.index)
            && slot.as_ref().is_some_and(|slot| slot.generation == subscription.generation)
        {
            *slot = None;
        }
        drop(table);
        let member = &subscription.member;
        let _subscriber = member.lock();
        member.detached.store(true, Ordering::Relaxed);
        member.ready.notify_all();
    }

    /// Applies a client command (`sub`, `unsub`, `filter`; `ping` is the stream's) and
    /// starts a new epoch for its topic.
    ///
    /// Fails with [`HubError::InvalidCommand`] for a command the protocol refuses, or one a
    /// peer may not send (anything but unfiltered `stats`), [`HubError::Stale`] after
    /// [`Hub::detach`], or [`HubError::Stopping`].
    pub fn command(&self, subscription: &Subscription, command: &Command) -> Result<(), HubError> {
        validate(command).map_err(|_| HubError::InvalidCommand)?;
        // Management links carry an unfiltered local source, never a browser selection.
        let peer = subscription.index >= BROWSERS;
        if peer && (command.topic != Some(Topic::Stats) || command.args.node.is_some()) {
            return Err(HubError::InvalidCommand);
        }
        let mut table = lock(&self.table);
        if self.stopping.load(Ordering::Acquire) {
            return Err(HubError::Stopping);
        }
        let current = table.slots.get(subscription.index).and_then(Option::as_ref);
        if current.is_none_or(|slot| slot.generation != subscription.generation) {
            return Err(HubError::Stale);
        }
        let epoch = table.next_epoch;
        if epoch == u64::MAX {
            return Err(HubError::InvalidCommand);
        }
        table.next_epoch += 1;
        subscription.member.lock().command(command, epoch);
        Ok(())
    }

    /// Takes the next item of `subscription`'s outbox, waiting at most `wait` for one;
    /// `None` when none arrived, after [`Hub::detach`], or while the console stops.
    pub fn take(&self, subscription: &Subscription, wait: Duration) -> Option<Item> {
        let member = &subscription.member;
        let deadline = Instant::now() + wait;
        let mut subscriber = member.lock();
        loop {
            if member.detached.load(Ordering::Relaxed) || self.stopping.load(Ordering::Acquire) {
                return None;
            }
            if let Some(item) = subscriber.outbox.pop() {
                return Some(item);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            subscriber = member
                .ready
                .wait_timeout(subscriber, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Refuses new attachments and commands and wakes every waiting [`Hub::take`]; the
    /// console calls it first when it stops.
    pub fn stop(&self) {
        let table = lock(&self.table);
        self.stopping.store(true, Ordering::Release);
        for slot in table.slots.iter().flatten() {
            // Taking the subscriber lock orders the store before a taker's check-then-wait.
            let _subscriber = slot.member.lock();
            slot.member.ready.notify_all();
        }
    }

    /// Returns, per topic, whether any subscriber wants it now.
    pub(crate) fn wanted(&self) -> [bool; TOPIC_COUNT] {
        let table = lock(&self.table);
        let mut wanted = [false; TOPIC_COUNT];
        for slot in table.slots.iter().flatten() {
            let subscriber = slot.member.lock();
            for (index, flag) in wanted.iter_mut().enumerate() {
                *flag = *flag || subscriber.wants(Topic::ALL[index]);
            }
        }
        wanted
    }

    /// Makes `view` the state of `topic` (a state topic).
    ///
    /// Fails like the topic store: a view over 64 KiB or not a JSON object.
    pub(crate) fn publish_state(&self, topic: Topic, view: &str) -> Result<(), TopicError> {
        lock(&self.topics).store(topic).state(view)
    }

    /// Makes `view` the state of the `nodes` topic.
    ///
    /// Fails like [`Hub::publish_state`].
    pub(crate) fn publish_nodes(&self, view: NodesView) -> Result<(), TopicError> {
        let mut topics = lock(&self.topics);
        topics.store(Topic::Nodes).state(&to_json(&view))?;
        topics.nodes = Some(view);
        Ok(())
    }

    /// Journals the rows of a feed `page` into its topic and advances its coverage.
    ///
    /// Fails when a row is too large, or past nine issuers.
    pub(crate) fn publish_page(&self, topic: Topic, page: &Page) -> Result<(), TopicError> {
        let mut topics = lock(&self.topics);
        let store = topics.store(topic);
        for row in &page.rows {
            store.row(row)?;
        }
        store.advance(page)
    }

    /// Sets how many issuers the `events` feed should cover.
    pub(crate) fn expect_sources(&self, count: u8) {
        lock(&self.topics).store(Topic::Events).expected_sources = count;
    }

    /// Merges the local statistics `local` with the peers' `observations` into the
    /// dashboard at `now`, and journals a tick so every browser view is computed again.
    ///
    /// Fails with [`TopicError::SequenceExhausted`] when the dashboard journal is.
    pub(crate) fn collect_dashboard(
        &self,
        local: &StatsSnapshot,
        observations: &[Observation],
        now: u64,
    ) -> Result<(), TopicError> {
        let mut topics = lock(&self.topics);
        topics.dashboard.collect(local, observations, now);
        topics.dashboard_ready = true;
        let generation = topics.dashboard_store.update.saturating_add(1);
        topics.dashboard_store.state(&format!("{{\"generation\":{generation}}}"))
    }

    /// Pumps every subscriber once: snapshots, fragments and deltas into their outboxes,
    /// and wakes the writers that have something to send. The feeder calls it once a second.
    pub(crate) fn fanout(&self) {
        let topics = lock(&self.topics);
        let table = lock(&self.table);
        let mut stores: [&Store; TOPIC_COUNT] = std::array::from_fn(|index| &topics.stores[index]);
        let browser = Sources {
            boot: &self.boot,
            stores,
            dashboard: topics.dashboard_ready.then_some(&topics.dashboard),
            nodes: topics.nodes.as_ref(),
        };
        if browser.dashboard.is_some() {
            stores[Topic::Stats.index()] = &topics.dashboard_store;
        }
        let browser = Sources { stores, ..browser };
        let peer = Sources {
            stores: std::array::from_fn(|index| &topics.stores[index]),
            dashboard: None,
            ..browser
        };
        for (index, slot) in table.slots.iter().enumerate() {
            let Some(slot) = slot else { continue };
            let sources = if index < BROWSERS { &browser } else { &peer };
            let mut subscriber = slot.member.lock();
            if subscriber.pump(sources).is_err() {
                subscriber.fail();
            }
            if subscriber.outbox.is_ready() {
                slot.member.ready.notify_all();
            }
        }
    }
}
