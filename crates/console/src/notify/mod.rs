//! Notifications (unit U6; Zig's `notifier_job.zig`, `notify_delivery.zig`,
//! `notify_target.zig` and `notify_syslog.zig`).
//!
//! [`Notifier::raise`] keeps an observed event (denial spike, ban, node unhealthy) in a
//! bounded ring; [`run`] is the notifier thread. Every second it moves raised events into
//! the replicated queue with this node's identity (S24), then, while it holds the cluster's
//! notifier lease, claims due deliveries one at a time (S25), sends each, and records the
//! outcome under the lease's fence (S26). Standby nodes only enqueue. A delivery is a
//! signed HTTPS webhook (plain HTTP only to loopback literals) or an RFC 5424 syslog line
//! over UDP or framed TCP ([`delivery`]); targets are checked by one rule ([`target`]) when
//! they are saved and again before each attempt.
//!
//! The lease is renewed before every claim, never a batch of network attempts under an old
//! grant, and each attempt is bounded by a budget measured from before the renewal, so a
//! late storage reply cannot extend the notifier's authority.
//!
//! Changes from Zig: storage calls are background jobs with tickets (at most 4 for every
//! background task together, [`wait_for`]); the notifier waits for each on its own thread,
//! at most 10 seconds including the wait for a free slot. Zig logged lost local events and
//! failed rounds; the library does not print: a full ring of raised events drops the
//! newest (the ring is bounded), and a failed round is retried a second later.

pub mod delivery;
mod syslog;
pub mod target;

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::notifications::{
    self, Claimed, Destination, Enqueue, Event, MAX_DETAIL, Pending, Read, Record,
};
use sibuna_console_protocol::retention::{Holder, Lease};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::leases::{Job, acquire_lease};
use sibuna_console_storage::notifications::{claim_delivery, enqueue_event, finish_delivery};
use sibuna_storage::{BorrowedFuture, Transaction};

use self::delivery::{Attempt, SystemTrust};
use crate::collector::alerts::{CAPACITY, Raised, Ring};
use crate::collector::storage_node;
use crate::shared::{Setup, Shared};
use crate::storage::{ConsoleStorage, HTTP_WAIT, StorageFailure};

/// How long the notifier sleeps between rounds.
pub const POLL: Duration = Duration::from_secs(1);
/// The budget of one claim and its attempt, measured from before the lease renewal.
const ATTEMPT_BUDGET: Duration = Duration::from_secs(20);
/// How often a wait for storage looks at the stop flag.
const WAIT_STEP: Duration = Duration::from_millis(100);
/// How long a background job waits before it is submitted again when no slot is free.
const DEFER_STEP: Duration = Duration::from_millis(10);

/// The outcome of one delivery attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    /// The destination accepted it (a 2xx webhook reply, or a syslog line written).
    pub delivered: bool,
    /// A redacted outcome, at most 96 bytes, never containing the secret.
    pub detail: String,
}

/// The notifier's queue of raised events and its delivery state.
#[derive(Debug)]
pub struct Notifier {
    /// Raised events waiting to be enqueued durably. The lock is held only to offer or
    /// take one event.
    ring: Mutex<Ring>,
    /// This node and boot, the identity of enqueued events and of the lease.
    holder: Holder,
    /// This node's id, as test deliveries report it.
    node_id: u32,
    /// The trust store of HTTPS webhooks.
    trust: SystemTrust,
}

impl Notifier {
    /// Returns an idle notifier for this console's node and boot.
    pub fn new(setup: &Setup<'_>) -> Notifier {
        let identity = setup.identity;
        Notifier {
            ring: Mutex::new(Ring::default()),
            holder: Holder { node: storage_node(identity.node_id), boot: identity.boot },
            node_id: identity.node_id,
            trust: SystemTrust::default(),
        }
    }

    /// Records that `event` was observed at `second` (Unix seconds) with a short `detail`;
    /// the notifier thread enqueues it durably. Never blocks on storage; a full ring counts
    /// the event as dropped.
    pub fn raise(&self, event: Event, second: u64, detail: &str) {
        self.ring.lock().unwrap_or_else(PoisonError::into_inner).offer(event, second, detail);
    }

    /// Sends a test delivery to `destination`, reading its sealed secret with `read`, and
    /// returns the outcome; called by the `notifications/test` route on its own thread. The
    /// event is a denial spike with id 0, so it carries no `Idempotency-Key`.
    pub fn test_destination(
        &self,
        shared: &Shared,
        destination: &Destination,
        read: &Read,
    ) -> Delivery {
        let event = Pending {
            id: 0,
            node: self.node_id,
            event: Event::DenialSpike,
            raised_at: shared.now(),
            detail: Text::new(delivery::TEST_DETAIL).unwrap_or_default(),
            attempts: 0,
        };
        let attempt = Attempt { destination, event: &event, read, not_after: None };
        delivery::deliver(shared, &self.trust, &attempt)
    }

    fn take(&self) -> Option<Raised> {
        self.ring.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// The notifier thread's body: returns when the console stops.
pub fn run(shared: &Shared) {
    let mut pending = None;
    loop {
        flush(shared, &mut pending);
        // A failed round is retried after the pause, with a fresh lease.
        let _ = deliver(shared);
        if !shared.sleep(POLL) {
            return;
        }
    }
}

/// Runs `job` as a background storage job (one transaction) and waits for its result on
/// the caller's thread: at most [`HTTP_WAIT`] in all, and no longer once `stopping` returns
/// true. While the background allowance is spent or the queue is full, it submits again
/// every [`DEFER_STEP`]; that is why `job` is `Clone` (its captures are plain data).
///
/// Fails with [`StorageFailure::Deferred`] or [`StorageFailure::Busy`] when no slot freed
/// in time, with [`StorageFailure::Timeout`] when the wait ends first (the job may still
/// commit), and with the job's failure.
pub(crate) fn wait_for<T, F>(
    storage: &ConsoleStorage,
    stopping: &dyn Fn() -> bool,
    job: F,
) -> Result<T, StorageFailure>
where
    T: Send + 'static,
    F: for<'a> FnOnce(&'a mut Transaction) -> BorrowedFuture<'a, Result<T, ConsoleStorageError>>
        + Clone
        + Send
        + 'static,
{
    let started = Instant::now();
    let in_time = || !stopping() && started.elapsed() < HTTP_WAIT;
    let mut ticket = loop {
        match storage.submit_background(job.clone()) {
            Ok(ticket) => break ticket,
            Err(StorageFailure::Deferred | StorageFailure::Busy) if in_time() => {
                std::thread::sleep(DEFER_STEP);
            }
            Err(failure) => return Err(failure),
        }
    };
    loop {
        if let Some(result) = ticket.wait_timeout(WAIT_STEP) {
            return result;
        }
        if !in_time() {
            return Err(StorageFailure::Timeout);
        }
    }
}

/// Moves locally raised events into the replicated queue (S24), oldest first. An event
/// storage did not take stays in `pending` and is tried again next round.
fn flush(shared: &Shared, pending: &mut Option<Raised>) {
    let notifier = &shared.notifier;
    for _ in 0..CAPACITY {
        if pending.is_none() {
            *pending = notifier.take();
        }
        let Some(item) = pending.as_ref() else { return };
        let input = Enqueue {
            node: notifier.holder.node,
            boot: notifier.holder.boot,
            sequence: item.sequence,
            event: item.event,
            raised_at: item.raised_at,
            detail: Text::new(clip(&item.detail, MAX_DETAIL)).unwrap_or_default(),
        };
        let now = shared.now();
        let queued = wait_for(&shared.storage, &|| shared.is_stopping(), move |tx| {
            Box::pin(async move { enqueue_event(tx, &input, now).await })
        });
        if queued.is_err() {
            return;
        }
        *pending = None;
    }
}

/// Claims and sends due deliveries while this node holds the notifier lease, renewing the
/// lease before each claim. Returns when nothing is due, the lease is held elsewhere, or a
/// step fails.
fn deliver(shared: &Shared) -> Result<(), StorageFailure> {
    let notifier = &shared.notifier;
    let stopping = || shared.is_stopping();
    for _ in 0..notifications::CAPACITY {
        if stopping() {
            return Ok(());
        }
        let started = Instant::now();
        let (holder, now) = (notifier.holder, shared.now());
        let acquired = wait_for(&shared.storage, &stopping, move |tx| {
            Box::pin(async move { acquire_lease(tx, Job::Notifier, &holder, now).await })
        });
        let lease = match acquired {
            Ok(lease) => lease,
            // Another node holds the lease: this one is a standby.
            Err(StorageFailure::Console(ConsoleStorageError::Conflict)) => return Ok(()),
            Err(failure) => return Err(failure),
        };
        let not_after = started + ATTEMPT_BUDGET;
        if !is_fresh(shared, &lease, not_after) {
            return Ok(());
        }
        let now = shared.now();
        let claimed = wait_for(&shared.storage, &stopping, move |tx| {
            Box::pin(async move { claim_delivery(tx, &lease, now).await })
        })?;
        let Some(claimed) = claimed else { return Ok(()) };
        if !is_fresh(shared, &lease, not_after) {
            return Ok(());
        }
        send(shared, lease, &claimed, not_after)?;
    }
    Ok(())
}

/// True while the console runs, the lease has at least the claim margin left, and the
/// attempt's budget has not run out.
fn is_fresh(shared: &Shared, lease: &Lease, not_after: Instant) -> bool {
    !shared.is_stopping()
        && lease.expires.saturating_sub(shared.now()) >= notifications::CLAIM_MARGIN_SECONDS
        && Instant::now() < not_after
}

/// Sends one claimed delivery and records its outcome under `lease` (S26).
fn send(
    shared: &Shared,
    lease: Lease,
    claimed: &Claimed,
    not_after: Instant,
) -> Result<(), StorageFailure> {
    let destination = &claimed.destination;
    let read = Read {
        id: destination.id,
        revision: destination.revision,
        lease: Some(lease),
        ..Read::default()
    };
    let attempt =
        Attempt { destination, event: &claimed.event, read: &read, not_after: Some(not_after) };
    let outcome = delivery::deliver(shared, &shared.notifier.trust, &attempt);
    let record = Record {
        lease,
        delivery_id: claimed.delivery_id,
        attempt: claimed.event.attempts,
        delivered: outcome.delivered,
        detail: Text::new(clip(&outcome.detail, MAX_DETAIL)).unwrap_or_default(),
    };
    let now = shared.now();
    wait_for(&shared.storage, &|| shared.is_stopping(), move |tx| {
        Box::pin(async move { finish_delivery(tx, &record, now).await })
    })
}

/// Returns `text` cut to at most `limit` bytes at a character boundary.
pub(crate) fn clip(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_are_cut_at_character_boundaries() {
        assert_eq!(clip("abc", 2), "ab");
        assert_eq!(clip("\u{e9}\u{e9}", 3), "\u{e9}");
        assert_eq!(clip("", 3), "");
        assert_eq!(clip(&"x".repeat(200), MAX_DETAIL).len(), MAX_DETAIL);
    }
}
