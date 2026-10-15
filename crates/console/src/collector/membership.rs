//! Membership announcements (Zig's `console_membership.zig`): this node writes its own row
//! of the membership table at start, every minute, and soon after its applied policy
//! revision or control revision moved. A row states facts about its writer only; consoles
//! never probe an address read from the table.
//!
//! Zig announced from the storage owner's tick with a blocking write; here the collector
//! submits a background job and polls it, so a slow database never delays a tick. Requests
//! within two seconds of the last announcement are coalesced; after a failure, a requested
//! announcement waits thirty seconds.

use sibuna_console_storage::nodes::{Announcement, MAX_VERSION, announce};

use super::journal::{Lane, Outcome};
use crate::storage::ConsoleStorage;

/// Seconds between heartbeats.
const HEARTBEAT_SECONDS: u64 = 60;
/// Seconds before a requested announcement is retried after a failure.
const RETRY_SECONDS: u64 = 30;
/// Seconds within which requested announcements are coalesced.
const COALESCE_SECONDS: u64 = 2;
/// The address a node without a cluster listener announces.
const LOCAL_ADDRESS: &str = "local";

/// The facts this node announces that do not change while it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    /// The node, 1 or above.
    pub node: u32,
    /// The console link: empty, or the configured advertised origin.
    pub console_url: String,
    /// The software version, 1 to 32 bytes.
    pub version: String,
    /// This boot.
    pub boot: [u8; 16],
}

impl Identity {
    /// Returns the identity of `node` with `version` (when it is not 1 to 32 bytes,
    /// `unknown` is announced instead).
    pub(crate) fn new(node: u32, console_url: &str, version: &str, boot: [u8; 16]) -> Identity {
        let version = if (1..=MAX_VERSION).contains(&version.len()) { version } else { "unknown" };
        Identity { node, console_url: console_url.to_owned(), version: version.to_owned(), boot }
    }
}

/// The facts that change: read once per tick.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    /// The applied policy revision.
    pub applied_revision: u64,
    /// The control revision (one per applied node command).
    pub control_revision: u64,
    /// The node is draining.
    pub draining: bool,
}

/// The announcer's state.
#[derive(Debug)]
pub(crate) struct Membership {
    identity: Identity,
    last: Option<u64>,
    failed: bool,
    requested: bool,
    /// Whether the announcement in flight was requested; restored on failure.
    in_flight: Option<bool>,
    seen: Option<Facts>,
    lane: Lane<()>,
}

impl Membership {
    /// Returns an announcer for `identity`, with an announcement due at once.
    pub(crate) fn new(identity: Identity) -> Membership {
        Membership {
            identity,
            last: None,
            failed: false,
            requested: true,
            in_flight: None,
            seen: None,
            lane: Lane::default(),
        }
    }

    /// Asks for an announcement soon (an applied node command, say).
    pub(crate) fn request(&mut self) {
        self.requested = true;
    }

    /// Returns the announcement due at `now` with `facts` and marks it in flight; a change
    /// of the facts since the last call requests one.
    pub(crate) fn next(&mut self, facts: Facts, now: u64) -> Option<Announcement<'_>> {
        if self.seen.is_some_and(|seen| seen.applied_revision != facts.applied_revision)
            || self.seen.is_some_and(|seen| seen.control_revision != facts.control_revision)
        {
            self.requested = true;
        }
        self.seen = Some(facts);
        if self.in_flight.is_some() {
            return None;
        }
        if let Some(last) = self.last {
            let since = now.saturating_sub(last);
            let spacing = if self.failed { RETRY_SECONDS } else { COALESCE_SECONDS };
            if since < spacing || (!self.requested && since < HEARTBEAT_SECONDS) {
                return None;
            }
        }
        self.in_flight = Some(self.requested);
        self.requested = false;
        self.last = Some(now);
        Some(Announcement {
            node: self.identity.node,
            address: LOCAL_ADDRESS,
            console_url: &self.identity.console_url,
            version: &self.identity.version,
            boot: self.identity.boot,
            applied_revision: facts.applied_revision,
            control_revision: facts.control_revision,
            draining: facts.draining,
        })
    }

    /// Records the outcome of the announcement [`Membership::next`] handed out.
    pub(crate) fn finish<T>(&mut self, outcome: Outcome<T>) {
        let Some(requested) = self.in_flight.take() else { return };
        match outcome {
            Outcome::Done(_) => self.failed = false,
            Outcome::NotQueued => {
                self.requested |= requested;
                self.last = None;
            }
            Outcome::Failed(_) | Outcome::Unknown => {
                self.requested |= requested;
                self.failed = true;
            }
        }
    }

    /// Polls the announcement in flight and submits the next one due; never waits.
    pub(crate) fn tick(&mut self, storage: &ConsoleStorage, facts: Facts, now: u64, ms: u64) {
        if let Some(outcome) = self.lane.poll(ms) {
            self.finish(outcome);
        }
        if self.lane.is_busy() {
            return;
        }
        let Some(announcement) = self.next(facts, now) else { return };
        let (url, version) =
            (announcement.console_url.to_owned(), announcement.version.to_owned());
        let Announcement { node, boot, applied_revision, control_revision, draining, .. } =
            announcement;
        let submitted = storage.submit_background(move |tx| {
            Box::pin(async move {
                let announcement = Announcement {
                    node,
                    address: LOCAL_ADDRESS,
                    console_url: &url,
                    version: &version,
                    boot,
                    applied_revision,
                    control_revision,
                    draining,
                };
                announce(tx, &announcement, now).await
            })
        });
        if let Some(outcome) = self.lane.start(submitted, ms) {
            self.finish(outcome);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership() -> Membership {
        Membership::new(Identity::new(1, "http://127.0.0.1:9443", "0.2.0", [1; 16]))
    }

    #[test]
    fn announcements_coalesce_beat_every_minute_and_follow_revisions() {
        let mut membership = membership();
        let facts = Facts { applied_revision: 3, ..Facts::default() };
        let first = membership.next(facts, 100).unwrap();
        assert_eq!((first.node, first.address, first.applied_revision), (1, "local", 3));
        assert_eq!(first.console_url, "http://127.0.0.1:9443");
        membership.finish(Outcome::Done(()));
        assert!(membership.next(facts, 101).is_none());
        assert!(membership.next(facts, 159).is_none());
        assert!(membership.next(facts, 160).is_some());
        membership.finish(Outcome::Done(()));
        // A new applied revision is announced after the coalescing window.
        let moved = Facts { applied_revision: 4, ..facts };
        assert!(membership.next(moved, 161).is_none());
        assert_eq!(membership.next(moved, 162).unwrap().applied_revision, 4);
        membership.finish(Outcome::<()>::failed());
        membership.request();
        assert!(membership.next(moved, 191).is_none());
        assert!(membership.next(moved, 192).is_some());
        membership.finish(Outcome::<()>::NotQueued);
        assert!(membership.next(moved, 192).is_some());
    }

    #[test]
    fn an_unusable_version_is_announced_as_unknown() {
        assert_eq!(Identity::new(1, "", "", [1; 16]).version, "unknown");
        assert_eq!(Identity::new(1, "", &"v".repeat(33), [1; 16]).version, "unknown");
    }
}
