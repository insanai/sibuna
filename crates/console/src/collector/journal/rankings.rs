//! The ranking archive journal (Zig's `rankings_journal.zig`): encodes each sealed
//! collector minute as an SBR2 archive and stores it whole (S32), and reads the archive
//! inventory every five seconds for the rankings page.
//!
//! Zig wrote an archive in three acknowledged phases (reserve, 2,048-byte chunks, publish)
//! to fit its storage envelope; `console_storage::rankings::store_archive` stores it in one
//! transaction, so a retry repeats one idempotent step (SID 0013, review of 2026-10-15).

use std::collections::VecDeque;

use sibuna_console_protocol::ranking_storage::Minute;
use sibuna_console_protocol::rankings::{ArchiveStatus, Inventory};
use sibuna_console_protocol::rankings_archive::{self, Archive, Identity};
use sibuna_console_storage::rankings::{inventory, store_archive};
use sibuna_crypto::sha256::Sha256;

use super::{Lane, MAX_RETRIES, Outcome};
use crate::storage::ConsoleStorage;

/// How many archives wait.
const PENDING: usize = 2;
/// How often the inventory is read, in milliseconds.
const INVENTORY_MS: u64 = 5_000;

/// One encoded archive waiting to be stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Job {
    /// The SBR2 bytes.
    pub bytes: Vec<u8>,
    /// Their SHA-256.
    pub digest: [u8; 32],
    /// The archived minute.
    pub minute: u64,
    retries: u8,
}

/// What the journal asks storage to do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Work {
    /// Store the head archive.
    Store(Job),
    /// Read the inventory.
    Inventory,
}

/// What a finished [`Work`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Done {
    /// The archive is stored (newly, or already).
    Stored,
    /// The inventory.
    Inventory(Inventory),
}

/// The ranking archive journal of this node and boot.
#[derive(Debug)]
pub(crate) struct RankingJournal {
    node: u32,
    boot: [u8; 16],
    jobs: VecDeque<Job>,
    in_flight: Option<bool>,
    retry_at: u64,
    inventory_at: u64,
    lane: Lane<Done>,
    status: ArchiveStatus,
}

impl RankingJournal {
    /// Returns an empty journal for `node` and `boot`; the inventory is read at once.
    pub(crate) fn new(node: u32, boot: [u8; 16]) -> RankingJournal {
        RankingJournal {
            node,
            boot,
            jobs: VecDeque::with_capacity(PENDING),
            in_flight: None,
            retry_at: 0,
            inventory_at: 0,
            lane: Lane::default(),
            status: ArchiveStatus::default(),
        }
    }

    /// Encodes the sealed `minute` with the cumulative queue loss `queue_loss` and queues
    /// it. A full queue, or a minute that does not encode, counts as unconfirmed.
    pub(crate) fn offer(&mut self, minute: &Minute, queue_loss: u64) {
        let Some(number) = minute.minute.filter(|_| self.jobs.len() < PENDING) else {
            self.unconfirmed();
            return;
        };
        let archive = Archive {
            identity: Identity {
                node: self.node,
                boot: self.boot,
                queue_loss_end: queue_loss,
                ..Identity::default()
            },
            minute: minute.clone(),
        };
        let Ok(bytes) = rankings_archive::encode(&archive) else {
            self.unconfirmed();
            return;
        };
        let digest = Sha256::digest(&bytes);
        self.jobs.push_back(Job { bytes, digest, minute: number, retries: 0 });
        self.status.pending = self.jobs.len() as u32;
    }

    fn unconfirmed(&mut self) {
        self.status.unconfirmed_since_boot = self.status.unconfirmed_since_boot.saturating_add(1);
    }

    /// Returns the work to submit at monotonic `ms` and marks it in flight: the inventory
    /// read when due, otherwise the head archive once its retry time has come.
    pub(crate) fn next(&mut self, ms: u64) -> Option<Work> {
        if self.in_flight.is_some() || ms < self.retry_at {
            return None;
        }
        if ms >= self.inventory_at {
            self.inventory_at = ms.saturating_add(INVENTORY_MS);
            self.in_flight = Some(false);
            return Some(Work::Inventory);
        }
        let job = self.jobs.front()?;
        self.in_flight = Some(true);
        Some(Work::Store(job.clone()))
    }

    /// Records the outcome of the work [`RankingJournal::next`] handed out.
    pub(crate) fn finish(&mut self, outcome: Outcome<Done>, ms: u64) {
        let Some(storing) = self.in_flight.take() else { return };
        match (storing, outcome) {
            (_, Outcome::NotQueued) => {
                if !storing {
                    self.inventory_at = 0;
                }
            }
            (false, Outcome::Done(Done::Inventory(stored))) => self.status.stored = stored,
            (false, _) => {
                let failures = self.status.maintenance_failures_since_boot.saturating_add(1);
                self.status.maintenance_failures_since_boot = failures;
            }
            (true, Outcome::Done(_)) => {
                if let Some(job) = self.jobs.pop_front() {
                    self.status.last_saved_minute = Some(job.minute);
                    self.status.saved_since_boot = self.status.saved_since_boot.saturating_add(1);
                }
            }
            (true, Outcome::Failed(_) | Outcome::Unknown) => self.retry(ms),
        }
        self.status.pending = self.jobs.len() as u32;
    }

    /// Counts a failed attempt of the head archive: dropped as unconfirmed after
    /// [`MAX_RETRIES`], otherwise the journal waits 1, 2, 4, ... seconds.
    fn retry(&mut self, ms: u64) {
        let Some(job) = self.jobs.front_mut() else { return };
        job.retries += 1;
        if job.retries >= MAX_RETRIES {
            self.jobs.pop_front();
            self.unconfirmed();
        } else {
            self.retry_at = ms.saturating_add(1000 << (job.retries - 1));
        }
    }

    /// Polls the work in flight and submits the next; never waits.
    pub(crate) fn tick(&mut self, storage: &ConsoleStorage, now: u64, ms: u64) {
        if let Some(outcome) = self.lane.poll(ms) {
            self.finish(outcome, ms);
        }
        if self.lane.is_busy() {
            return;
        }
        let submitted = match self.next(ms) {
            None => return,
            Some(Work::Inventory) => storage.submit_background(move |tx| {
                Box::pin(async move { inventory(tx, now).await.map(Done::Inventory) })
            }),
            Some(Work::Store(job)) => storage.submit_background(move |tx| {
                Box::pin(async move {
                    store_archive(tx, &job.digest, &job.bytes, now).await.map(|_| Done::Stored)
                })
            }),
        };
        if let Some(outcome) = self.lane.start(submitted, ms) {
            self.finish(outcome, ms);
        }
    }

    /// Returns the archive writer's health.
    pub(crate) fn status(&self, maintenance_failures: u64) -> ArchiveStatus {
        let mut status = self.status;
        status.maintenance_failures_since_boot =
            status.maintenance_failures_since_boot.saturating_add(maintenance_failures);
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minute() -> Minute {
        let mut result =
            Minute { minute: Some(1), first_second: 100, last_second: 100, ..Minute::default() };
        result.paths.add(b"/observed").unwrap();
        result
    }

    fn journal() -> RankingJournal {
        let mut journal = RankingJournal::new(1, [1; 16]);
        journal.inventory_at = u64::MAX;
        journal
    }

    // rankings_journal_test.zig: "journal never waits for storage and publishes only after
    // the finish acknowledgement". One store step replaces begin, chunk and finish.
    #[test]
    fn archives_are_saved_only_after_their_acknowledgement() {
        let mut journal = journal();
        let source = minute();
        for _ in 0..3 {
            journal.offer(&source, 3);
        }
        assert_eq!(journal.status(0).pending, 2);
        assert_eq!(journal.status(0).unconfirmed_since_boot, 1);
        let Some(Work::Store(job)) = journal.next(0) else { panic!("a store step") };
        assert_eq!(Sha256::digest(&job.bytes), job.digest);
        let decoded = rankings_archive::decode(&job.bytes).unwrap();
        assert_eq!(decoded.identity.queue_loss_end, 3);
        assert_eq!(decoded.minute.paths.samples(), 1);
        assert_eq!(journal.status(0).saved_since_boot, 0);
        assert!(journal.next(250).is_none());
        journal.finish(Outcome::Done(Done::Stored), 250);
        let status = journal.status(0);
        assert_eq!(status.saved_since_boot, 1);
        assert_eq!(status.last_saved_minute, Some(1));
        assert_eq!(status.pending, 1);
    }

    // rankings_journal_test.zig: "timed out executing writes retain mailbox ownership and
    // retries stop at their bound".
    #[test]
    fn unknown_writes_repeat_the_same_archive_and_retries_stop_at_their_bound() {
        let mut journal = journal();
        journal.offer(&minute(), 0);
        let Some(Work::Store(old)) = journal.next(0) else { panic!("a store step") };
        journal.finish(Outcome::Unknown, 10_000);
        assert!(journal.next(10_500).is_none());
        let Some(Work::Store(retry)) = journal.next(11_000) else { panic!("a retry") };
        assert_eq!((retry.digest, retry.bytes.len()), (old.digest, old.bytes.len()));
        journal.finish(Outcome::failed(), 11_250);
        let mut ms = 80_000;
        for _ in 0..6 {
            assert!(journal.next(ms).is_some());
            journal.finish(Outcome::failed(), ms + 250);
            ms += 80_000;
        }
        let status = journal.status(0);
        assert_eq!(status.pending, 0);
        assert_eq!(status.unconfirmed_since_boot, 1);
        assert_eq!(status.saved_since_boot, 0);
    }

    // rankings_journal_test.zig: "maintenance errors are visible and shutdown releases
    // pending tickets". The inventory read replaces Zig's prune step.
    #[test]
    fn inventory_failures_are_visible() {
        let mut journal = RankingJournal::new(1, [1; 16]);
        assert_eq!(journal.next(0), Some(Work::Inventory));
        journal.finish(Outcome::failed(), 250);
        assert_eq!(journal.status(0).maintenance_failures_since_boot, 1);
        assert_eq!(journal.status(2).maintenance_failures_since_boot, 3);
        assert!(journal.next(4_999).is_none());
        assert_eq!(journal.next(5_000), Some(Work::Inventory));
        let stored = Inventory { available: true, archives: 4, ..Inventory::default() };
        journal.finish(Outcome::Done(Done::Inventory(stored)), 5_250);
        assert_eq!(journal.status(0).stored, stored);
    }

    // rankings_journal_test.zig: "a slow pruning acknowledgement leaves room for queued
    // ranking publication".
    #[test]
    fn a_slow_inventory_read_leaves_room_for_the_next_archive() {
        let mut journal = RankingJournal::new(1, [1; 16]);
        journal.offer(&minute(), 0);
        assert_eq!(journal.next(0), Some(Work::Inventory));
        journal.finish(Outcome::Done(Done::Inventory(Inventory::default())), 4_000);
        assert!(matches!(journal.next(4_250), Some(Work::Store(_))));
        journal.finish(Outcome::Done(Done::Stored), 4_500);
        assert_eq!(journal.status(0).saved_since_boot, 1);
    }
}
