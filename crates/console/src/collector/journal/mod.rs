//! The collector's journals: traffic minutes, challenge minutes, challenge records, ranking
//! archives and rule hits, each written to storage through background tickets.
//!
//! Every journal is a state machine the collector thread owns. It never waits for storage:
//! at most one storage job per journal lane is in flight, polled once per collector tick
//! with [`Lane::poll`]. A job that has not answered after [`TIMEOUT_MS`] is abandoned (its
//! ticket dropped; the job still commits or rolls back whole) and counts as an unknown
//! outcome, as Zig's mailbox abandonment did. Snapshots wait in small bounded queues
//! ([`Pending`]); a full queue, or a snapshot whose retries are spent, is counted as
//! unconfirmed rather than dropped silently.
//!
//! The state machines are separate from storage: `next` hands out the write to submit and
//! `finish` takes its [`Outcome`]. The collector drives them through storage; the tests
//! drive them directly, as the Zig tests drove the mailbox.

pub(crate) mod challenges;
pub(crate) mod minutes;
pub(crate) mod rankings;
pub(crate) mod records;
pub(crate) mod rule_hits;

use std::collections::VecDeque;

use sibuna_console_protocol::minutes::{Cursor, Status};

use crate::storage::{BackgroundTicket, StorageFailure};

/// How long a lane waits for its job before it abandons the ticket, in milliseconds.
pub(crate) const TIMEOUT_MS: u64 = 10_000;
/// How many attempts a snapshot gets before it is counted as unconfirmed.
pub(crate) const MAX_RETRIES: u8 = 8;
/// How often the open minute is offered as a partial snapshot, in milliseconds.
pub(crate) const OFFER_MS: u64 = 5_000;
/// How many snapshots a minute journal keeps waiting.
const PENDING: usize = 2;

/// What became of one storage job.
#[derive(Debug)]
pub(crate) enum Outcome<T> {
    /// The job ran and its transaction committed with this value.
    Done(T),
    /// The job ran and failed (its transaction rolled back), or storage refused it.
    Failed(StorageFailure),
    /// The job did not answer in time and was abandoned: it may or may not have committed.
    Unknown,
    /// The job was never queued (the background allowance was spent or the storage queue
    /// was full); nothing ran, so the attempt does not count.
    NotQueued,
}

impl<T> Outcome<T> {
    /// Returns the outcome of a submission that failed before anything was queued or run.
    pub(crate) fn refused(failure: StorageFailure) -> Outcome<T> {
        match failure {
            StorageFailure::Deferred | StorageFailure::Busy => Outcome::NotQueued,
            failure => Outcome::Failed(failure),
        }
    }

    /// Returns the outcome of a finished job.
    pub(crate) fn of(result: Result<T, StorageFailure>) -> Outcome<T> {
        match result {
            Ok(value) => Outcome::Done(value),
            Err(failure) => Outcome::refused(failure),
        }
    }

    /// Returns a failed outcome, for tests.
    #[cfg(test)]
    pub(crate) fn failed() -> Outcome<T> {
        Outcome::Failed(StorageFailure::Stopped)
    }
}

/// At most one background storage job in flight, with its deadline.
#[derive(Debug)]
pub(crate) struct Lane<T> {
    ticket: Option<BackgroundTicket<T>>,
    submitted_ms: u64,
}

impl<T> Default for Lane<T> {
    fn default() -> Lane<T> {
        Lane { ticket: None, submitted_ms: 0 }
    }
}

impl<T> Lane<T> {
    /// Returns true while a job is in flight.
    pub(crate) fn is_busy(&self) -> bool {
        self.ticket.is_some()
    }

    /// Takes the result of a submission at monotonic `ms`: a queued job is now in flight
    /// (returns `None`); a refused one returns its outcome at once.
    pub(crate) fn start(
        &mut self,
        submitted: Result<BackgroundTicket<T>, StorageFailure>,
        ms: u64,
    ) -> Option<Outcome<T>> {
        match submitted {
            Ok(ticket) => {
                self.ticket = Some(ticket);
                self.submitted_ms = ms;
                None
            }
            Err(failure) => Some(Outcome::refused(failure)),
        }
    }

    /// Returns the outcome of the job in flight at monotonic `ms`, without waiting: `None`
    /// while it runs (or when none is in flight); [`Outcome::Unknown`] once it has run for
    /// [`TIMEOUT_MS`], abandoning its ticket.
    pub(crate) fn poll(&mut self, ms: u64) -> Option<Outcome<T>> {
        let ticket = self.ticket.as_mut()?;
        if let Some(result) = ticket.try_take() {
            self.ticket = None;
            return Some(Outcome::of(result));
        }
        if ms.saturating_sub(self.submitted_ms) >= TIMEOUT_MS {
            self.ticket = None;
            return Some(Outcome::Unknown);
        }
        None
    }
}

/// A minute snapshot a [`Pending`] queue can coalesce: a later snapshot of the same minute
/// replaces an earlier one that is still waiting.
pub(crate) trait Snapshot: Clone {
    /// Returns the minute's identity.
    fn cursor(&self) -> Cursor;
    /// Returns the end of the observed interval, in monotonic milliseconds.
    fn end_ms(&self) -> u64;
}

/// One waiting snapshot with its retry state.
#[derive(Clone, Debug)]
struct Job<R> {
    record: R,
    retries: u8,
    retry_at: u64,
}

/// Two waiting minute snapshots with bounded retries and their counters (Zig's journal
/// queue, shared by traffic and challenge minutes).
#[derive(Debug)]
pub(crate) struct Pending<R> {
    jobs: VecDeque<Job<R>>,
    /// The head job is in flight; its snapshot is not replaced until it is acknowledged.
    in_flight: bool,
    saved: u64,
    unconfirmed: u64,
    last_saved_end_ms: u64,
}

impl<R: Snapshot> Default for Pending<R> {
    fn default() -> Pending<R> {
        Pending {
            jobs: VecDeque::with_capacity(PENDING),
            in_flight: false,
            saved: 0,
            unconfirmed: 0,
            last_saved_end_ms: 0,
        }
    }
}

impl<R: Snapshot> Pending<R> {
    /// Queues `record`. A waiting snapshot of the same minute is replaced, keeping its
    /// retry count and backoff; the job in flight keeps its own snapshot. A full queue
    /// counts the snapshot as unconfirmed.
    pub(crate) fn offer(&mut self, record: R) {
        let cursor = record.cursor();
        let skip = usize::from(self.in_flight);
        if let Some(job) =
            self.jobs.iter_mut().skip(skip).rev().find(|j| j.record.cursor() == cursor)
        {
            job.record = record;
            return;
        }
        if self.jobs.len() == PENDING {
            self.unconfirmed = self.unconfirmed.saturating_add(1);
            return;
        }
        self.jobs.push_back(Job { record, retries: 0, retry_at: 0 });
    }

    /// Returns a copy of the snapshot to write now at monotonic `ms`, and marks it in
    /// flight; `None` while one is in flight, the queue is empty or the head waits for its
    /// retry time.
    pub(crate) fn next(&mut self, ms: u64) -> Option<R> {
        if self.in_flight {
            return None;
        }
        let job = self.jobs.front()?;
        if ms < job.retry_at {
            return None;
        }
        self.in_flight = true;
        Some(job.record.clone())
    }

    /// Records the outcome of the write [`Pending::next`] handed out, at monotonic `ms`.
    pub(crate) fn finish<T>(&mut self, outcome: Outcome<T>, ms: u64) {
        if !self.in_flight {
            return;
        }
        self.in_flight = false;
        match outcome {
            Outcome::Done(_) => {
                if let Some(job) = self.jobs.pop_front() {
                    self.last_saved_end_ms = job.record.end_ms();
                    self.saved = self.saved.saturating_add(1);
                }
            }
            Outcome::Failed(_) | Outcome::Unknown => self.retry(ms),
            Outcome::NotQueued => {}
        }
    }

    /// Counts a failed attempt of the head: after [`MAX_RETRIES`] it is dropped as
    /// unconfirmed; otherwise it waits 1, 2, 4, ... seconds.
    fn retry(&mut self, ms: u64) {
        let Some(job) = self.jobs.front_mut() else { return };
        job.retries += 1;
        if job.retries >= MAX_RETRIES {
            self.jobs.pop_front();
            self.unconfirmed = self.unconfirmed.saturating_add(1);
        } else {
            job.retry_at = ms.saturating_add(1000 << (job.retries - 1));
        }
    }

    /// Returns the queue's health; `retention_failures` is the caller's.
    pub(crate) fn status(&self, retention_failures: u64) -> Status {
        Status {
            available: true,
            // At most `PENDING` jobs wait.
            pending: self.jobs.len() as u32,
            saved_snapshots: self.saved,
            unconfirmed_snapshots: self.unconfirmed,
            retention_failures,
            last_saved_end_ms: self.last_saved_end_ms,
        }
    }

    /// Returns how many snapshots wait (including the one in flight).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.jobs.len()
    }
}
