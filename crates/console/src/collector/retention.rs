//! The retention driver (Zig's `retention_job.zig`): runs the steps of
//! [`console_storage::retention::RetentionJob`](RetentionJob) as background storage jobs,
//! one at a time, from the collector tick.
//!
//! The job itself decides what is due (the lease, then batches of every kind, a pass every
//! five seconds); the driver only submits each step, polls its ticket and reports the
//! outcome. A lease held by another node is a normal standby, not a failure. A step that
//! does not answer within ten seconds counts as failed and ends its kind (the database fence
//! protects any late deletion). Failures are counted in total and per kind, so the minute and
//! ranking journals can show the failures of their own retention.

use sibuna_console_protocol::retention::Holder;
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::leases::{Job, acquire_lease};
use sibuna_console_storage::retention::{
    Kind, Outcome as StepOutcome, RetentionJob, Step, prune_batch,
};

use super::journal::{Lane, Outcome};
use crate::storage::{ConsoleStorage, StorageFailure};

/// Failed retention steps since boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Failures {
    /// Every failed step.
    pub total: u64,
    /// Failed batches of traffic and challenge minutes.
    pub minutes: u64,
    /// Failed batches of ranking archives.
    pub rankings: u64,
}

/// The retention job of this node and its step in flight.
#[derive(Debug)]
pub(crate) struct Retention {
    job: RetentionJob,
    step: Option<Step>,
    lane: Lane<StepOutcome>,
    failures: Failures,
}

impl Retention {
    /// Returns the driver for `holder`, with a pass due at once.
    pub(crate) fn new(holder: Holder) -> Retention {
        Retention {
            job: RetentionJob::new(holder),
            step: None,
            lane: Lane::default(),
            failures: Failures::default(),
        }
    }

    /// Returns the failures since boot.
    pub(crate) fn failures(&self) -> Failures {
        self.failures
    }

    /// Returns the step to run at `now` (Unix seconds) and marks it in flight; `None` while
    /// one is in flight or nothing is due.
    pub(crate) fn next(&mut self, now: u64) -> Option<Step> {
        if self.step.is_some() {
            return None;
        }
        let step = self.job.next_step(now)?;
        self.step = Some(step);
        Some(step)
    }

    /// Reports the outcome of the step [`Retention::next`] handed out, at `now`.
    pub(crate) fn finish(&mut self, outcome: Outcome<StepOutcome>, now: u64) {
        let Some(step) = self.step.take() else { return };
        let result = match outcome {
            // Nothing ran; the job hands out the same step again.
            Outcome::NotQueued => return,
            Outcome::Done(value) => Ok(value),
            // The step's own refusal: a conflict means the lease is another node's.
            Outcome::Failed(StorageFailure::Console(error)) => Err(error),
            Outcome::Failed(_) | Outcome::Unknown => Err(ConsoleStorageError::Unavailable),
        };
        if self.job.complete(&step, result, now).is_none() {
            return;
        }
        self.failures.total = self.failures.total.saturating_add(1);
        if let Step::Prune { kind, .. } = step {
            match kind {
                Kind::Minutes => self.failures.minutes = self.failures.minutes.saturating_add(1),
                Kind::Rankings => {
                    self.failures.rankings = self.failures.rankings.saturating_add(1);
                }
                _ => {}
            }
        }
    }

    /// Polls the step in flight and submits the next; never waits.
    pub(crate) fn tick(&mut self, storage: &ConsoleStorage, now: u64, ms: u64) {
        if let Some(outcome) = self.lane.poll(ms) {
            self.finish(outcome, now);
        }
        if self.lane.is_busy() {
            return;
        }
        let Some(step) = self.next(now) else { return };
        let submitted = storage.submit_background(move |tx| {
            Box::pin(async move {
                match step {
                    Step::Acquire(holder) => acquire_lease(tx, Job::Retention, &holder, now)
                        .await
                        .map(StepOutcome::Lease),
                    Step::Prune { lease, kind } => {
                        prune_batch(tx, &lease, kind, now).await.map(StepOutcome::Deleted)
                    }
                }
            })
        });
        if let Some(outcome) = self.lane.start(submitted, ms) {
            self.finish(outcome, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use sibuna_console_protocol::retention::Lease;

    use super::*;

    const HOLDER: Holder = Holder { node: 1, boot: [1; 16] };

    // retention_job.zig: "retention standby, renewal, scheduling and cancellation do not
    // block collection". The schedule itself is `RetentionJob`'s; this checks the driver.
    #[test]
    fn standby_renewal_and_failures_never_block_the_collector() {
        let mut retention = Retention::new(HOLDER);
        assert_eq!(retention.next(0), Some(Step::Acquire(HOLDER)));
        assert_eq!(retention.next(0), None);
        // Another node holds the lease: a standby until the next pass, not a failure.
        let held = StorageFailure::Console(ConsoleStorageError::Conflict);
        retention.finish(Outcome::Failed(held), 0);
        assert_eq!(retention.failures().total, 0);
        assert_eq!(retention.next(4), None);
        assert_eq!(retention.next(5), Some(Step::Acquire(HOLDER)));
        let lease = Lease { holder: HOLDER, fence: 1, expires: 100 };
        retention.finish(Outcome::Done(StepOutcome::Lease(lease)), 5);
        let prune = retention.next(5).unwrap();
        assert_eq!(prune, Step::Prune { lease, kind: Kind::Incidents });
        retention.finish(Outcome::Done(StepOutcome::Deleted(0)), 5);
        assert_eq!(retention.next(5), Some(Step::Prune { lease, kind: Kind::Audit }));
        // A step that is never queued is handed out again and costs nothing.
        retention.finish(Outcome::NotQueued, 5);
        assert_eq!(retention.next(5), Some(Step::Prune { lease, kind: Kind::Audit }));
        // A step without an answer fails its kind; the pass goes on with the next one.
        retention.finish(Outcome::Unknown, 14);
        assert_eq!(retention.failures().total, 1);
        assert_eq!(retention.next(14), Some(Step::Prune { lease, kind: Kind::Minutes }));
        retention.finish(Outcome::failed(), 14);
        assert_eq!(retention.failures(), Failures { total: 2, minutes: 1, rankings: 0 });
        // Ten seconds after the lease was taken, it is renewed before the next batch.
        assert_eq!(retention.next(15), Some(Step::Acquire(HOLDER)));
    }
}
