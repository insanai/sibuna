//! The job's schedule, without a database: standby, renewal, the per-kind batch bound and
//! the pass interval. Ported in spirit from Zig's "retention standby, renewal, scheduling
//! and cancellation do not block collection".

use super::*;

const HOLDER: Holder = Holder { node: 1, boot: [1; 16] };

fn lease(fence: u64, expires: u64) -> Lease {
    Lease { holder: HOLDER, fence, expires }
}

fn prune(job: &mut RetentionJob, now: u64) -> Kind {
    match job.next_step(now) {
        Some(Step::Prune { kind, .. }) => kind,
        other => panic!("expected a prune step, got {other:?}"),
    }
}

#[test]
fn standby_while_another_node_holds_the_lease() {
    let mut job = RetentionJob::new(HOLDER);
    let step = job.next_step(0).expect("a pass is due at once");
    assert_eq!(step, Step::Acquire(HOLDER));
    assert!(job.complete(&step, Err(ConsoleStorageError::Conflict), 0).is_none());
    assert_eq!(job.lease(), None);
    assert_eq!(job.next_step(4), None);
    assert_eq!(job.next_step(5), Some(Step::Acquire(HOLDER)));
}

#[test]
fn a_pass_visits_every_kind_and_stops_each_at_its_bounds() {
    let mut job = RetentionJob::new(HOLDER);
    let step = job.next_step(100).expect("due");
    assert!(job.complete(&step, Ok(Outcome::Lease(lease(3, 130))), 100).is_none());
    // A full batch continues the kind; the eighth full batch ends it.
    for _ in 0..BATCHES_PER_KIND {
        assert_eq!(prune(&mut job, 100), Kind::Incidents);
        let step = Step::Prune { lease: lease(3, 130), kind: Kind::Incidents };
        job.complete(&step, Ok(Outcome::Deleted(u64::from(BATCH_ROWS))), 100);
    }
    // A short batch ends a kind at once; a failed batch skips the rest of its kind.
    assert_eq!(prune(&mut job, 101), Kind::Audit);
    let step = Step::Prune { lease: lease(3, 130), kind: Kind::Audit };
    job.complete(&step, Ok(Outcome::Deleted(255)), 101);
    assert_eq!(prune(&mut job, 101), Kind::Minutes);
    let step = Step::Prune { lease: lease(3, 130), kind: Kind::Minutes };
    let failure = ConsoleStorageError::InvalidInput("test");
    assert!(job.complete(&step, Err(failure), 101).is_some());
    let mut visited = vec![Kind::Incidents, Kind::Audit, Kind::Minutes];
    while let Some(Step::Prune { lease, kind }) = job.next_step(102) {
        visited.push(kind);
        job.complete(&Step::Prune { lease, kind }, Ok(Outcome::Deleted(0)), 102);
    }
    assert_eq!(visited, Kind::ALL);
    // The next pass starts five seconds after this one started.
    assert_eq!(job.next_step(104), None);
    assert!(matches!(job.next_step(105), Some(Step::Prune { kind: Kind::Incidents, .. })));
}

#[test]
fn the_lease_is_renewed_after_ten_seconds_and_a_lost_lease_ends_the_pass() {
    let mut job = RetentionJob::new(HOLDER);
    let step = job.next_step(0).expect("due");
    job.complete(&step, Ok(Outcome::Lease(lease(1, 30))), 0);
    assert_eq!(prune(&mut job, 9), Kind::Incidents);
    assert_eq!(job.next_step(10), Some(Step::Acquire(HOLDER)));
    job.complete(&Step::Acquire(HOLDER), Ok(Outcome::Lease(lease(1, 40))), 10);
    assert_eq!(job.lease(), Some(lease(1, 40)));
    let step = Step::Prune { lease: lease(1, 40), kind: Kind::Incidents };
    assert!(job.complete(&step, Err(ConsoleStorageError::Conflict), 11).is_none());
    assert_eq!((job.lease(), job.kind()), (None, None));
    assert_eq!(job.next_step(15), None);
    assert_eq!(job.next_step(16), Some(Step::Acquire(HOLDER)));
}

#[test]
fn a_failed_acquisition_is_reported_and_retried_next_pass() {
    let mut job = RetentionJob::new(HOLDER);
    let step = job.next_step(0).expect("due");
    assert!(job.complete(&step, Err(ConsoleStorageError::Capacity), 0).is_some());
    assert_eq!(job.next_step(4), None);
    assert_eq!(job.next_step(5), Some(Step::Acquire(HOLDER)));
}
