//! `Storage::submit` and its tickets: the ports of the Zig mailbox tests "disconnect cannot
//! recycle executing work or consume another caller's result" and "completion waiter pins
//! the ticket and queued shutdown wakes it". The mailbox's third test, "urgent work overtakes
//! background but cannot starve it", has no counterpart: jobs run in the order they were
//! queued (SID 0011, "The storage thread").

// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::mpsc;
use std::time::Duration;

use common::{scratch_dir, sqlite_config};
use sibuna_storage::{Hooks, JOB_QUEUE, Storage, StorageError, Ticket};

/// Submits a job that reports its start and then holds the storage thread until the gate
/// opens; returns its ticket and the gate.
fn hold(storage: &Storage) -> (Ticket<u32>, mpsc::Sender<()>) {
    let (started_tx, started_rx) = mpsc::channel();
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let ticket = storage
        .submit(move |_db| async move {
            started_tx.send(()).unwrap();
            // Blocking inside the job holds the whole storage thread, which is the point.
            let _ = gate_rx.recv();
            Ok(u32::MAX)
        })
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).expect("the held job runs");
    (ticket, gate_tx)
}

#[test]
fn an_abandoned_ticket_cannot_take_a_slot_or_another_callers_result() {
    let dir = scratch_dir("tickets-abandon");
    let storage = Storage::start(&sqlite_config(&dir, 50), Hooks::default()).expect("start");
    let (first, gate) = hold(&storage);
    // Abandoning executing work frees no queue slot under it and runs nothing twice.
    drop(first);
    let mut tickets: Vec<Ticket<u32>> = (0..JOB_QUEUE)
        .map(|index| {
            let value = u32::try_from(index).unwrap();
            storage.submit(move |_db| async move { Ok(value) }).unwrap()
        })
        .collect();
    assert!(matches!(storage.submit(|_db| async { Ok(0u32) }), Err(StorageError::Busy)));
    assert!(tickets.iter_mut().all(|ticket| ticket.try_take().is_none()));
    gate.send(()).unwrap();
    // Every caller receives its own result and only its own, exactly once.
    for (index, ticket) in tickets.iter_mut().enumerate() {
        let result = ticket.wait_timeout(Duration::from_secs(5)).expect("finished");
        assert_eq!(result.unwrap(), u32::try_from(index).unwrap());
        assert!(ticket.is_taken());
        assert!(ticket.try_take().is_none());
        assert!(ticket.wait_timeout(Duration::ZERO).is_none());
    }
    // The queue has room again.
    assert_eq!(storage.with_database(|_db| async { Ok(7u32) }).unwrap(), 7);
    assert!(storage.shutdown());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shutdown_wakes_the_waiters_of_queued_jobs() {
    let dir = scratch_dir("tickets-shutdown");
    let storage = Storage::start(&sqlite_config(&dir, 50), Hooks::default()).expect("start");
    let (held, gate) = hold(&storage);
    let queued = storage.submit(|_db| async { Ok(1u32) }).unwrap();
    let mut polled = storage.submit(|_db| async { Ok(2u32) }).unwrap();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(move || queued.wait());
        // The waiter waits for a job that has not started.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!waiter.is_finished());
        assert!(polled.try_take().is_none());
        let stopper = scope.spawn(|| {
            // `shutdown` takes the handle; the storage thread finishes the held job first.
            let storage = storage;
            storage.shutdown()
        });
        std::thread::sleep(Duration::from_millis(50));
        gate.send(()).unwrap();
        assert!(stopper.join().unwrap());
        // The held job finished; the queued ones were dropped unrun and their callers woke.
        assert_eq!(held.wait().unwrap(), u32::MAX);
        assert!(matches!(waiter.join().unwrap(), Err(StorageError::Stopped)));
        assert!(matches!(polled.try_take(), Some(Err(StorageError::Stopped))));
    });
    std::fs::remove_dir_all(&dir).unwrap();
}
