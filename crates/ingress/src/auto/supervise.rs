//! The supervisor of the thread `edge-acme` (SID 0021).
//!
//! ```text
//!   run the driver --returns--> the daemon stops: done
//!        |
//!      panics
//!        v
//!   report, withdraw challenge answers, wait 5 s, 10 s, ... 300 s --> run a new driver
//! ```
//!
//! A new driver knows nothing of the old one. It reads the names, the stored
//! certificates and the stored retry state, as a daemon does after a restart. The
//! certificates in the tables stay, so the handshakes notice nothing.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::driver::Driver;
use super::{Event, Notify, Shared};

/// The wait before the first restart, in seconds.
pub(crate) const FIRST_RESTART: u64 = 5;
/// The longest wait before a restart, in seconds.
pub(crate) const LONGEST_RESTART: u64 = 300;
/// A driver that ran this long without a panic counts as healthy: the next panic waits
/// the first delay again.
const HEALTHY: Duration = Duration::from_secs(3600);

/// The seconds to wait before the restart after the `panics`-th panic in a row, from
/// 1: 5, 10, 20, and so on, at most 300.
pub(crate) fn restart_delay(panics: u32) -> u64 {
    let doublings = panics.saturating_sub(1).min(16);
    FIRST_RESTART.saturating_mul(1 << doublings).min(LONGEST_RESTART)
}

/// What a panic said, when it said it in text.
pub(super) fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    let text = payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned());
    let text = text.unwrap_or_else(|| "no message".to_owned());
    text.chars().filter(|c| !c.is_control()).take(512).collect()
}

/// Runs the driver until the daemon stops. A panic of the driver is reported and a new
/// driver starts after the restart delay.
pub(super) fn run(shared: &Arc<Shared>, report: &Notify) {
    let mut panics = 0;
    loop {
        let started = Instant::now();
        let driver = Driver::new(Arc::clone(shared), Arc::clone(report));
        // The driver is dropped with its panic, so nothing of its state is seen again.
        // What it shares with others are the tables of `Shared`. Each of them is behind
        // a lock that readers take over when it is poisoned, and each write is a single
        // insertion or removal, so a panic leaves a table as it was before or after one
        // write, never in between.
        let Err(payload) = catch_unwind(AssertUnwindSafe(|| driver.run())) else { return };
        if started.elapsed() >= HEALTHY {
            panics = 0;
        }
        panics += 1;
        let restart_in = restart_delay(panics);
        // The order that was running is gone, and with it the meaning of its answers.
        shared.withdraw();
        report(&Event::Panicked { message: panic_text(payload.as_ref()), restart_in });
        if !shared.pause(Duration::from_secs(restart_in)) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_restart_delay_doubles_from_five_seconds_to_five_minutes() {
        let delays: Vec<u64> = (1..=9).map(restart_delay).collect();
        assert_eq!(delays, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(restart_delay(0), 5);
        assert_eq!(restart_delay(u32::MAX), 300);
        assert!((1..200).all(|n| restart_delay(n) <= restart_delay(n + 1)));
    }

    /// The thread panics once. The supervisor reports it and starts the work again,
    /// which then issues the certificate of the name. The only way to make the thread
    /// panic is a flag that exists in test builds of this crate.
    #[test]
    fn the_work_starts_again_after_a_panic_and_issues() {
        use std::sync::Mutex;
        use std::sync::atomic::Ordering;

        use sibuna_lb::{AcmeOptions, AutoName, AutomaticHttps};

        let storage =
            std::env::temp_dir().join(format!("sibuna-supervise-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&storage);
        let config = AutomaticHttps {
            options: AcmeOptions {
                storage: storage.display().to_string(),
                ..AcmeOptions::default()
            },
            names: vec![AutoName { name: "localhost".to_owned(), port: 443, local: true }],
            plain_frontend: false,
            on_demand: false,
        };
        let shared = Arc::new(Shared::new(config));
        shared.panic_once.store(true, Ordering::Release);
        shared.ordering.store(true, Ordering::Release);
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let report: Notify = Arc::new(move |event: &Event| {
            let line = match event {
                Event::Panicked { message, restart_in } => format!("panic {restart_in} {message}"),
                Event::Obtained { name, .. } => format!("obtained {name}"),
                other => format!("{other:?}"),
            };
            sink.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
        });
        let begun = Instant::now();
        let thread = Arc::clone(&shared);
        let worker = std::thread::spawn(move || run(&thread, &report));
        let seen = || events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        while !seen().iter().any(|line| line == "obtained localhost") {
            assert!(begun.elapsed() < Duration::from_secs(30), "{:?}", seen());
            std::thread::sleep(Duration::from_millis(50));
        }
        let seen = seen();
        assert_eq!(seen[0], "panic 5 the test of the supervisor asked for this panic");
        assert_eq!(seen.iter().filter(|line| line.starts_with("panic")).count(), 1, "{seen:?}");
        // The restart waited its delay, and the certificate is served.
        assert!(begun.elapsed() >= Duration::from_secs(FIRST_RESTART));
        assert!(shared.certificate("localhost").is_some());
        shared.stopping.store(true, Ordering::Release);
        shared.notify();
        assert!(worker.join().is_ok());
        let _ = std::fs::remove_dir_all(&storage);
    }

    #[test]
    fn a_panic_is_told_in_one_printable_line() {
        let text: Box<dyn std::any::Any + Send> = Box::new("index out of\nbounds");
        assert_eq!(panic_text(text.as_ref()), "index out ofbounds");
        let owned: Box<dyn std::any::Any + Send> = Box::new(String::from("owned"));
        assert_eq!(panic_text(owned.as_ref()), "owned");
        let other: Box<dyn std::any::Any + Send> = Box::new(7_u8);
        assert_eq!(panic_text(other.as_ref()), "no message");
    }
}
