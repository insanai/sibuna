//! Configuration, command-line parsing, diagnostics, metrics and incident types for the
//! Sibuna daemon.
//!
//! This is the one application-level crate every other application crate may depend on.
//! It depends on no workspace crate itself, and on no external crate.
//!
//! - [`Config`] holds every daemon option with the Zig daemon's defaults;
//!   [`Config::parse_args`] fills it from a command line and rejects it with an
//!   [`ArgError`] that renders as the `INVALID COMMAND LINE` diagnostic.
//! - [`diagnostic`] renders Elm-style diagnostics; [`errors`] holds the explanations the
//!   daemon sends to clients.
//! - [`Metrics`] holds the request-path counters and writes them for Prometheus.
//! - [`Incident`] and [`incident_heads`] describe incidents and capture redacted heads.
//! - [`log`] formats leveled log lines into a sink the caller owns.
//!
//! ```
//! use sibuna_core::{ArgErrorKind, Config, Mode};
//!
//! let config = Config::parse_args(&["--port", "9090", "-m", "auth"]).unwrap();
//! assert_eq!((config.listen_port, config.mode), (9090, Mode::ForwardAuth));
//!
//! let error = Config::parse_args(&["--cluster-peer", "1@h:9901"]).unwrap_err();
//! assert_eq!(error.kind, ArgErrorKind::RemovedOption);
//! assert!(error.to_string().starts_with("-- INVALID COMMAND LINE ---"));
//! ```
//!
//! # Changes from the Zig version
//!
//! `libs/core/src` of the Zig repository is the specification. The port differs
//! deliberately as follows.
//!
//! - Storage options follow SID 0011. `--data-dir` now selects SQLite; `--database-url`
//!   and `--database-url-file` select PostgreSQL and require `--cluster-node`; a database
//!   URL beside `--data-dir` is rejected. The Zaxonlite options `--cluster-listen`,
//!   `--cluster-peer`, `--cluster-secret-file` and `--cluster-tls-{cert,key,ca}` fail with
//!   [`ArgErrorKind::RemovedOption`], whose hint names SID 0011. With `--cluster-peer` gone,
//!   so are `max_cluster_peers` and the `TooManyPeers` error. `cluster_node` is an
//!   `Option<u32>` so that "not given" can be checked; [`Config::node_id`] gives Zig's 0.
//! - Command-line parsing returns `Result<Config, ArgError>` instead of an error code plus
//!   an out-parameter `Diagnostic`. `ArgError` carries the same option, value and expected
//!   text, and its `Display` is the daemon's report, so the hint table moved here from the
//!   daemon. The report is not cut at 1,024 bytes as Zig's fixed buffer cut it. A rejected
//!   database URL is shown as `[redacted]`, and `Debug` of a `Config` hides the seed and the
//!   URL. Strings are owned, so a `Config` has no lifetime.
//! - `explainError(anyerror)` became [`errors::ErrorKind::explain`] over an enum, plus
//!   [`errors::explain_name`] for errors known only by name; the module documents why.
//! - Counters are a [`Counter`] newtype over `AtomicU64` with `bump`, `add` and `value`
//!   instead of a static `Metrics.bump(&counter)`, and each sits on its own 128-byte line
//!   (measured faster under 16 threads; see [`metrics`]).
//! - Header capture matches names folded to lower case against fixed patterns, and checks
//!   the kept list before the credential scan; the output is unchanged (a differential test
//!   compares it with Zig's list-by-list rules).
//! - Incident fields taken off the wire are byte slices; [`incident_heads::request_head`]
//!   takes the request line and an iterator of `(name, value)` pairs instead of `anytype`.
//!   [`incident_heads::Head::len`] is a `usize`.
//! - `Lock` (a spin-then-park mutex) is gone: `std::sync::Mutex` is the same adaptive
//!   futex design (it spins briefly, then parks), so crates use it directly (SID 0010).
//! - `log` no longer prints: [`log::write_line`] writes the same `[LEVEL] message` line into
//!   a sink the daemon provides.
//! - The `time` constants are gone; `std::time::Duration` replaces them.
//! - `Config::default()` became the `Default` trait; `parseArgs` and `parseArgsDiagnosed`
//!   became [`Config::parse_args`]; the cross-option storage rule is
//!   [`Config::check_storage`]. The help text ([`config::HELP`]) and the banner
//!   ([`Config::write_banner`]) moved here from the daemon so they stay beside the options;
//!   the banner's storage line names SQLite or PostgreSQL instead of Zaxonlite.

pub mod config;
pub mod diagnostic;
pub mod errors;
pub mod incident;
pub mod incident_heads;
pub mod log;
pub mod metrics;

pub use config::{
    ArgError, ArgErrorKind, Config, Mode, PowAlgorithm, StorageBackend, TokenScheme,
};
pub use diagnostic::Diagnostic;
pub use errors::ErrorKind;
pub use incident::{Evidence, Incident};
pub use metrics::{Counter, Metrics};

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    /// Zig's `Lock` test, run against `std::sync::Mutex`, which replaces it: eight threads
    /// do a non-atomic read-modify-write under the lock, yielding inside the critical
    /// section now and then so waiters must park. No update may be lost.
    #[test]
    fn the_lock_excludes_concurrent_writers_and_parks_waiters_past_the_spin_limit() {
        let count = Mutex::new(0u64);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..20_000 {
                        let mut guard = count.lock().unwrap();
                        let seen = *guard;
                        if seen.is_multiple_of(4096) {
                            std::thread::yield_now();
                        }
                        *guard = seen + 1;
                    }
                });
            }
        });
        assert_eq!(*count.lock().unwrap(), 8 * 20_000);
        assert!(count.try_lock().is_ok());
    }

    #[test]
    fn core_sanity() {
        assert_eq!(std::time::Duration::from_secs(1).as_nanos(), 1_000_000_000);
    }
}
