//! Console-only challenge observations: fixed counters, no allocation.
//!
//! Producers on the request path only increment counters. Authenticated challenge
//! parameters select a bin; client metadata never does, so a client cannot create state.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// The proof-of-work algorithm of a challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    /// Hashcash.
    Hashcash = 0,
    /// Cohen-Pietrzak proof of sequential work.
    Posw = 1,
}

/// Why a challenge submission was refused, in the console protocol's numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cause {
    /// The client address is banned.
    AddressBanned = 0,
    /// The submission body exceeds the limit.
    BodyTooLarge,
    /// The submission names no challenge.
    MissingId,
    /// The solution cannot be parsed.
    MalformedSolution,
    /// The challenge identifier cannot be parsed.
    MalformedChallenge,
    /// The challenge identifier failed authentication.
    InvalidTag,
    /// The challenge expired.
    Expired,
    /// The client does not match the challenge binding.
    FingerprintMismatch,
    /// The hashcash difficulty is not met.
    DifficultyNotMet,
    /// The proof of sequential work does not verify.
    InvalidProof,
    /// The solution is of the wrong kind for the challenge.
    WrongSolutionType,
    /// The challenge was already spent.
    Replay,
    /// The spent set had no room.
    Capacity,
}

/// The number of [`Cause`] values.
pub const CAUSE_COUNT: usize = 13;
/// The number of parameter bins: two algorithms, 32 parameter bins, 4 opening bins.
pub const BIN_COUNT: usize = 256;
/// The number of solve-time histogram buckets.
pub const BUCKET_COUNT: usize = 16;
/// The largest solve time, in milliseconds, that counts as valid (one hour).
const MAX_VALID_MS: f64 = 3_600_000.0;

/// The solve time a client reported with its solution.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Timing {
    /// No time was reported.
    Missing,
    /// The report could not be used.
    Invalid,
    /// The reported time in milliseconds; validated by [`Metrics::accept`].
    Milliseconds(f64),
}

/// The solver implementation a client reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Solver {
    /// Not reported or not recognised.
    Unknown,
    /// The WebAssembly solver.
    Wasm,
    /// The JavaScript fallback.
    Javascript,
}

/// The counters of one parameter bin.
#[derive(Debug)]
pub struct Bin {
    /// Challenges issued.
    pub issued: AtomicU64,
    /// Solutions accepted.
    pub accepted: AtomicU64,
    /// Accepted solutions by solve-time bucket (see [`bucket`]).
    pub buckets: [AtomicU64; BUCKET_COUNT],
    /// Accepted solutions without a reported time.
    pub missing: AtomicU64,
    /// Accepted solutions with an unusable reported time.
    pub invalid: AtomicU64,
    /// Accepted solutions from the WebAssembly solver.
    pub wasm: AtomicU64,
    /// Accepted solutions from the JavaScript solver.
    pub javascript: AtomicU64,
    /// Accepted solutions from an unreported solver.
    pub unknown_solver: AtomicU64,
}

impl Bin {
    /// Returns a bin with every counter at zero.
    const fn new() -> Bin {
        Bin {
            issued: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            buckets: [const { AtomicU64::new(0) }; BUCKET_COUNT],
            missing: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            wasm: AtomicU64::new(0),
            javascript: AtomicU64::new(0),
            unknown_solver: AtomicU64::new(0),
        }
    }
}

/// Challenge counters for the console; about 47 KiB, all relaxed atomics.
///
/// Every counter uses `Relaxed` ordering: each is an independent monotonic count, and
/// readers want a recent value of each, not a snapshot across counters.
#[derive(Debug)]
pub struct Metrics {
    /// Solutions submitted.
    pub submitted: AtomicU64,
    /// Refused submissions by [`Cause`].
    pub causes: [AtomicU64; CAUSE_COUNT],
    /// Per-parameter counters, indexed by [`index`].
    pub bins: [Bin; BIN_COUNT],
    /// The parameters of the last issued challenge: algorithm in bits 0..8, parameter in
    /// bits 8..16, openings in bits 16..24, and bit 24 set once anything was issued.
    pub last_parameters: AtomicU32,
}

impl Metrics {
    /// Returns metrics with every counter at zero.
    pub const fn new() -> Self {
        Self {
            submitted: AtomicU64::new(0),
            causes: [const { AtomicU64::new(0) }; CAUSE_COUNT],
            bins: [const { Bin::new() }; BIN_COUNT],
            last_parameters: AtomicU32::new(0),
        }
    }

    /// Counts an issued challenge and remembers its parameters.
    pub fn issue(&self, algorithm: Algorithm, parameter: u8, openings: u8) {
        self.bins[index(algorithm, parameter, openings)].issued.fetch_add(1, Ordering::Relaxed);
        let encoded = u32::from(algorithm as u8)
            | (u32::from(parameter) << 8)
            | (u32::from(openings) << 16)
            | (1 << 24);
        self.last_parameters.store(encoded, Ordering::Relaxed);
    }

    /// Counts a refused submission.
    pub fn reject(&self, cause: Cause) {
        self.causes[cause as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts an accepted solution with its reported solve time and solver.
    ///
    /// A reported time that is not finite, negative or above one hour counts as invalid.
    pub fn accept(
        &self,
        algorithm: Algorithm,
        parameter: u8,
        openings: u8,
        timing: Timing,
        solver: Solver,
    ) {
        let bin = &self.bins[index(algorithm, parameter, openings)];
        let counter = match timing {
            Timing::Missing => &bin.missing,
            Timing::Milliseconds(ms) if ms.is_finite() && (0.0..=MAX_VALID_MS).contains(&ms) => {
                &bin.buckets[bucket(ms)]
            }
            Timing::Milliseconds(_) | Timing::Invalid => &bin.invalid,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let by_solver = match solver {
            Solver::Wasm => &bin.wasm,
            Solver::Javascript => &bin.javascript,
            Solver::Unknown => &bin.unknown_solver,
        };
        by_solver.fetch_add(1, Ordering::Relaxed);
        bin.accepted.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the bin of a parameter set: 32 parameter bins of width eight and four opening
/// bins of width sixteen per algorithm. Hashcash has no openings and always uses opening
/// bin zero; the last opening bin is saturated. The result is below [`BIN_COUNT`].
pub fn index(algorithm: Algorithm, parameter: u8, openings: u8) -> usize {
    let opening = match algorithm {
        Algorithm::Hashcash => 0,
        Algorithm::Posw => usize::from(openings / 16).min(3),
    };
    usize::from(algorithm as u8) * 128 + usize::from(parameter / 8) * 4 + opening
}

/// Returns the solve-time bucket of `ms`: bucket 0 holds times below 1 ms, bucket `k`
/// times in `[2^(k-1), 2^k)` ms, and bucket 15 everything from 16,384 ms. A NaN or
/// negative time falls in bucket 0; callers validate times first.
pub fn bucket(ms: f64) -> usize {
    let mut result = 0;
    let mut boundary = 1.0;
    while result < BUCKET_COUNT - 1 && ms >= boundary {
        result += 1;
        boundary *= 2.0;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_timing_partitions_parameters_and_covers_every_histogram_boundary() {
        assert_eq!(bucket(0.5), 0);
        let mut boundary = 1.0;
        for expected in 1..16 {
            assert_eq!(bucket(boundary), expected);
            boundary *= 2.0;
        }
        assert_eq!(bucket(3_600_000.0), 15);
        let metrics = Metrics::new();
        metrics.accept(Algorithm::Posw, 13, 16, Timing::Milliseconds(8.0), Solver::Wasm);
        metrics.accept(Algorithm::Posw, 13, 16, Timing::Milliseconds(f64::NAN), Solver::Unknown);
        metrics.accept(Algorithm::Posw, 13, 16, Timing::Missing, Solver::Javascript);
        let bin = &metrics.bins[index(Algorithm::Posw, 13, 16)];
        assert_eq!(bin.buckets[4].load(Ordering::Relaxed), 1);
        assert_eq!(bin.invalid.load(Ordering::Relaxed), 1);
        assert_eq!(bin.missing.load(Ordering::Relaxed), 1);
        assert_eq!(bin.accepted.load(Ordering::Relaxed), 3);
        assert_ne!(index(Algorithm::Hashcash, 13, 0), index(Algorithm::Posw, 13, 16));
    }

    #[test]
    fn every_parameter_set_has_a_bin_and_issue_records_parameters() {
        for algorithm in [Algorithm::Hashcash, Algorithm::Posw] {
            for parameter in 0..=u8::MAX {
                for openings in [0, 15, 16, 63, 64, u8::MAX] {
                    assert!(index(algorithm, parameter, openings) < BIN_COUNT);
                }
            }
        }
        let metrics = Metrics::new();
        metrics.issue(Algorithm::Posw, 13, 32);
        metrics.reject(Cause::Replay);
        assert_eq!(
            metrics.last_parameters.load(Ordering::Relaxed),
            1 | 13 << 8 | 32 << 16 | 1 << 24
        );
        assert_eq!(metrics.causes[Cause::Replay as usize].load(Ordering::Relaxed), 1);
        assert_eq!(Cause::Capacity as usize + 1, CAUSE_COUNT);
        for ms in [-1.0, f64::NEG_INFINITY, f64::INFINITY, 3_600_000.5] {
            metrics.accept(Algorithm::Hashcash, 0, 0, Timing::Milliseconds(ms), Solver::Wasm);
        }
        let bin = &metrics.bins[index(Algorithm::Hashcash, 0, 0)];
        assert_eq!(bin.invalid.load(Ordering::Relaxed), 4);
        assert_eq!(bucket(f64::NAN), 0);
        assert_eq!(bucket(-5.0), 0);
    }
}
