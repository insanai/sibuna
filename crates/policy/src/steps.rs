//! Work accounting for the bounded-work fuzz tests.
//!
//! The inspection loops whose cost is not obviously one step per input byte (literal
//! searches, tag and command comparisons, boundary searches) report their iterations here.
//! The fuzz tests assert that the total stays within a fixed multiple of the input length.
//! Outside `cfg(test)` the counter does not exist and `count` compiles to nothing.

#[cfg(test)]
thread_local! {
    static STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Records `amount` units of work on this thread (test builds only).
#[inline(always)]
pub(crate) fn count(amount: u64) {
    #[cfg(test)]
    STEPS.with(|steps| steps.set(steps.get().saturating_add(amount)));
    #[cfg(not(test))]
    let _ = amount;
}

/// Returns the work recorded on this thread since the last call and resets it.
#[cfg(test)]
pub(crate) fn take() -> u64 {
    STEPS.with(|steps| steps.replace(0))
}
