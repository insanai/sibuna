//! Graceful shutdown on SIGINT and SIGTERM.
//!
//! The standard library has no signal API, so this module declares the few POSIX functions
//! it needs from the C library that `std` already links. Rather than running code in a
//! signal handler, it blocks both signals in the calling thread (every thread spawned later
//! inherits the mask) and dedicates one thread to `sigwait`. That thread runs ordinary
//! Rust: it records the request in a [`Shutdown`] and wakes whoever waits on it. Every
//! descriptor operation, join and storage flush then happens on normal threads, as the Zig
//! daemon's handler-sets-a-flag design required.
//!
//! [`install`] must run before any other thread is spawned, so that no thread can receive
//! the signals with their default (terminating) disposition.

// The only unsafe code in the daemon: calls into the C library's signal functions, which
// `std` does not wrap. Each block states why the call is sound.
#![allow(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex, PoisonError};

/// A one-way stop request that threads can wait for.
#[derive(Debug, Default)]
pub struct Shutdown {
    requested: Mutex<bool>,
    wake: Condvar,
}

impl Shutdown {
    /// Returns a shutdown that has not been requested.
    pub fn new() -> Arc<Shutdown> {
        Arc::new(Shutdown::default())
    }

    /// Requests the stop and wakes every waiter. Requesting twice is harmless.
    pub fn request(&self) {
        *self.requested.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.wake.notify_all();
    }

    /// Returns true once a stop was requested.
    pub fn is_requested(&self) -> bool {
        *self.requested.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Blocks until a stop is requested.
    pub fn wait(&self) {
        let mut requested = self.requested.lock().unwrap_or_else(PoisonError::into_inner);
        while !*requested {
            requested = self.wake.wait(requested).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Why the signal waiter could not be installed.
#[derive(Debug)]
pub enum SignalError {
    /// `sigprocmask`-style blocking failed with this error number.
    Mask(i32),
    /// The waiter thread could not be spawned.
    Thread(std::io::Error),
}

impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalError::Mask(errno) => write!(f, "blocking SIGINT and SIGTERM failed ({errno})"),
            SignalError::Thread(error) => write!(f, "cannot start the signal thread: {error}"),
        }
    }
}

impl std::error::Error for SignalError {}

/// Blocks SIGINT and SIGTERM in the calling thread and starts a thread that waits for them
/// and calls [`Shutdown::request`] on `shutdown` for each one.
///
/// Call it from the main thread before spawning any other thread. On platforms without
/// the declarations below it does nothing and the signals keep their default action.
///
/// Fails with [`SignalError`] when the mask cannot be set or the thread cannot start.
pub fn install(shutdown: Arc<Shutdown>) -> Result<(), SignalError> {
    imp::block()?;
    std::thread::Builder::new()
        .name("sibuna-signals".into())
        .spawn(move || {
            while imp::wait() {
                shutdown.request();
            }
        })
        .map_err(SignalError::Thread)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use std::ffi::c_int;

    use super::SignalError;

    /// `sigset_t`: 1,024 bits with glibc and musl on Linux, 32 bits on macOS. The larger
    /// size is safe on both, because the functions write at most their own size.
    #[repr(C)]
    struct SigSet {
        bits: [u64; 16],
    }

    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;
    #[cfg(target_os = "linux")]
    const SIG_BLOCK: c_int = 0;
    #[cfg(target_os = "macos")]
    const SIG_BLOCK: c_int = 1;

    unsafe extern "C" {
        fn sigemptyset(set: *mut SigSet) -> c_int;
        fn sigaddset(set: *mut SigSet, signal: c_int) -> c_int;
        fn pthread_sigmask(how: c_int, set: *const SigSet, old: *mut SigSet) -> c_int;
        fn sigwait(set: *const SigSet, signal: *mut c_int) -> c_int;
    }

    /// The set {SIGINT, SIGTERM}.
    fn stop_signals() -> SigSet {
        let mut set = SigSet { bits: [0; 16] };
        // SAFETY: `set` is a valid, writable `sigset_t`-sized buffer owned by this frame;
        // both functions only write inside it and cannot fail for these signal numbers.
        unsafe {
            sigemptyset(&mut set);
            sigaddset(&mut set, SIGINT);
            sigaddset(&mut set, SIGTERM);
        }
        set
    }

    pub(super) fn block() -> Result<(), SignalError> {
        let set = stop_signals();
        // SAFETY: `set` is an initialised signal set and the old-mask pointer may be null;
        // `pthread_sigmask` changes only the calling thread's mask.
        let status = unsafe { pthread_sigmask(SIG_BLOCK, &set, std::ptr::null_mut()) };
        if status == 0 { Ok(()) } else { Err(SignalError::Mask(status)) }
    }

    /// Waits for SIGINT or SIGTERM; returns false only if waiting failed.
    pub(super) fn wait() -> bool {
        let set = stop_signals();
        let mut received: c_int = 0;
        // SAFETY: `set` is an initialised signal set blocked in every thread (see `block`),
        // and `received` is a valid place for the signal number.
        let status = unsafe { sigwait(&set, &mut received) };
        status == 0
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use super::SignalError;

    pub(super) fn block() -> Result<(), SignalError> {
        Ok(())
    }

    pub(super) fn wait() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_wakes_every_waiter() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.is_requested());
        std::thread::scope(|scope| {
            for _ in 0..3 {
                scope.spawn(|| shutdown.wait());
            }
            shutdown.request();
        });
        assert!(shutdown.is_requested());
    }
}
