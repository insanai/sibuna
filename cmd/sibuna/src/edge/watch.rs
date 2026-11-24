//! Where the topology comes from, and the optional watcher of its file (SID 0018).
//!
//! Every load records the stamp of the file it read. The watcher loads only a file whose
//! stamp differs from that record and has been the same for two looks, so one edit causes
//! one reload, whoever asked for it, and a half-written file is left alone.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use super::Revision;

/// The modification time and the length of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Stamp {
    modified: Option<SystemTime>,
    length: u64,
}

fn stamp(path: &str) -> Option<Stamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(Stamp { modified: metadata.modified().ok(), length: metadata.len() })
}

/// The file of the topology, or none for a daemon started by `sibuna lb`.
pub(super) struct Source {
    path: Option<String>,
    loaded: Mutex<Option<Stamp>>,
}

impl Source {
    /// The topology of the file at `path`.
    pub fn file(path: &str) -> Self {
        Self { path: Some(path.to_owned()), loaded: Mutex::new(None) }
    }

    /// The topology of a quick start. It cannot be loaded again.
    pub fn quick_start() -> Self {
        Self { path: None, loaded: Mutex::new(None) }
    }

    /// The path of the file, if there is one.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Reads, compiles and checks the file, and records its stamp even when the file is
    /// rejected. Fails with the reason, or because there is no file.
    pub fn load(&self) -> io::Result<Revision> {
        let Some(path) = &self.path else {
            return Err(io::Error::other(
                "the daemon was started by `sibuna lb` and has no file to reload",
            ));
        };
        // The stamp is taken first. A write during the load then shows as a new stamp.
        *self.loaded.lock().unwrap_or_else(PoisonError::into_inner) = stamp(path);
        super::load(path)
    }

    fn loaded(&self) -> Option<Stamp> {
        *self.loaded.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether the watcher loads now: the file exists, differs from the last load and did
/// not change since the previous look.
fn due(loaded: Option<Stamp>, previous: Option<Stamp>, now: Option<Stamp>) -> bool {
    now.is_some() && now != loaded && now == previous
}

/// The watcher thread and its interval. The thread starts with the first interval and
/// then stays, idle while the interval is off.
pub(super) struct Watcher {
    /// Milliseconds between looks. Zero turns the watcher off.
    interval: Arc<AtomicU64>,
    started: AtomicBool,
}

impl Watcher {
    /// A watcher that is off.
    pub fn new() -> Self {
        Self { interval: Arc::new(AtomicU64::new(0)), started: AtomicBool::new(false) }
    }

    /// The interval in use, if the watcher is on.
    pub fn interval(&self) -> Option<Duration> {
        let millis = self.interval.load(Ordering::Relaxed);
        (millis > 0).then(|| Duration::from_millis(millis))
    }

    /// Sets the interval of `global.watch`. On every due look the watcher calls `offer`,
    /// which loads the source and hands the revision to the worker. Fails when the
    /// thread cannot start.
    pub fn set(
        &self,
        interval: Option<Duration>,
        source: &Arc<Source>,
        offer: impl Fn(&Source) + Send + 'static,
    ) -> io::Result<()> {
        let millis = interval.map_or(0, |interval| interval.as_millis() as u64);
        self.interval.store(millis, Ordering::Relaxed);
        if millis == 0 || self.started.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        let (interval, source) = (Arc::clone(&self.interval), Arc::clone(source));
        std::thread::Builder::new()
            .name("edge-watch".into())
            .spawn(move || watch(&interval, &source, offer))
            .map(drop)
    }
}

fn watch(interval: &AtomicU64, source: &Source, offer: impl Fn(&Source)) {
    let Some(path) = source.path() else { return };
    let mut previous = None;
    loop {
        let millis = interval.load(Ordering::Relaxed);
        if millis == 0 {
            previous = None;
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        std::thread::sleep(Duration::from_millis(millis));
        let now = stamp(path);
        if due(source.loaded(), previous, now) {
            offer(source);
        }
        previous = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_watcher_waits_for_a_new_and_stable_stamp() {
        let at = |length| Some(Stamp { modified: None, length });
        // Nothing changed since the load.
        assert!(!due(at(1), at(1), at(1)));
        // The file changed between two looks: an editor may still be writing.
        assert!(!due(at(1), at(1), at(2)));
        // It is the same at the next look.
        assert!(due(at(1), at(2), at(2)));
        // A load, accepted or rejected, records the stamp, so nothing is due again.
        assert!(!due(at(2), at(2), at(2)));
        // A file that is absent is never loaded.
        assert!(!due(at(1), None, None));
    }
}
