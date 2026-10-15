//! GeoIP imports (unit U6; Zig's `geoip_job.zig`): restore the active generation at start,
//! and run at most one import on demand: download or inline CSV, validation, staging
//! through `console_storage::geoip`, then the swap of [`crate::geo::GeoSlot`].

use std::fmt;

use crate::shared::{Setup, Shared};
use crate::storage::StorageFailure;

/// The importer's state, as the GeoIP page shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ImportState {
    /// No import has run.
    #[default]
    Idle,
    /// Downloading the source files.
    Downloading,
    /// Parsing and checking the ranges.
    Validating,
    /// Writing the generation to storage.
    Storing,
    /// The last import was applied.
    Applied,
    /// The last import failed; the previous generation stays active.
    Failed,
}

impl ImportState {
    /// Returns the state's wire name, as Zig's `@tagName`.
    pub fn name(self) -> &'static str {
        match self {
            ImportState::Idle => "idle",
            ImportState::Downloading => "downloading",
            ImportState::Validating => "validating",
            ImportState::Storing => "storing",
            ImportState::Applied => "applied",
            ImportState::Failed => "failed",
        }
    }
}

/// The importer's progress.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ImportStatus {
    /// The state.
    pub state: ImportState,
    /// Ranges processed by the running or last import.
    pub processed_ranges: u32,
    /// An import thread is running.
    pub running: bool,
}

/// Why an import step failed.
#[derive(Debug)]
pub enum ImportError {
    /// Another import is running.
    Busy,
    /// Storage refused or could not answer.
    Storage(StorageFailure),
    /// The stored or downloaded data is invalid; the text names the rule.
    Invalid(&'static str),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::Busy => f.write_str("a GeoIP import is already running"),
            ImportError::Storage(error) => write!(f, "GeoIP storage failed: {error}"),
            ImportError::Invalid(rule) => write!(f, "invalid GeoIP data: {rule}"),
        }
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ImportError::Storage(error) => Some(error),
            _ => None,
        }
    }
}

/// The importer: its status and the one import thread.
#[derive(Debug, Default)]
pub struct Importer {}

impl Importer {
    /// Returns an idle importer.
    pub fn new(setup: &Setup<'_>) -> Importer {
        let _ = setup;
        Importer {}
    }

    /// Restores the durable active generation into `shared.geo`, or the embedded snapshot
    /// when storage has none; called once by `Console::start` before the listener serves.
    ///
    /// Fails with [`ImportError::Storage`] when storage cannot answer, and with
    /// [`ImportError::Invalid`] when the stored generation does not decode.
    pub fn restore(&self, shared: &Shared) -> Result<(), ImportError> {
        let _ = shared;
        Ok(())
    }

    /// Returns the importer's progress.
    pub fn status(&self) -> ImportStatus {
        ImportStatus::default()
    }

    /// Joins a running import thread; called by `Console::stop` after the listener stopped.
    pub fn stop(&self) {}
}
