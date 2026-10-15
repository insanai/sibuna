//! GeoIP imports (unit U6; Zig's `geoip_job.zig`): restore the active generation at start,
//! and run at most one import on demand: download or inline CSV, validation, staging
//! through `console_storage::geoip`, then the swap of [`crate::geo::GeoSlot`].
//!
//! An import is one joined thread that owns its inputs and its staged generation. It stages
//! the generation in storage (`begin_generation`, `store_chunk` per 100 ranges,
//! `activate_generation`, S12) and only then makes it the active generation of this
//! console: durable publication precedes the in-memory swap, and a failure at any step
//! leaves the previous generation active. Startup restores only the durable active
//! generation; an unfinished staging is invisible.
//!
//! # Changes from Zig
//!
//! - The import thread holds clones of what it needs (the storage handle, the GeoIP slot,
//!   the clock) and the slot's import claim, which ends the import when dropped; Zig's
//!   `begin`/`end` pair and the `errdefer` around the thread are gone.
//! - Restore reads up to 64 chunks per transaction (Zig read one per call); the import
//!   thread runs one background storage job at a time.
//! - An operator checksum must be 64 hex digits, where Zig checked only the length; a
//!   request whose field exceeds its bound answers 400, where Zig answered 503.
//! - Stopping cancels the import: every download step blocks at most 250 ms before it
//!   checks the cancellation, and storage steps check it between jobs.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use sibuna_console_protocol::Text;
use sibuna_console_protocol::geo::{self, Activate, Authorization, Batch, Begin, Metadata, Read};
use sibuna_console_storage::access::Credential;
use sibuna_console_storage::geoip::{
    MAX_CHUNKS, activate_generation, begin_generation, metadata, read_chunk, store_chunk,
};
use sibuna_crypto::{ct, sha256::Sha256};
use sibuna_geoip::wire::{self, BATCH_BYTES, BATCH_ROWS, ROW_BYTES};
use sibuna_geoip::{
    Compression, Database, Loader, MAX_RANGES, Provenance, Provider, Range, Version, gzip,
};
use sibuna_serve::stack;

use super::download::{self, MAX_SOURCE_BYTES};
use super::embedded;
use super::slot::{GeoSlot, ImportClaim};
use crate::clock::Clock;
use crate::notify::delivery::SystemTrust;
use crate::notify::wait_for;
use crate::shared::{Setup, Shared};
use crate::storage::{ConsoleStorage, StorageFailure};

/// The largest inline CSV an import accepts.
pub const MAX_CSV: usize = 8192;
/// Chunks read per storage transaction while restoring.
const RESTORE_CHUNKS: u32 = 64;

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
    const ALL: [ImportState; 6] = [
        ImportState::Idle,
        ImportState::Downloading,
        ImportState::Validating,
        ImportState::Storing,
        ImportState::Applied,
        ImportState::Failed,
    ];

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
    /// The import thread could not start.
    Spawn(std::io::Error),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::Busy => f.write_str("a GeoIP import is already running"),
            ImportError::Storage(error) => write!(f, "GeoIP storage failed: {error}"),
            ImportError::Invalid(rule) => write!(f, "invalid GeoIP data: {rule}"),
            ImportError::Spawn(error) => write!(f, "cannot start the GeoIP import: {error}"),
        }
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ImportError::Storage(error) => Some(error),
            ImportError::Spawn(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageFailure> for ImportError {
    fn from(failure: StorageFailure) -> ImportError {
        ImportError::Storage(failure)
    }
}

/// What the administrator asked to import, checked by the route.
#[derive(Debug)]
pub struct ImportRequest {
    /// The administrator's credential, rechecked by every storage step.
    pub credential: Credential,
    /// The same credential in the protocol's form.
    pub auth: Authorization,
    /// The active revision the administrator saw.
    pub expected_revision: u64,
    /// The publisher.
    pub provider: Provider,
    /// The publisher's version, valid for the provider.
    pub version: String,
    /// The operator's expected generation digest as 64 hex digits, or empty.
    pub checksum: String,
    /// Inline CSV rows (at most [`MAX_CSV`] bytes) instead of a download, or empty.
    pub csv: Vec<u8>,
}

impl Drop for ImportRequest {
    fn drop(&mut self) {
        ct::zeroize(&mut self.credential.digest);
        ct::zeroize(&mut self.auth.session_digest);
    }
}

/// The active generation's metadata as the GeoIP page shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shown {
    /// The metadata; all empty when no generation is loaded.
    pub metadata: Metadata,
    /// The embedded build snapshot serves lookups.
    pub embedded: bool,
}

/// State shared by the importer and its thread.
#[derive(Debug, Default)]
struct Progress {
    /// An [`ImportState`] index. Release on store, Acquire on load.
    state: AtomicU8,
    /// Ranges processed. Relaxed: a progress figure only.
    processed: AtomicU32,
    /// An import thread is running. Release on store, Acquire on load.
    running: AtomicBool,
    /// Set by [`Importer::stop`]; the thread stops at its next step. Release/Acquire.
    cancel: AtomicBool,
    shown: Mutex<Shown>,
    trust: SystemTrust,
}

impl Progress {
    fn set(&self, state: ImportState) {
        let index = ImportState::ALL.iter().position(|&known| known == state).unwrap_or(0);
        self.state.store(u8::try_from(index).unwrap_or(0), Ordering::Release);
    }

    fn state(&self) -> ImportState {
        let index = usize::from(self.state.load(Ordering::Acquire));
        ImportState::ALL.get(index).copied().unwrap_or_default()
    }

    fn is_canceled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    fn show(&self, shown: Shown) {
        *self.shown.lock().unwrap_or_else(PoisonError::into_inner) = shown;
    }
}

/// The importer: its status and the one import thread.
#[derive(Debug, Default)]
pub struct Importer {
    progress: Arc<Progress>,
    thread: Mutex<Option<JoinHandle<()>>>,
    embedded: Option<&'static [u8]>,
}

impl Importer {
    /// Returns an idle importer that restores the embedded snapshot `embedded` (decision
    /// 7) when storage holds no generation.
    pub fn with_embedded(setup: &Setup<'_>, embedded: Option<&'static [u8]>) -> Importer {
        let _ = setup;
        Importer { embedded, ..Importer::default() }
    }

    /// Restores the durable active generation into `shared.geo`, or the embedded snapshot
    /// when storage has none; called once by `Console::start` before the listener serves.
    ///
    /// Fails with [`ImportError::Storage`] when storage cannot answer, and with
    /// [`ImportError::Invalid`] when the stored generation or the embedded snapshot does
    /// not decode.
    pub fn restore(&self, shared: &Shared) -> Result<(), ImportError> {
        let active = shared.storage.transact(|tx| Box::pin(metadata(tx)))?;
        if active.ranges == 0 {
            return self.restore_embedded(shared, active.revision);
        }
        let database = load_generation(&shared.storage, &active)?;
        shared.geo.restore(database, active.revision, false);
        self.progress.show(Shown { metadata: active, embedded: false });
        Ok(())
    }

    fn restore_embedded(&self, shared: &Shared, revision: u64) -> Result<(), ImportError> {
        let Some(bytes) = self.embedded else { return Ok(()) };
        let loaded =
            embedded::load(bytes).map_err(|_| ImportError::Invalid("embedded snapshot"))?;
        let Some(database) = loaded else { return Ok(()) };
        let metadata = embedded::metadata(&database, revision);
        shared.geo.restore(database, revision, true);
        self.progress.show(Shown { metadata, embedded: true });
        Ok(())
    }

    /// Returns the importer's progress.
    pub fn status(&self) -> ImportStatus {
        ImportStatus {
            state: self.progress.state(),
            processed_ranges: self.progress.processed.load(Ordering::Relaxed),
            running: self.progress.running.load(Ordering::Acquire),
        }
    }

    /// Returns the active generation's metadata as this console restored or imported it.
    pub fn shown(&self) -> Shown {
        self.progress.shown.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Starts importing `request` on its own thread and returns at once.
    ///
    /// Fails with [`ImportError::Invalid`] for a version the provider does not use, a
    /// checksum that is not 64 hex digits or a CSV over [`MAX_CSV`] bytes; with
    /// [`ImportError::Busy`] while an import runs; and with [`ImportError::Spawn`].
    pub fn start(&self, shared: &Shared, request: ImportRequest) -> Result<(), ImportError> {
        check_request(&request)?;
        let mut thread = self.thread.lock().unwrap_or_else(PoisonError::into_inner);
        if self.progress.running.load(Ordering::Acquire) {
            return Err(ImportError::Busy);
        }
        let claim = shared.geo.begin_import().map_err(|_| ImportError::Busy)?;
        if let Some(finished) = thread.take() {
            // The previous import has ended (`running` is false); joining is immediate.
            let _ = finished.join();
        }
        self.progress.processed.store(0, Ordering::Relaxed);
        self.progress.set(ImportState::Validating);
        self.progress.running.store(true, Ordering::Release);
        let job = Job {
            storage: shared.storage.clone(),
            geo: Arc::clone(&shared.geo),
            clock: Arc::clone(&shared.clock),
            progress: Arc::clone(&self.progress),
            request,
        };
        let usable = usize::try_from(shared.config.budget.stack_bytes).unwrap_or(stack::USABLE);
        let spawned = std::thread::Builder::new()
            .name("sibuna-console-geoip".into())
            .stack_size(stack::bytes(usable))
            .spawn(move || job.run(claim));
        match spawned {
            Ok(handle) => {
                *thread = Some(handle);
                Ok(())
            }
            Err(error) => {
                self.progress.running.store(false, Ordering::Release);
                self.progress.set(ImportState::Failed);
                Err(ImportError::Spawn(error))
            }
        }
    }

    /// Asks a running import to stop and joins its thread; called by `Console::stop`
    /// after the listener stopped.
    pub fn stop(&self) {
        self.progress.cancel.store(true, Ordering::Release);
        let handle = self.thread.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(handle) = handle {
            // A panicked import has already ended; its claim was dropped with it.
            let _ = handle.join();
        }
    }
}

fn check_request(request: &ImportRequest) -> Result<(), ImportError> {
    if !request.provider.is_version_valid(&request.version) {
        return Err(ImportError::Invalid("version"));
    }
    let checksum = request.checksum.as_bytes();
    if !(checksum.is_empty()
        || (checksum.len() == 64 && checksum.iter().all(u8::is_ascii_hexdigit)))
    {
        return Err(ImportError::Invalid("checksum"));
    }
    if request.csv.len() > MAX_CSV {
        return Err(ImportError::Invalid("csv"));
    }
    Ok(())
}

/// Reads the active generation `active` back from storage and rebuilds it.
fn load_generation(storage: &ConsoleStorage, active: &Metadata) -> Result<Database, ImportError> {
    let invalid = ImportError::Invalid("stored generation");
    let total = usize::try_from(active.ranges).unwrap_or(usize::MAX);
    if total > MAX_RANGES || active.digest.len() != 64 {
        return Err(invalid);
    }
    let mut digest = [0u8; 32];
    sibuna_encoding::hex::decode_to_slice(active.digest.as_bytes(), &mut digest)
        .map_err(|_| ImportError::Invalid("stored generation"))?;
    let mut ranges: Vec<Range> = Vec::new();
    ranges.try_reserve_exact(total).map_err(|_| ImportError::Invalid("stored generation"))?;
    let mut ordinal = 0;
    while ranges.len() < total {
        if ordinal >= MAX_CHUNKS {
            return Err(ImportError::Invalid("stored generation"));
        }
        let chunks = read_chunks(storage, &active.digest, ordinal, total - ranges.len())?;
        for chunk in &chunks {
            if chunk.is_empty() || chunk.len() % ROW_BYTES != 0 {
                return Err(ImportError::Invalid("stored generation"));
            }
            wire::decode_rows(&mut ranges, total, chunk)
                .map_err(|_| ImportError::Invalid("stored generation"))?;
        }
        ordinal = ordinal.saturating_add(u32::try_from(chunks.len().max(1)).unwrap_or(u32::MAX));
    }
    let provenance = Provenance {
        provider: Provider::parse(active.provider.as_str()).unwrap_or(Provider::Dbip),
        version: Version::new(active.source_version.as_str()).unwrap_or_default(),
        digest,
        file_digests: file_digests(active.source_digests.as_str(), digest)?,
    };
    Database::from_ranges(&ranges, provenance)
        .map_err(|_| ImportError::Invalid("stored generation"))
}

/// Reads up to [`RESTORE_CHUNKS`] chunks from `first` in one transaction, stopping after
/// the chunk that holds the last of `wanted` ranges or at a missing chunk.
fn read_chunks(
    storage: &ConsoleStorage,
    digest: &Text<64>,
    first: u32,
    wanted: usize,
) -> Result<Vec<Vec<u8>>, ImportError> {
    let digest = digest.clone();
    let chunks = storage.transact(move |tx| {
        Box::pin(async move {
            let mut chunks = Vec::new();
            let mut ranges = 0;
            for ordinal in first..first.saturating_add(RESTORE_CHUNKS).min(MAX_CHUNKS) {
                let chunk = read_chunk(tx, &Read { digest: digest.clone(), ordinal }).await?;
                ranges += chunk.len() / ROW_BYTES;
                let last = chunk.is_empty() || ranges >= wanted;
                chunks.push(chunk);
                if last {
                    break;
                }
            }
            Ok(chunks)
        })
    })?;
    Ok(chunks)
}

/// Returns `hex` or `hex:hex`, the generation's source file digests in provider file order.
pub(crate) fn source_digests(database: &Database) -> String {
    let files = usize::from(database.provider().file_count());
    let digests = database.file_digests().iter().take(files);
    let hex: Vec<String> = digests.map(|digest| sibuna_encoding::hex::encode(digest)).collect();
    hex.join(":")
}

/// Parses stored source digests; an empty text falls back to the generation digest for the
/// first file, as Zig did.
fn file_digests(text: &str, fallback: [u8; 32]) -> Result<[[u8; 32]; 2], ImportError> {
    let invalid = || ImportError::Invalid("stored source digests");
    if !geo::valid_source_digests(text) {
        return Err(invalid());
    }
    let mut digests = [fallback, [0; 32]];
    for (slot, hex) in digests.iter_mut().zip(text.split(':').filter(|hex| !hex.is_empty())) {
        sibuna_encoding::hex::decode_to_slice(hex.as_bytes(), slot).map_err(|_| invalid())?;
    }
    Ok(digests)
}

/// Why an import failed; the state shows only `failed`.
#[derive(Debug)]
enum JobError {
    Download,
    Load,
    ChecksumMismatch,
    Storage,
    Conflict,
    Canceled,
}

/// One import, owned by its thread.
struct Job {
    storage: ConsoleStorage,
    geo: Arc<GeoSlot>,
    clock: Arc<dyn Clock>,
    progress: Arc<Progress>,
    request: ImportRequest,
}

impl Job {
    fn run(self, claim: ImportClaim) {
        let result = self.execute(&claim);
        if result.is_err() {
            self.progress.set(ImportState::Failed);
        }
        // The claim ends before `running` clears, so a new import can claim at once.
        drop(claim);
        self.progress.running.store(false, Ordering::Release);
    }

    fn execute(&self, claim: &ImportClaim) -> Result<(), JobError> {
        let staged = self.stage()?;
        let digest = sibuna_encoding::hex::encode(staged.digest());
        let checksum = &self.request.checksum;
        if !checksum.is_empty() && !checksum.eq_ignore_ascii_case(&digest) {
            return Err(JobError::ChecksumMismatch);
        }
        let digest = Text::from_string(digest).map_err(|_| JobError::Load)?;
        let source_digests =
            Text::from_string(source_digests(&staged)).map_err(|_| JobError::Load)?;
        let ranges = u32::try_from(staged.range_count()).map_err(|_| JobError::Load)?;
        self.progress.set(ImportState::Storing);
        let request = &self.request;
        let provider = Text::new(request.provider.name()).map_err(|_| JobError::Load)?;
        let source_version = Text::new(&request.version).map_err(|_| JobError::Load)?;
        let begin = Begin {
            auth: request.auth.clone(),
            expected_revision: request.expected_revision,
            digest: digest.clone(),
            provider: provider.clone(),
            source_version: source_version.clone(),
            source_digests: source_digests.clone(),
            ranges,
        };
        self.call(move |tx, credential, now| {
            Box::pin(async move { begin_generation(tx, &credential, &begin, now).await })
        })?;
        self.store_ranges(&digest, &staged)?;
        let activate = Activate {
            auth: request.auth.clone(),
            expected_revision: request.expected_revision,
            digest: digest.clone(),
        };
        let loaded_at = self.call(move |tx, credential, now| {
            Box::pin(async move { activate_generation(tx, &credential, &activate, now).await })
        })?;
        self.geo
            .activate(claim, staged, request.expected_revision)
            .map_err(|_| JobError::Conflict)?;
        let metadata = Metadata {
            revision: request.expected_revision + 1,
            digest,
            provider,
            source_version,
            source_digests,
            ranges,
            loaded_at,
        };
        self.progress.show(Shown { metadata, embedded: false });
        self.progress.set(ImportState::Applied);
        Ok(())
    }

    /// Runs one storage step with the administrator's credential at the current time.
    fn call<T, F>(&self, step: F) -> Result<T, JobError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(
                &'a mut sibuna_storage::Transaction,
                Credential,
                u64,
            ) -> sibuna_storage::BorrowedFuture<
                'a,
                Result<T, sibuna_console_storage::ConsoleStorageError>,
            > + Clone
            + Send
            + 'static,
    {
        if self.progress.is_canceled() {
            return Err(JobError::Canceled);
        }
        let credential = self.request.credential.clone();
        let now = self.clock.unix_seconds();
        let progress = Arc::clone(&self.progress);
        wait_for(&self.storage, &move || progress.is_canceled(), move |tx| {
            step(tx, credential, now)
        })
        .map_err(|_| JobError::Storage)
    }

    /// Stages the generation from the inline CSV, the provider's archive, or its files.
    fn stage(&self) -> Result<Database, JobError> {
        let request = &self.request;
        let (provider, version) = (request.provider, request.version.as_str());
        if !request.csv.is_empty() {
            return Database::from_csv(provider, version, &request.csv)
                .map_err(|_| JobError::Load);
        }
        if provider.compression() == Compression::Gzip {
            self.progress.set(ImportState::Downloading);
            let trust = &self.progress.trust;
            let canceled = || self.progress.is_canceled();
            let most = gzip::MAX_COMPRESSED_BYTES;
            let bytes = download::fetch(trust, provider, 0, version, most, &canceled)
                .map_err(|_| JobError::Download)?;
            self.progress.set(ImportState::Validating);
            return gzip::decode(provider, version, &bytes, &self.progress.cancel)
                .map_err(|_| JobError::Load);
        }
        self.stage_files(provider, version)
    }

    /// Uncompressed providers publish one file per family with a digest file each; every
    /// file is checked against its publisher digest before a row enters the loader.
    fn stage_files(&self, provider: Provider, version: &str) -> Result<Database, JobError> {
        let trust = &self.progress.trust;
        let canceled = || self.progress.is_canceled();
        let mut loader = Loader::new();
        for file in 0..provider.file_count() {
            if self.progress.is_canceled() {
                return Err(JobError::Canceled);
            }
            self.progress.set(ImportState::Downloading);
            let expected = download::fetch_checksum(trust, provider, file, version, &canceled)
                .map_err(|_| JobError::Download)?;
            let bytes =
                download::fetch(trust, provider, file, version, MAX_SOURCE_BYTES, &canceled)
                    .map_err(|_| JobError::Download)?;
            if !ct::eq(&Sha256::digest(&bytes), &expected) {
                return Err(JobError::ChecksumMismatch);
            }
            self.progress.set(ImportState::Validating);
            loader.feed(&bytes).map_err(|_| JobError::Load)?;
            loader.end_file().map_err(|_| JobError::Load)?;
            let count = u32::try_from(loader.range_count()).unwrap_or(u32::MAX);
            self.progress.processed.store(count, Ordering::Relaxed);
        }
        loader.finish(provider, version).map_err(|_| JobError::Load)
    }

    /// Stores the generation's ranges in chunks of [`BATCH_ROWS`] at consecutive ordinals.
    fn store_ranges(&self, digest: &Text<64>, staged: &Database) -> Result<(), JobError> {
        let mut batch: Vec<Range> = Vec::with_capacity(BATCH_ROWS);
        let mut ranges = staged.ranges().peekable();
        let mut ordinal: u32 = 0;
        let mut stored: u32 = 0;
        while ranges.peek().is_some() {
            batch.clear();
            batch.extend(ranges.by_ref().take(BATCH_ROWS));
            let mut bytes = [0u8; BATCH_BYTES];
            let length = wire::encode_batch(&batch, &mut bytes).map_err(|_| JobError::Load)?;
            let input = Batch {
                auth: self.request.auth.clone(),
                digest: digest.clone(),
                ordinal,
                bytes: bytes.get(..length).unwrap_or_default().to_vec(),
            };
            self.call(move |tx, credential, now| {
                Box::pin(async move { store_chunk(tx, &credential, &input, now).await })
            })?;
            ordinal += 1;
            stored = stored.saturating_add(u32::try_from(batch.len()).unwrap_or(u32::MAX));
            self.progress.processed.store(stored, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_round_trip_through_the_atomic() {
        let progress = Progress::default();
        for state in ImportState::ALL {
            progress.set(state);
            assert_eq!(progress.state(), state);
        }
        assert_eq!(ImportState::Storing.name(), "storing");
    }

    #[test]
    fn source_digests_round_trip() {
        let csv = b"8.8.8.0,8.8.8.255,US\n";
        let one = Database::from_csv(Provider::Dbip, "2026-09", csv).unwrap();
        let text = source_digests(&one);
        assert_eq!(text.len(), 64);
        let digests = file_digests(&text, [9; 32]).unwrap();
        assert_eq!(digests[0], one.file_digests()[0]);
        assert_eq!(digests[1], [0; 32]);
        let two = Database::from_csv(Provider::UserCountry, "2026-09-09", csv).unwrap();
        let text = source_digests(&two);
        assert_eq!(text.len(), geo::MAX_SOURCE_DIGESTS);
        assert_eq!(file_digests(&text, [0; 32]).unwrap().as_slice(), two.file_digests());
        assert_eq!(file_digests("", [9; 32]).unwrap(), [[9; 32], [0; 32]]);
        assert!(file_digests("xyz", [0; 32]).is_err());
    }

    #[test]
    fn requests_are_checked_before_a_thread_starts() {
        let request = |version: &str, checksum: &str, csv: usize| ImportRequest {
            credential: Credential::default(),
            auth: Authorization::default(),
            expected_revision: 0,
            provider: Provider::UserCountry,
            version: version.into(),
            checksum: checksum.into(),
            csv: vec![b'x'; csv],
        };
        assert!(check_request(&request("2026-09-09", "", 0)).is_ok());
        assert!(check_request(&request("2026-09-09", &"A".repeat(64), MAX_CSV)).is_ok());
        assert!(check_request(&request("2026-09", "", 0)).is_err());
        assert!(check_request(&request("2026-09-09", "abc", 0)).is_err());
        assert!(check_request(&request("2026-09-09", &"g".repeat(64), 0)).is_err());
        assert!(check_request(&request("2026-09-09", "", MAX_CSV + 1)).is_err());
    }
}
