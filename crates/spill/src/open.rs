//! Opening a cache file: reuse it when it is whole, discard it when it is not ours to
//! trust, refuse it when it is not ours at all.

use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, RandomState};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::cache::Cache;
use crate::error::Error;
use crate::format::{Geometry, HEADER_LEN, Header, HeaderState, read_header, write_header};
use crate::map::{CAN_MAP, Store};

/// How to open a cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The size of the file in bytes, from [`crate::MIN_SIZE`] to [`crate::MAX_SIZE`].
    /// The file takes the largest whole number of buckets that fits.
    pub size: u64,
    /// The longest life of a hint in seconds. A slot that claims to expire later than
    /// this after now is treated as corrupt.
    pub max_ttl: u64,
}

impl Default for Options {
    /// 64 MiB and one day.
    fn default() -> Self {
        Self { size: 64 << 20, max_ttl: 86_400 }
    }
}

/// Why a file that was a cache could not be reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The header is cut short or fails its checksum.
    Header,
    /// The file has another version of the format.
    Version(u32),
    /// The file was made for another size.
    Size {
        /// The length the header of the file states.
        found: u64,
    },
    /// The file has another length than its header states.
    Length {
        /// The length of the file.
        found: u64,
    },
}

impl std::fmt::Display for Reason {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header => out.write_str("its header is damaged"),
            Self::Version(version) => write!(out, "it has format version {version}"),
            Self::Size { found } => write!(out, "it was made for {found} bytes"),
            Self::Length { found } => write!(out, "it has {found} bytes, not what it states"),
        }
    }
}

/// What opening found at the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// There was no file, or an empty one. A new cache was made.
    Created,
    /// The file was whole and is in use again. Its slots are checked as they are read.
    Reused,
    /// The file was a cache that cannot be trusted or does not fit. A new one replaced it.
    Discarded(Reason),
}

/// What [`load_cache`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// What was found at the path.
    pub outcome: Outcome,
    /// Whether the hints outlive the process. `false` on a platform that cannot map a
    /// file: the cache then lives in memory and the path is not touched.
    pub persistent: bool,
    /// The slots of the cache.
    pub slots: u64,
}

/// A salt that differs for every file: a client must not be able to choose its bucket.
fn fresh_salt(now: u64) -> u64 {
    RandomState::new().hash_one(now) | 1
}

/// Opens the cache file at `path`, or creates it, at the Unix second `now`.
///
/// A whole file of the right size is reused. A cache file that is damaged, of another
/// version or of another size is replaced by a new one, and the report says why. On a
/// platform that cannot map files the cache lives in memory.
///
/// # Errors
///
/// `SPILL001` for a size out of range, `SPILL002` when the file is not a cache (it is
/// left alone), `SPILL003` when another process holds it, `SPILL004` for an error of the
/// system.
pub fn load_cache(path: &Path, options: &Options, now: u64) -> Result<(Cache, Report), Error> {
    let geometry = Geometry::for_size(options.size).ok_or_else(|| Error::size(options.size))?;
    if !CAN_MAP {
        let cache = load_memory_cache(options).map_err(|error| Error::io(path, "hold", error))?;
        let report =
            Report { outcome: Outcome::Created, persistent: false, slots: cache.slot_count() };
        return Ok((cache, report));
    }
    let (file, header, outcome) = open_file(path, geometry, now)?;
    let fail = |error| Error::io(path, "map", error);
    let store = Store::map(file, header.file_len).map_err(fail)?;
    let cache = Cache::new(store, geometry, header.salt, options.max_ttl).map_err(fail)?;
    let report = Report { outcome, persistent: true, slots: cache.slot_count() };
    Ok((cache, report))
}

/// A cache in memory that is lost with the process, for tests and for platforms that
/// cannot map a file.
///
/// # Errors
///
/// `InvalidInput` for a size out of range and `OutOfMemory` when the memory cannot be
/// had.
pub fn load_memory_cache(options: &Options) -> io::Result<Cache> {
    let geometry = Geometry::for_size(options.size).ok_or(io::ErrorKind::InvalidInput)?;
    let store = Store::memory(geometry.file_len())?;
    Cache::new(store, geometry, fresh_salt(options.size), options.max_ttl)
}

/// Opens `path` for its owner alone. With `new` the file must not exist, and a
/// symbolic link in its place is not followed.
fn open_private(path: &Path, new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).truncate(false);
    if new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Hints say which server served a client. Nobody else needs them.
        options.mode(0o600);
    }
    options.open(path)
}

/// Takes the lock of `file` without waiting.
fn lock(path: &Path, file: File) -> Result<File, Error> {
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::busy(path)),
        Err(std::fs::TryLockError::Error(error)) => Err(Error::io(path, "lock", error)),
    }
}

/// Whether `path` still names `file`.
#[cfg(unix)]
fn names(path: &Path, file: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(held), Ok(named)) = (file.metadata(), std::fs::metadata(path)) else {
        return false;
    };
    held.dev() == named.dev() && held.ino() == named.ino()
}

/// Whether `path` still names `file`. This platform cannot tell.
#[cfg(not(unix))]
fn names(_path: &Path, _file: &File) -> bool {
    true
}

/// Opens `path` and takes its lock without waiting.
///
/// Another process may have renamed a new file over the path between our open and
/// our lock. Then we hold the lock of a file without a name, and the cache is in use.
fn open_locked(path: &Path) -> Result<File, Error> {
    let file = open_private(path, false).map_err(|error| Error::io(path, "open", error))?;
    let file = lock(path, file)?;
    if names(path, &file) { Ok(file) } else { Err(Error::busy(path)) }
}

/// Reads the first bytes of `file` into `start`. Returns how many there were.
fn read_start(mut file: &File, start: &mut [u8; HEADER_LEN]) -> io::Result<usize> {
    file.seek(SeekFrom::Start(0))?;
    let mut filled = 0;
    while let Some(rest) = start.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match file.read(rest) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Opens the file at `path` and decides whether to reuse it. Returns the locked file,
/// its header and what was found.
fn open_file(path: &Path, geometry: Geometry, now: u64) -> Result<(File, Header, Outcome), Error> {
    let file = open_locked(path)?;
    let fail = |error| Error::io(path, "read", error);
    let len = file.metadata().map_err(fail)?.len();
    let mut start = [0; HEADER_LEN];
    let filled = read_start(&file, &mut start).map_err(fail)?;
    let outcome = if len == 0 {
        Outcome::Created
    } else {
        match read_header(start.get(..filled).unwrap_or(&[])) {
            HeaderState::Foreign => return Err(Error::foreign(path)),
            HeaderState::Damaged => Outcome::Discarded(Reason::Header),
            HeaderState::Version(version) => Outcome::Discarded(Reason::Version(version)),
            HeaderState::Valid(header) if header.file_len != len => {
                Outcome::Discarded(Reason::Length { found: len })
            }
            HeaderState::Valid(header)
                if header.geometry != geometry || header.file_len != geometry.file_len() =>
            {
                Outcome::Discarded(Reason::Size { found: header.file_len })
            }
            HeaderState::Valid(header) => return Ok((file, header, Outcome::Reused)),
        }
    };
    // The old file stays locked until the new one has its name.
    let (created, header) = create(path, geometry, now)?;
    drop(file);
    Ok((created, header, outcome))
}

/// Makes a complete new cache file beside `path` and renames it over `path`. So `path`
/// never names a half-made file. Returns the locked new file and its header.
fn create(path: &Path, geometry: Geometry, now: u64) -> Result<(File, Header), Error> {
    let salt = fresh_salt(now);
    let building = path.with_file_name(format!(".sibuna-spill-{salt:016x}.tmp"));
    let fail = |error| Error::io(path, "create", error);
    let file = open_private(&building, true).map_err(fail)?;
    let made = lock(path, file).and_then(|file| {
        fill(&file, geometry, salt, now).map_err(fail)?;
        std::fs::rename(&building, path).map_err(fail)?;
        Ok(file)
    });
    let file = made.inspect_err(|_| {
        // A half-made file of up to the whole size must not stay on a full disk.
        let _ = std::fs::remove_file(&building);
    })?;
    Ok((file, Header { geometry, file_len: geometry.file_len(), salt }))
}

/// Writes zeros over the whole length, so that every block is allocated now and a full
/// disk is an error here and not a signal later. Then writes the header and flushes.
fn fill(mut file: &File, geometry: Geometry, salt: u64, now: u64) -> io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    let zeros = [0u8; 64 << 10];
    let mut left = geometry.file_len();
    while left > 0 {
        let count = left.min(zeros.len() as u64) as usize;
        file.write_all(zeros.get(..count).unwrap_or(&zeros))?;
        left -= count as u64;
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&write_header(geometry, salt, now))?;
    file.sync_all()
}

#[cfg(test)]
mod tests;
