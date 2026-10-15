//! Streaming CSV loading: bounded chunks in, one validated generation out.
//!
//! The [`Loader`] hashes every byte it is fed for the generation digest, splits rows across
//! chunk boundaries with a fixed 128-byte line buffer, and validates each row before the
//! caller may publish the result.

use std::fmt;

use sibuna_crypto::sha256::Sha256;

use crate::database::{Database, MAX_CSV_BYTES, MAX_RANGES, Provenance, Version};
use crate::provider::{MAX_FILES, Provider};
use crate::range::{Builder, MAX_LINE, RangeError};

/// Why a load failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoadError {
    /// A row was refused (also when it is the row past [`MAX_RANGES`]).
    Row {
        /// What is wrong with the row.
        error: RangeError,
        /// The source file, counted from zero.
        file: u8,
        /// The line in that file, counted from one.
        line: u64,
    },
    /// The merged ranges of both families overlap (IPv6 rows inside the mapped IPv4 space).
    Ranges(RangeError),
    /// No row with a known country was loaded.
    NoRanges,
    /// The input is empty (one-call loading only).
    Empty,
    /// More than [`MAX_CSV_BYTES`] were fed.
    TooManyBytes,
    /// More than [`MAX_FILES`] files were ended.
    TooManyFiles,
    /// The number of files ended is not the provider's file count.
    FileCount {
        /// The provider's file count.
        expected: u8,
        /// The files ended.
        found: u8,
    },
    /// The version text is empty or longer than ten bytes.
    InvalidVersion,
}

impl LoadError {
    /// Returns the range error behind a row or merge failure, or `None`.
    pub fn range_error(&self) -> Option<RangeError> {
        match *self {
            LoadError::Row { error, .. } | LoadError::Ranges(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Row { error, file, line } => {
                write!(f, "file {file}, line {line}: {error}")
            }
            LoadError::Ranges(error) => write!(f, "merged ranges: {error}"),
            LoadError::NoRanges => f.write_str("no range with a known country"),
            LoadError::Empty => f.write_str("the input is empty"),
            LoadError::TooManyBytes => f.write_str("the input exceeds 128 MiB"),
            LoadError::TooManyFiles => f.write_str("more than two source files"),
            LoadError::FileCount { expected, found } => {
                write!(f, "{found} source files where the provider publishes {expected}")
            }
            LoadError::InvalidVersion => f.write_str("the version is empty or too long"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Accepts source bytes in chunks of any size and builds one generation.
///
/// ```
/// use sibuna_geoip::{Loader, Provider};
///
/// let mut loader = Loader::new();
/// loader.feed(b"1.0.0.0,1.0.0.255,AU\n").unwrap();
/// loader.end_file().unwrap();
/// loader.feed(b"2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP\n").unwrap();
/// loader.end_file().unwrap();
/// let db = loader.finish(Provider::UserCountry, "2026-09-09").unwrap();
/// assert_eq!(db.lookup_text("1.0.0.1").unwrap().as_str(), "AU");
/// ```
///
/// After an error the loader is spent: every later call returns the same error, so a
/// partly loaded generation can never be finished.
pub struct Loader {
    builder: Builder,
    line: [u8; MAX_LINE],
    length: usize,
    bytes: usize,
    /// Whether the loader computes digests; the gzip path hashes the archive instead.
    hashing: bool,
    all: Sha256,
    file: Sha256,
    file_digests: [[u8; 32]; MAX_FILES],
    files: u8,
    /// Lines completed in the current file.
    lines: u64,
    failed: Option<LoadError>,
}

impl fmt::Debug for Loader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loader")
            .field("rows", &self.builder.row_count())
            .field("ranges", &self.builder.range_count())
            .field("bytes", &self.bytes)
            .field("files", &self.files)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Default for Loader {
    fn default() -> Self {
        Loader::new()
    }
}

impl Loader {
    /// Returns an empty loader. Range storage grows as rows arrive, up to [`MAX_RANGES`].
    pub fn new() -> Loader {
        Loader {
            builder: Builder::new(MAX_RANGES),
            line: [0; MAX_LINE],
            length: 0,
            bytes: 0,
            hashing: true,
            all: Sha256::new(),
            file: Sha256::new(),
            file_digests: [[0; 32]; MAX_FILES],
            files: 0,
            lines: 0,
            failed: None,
        }
    }

    /// Returns a loader that skips the digests; its caller supplies them.
    pub(crate) fn without_digests() -> Loader {
        Loader { hashing: false, ..Loader::new() }
    }

    /// Hashes `bytes` and appends every complete row; an unfinished row waits for the next
    /// chunk.
    ///
    /// Borrows `bytes` for the call. Fails with [`LoadError::TooManyBytes`] past
    /// [`MAX_CSV_BYTES`] (before reading any of `bytes`) and [`LoadError::Row`] for the
    /// first refused row.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), LoadError> {
        self.check()?;
        let result = self.feed_rows(bytes);
        self.remember(result)
    }

    fn feed_rows(&mut self, bytes: &[u8]) -> Result<(), LoadError> {
        if bytes.len() > MAX_CSV_BYTES - self.bytes {
            return Err(LoadError::TooManyBytes);
        }
        self.bytes += bytes.len();
        if self.hashing {
            self.all.update(bytes);
            self.file.update(bytes);
        }
        let mut rest = bytes;
        while let Some(end) = rest.iter().position(|&byte| byte == b'\n') {
            let (piece, after) = rest.split_at(end);
            if self.length == 0 {
                // The whole row is in this chunk: parse it in place, refusing a row longer
                // than the line buffer before the builder sees it, as the buffer would.
                if piece.len() > MAX_LINE {
                    return Err(self.row_error(RangeError::InvalidRow, self.lines + 1));
                }
                self.append(piece)?;
            } else {
                self.buffer(piece)?;
                let length = std::mem::take(&mut self.length);
                let line = self.line;
                self.append(&line[..length])?;
            }
            // `after` starts with the newline that `position` found.
            rest = &after[1..];
        }
        self.buffer(rest)
    }

    /// Adds part of an unfinished row to the line buffer.
    fn buffer(&mut self, piece: &[u8]) -> Result<(), LoadError> {
        let end = self.length + piece.len();
        let Some(slot) = self.line.get_mut(self.length..end) else {
            return Err(self.row_error(RangeError::InvalidRow, self.lines + 1));
        };
        slot.copy_from_slice(piece);
        self.length = end;
        Ok(())
    }

    fn append(&mut self, line: &[u8]) -> Result<(), LoadError> {
        self.lines += 1;
        self.builder.append(line).map_err(|error| self.row_error(error, self.lines))
    }

    fn row_error(&self, error: RangeError, line: u64) -> LoadError {
        LoadError::Row { error, file: self.files, line }
    }

    /// Ends one source file: appends an unterminated final row and records the file digest.
    ///
    /// Fails with [`LoadError::TooManyFiles`] past [`MAX_FILES`] and with the final row's
    /// error.
    pub fn end_file(&mut self) -> Result<(), LoadError> {
        self.check()?;
        let result = self.end_file_rows();
        self.remember(result)
    }

    fn end_file_rows(&mut self) -> Result<(), LoadError> {
        let slot = usize::from(self.files);
        if slot >= MAX_FILES {
            return Err(LoadError::TooManyFiles);
        }
        if self.length != 0 {
            let length = std::mem::take(&mut self.length);
            let line = self.line;
            self.append(&line[..length])?;
        }
        if self.hashing {
            self.file_digests[slot] = std::mem::take(&mut self.file).finalize();
        }
        self.files += 1;
        self.lines = 0;
        Ok(())
    }

    /// Returns how many known ranges were kept so far.
    pub fn range_count(&self) -> usize {
        self.builder.range_count()
    }

    /// Returns how many rows were appended so far, `ZZ` rows included.
    pub fn row_count(&self) -> usize {
        self.builder.row_count()
    }

    /// Returns how many bytes were fed so far.
    pub fn byte_count(&self) -> usize {
        self.bytes
    }

    /// Returns how many files were ended so far.
    pub fn file_count(&self) -> u8 {
        self.files
    }

    /// Sorts and checks the ranges and returns the generation; consumes the loader.
    ///
    /// Fails with [`LoadError::FileCount`] unless exactly `provider.file_count()` files were
    /// ended, [`LoadError::NoRanges`], [`LoadError::Ranges`] for overlap between the
    /// families, and [`LoadError::InvalidVersion`] for an empty or long `version`. The
    /// version syntax is not checked here (see [`Provider::is_version_valid`]).
    pub fn finish(self, provider: Provider, version: &str) -> Result<Database, LoadError> {
        let Loader { all, file_digests, .. } = &self;
        let (digest, file_digests) = (all.clone().finalize(), *file_digests);
        self.finish_with(provider, version, digest, file_digests)
    }

    pub(crate) fn finish_with(
        self,
        provider: Provider,
        version: &str,
        digest: [u8; 32],
        file_digests: [[u8; 32]; MAX_FILES],
    ) -> Result<Database, LoadError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.files == 0 || self.files != provider.file_count() {
            let expected = provider.file_count();
            return Err(LoadError::FileCount { expected, found: self.files });
        }
        let ranges = self.builder.finish().map_err(|error| match error {
            RangeError::InvalidRow => LoadError::NoRanges,
            other => LoadError::Ranges(other),
        })?;
        let version = Version::new(version).map_err(|_| LoadError::InvalidVersion)?;
        let provenance = Provenance { provider, version, digest, file_digests };
        Ok(Database::from_sorted(&ranges, provenance))
    }

    /// Drops the loader and everything it loaded. Dropping it has the same effect.
    pub fn abandon(self) {}

    fn check(&self) -> Result<(), LoadError> {
        self.failed.map_or(Ok(()), Err)
    }

    fn remember(&mut self, result: Result<(), LoadError>) -> Result<(), LoadError> {
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }
}

impl Database {
    /// Loads one in-memory CSV as a complete generation (pasted imports and tests).
    ///
    /// Borrows `csv` for the call. For a two-file provider the CSV is the first file and
    /// the second is empty. Fails with [`LoadError::Empty`] for empty input,
    /// [`LoadError::TooManyBytes`] above [`MAX_CSV_BYTES`], and as [`Loader`] does.
    pub fn from_csv(provider: Provider, version: &str, csv: &[u8]) -> Result<Database, LoadError> {
        if csv.is_empty() {
            return Err(LoadError::Empty);
        }
        if csv.len() > MAX_CSV_BYTES {
            return Err(LoadError::TooManyBytes);
        }
        let mut loader = Loader::new();
        loader.feed(csv)?;
        for _ in 0..provider.file_count() {
            loader.end_file()?;
        }
        loader.finish(provider, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &[u8] = include_bytes!("../testdata/user-country-ipv4.csv");
    const V6: &[u8] = include_bytes!("../testdata/user-country-ipv6.csv");

    fn code(db: &Database, ip: &str) -> Option<String> {
        db.lookup_text(ip).map(|country| country.to_string())
    }

    #[test]
    fn loader_hashes_all_fed_bytes_and_splits_rows_across_chunk_boundaries() {
        let mut loader = Loader::new();
        loader.feed(b"1.0.0.0,1.0.0.").unwrap();
        loader.feed(b"255,AU\n8.8.8.0,8.8.8.255,US").unwrap();
        loader.end_file().unwrap();
        loader.feed(b"2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n").unwrap();
        loader.end_file().unwrap();
        let db = loader.finish(Provider::UserCountry, "2026-09-09").unwrap();
        assert_eq!(db.range_count(), 3);
        assert_eq!(code(&db, "1.0.0.1").as_deref(), Some("AU"));
        assert_eq!(code(&db, "2001:4860::8888").as_deref(), Some("US"));
        assert_eq!(code(&db, "9.9.9.9"), None);
        assert_eq!(code(&db, "nonsense"), None);
        assert_eq!(db.file_digests().len(), 2);
        let expected = Sha256::digest(
            b"1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\
              2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n",
        );
        assert_eq!(db.digest(), &expected);
        assert_eq!(db.version().as_str(), "2026-09-09");
    }

    #[test]
    fn loader_rejects_an_invalid_row_without_publishing_and_frees_on_abandon() {
        let mut loader = Loader::new();
        let error = loader.feed(b"8.8.8.0,8.8.8.255,AA\n").unwrap_err();
        assert_eq!(error.range_error(), Some(RangeError::InvalidCountry));
        assert_eq!(error, LoadError::Row { error: RangeError::InvalidCountry, file: 0, line: 1 });
        // A spent loader keeps refusing.
        assert_eq!(loader.feed(b"8.8.8.0,8.8.8.255,US\n"), Err(error));
        assert_eq!(loader.end_file(), Err(error));
        loader.abandon();
        let empty_row = Database::from_csv(Provider::Dbip, "2026-09", b"\n").unwrap_err();
        assert_eq!(empty_row.range_error(), Some(RangeError::InvalidRow));
        let one = Database::from_csv(Provider::Dbip, "2026-09", b"8.8.8.0,8.8.8.255,US").unwrap();
        assert_eq!(one.file_digests().len(), 1);
        assert_eq!(one.digest(), &one.file_digests()[0]);
    }

    #[test]
    fn committed_user_country_fixtures_load_as_one_two_file_generation() {
        let mut loader = Loader::new();
        loader.feed(V4).unwrap();
        loader.end_file().unwrap();
        loader.feed(V6).unwrap();
        loader.end_file().unwrap();
        let db = loader.finish(Provider::UserCountry, "2026-09-09").unwrap();
        assert_eq!(db.range_count(), 25);
        assert_eq!(code(&db, "1.0.0.1").as_deref(), Some("AU"));
        assert_eq!(code(&db, "2001:200::1").as_deref(), Some("JP"));
        assert_eq!(code(&db, "2401:b60:1a10::1").as_deref(), Some("AN"));
        assert_eq!(code(&db, "176.23.148.5").as_deref(), Some("FX"));
        assert_eq!(db.file_digests()[0], Sha256::digest(V4));
        assert_eq!(db.file_digests()[1], Sha256::digest(V6));
    }

    #[test]
    fn rows_report_their_file_and_line() {
        let mut loader = Loader::new();
        loader.feed(V4).unwrap();
        loader.end_file().unwrap();
        loader.feed(b"2001:200::,2001:200::ff,JP\r\n").unwrap();
        let error = loader.feed(b"\n").unwrap_err();
        assert_eq!(error, LoadError::Row { error: RangeError::InvalidRow, file: 1, line: 2 });
        let mut long = Loader::new();
        long.feed(b"1.0.0.0,1.0.0.1,US\n").unwrap();
        let error = long.feed(&[b'1'; MAX_LINE + 1]).unwrap_err();
        assert_eq!(error, LoadError::Row { error: RangeError::InvalidRow, file: 0, line: 2 });
        let mut exact = Loader::new();
        let mut row = b"1.0.0.0,1.0.0.1,US".to_vec();
        row.resize(MAX_LINE, b'\r');
        exact.feed(&row[..50]).unwrap();
        exact.feed(&row[50..]).unwrap();
        exact.end_file().unwrap();
        assert_eq!(exact.range_count(), 1);
    }

    #[test]
    fn file_counts_versions_and_merge_overlaps_fail_finish() {
        let mut loader = Loader::new();
        loader.feed(b"1.0.0.0,1.0.0.1,US\n").unwrap();
        loader.end_file().unwrap();
        let error = loader.finish(Provider::UserCountry, "2026-09-09").unwrap_err();
        assert_eq!(error, LoadError::FileCount { expected: 2, found: 1 });
        let none = Loader::new().finish(Provider::Dbip, "2026-09").unwrap_err();
        assert_eq!(none, LoadError::FileCount { expected: 1, found: 0 });
        let zz = Database::from_csv(Provider::Dbip, "2026-09", b"1.0.0.0,1.0.0.1,ZZ").unwrap_err();
        assert_eq!(zz, LoadError::NoRanges);
        let long = Database::from_csv(Provider::Dbip, "2026-09-091", b"1.0.0.0,1.0.0.1,US");
        assert_eq!(long.unwrap_err(), LoadError::InvalidVersion);
        let overlap = b"1.0.0.0,1.0.0.255,US\n::fffe:0:0,::ffff:1.0.0.0,DE\n";
        let error = Database::from_csv(Provider::Dbip, "2026-09", overlap).unwrap_err();
        assert_eq!(error, LoadError::Ranges(RangeError::Overlap));
        assert_eq!(Database::from_csv(Provider::Dbip, "2026-09", b""), Err(LoadError::Empty));
        let mut three = Loader::new();
        three.end_file().unwrap();
        three.end_file().unwrap();
        assert_eq!(three.end_file(), Err(LoadError::TooManyFiles));
    }
}
