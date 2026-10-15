//! Streaming expansion of gzip publishers into a generation.
//!
//! Compressed bytes, expanded bytes, rows and line length are bounded, and the gzip footer
//! (CRC-32 and size) is verified before the generation is returned. The generation digest
//! is the SHA-256 of the compressed bytes, exactly as the publisher ships them.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use sibuna_crypto::sha256::Sha256;
use sibuna_inflate::{Decoder, Format, Limits, Status};

use crate::database::{Database, MAX_CSV_BYTES};
use crate::loader::{LoadError, Loader};
use crate::provider::{Compression, Provider};

/// The largest compressed archive accepted.
pub const MAX_COMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// How much expanded data one decoder call produces before it is fed to the loader.
const CHUNK_BYTES: usize = 64 * 1024;

/// Why an archive did not become a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GzipError {
    /// The archive is empty or larger than [`MAX_COMPRESSED_BYTES`].
    Size,
    /// The provider does not publish gzip archives.
    Provider,
    /// The archive expands to more than [`MAX_CSV_BYTES`].
    TooManyBytes,
    /// The archive is not a valid gzip stream.
    Inflate(sibuna_inflate::Error),
    /// The CRC-32 or size in the footer does not match, or bytes follow the stream.
    Checksum,
    /// The stop flag was raised.
    Canceled,
    /// The expanded CSV was refused.
    Load(LoadError),
}

impl fmt::Display for GzipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GzipError::Size => f.write_str("the archive is empty or larger than 16 MiB"),
            GzipError::Provider => f.write_str("the provider does not publish gzip archives"),
            GzipError::TooManyBytes => f.write_str("the archive expands to more than 128 MiB"),
            GzipError::Inflate(error) => write!(f, "the archive is corrupt: {error}"),
            GzipError::Checksum => f.write_str("the archive footer does not match its data"),
            GzipError::Canceled => f.write_str("the import was canceled"),
            GzipError::Load(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for GzipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GzipError::Inflate(error) => Some(error),
            GzipError::Load(error) => Some(error),
            _ => None,
        }
    }
}

impl From<LoadError> for GzipError {
    fn from(error: LoadError) -> Self {
        GzipError::Load(error)
    }
}

fn inflate_error(error: sibuna_inflate::Error) -> GzipError {
    use sibuna_inflate::Error;
    match error {
        Error::CrcMismatch | Error::SizeMismatch | Error::TrailingData => GzipError::Checksum,
        Error::InputLimit => GzipError::Size,
        Error::OutputLimit => GzipError::TooManyBytes,
        other => GzipError::Inflate(other),
    }
}

/// Expands a gzip archive of `provider` and loads it as one generation.
///
/// Borrows `compressed` for the call and works in bounded memory besides the generation.
/// `stopping` is read before every chunk with `Acquire` ordering, pairing with the
/// `Release` store of the thread that asks the import to stop. Fails with [`GzipError`].
pub fn decode(
    provider: Provider,
    version: &str,
    compressed: &[u8],
    stopping: &AtomicBool,
) -> Result<Database, GzipError> {
    if compressed.is_empty() || compressed.len() > MAX_COMPRESSED_BYTES {
        return Err(GzipError::Size);
    }
    if provider.compression() != Compression::Gzip {
        return Err(GzipError::Provider);
    }
    let limits = Limits {
        max_input_bytes: MAX_COMPRESSED_BYTES as u64,
        max_output_bytes: MAX_CSV_BYTES as u64,
        ..Limits::default()
    };
    let mut decoder = Decoder::new(Format::Gzip, limits);
    let mut loader = Loader::without_digests();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut input = compressed;
    loop {
        if stopping.load(Ordering::Acquire) {
            return Err(GzipError::Canceled);
        }
        let progress = decoder.decompress(input, true, &mut buffer).map_err(inflate_error)?;
        // Every call that does not finish consumes input or produces output; a call that
        // does neither would loop forever, so treat it as a broken stream.
        if progress.status != Status::Done && progress.consumed == 0 && progress.written == 0 {
            return Err(GzipError::Inflate(sibuna_inflate::Error::Truncated));
        }
        input = input.get(progress.consumed..).unwrap_or_default();
        loader.feed(buffer.get(..progress.written).unwrap_or_default())?;
        if progress.status == Status::Done {
            break;
        }
    }
    if !input.is_empty() {
        return Err(GzipError::Checksum);
    }
    loader.end_file()?;
    let digest = Sha256::digest(compressed);
    Ok(loader.finish_with(provider, version, digest, [digest, [0; 32]])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GZ: &[u8] = include_bytes!("../testdata/countries.csv.gz");

    #[test]
    fn gzip_crc_corruption_and_shutdown_cannot_activate_a_partial_country_dataset() {
        let stopping = AtomicBool::new(false);
        let valid = decode(Provider::Dbip, "2026-09", GZ, &stopping).unwrap();
        assert_eq!(valid.range_count(), 2);
        assert_eq!(valid.digest(), &Sha256::digest(GZ));
        assert_eq!(valid.file_digests(), &[Sha256::digest(GZ)]);
        let mut corrupt = GZ.to_vec();
        let at = corrupt.len() - 8;
        corrupt[at] ^= 1;
        assert_eq!(
            decode(Provider::Dbip, "2026-09", &corrupt, &stopping),
            Err(GzipError::Checksum)
        );
        let wrong = decode(Provider::UserCountry, "2026-09-09", GZ, &stopping);
        assert_eq!(wrong, Err(GzipError::Provider));
        stopping.store(true, Ordering::Release);
        assert_eq!(decode(Provider::Dbip, "2026-09", GZ, &stopping), Err(GzipError::Canceled));
    }

    #[test]
    fn archives_are_bounded_and_complete() {
        let stopping = AtomicBool::new(false);
        assert_eq!(decode(Provider::Dbip, "2026-09", b"", &stopping), Err(GzipError::Size));
        let mut trailing = GZ.to_vec();
        trailing.push(0);
        assert_eq!(
            decode(Provider::Dbip, "2026-09", &trailing, &stopping),
            Err(GzipError::Checksum)
        );
        let truncated = decode(Provider::Dbip, "2026-09", &GZ[..GZ.len() - 9], &stopping);
        assert_eq!(truncated, Err(GzipError::Inflate(sibuna_inflate::Error::Truncated)));
        let large = vec![0u8; MAX_COMPRESSED_BYTES + 1];
        assert_eq!(decode(Provider::Dbip, "2026-09", &large, &stopping), Err(GzipError::Size));
    }
}
