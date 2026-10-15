//! The errors of decompression.

use std::fmt;

/// Why a DEFLATE or gzip stream was rejected.
///
/// The variants name the first defect found while reading the stream from the front, in the
/// same order as Zig 0.16 `std.compress.flate` and zlib find them. Each comment names the
/// Zig error it corresponds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The input ended inside the stream (Zig `EndOfStream`).
    Truncated,
    /// A block header has the reserved block type 3 (Zig `InvalidBlockType`).
    InvalidBlockType,
    /// A stored block's length is not the complement of its check field
    /// (Zig `WrongStoredBlockNlen`).
    StoredLengthMismatch,
    /// A dynamic block header declares more than 286 literal/length or 30 distance codes, or
    /// a code length repeat starts at the first length or runs past the last one
    /// (Zig `InvalidDynamicBlockHeader`).
    InvalidDynamicHeader,
    /// A set of code lengths describes more codes than its bit lengths allow
    /// (Zig `OversubscribedHuffmanTree`).
    OversubscribedTree,
    /// A set of code lengths leaves codes unused; only a single code of length one may do
    /// so, and never for the code length code (Zig `IncompleteHuffmanTree`).
    IncompleteTree,
    /// A dynamic block gives the end-of-block symbol no code (Zig `MissingEndOfBlockCode`).
    MissingEndOfBlock,
    /// The input holds a bit pattern that is no code of the current table, or the code of a
    /// symbol DEFLATE reserves (literal/length 286 and 287, distance 30 and 31)
    /// (Zig `InvalidCode`).
    InvalidCode,
    /// A match refers further back than the start of the output (Zig `InvalidMatch`).
    DistanceTooFar,
    /// The input does not start with the gzip magic bytes `1f 8b` (Zig `BadGzipHeader`).
    NotGzip,
    /// The gzip compression method is not 8, DEFLATE (Zig `BadGzipHeader`).
    UnsupportedMethod,
    /// The gzip header sets one of the flag bits RFC 1952 reserves. Zig ignores them.
    ReservedFlags,
    /// The gzip header CRC (flag FHCRC) does not match the header. Zig does not check it.
    HeaderCrcMismatch,
    /// The CRC-32 in a gzip footer does not match the decompressed data
    /// (Zig `WrongGzipChecksum`; Sibuna's GeoIP loader `InvalidChecksum`).
    CrcMismatch,
    /// The size in a gzip footer is not the decompressed size modulo 2^32
    /// (Zig `WrongGzipSize`; Sibuna's GeoIP loader `InvalidChecksum`).
    SizeMismatch,
    /// Bytes follow the end of the stream, or the last gzip member allowed by
    /// [`Limits::max_members`](crate::Limits::max_members)
    /// (Sibuna's GeoIP loader `InvalidChecksum`).
    TrailingData,
    /// The stream needs more input than [`Limits::max_input_bytes`](crate::Limits) allows
    /// (Sibuna's GeoIP loader `Capacity`).
    InputLimit,
    /// The stream decompresses to more than [`Limits::max_output_bytes`](crate::Limits)
    /// (Sibuna's GeoIP loader `Capacity`).
    OutputLimit,
    /// The output vector could not grow; only the one-call helpers report this.
    OutOfMemory,
}

impl Error {
    /// Returns a short title for the error, suitable for the rule of an Elm-style message.
    pub const fn title(self) -> &'static str {
        match self {
            Error::Truncated => "TRUNCATED STREAM",
            Error::InvalidBlockType
            | Error::StoredLengthMismatch
            | Error::InvalidDynamicHeader
            | Error::OversubscribedTree
            | Error::IncompleteTree
            | Error::MissingEndOfBlock
            | Error::InvalidCode
            | Error::DistanceTooFar => "CORRUPT DEFLATE DATA",
            Error::NotGzip
            | Error::UnsupportedMethod
            | Error::ReservedFlags
            | Error::HeaderCrcMismatch => "BAD GZIP HEADER",
            Error::CrcMismatch | Error::SizeMismatch => "GZIP CHECKSUM MISMATCH",
            Error::TrailingData => "TRAILING DATA",
            Error::InputLimit | Error::OutputLimit => "DECOMPRESSION LIMIT",
            Error::OutOfMemory => "OUT OF MEMORY",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "the compressed stream ends early",
            Error::InvalidBlockType => "a DEFLATE block has the reserved type 3",
            Error::StoredLengthMismatch => "a stored block's length does not match its check",
            Error::InvalidDynamicHeader => "a dynamic block header has invalid code counts",
            Error::OversubscribedTree => "a Huffman code has too many codes for its lengths",
            Error::IncompleteTree => "a Huffman code leaves codes unused",
            Error::MissingEndOfBlock => "a dynamic block has no end-of-block code",
            Error::InvalidCode => "the stream holds an invalid Huffman code",
            Error::DistanceTooFar => "a match refers before the start of the output",
            Error::NotGzip => "the input does not start with the gzip magic bytes",
            Error::UnsupportedMethod => "the gzip compression method is not DEFLATE",
            Error::ReservedFlags => "the gzip header sets reserved flags",
            Error::HeaderCrcMismatch => "the gzip header CRC does not match the header",
            Error::CrcMismatch => "the gzip CRC-32 does not match the decompressed data",
            Error::SizeMismatch => "the gzip size does not match the decompressed data",
            Error::TrailingData => "unexpected bytes follow the compressed stream",
            Error::InputLimit => "the compressed input exceeds the input limit",
            Error::OutputLimit => "the decompressed output exceeds the output limit",
            Error::OutOfMemory => "the output buffer could not grow",
        })
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_ascii_and_titled() {
        let all = [
            Error::Truncated,
            Error::InvalidBlockType,
            Error::StoredLengthMismatch,
            Error::InvalidDynamicHeader,
            Error::OversubscribedTree,
            Error::IncompleteTree,
            Error::MissingEndOfBlock,
            Error::InvalidCode,
            Error::DistanceTooFar,
            Error::NotGzip,
            Error::UnsupportedMethod,
            Error::ReservedFlags,
            Error::HeaderCrcMismatch,
            Error::CrcMismatch,
            Error::SizeMismatch,
            Error::TrailingData,
            Error::InputLimit,
            Error::OutputLimit,
            Error::OutOfMemory,
        ];
        for error in all {
            let message = error.to_string();
            assert!(message.is_ascii() && !message.is_empty());
            assert!(error.title().chars().all(|c| c.is_ascii_uppercase() || c == ' '));
        }
    }
}
