//! IP address to country lookup from open datasets.
//!
//! We load the `start,end,country` CSV rows that open datasets publish, validate every
//! row, keep one immutable sorted generation, and answer lookups with a binary search. The
//! crate also owns a compact canonical snapshot format, the 34-byte storage rows the
//! console replicates, and the facts about each provider (licence, attribution, URLs,
//! version syntax) that callers must not invent. It never touches storage or sockets.
//!
//! ```
//! use sibuna_geoip::{Database, Provider};
//!
//! let csv = b"8.8.8.0,8.8.8.255,US\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n";
//! let db = Database::from_csv(Provider::Dbip, "2026-09", csv).unwrap();
//! assert_eq!(db.lookup_text("8.8.8.8").unwrap().as_str(), "US");
//! assert_eq!(db.lookup_text("10.0.0.1"), None); // private space is never mapped
//! ```
//!
//! Large downloads go through a [`Loader`], which accepts bytes in chunks of any size and
//! ends each source file explicitly, so a two-file provider becomes one generation with one
//! digest. [`gzip::decode`] does the same for a compressed archive.
//!
//! # Rows and bounds
//!
//! - A row is `start,end,CC` in dotted or colon notation; quoted columns and a trailing CR
//!   are accepted.
//! - Each family must be strictly ascending in the source. `ZZ` rows are checked for order
//!   and then omitted. IPv4 is normalized into `::ffff:0:0/96` before both families are
//!   merged and checked for overlap.
//! - Country codes are the assigned ISO 3166-1 list plus the transitionally reserved `AN`
//!   and `FX`. Anything else fails the whole import.
//! - Bounds: 1,048,576 rows ([`MAX_RANGES`]), 128 MiB of CSV ([`MAX_CSV_BYTES`]), 128-byte
//!   lines ([`MAX_LINE`]), 16 MiB compressed ([`gzip::MAX_COMPRESSED_BYTES`]).
//! - Lookups return `None` for private, reserved, documentation and transition space even
//!   when a publisher row covers it.
//!
//! # Lookup layout
//!
//! An address is a `u128`: the big-endian value of its sixteen bytes, with IPv4 mapped.
//! A [`Database`] keeps the first addresses of its ranges in one sorted `u128` array, the
//! last addresses in a second and the two-byte country codes in a third. A lookup is a
//! branch-free binary search over the first array followed by one comparison with the last
//! address; it allocates nothing.
//!
//! # Changes from the Zig version
//!
//! `libs/geoip` of the Zig repository is the specification. The port differs as follows.
//!
//! - Addresses are `u128` values instead of `[16]u8` arrays; the order is the same.
//!   [`Database::lookup_ip`] takes a `std::net::IpAddr` directly.
//! - Errors carry more detail. A refused row reports its file and line
//!   ([`LoadError::Row`]); a wrong file count, an empty generation and an empty input have
//!   their own variants where Zig reported `InvalidRow` or `Capacity`; snapshot and storage
//!   row errors name the defect where Zig had one `InvalidSnapshot` or `InvalidGeneration`.
//!   The set of accepted inputs is unchanged, except for the two snapshot rules below.
//! - The snapshot decoder also requires the bytes after the version text and the unused
//!   file digest slot (for one-file providers) to be zero. The Zig decoder ignored them;
//!   the Zig encoder always writes zeros, so every snapshot it wrote still decodes, and now
//!   each valid snapshot has exactly one encoding (decoding and re-encoding gives the same
//!   bytes).
//! - A [`Loader`] reserves nothing up front (Zig reserved space for 1,048,576 ranges) and
//!   is spent after its first error: later calls return that error. [`Loader::abandon`]
//!   is the same as dropping it.
//! - [`wire::decode_rows`] appends to a `Vec` up to a caller bound and appends nothing on
//!   an error; Zig left the rows before the bad one in place. [`wire::encode_batch`]
//!   returns an error for more than 100 ranges where Zig asserted.
//! - [`gzip::decode`] uses `sibuna-inflate` and an `AtomicBool` stop flag; Zig also
//!   checked its I/O cancellation. Corrupt CRC, size and trailing bytes are all
//!   [`gzip::GzipError::Checksum`] as before.
//! - Provider URLs and file names are returned as `String` values instead of being written
//!   into caller buffers.
//! - The IPv6 parser is `sibuna_cidr::parse_ipv6`, a port of Zig's `Ip6Address.parse`. The
//!   IPv4 parser is our own, because `sibuna-cidr` accepts the lenient IPv4 syntax of the
//!   Zig policy code (`010`, `+1`) which this library's Zig parser refused. A test checks
//!   both against 6,050 texts parsed by the Zig library.

pub mod address;
pub mod country;
mod database;
pub mod gzip;
mod loader;
pub mod prefixes;
pub mod provider;
pub mod range;
pub mod snapshot;
pub mod wire;

pub use country::Country;
pub use database::{Database, MAX_CSV_BYTES, MAX_RANGES, Provenance, Version, VersionError};
pub use loader::{LoadError, Loader};
pub use provider::{Compression, Provider};
pub use range::{MAX_LINE, Range, RangeError};
