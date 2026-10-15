//! Versioned archives of complete collector minutes (SBR1 and SBR2). The byte order is
//! fixed little-endian, so no native struct layout is ever persisted.
//!
//! An SBR2 archive is, in order: the magic `SBR2`; the node (u32); the boot id (16 bytes);
//! the minute, first and last sampled second, truncated and rejected records, and the
//! queue-loss interval (u64 each); then the path sketch: samples (u64), the constant 64
//! (u16), the counter count (u16) and each counter as key length (u16), key bytes,
//! estimate and error bound (u64); then the referrer sketch in the same shape with the
//! constant 24; then the operating-system, browser and status histograms (u64 each). SBR1
//! ends after the path sketch; it is read, never written.

use std::fmt;

use crate::client_family::STATUS_SLOTS;
use crate::ranking_storage::{Families, Minute, Referrers};
use crate::space_saving::{Counter, Sketch, SketchKey, Summary};

/// The largest SBR1 archive.
pub const LEGACY_BYTES: usize = 92 + 256 * (2 + 128 + 16);

/// The largest archive accepted: the largest possible SBR2 archive. The Zig console counted
/// the referrer section header as 4 bytes instead of 12, so it refused a minute whose two
/// sketches were both full and never archived it, contrary to SID 0007; we count it right.
pub const MAX_BYTES: usize = LEGACY_BYTES + 12 + 256 * (2 + 24 + 16) + 8 * (8 + 8 + STATUS_SLOTS);

/// Why an archive could not be written or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArchiveError {
    /// The bytes or the minute break the format or its invariants.
    InvalidArchive,
    /// The archive is longer than [`MAX_BYTES`] or the output buffer.
    TooLarge,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ArchiveError::InvalidArchive => "the ranking archive is malformed or inconsistent",
            ArchiveError::TooLarge => "the ranking archive is too large",
        })
    }
}

impl std::error::Error for ArchiveError {}

/// Who produced an archive and the queue loss it observed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Identity {
    /// The node.
    pub node: u32,
    /// The node's boot id; never all zeros.
    pub boot: [u8; 16],
    /// Cumulative queue loss when the minute began.
    pub queue_loss_start: u64,
    /// Cumulative queue loss when the minute ended.
    pub queue_loss_end: u64,
}

/// One archived minute.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Archive {
    /// The producer.
    pub identity: Identity,
    /// The collector minute.
    pub minute: Minute,
}

/// Encodes an archive as SBR2.
///
/// # Errors
///
/// [`ArchiveError::InvalidArchive`] for a minute that breaks the invariants (see
/// [`decode`]) and [`ArchiveError::TooLarge`] beyond [`MAX_BYTES`].
pub fn encode(archive: &Archive) -> Result<Vec<u8>, ArchiveError> {
    validate(archive)?;
    let mut out = Vec::with_capacity(MAX_BYTES);
    write(archive, &mut out);
    if out.len() > MAX_BYTES {
        return Err(ArchiveError::TooLarge);
    }
    Ok(out)
}

/// Encodes an archive into `buffer` and returns its length.
///
/// # Errors
///
/// As [`encode`], and [`ArchiveError::TooLarge`] when `buffer` is too short.
pub fn encode_into(archive: &Archive, buffer: &mut [u8]) -> Result<usize, ArchiveError> {
    let bytes = encode(archive)?;
    let output = buffer.get_mut(..bytes.len()).ok_or(ArchiveError::TooLarge)?;
    output.copy_from_slice(&bytes);
    Ok(bytes.len())
}

fn write(archive: &Archive, out: &mut Vec<u8>) {
    let minute = &archive.minute;
    out.extend_from_slice(b"SBR2");
    out.extend_from_slice(&archive.identity.node.to_le_bytes());
    out.extend_from_slice(&archive.identity.boot);
    for value in [
        minute.minute.unwrap_or_default(),
        minute.first_second,
        minute.last_second,
        minute.truncated_records,
        minute.rejected_records,
        archive.identity.queue_loss_start,
        archive.identity.queue_loss_end,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    write_sketch(out, &minute.paths, 64);
    write_sketch(out, &minute.referrers, 24);
    let families = &minute.families;
    for count in families.os.iter().chain(&families.browser).chain(&families.status) {
        out.extend_from_slice(&count.to_le_bytes());
    }
}

fn write_sketch<const C: usize, const K: usize>(
    out: &mut Vec<u8>,
    sketch: &Sketch<C, K>,
    tag: u16,
) {
    out.extend_from_slice(&sketch.samples().to_le_bytes());
    out.extend_from_slice(&tag.to_le_bytes());
    // A sketch holds at most 256 counters of keys of at most 128 bytes, so both fit a u16.
    out.extend_from_slice(&(sketch.len() as u16).to_le_bytes());
    for counter in sketch.counters() {
        out.extend_from_slice(&(counter.key.len() as u16).to_le_bytes());
        out.extend_from_slice(counter.key.as_bytes());
        out.extend_from_slice(&counter.estimate.to_le_bytes());
        out.extend_from_slice(&counter.error_bound.to_le_bytes());
    }
}

/// Decodes an SBR1 or SBR2 archive. SBR1 archives read with `extended` false and empty
/// referrers and families, never as zero observations.
///
/// # Errors
///
/// [`ArchiveError::TooLarge`] beyond [`MAX_BYTES`]; [`ArchiveError::InvalidArchive`] for
/// a wrong magic or tag, truncated or trailing bytes, an oversized key or count, or a
/// minute that breaks the invariants: a minute index and boot are present, the queue-loss
/// interval is ordered, sampled seconds lie in the minute, every counter has a positive
/// estimate, an error below it and at most N/256, keys are distinct, estimates sum to N,
/// and referrer samples do not exceed path samples.
pub fn decode(bytes: &[u8]) -> Result<Archive, ArchiveError> {
    if bytes.len() > MAX_BYTES {
        return Err(ArchiveError::TooLarge);
    }
    let mut reader = Reader { bytes };
    let archive = read(&mut reader).ok_or(ArchiveError::InvalidArchive)?;
    if !reader.bytes.is_empty() {
        return Err(ArchiveError::InvalidArchive);
    }
    validate(&archive)?;
    Ok(archive)
}

/// A cursor over the archive bytes; every read is bounds-checked.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.bytes.split_at_checked(length)?;
        self.bytes = tail;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }
}

fn read(r: &mut Reader<'_>) -> Option<Archive> {
    let legacy = match r.take(4)? {
        b"SBR1" => true,
        b"SBR2" => false,
        _ => return None,
    };
    let node = r.u32()?;
    let boot = r.array::<16>()?;
    let mut minute = Minute { minute: Some(r.u64()?), ..Minute::default() };
    minute.first_second = r.u64()?;
    minute.last_second = r.u64()?;
    minute.truncated_records = r.u64()?;
    minute.rejected_records = r.u64()?;
    let identity = Identity { node, boot, queue_loss_start: r.u64()?, queue_loss_end: r.u64()? };
    minute.paths = read_sketch::<256, 128>(r, 64)?;
    minute.extended = !legacy;
    if !legacy {
        minute.referrers = read_sketch::<256, 24>(r, 24)?;
        minute.families = read_families(r)?;
    }
    Some(Archive { identity, minute })
}

fn read_sketch<const C: usize, const K: usize>(
    r: &mut Reader<'_>,
    tag: u16,
) -> Option<Sketch<C, K>> {
    let samples = r.u64()?;
    if r.u16()? != tag {
        return None;
    }
    let count = usize::from(r.u16()?);
    if count > C {
        return None;
    }
    let mut counters = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::from(r.u16()?);
        let key = SketchKey::new(r.take(length)?).ok()?;
        counters.push(Counter { key, estimate: r.u64()?, error_bound: r.u64()? });
    }
    Sketch::from_parts(counters, samples).ok()
}

fn read_families(r: &mut Reader<'_>) -> Option<Families> {
    let mut families = Families::default();
    let slots = families.os.iter_mut().chain(&mut families.browser).chain(&mut families.status);
    for slot in slots {
        *slot = r.u64()?;
    }
    Some(families)
}

fn invalid(condition: bool) -> Result<(), ArchiveError> {
    if condition { Err(ArchiveError::InvalidArchive) } else { Ok(()) }
}

fn validate(archive: &Archive) -> Result<(), ArchiveError> {
    let minute = &archive.minute;
    let index = minute.minute.ok_or(ArchiveError::InvalidArchive)?;
    invalid(
        index > (u64::MAX - 59) / 60
            || archive.identity.boot == [0; 16]
            || archive.identity.queue_loss_end < archive.identity.queue_loss_start,
    )?;
    let paths: &Summary = &minute.paths;
    invalid(paths.samples() == 0 && (minute.first_second != 0 || minute.last_second != 0))?;
    // `index * 60 + 60` cannot overflow: the index was bounded above.
    invalid(
        paths.samples() != 0
            && (minute.first_second < index * 60
                || minute.last_second >= index * 60 + 60
                || minute.first_second > minute.last_second),
    )?;
    validate_sketch(paths)?;
    let referrers: &Referrers = &minute.referrers;
    validate_sketch(referrers)?;
    invalid(referrers.samples() > paths.samples())
}

/// Only original collector minutes are archived: their counter estimates sum to the
/// retained N. Serializing local display winners instead would silently discard global
/// candidates.
fn validate_sketch<const C: usize, const K: usize>(
    sketch: &Sketch<C, K>,
) -> Result<(), ArchiveError> {
    let counters = sketch.counters();
    let mut estimates: u64 = 0;
    for (index, counter) in counters.iter().enumerate() {
        invalid(
            counter.estimate == 0
                || counter.error_bound >= counter.estimate
                || counter.error_bound > sketch.samples() / 256,
        )?;
        invalid(counters[..index].iter().any(|previous| previous.key == counter.key))?;
        estimates = estimates.checked_add(counter.estimate).ok_or(ArchiveError::InvalidArchive)?;
    }
    invalid(estimates != sketch.samples())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_archive() -> Archive {
        let mut archive = Archive {
            identity: Identity { node: 7, boot: [9; 16], queue_loss_start: 4, queue_loss_end: 6 },
            minute: Minute {
                minute: Some(2),
                first_second: 120,
                last_second: 179,
                ..Minute::default()
            },
        };
        for i in 0..512u16 {
            let mut key = [b'a'; 128];
            key[..2].copy_from_slice(&i.to_le_bytes());
            archive.minute.paths.add(&key).unwrap();
        }
        archive
    }

    // Port of rankings_archive.zig "archive retains all 256 counters, errors, node and boot
    // with exact capacity". The Zig test was never reached from the test root and expected
    // MAX_BYTES; this archive (full paths, no referrers) is 37,784 bytes, as Zig 0.16 also
    // encodes it.
    #[test]
    fn archive_retains_all_256_counters_errors_node_and_boot() {
        let mut archive = full_archive();
        let encoded = encode(&archive).unwrap();
        assert_eq!(encoded.len(), 37_784);
        assert_eq!(decode(&encoded), Ok(archive.clone()));
        let mut buffer = vec![0u8; encoded.len()];
        assert_eq!(encode_into(&archive, &mut buffer), Ok(encoded.len()));
        assert_eq!(
            encode_into(&archive, &mut buffer[..encoded.len() - 1]),
            Err(ArchiveError::TooLarge)
        );
        assert_eq!(decode(&encoded[..encoded.len() - 1]), Err(ArchiveError::InvalidArchive));
        let mut corrupt = encoded.clone();
        corrupt[0] = b'X';
        assert_eq!(decode(&corrupt), Err(ArchiveError::InvalidArchive));
        let counters = archive.minute.paths.counters()[..20].to_vec();
        archive.minute.paths =
            Summary::from_parts(counters, archive.minute.paths.samples()).unwrap();
        assert_eq!(encode(&archive), Err(ArchiveError::InvalidArchive));
    }

    #[test]
    fn the_largest_sbr2_archive_fits_the_bound_exactly() {
        let mut archive = full_archive();
        for i in 0..512u16 {
            let mut key = [b'r'; 24];
            key[..2].copy_from_slice(&i.to_le_bytes());
            archive.minute.referrers.add(&key).unwrap();
        }
        assert_eq!(MAX_BYTES, 48_536);
        let encoded = encode(&archive).unwrap();
        assert_eq!(encoded.len(), MAX_BYTES);
        assert_eq!(decode(&encoded).unwrap(), archive);
    }

    #[test]
    fn legacy_archives_read_without_extended_dimensions() {
        let archive = full_archive();
        let encoded = encode(&archive).unwrap();
        // An SBR1 archive is the SBR2 prefix up to the end of the path sketch.
        let mut legacy = encoded[..92 + 256 * 146].to_vec();
        legacy[..4].copy_from_slice(b"SBR1");
        let decoded = decode(&legacy).unwrap();
        assert!(!decoded.minute.extended);
        assert_eq!(decoded.minute.paths, archive.minute.paths);
        assert!(decoded.minute.referrers.is_empty());
        assert_eq!(decode(&vec![0; MAX_BYTES + 1]), Err(ArchiveError::TooLarge));
    }
}
