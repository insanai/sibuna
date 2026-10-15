//! The binary payloads of the minute tables: `SBM2` traffic minutes of 176 bytes and `SBC1`
//! challenge minutes of 128 bytes plus 96 bytes per partition, all little-endian. Their
//! counters are unsigned 64-bit values that SQL integers cannot hold, so the rows keep the
//! records whole (SID 0013, "Observations").
//!
//! ```text
//! SBM2: "SBM2" node:u32 boot:[16] epoch:u32 flags:u32 minute utc_start utc_end start_ms
//!       end_ms observed_ms (u64 each) observations:u32 present:u32 counts:[u64; 8]
//!       rss_last_kib rss_max_kib cpu_ms (u64 each; absent ones are 0 with their bit clear)
//! SBC1: "SBC1" node:u32 boot:[16] epoch:u32 flags:u32 minute start_ms end_ms observed_ms
//!       (u64 each) observations:u32 submitted:u32 causes:[u32; 13] count:u8 dropped:u8
//!       zero:u16, then per partition: bin:u8 zero:[3] issued:u32 accepted:u32
//!       buckets:[u32; 16] missing invalid wasm javascript unknown_solver (u32 each)
//! ```
//!
//! The Rust port writes and reads only `SBM2`; `SBM1` rows existed only in Zig databases,
//! and the schema's `CHECK` on the magic refuses them.

use sibuna_console_protocol::challenge_minutes::{self, MAX_BINS, Partition};
use sibuna_console_protocol::challenges::{BUCKET_COUNT, CAUSE_COUNT};
use sibuna_console_protocol::minutes;
use sibuna_console_protocol::timeline::Counts;

/// The length of an `SBM2` payload.
pub const MINUTE_BYTES: usize = 176;
/// The length of an `SBC1` header.
pub const CHALLENGE_HEADER: usize = 128;
/// The length of one `SBC1` partition.
pub const CHALLENGE_PARTITION: usize = 96;
/// The longest `SBC1` payload.
pub const CHALLENGE_MAX: usize = CHALLENGE_HEADER + MAX_BINS * CHALLENGE_PARTITION;

const MINUTE_MAGIC: &[u8; 4] = b"SBM2";
const CHALLENGE_MAGIC: &[u8; 4] = b"SBC1";
const MAX_I64: u64 = i64::MAX as u64;

/// A record that breaks its format's rules, or bytes that are not such a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidArchive;

fn check(ok: bool) -> Result<(), InvalidArchive> {
    if ok { Ok(()) } else { Err(InvalidArchive) }
}

fn flags(sealed: bool, complete: bool, gap: bool) -> u32 {
    u32::from(sealed) | (u32::from(complete) << 1) | (u32::from(gap) << 2)
}

/// Checks the rules of a traffic minute: a boot and epoch, at least one observation, an
/// ordered interval whose observed time is its length, a minute that is the end's minute,
/// a complete minute sealed and gap-free, and times and gauges below 2^63.
pub fn validate_minute(record: &minutes::Record) -> Result<(), InvalidArchive> {
    let times = [
        record.minute,
        record.utc_start,
        record.utc_end,
        record.start_ms,
        record.end_ms,
        record.observed_ms,
    ];
    let gauges = [record.rss_last_kib, record.rss_max_kib, record.cpu_ms];
    check(
        record.epoch != 0
            && record.boot != [0; 16]
            && record.observations != 0
            && record.utc_start <= record.utc_end
            && record.minute == record.utc_end / 60
            && record.end_ms > record.start_ms
            && record.observed_ms == record.end_ms - record.start_ms
            && (!record.complete || (record.sealed && !record.gap))
            && times.iter().all(|&time| time <= MAX_I64)
            && gauges.iter().flatten().all(|&gauge| gauge <= MAX_I64),
    )
}

/// Encodes a traffic minute as `SBM2`. Fails with [`InvalidArchive`] when
/// [`validate_minute`] does.
pub fn encode_minute(record: &minutes::Record) -> Result<Vec<u8>, InvalidArchive> {
    validate_minute(record)?;
    let mut out = Vec::with_capacity(MINUTE_BYTES);
    out.extend_from_slice(MINUTE_MAGIC);
    out.extend_from_slice(&record.node.to_le_bytes());
    out.extend_from_slice(&record.boot);
    out.extend_from_slice(&record.epoch.to_le_bytes());
    out.extend_from_slice(&flags(record.sealed, record.complete, record.gap).to_le_bytes());
    for time in [
        record.minute,
        record.utc_start,
        record.utc_end,
        record.start_ms,
        record.end_ms,
        record.observed_ms,
    ] {
        out.extend_from_slice(&time.to_le_bytes());
    }
    out.extend_from_slice(&record.observations.to_le_bytes());
    let gauges = [record.rss_last_kib, record.rss_max_kib, record.cpu_ms];
    let present = (0u32..)
        .zip(gauges)
        .fold(0, |bits, (bit, gauge)| bits | (u32::from(gauge.is_some()) << bit));
    out.extend_from_slice(&present.to_le_bytes());
    for count in record.counts.values() {
        out.extend_from_slice(&count.to_le_bytes());
    }
    for gauge in gauges {
        out.extend_from_slice(&gauge.unwrap_or(0).to_le_bytes());
    }
    Ok(out)
}

/// Decodes an `SBM2` payload and checks it with [`validate_minute`]. Fails with
/// [`InvalidArchive`] for another length or magic, reserved flag or presence bits, or a
/// record that breaks the rules.
pub fn decode_minute(bytes: &[u8]) -> Result<minutes::Record, InvalidArchive> {
    check(bytes.len() == MINUTE_BYTES)?;
    let mut r = Reader { bytes };
    check(r.take(4)? == MINUTE_MAGIC)?;
    let node = r.u32()?;
    let boot = r.array::<16>()?;
    let epoch = r.u32()?;
    let flags = r.u32()?;
    check(flags <= 7)?;
    let [minute, utc_start, utc_end, start_ms, end_ms, observed_ms] =
        [r.u64()?, r.u64()?, r.u64()?, r.u64()?, r.u64()?, r.u64()?];
    let observations = r.u32()?;
    let present = r.u32()?;
    check(present <= 7)?;
    let mut counts = [0u64; 8];
    for count in &mut counts {
        *count = r.u64()?;
    }
    let mut gauges = [None; 3];
    for (bit, gauge) in (0u32..).zip(&mut gauges) {
        let value = r.u64()?;
        let is_present = present >> bit & 1 != 0;
        // An absent gauge is written as zero; anything else is not a record we wrote.
        check(is_present || value == 0)?;
        *gauge = is_present.then_some(value);
    }
    let [rss_last_kib, rss_max_kib, cpu_ms] = gauges;
    let record = minutes::Record {
        node,
        boot,
        epoch,
        minute,
        utc_start,
        utc_end,
        start_ms,
        end_ms,
        observed_ms,
        observations,
        sealed: flags & 1 != 0,
        complete: flags & 2 != 0,
        gap: flags & 4 != 0,
        counts: Counts::from_values(counts),
        rss_last_kib,
        rss_max_kib,
        cpu_ms,
    };
    validate_minute(&record)?;
    Ok(record)
}

/// Checks the rules of a challenge minute: a boot and epoch, at least one observation, an
/// ordered interval whose observed time is its length, at most [`MAX_BINS`] consistent
/// partitions in ascending order, a complete minute sealed and gap-free, and times below
/// 2^63.
pub fn validate_challenge(record: &challenge_minutes::Record) -> Result<(), InvalidArchive> {
    check(
        record.epoch != 0
            && record.boot != [0; 16]
            && record.observations != 0
            && record.end_ms > record.start_ms
            && record.observed_ms == record.end_ms - record.start_ms
            && record.bins.len() <= MAX_BINS
            && record.minute <= MAX_I64
            && record.end_ms <= MAX_I64
            && (!record.complete || (record.sealed && !record.gap))
            && record.bins.iter().all(Partition::is_consistent)
            && record.bins.windows(2).all(|pair| matches!(pair, [a, b] if a.bin < b.bin)),
    )
}

/// Encodes a challenge minute as `SBC1`. Fails with [`InvalidArchive`] when
/// [`validate_challenge`] does.
pub fn encode_challenge(record: &challenge_minutes::Record) -> Result<Vec<u8>, InvalidArchive> {
    validate_challenge(record)?;
    let count = u8::try_from(record.bins.len()).map_err(|_| InvalidArchive)?;
    let mut out = Vec::with_capacity(CHALLENGE_HEADER + record.bins.len() * CHALLENGE_PARTITION);
    out.extend_from_slice(CHALLENGE_MAGIC);
    out.extend_from_slice(&record.node.to_le_bytes());
    out.extend_from_slice(&record.boot);
    out.extend_from_slice(&record.epoch.to_le_bytes());
    out.extend_from_slice(&flags(record.sealed, record.complete, record.gap).to_le_bytes());
    for time in [record.minute, record.start_ms, record.end_ms, record.observed_ms] {
        out.extend_from_slice(&time.to_le_bytes());
    }
    out.extend_from_slice(&record.observations.to_le_bytes());
    out.extend_from_slice(&record.submitted.to_le_bytes());
    for cause in record.causes {
        out.extend_from_slice(&cause.to_le_bytes());
    }
    out.extend_from_slice(&[count, record.bins_dropped, 0, 0]);
    for entry in &record.bins {
        out.extend_from_slice(&[entry.bin, 0, 0, 0]);
        let tail = [entry.missing, entry.invalid, entry.wasm, entry.javascript];
        let values = [entry.issued, entry.accepted].into_iter().chain(entry.buckets);
        for value in values.chain(tail).chain([entry.unknown_solver]) {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    Ok(out)
}

/// Decodes an `SBC1` payload and checks it with [`validate_challenge`]. Fails with
/// [`InvalidArchive`] for a length that is not a header and whole partitions, another
/// magic, reserved bits or padding, a partition count that disagrees with the length, or a
/// record that breaks the rules.
pub fn decode_challenge(bytes: &[u8]) -> Result<challenge_minutes::Record, InvalidArchive> {
    check(
        (CHALLENGE_HEADER..=CHALLENGE_MAX).contains(&bytes.len())
            && (bytes.len() - CHALLENGE_HEADER).is_multiple_of(CHALLENGE_PARTITION),
    )?;
    let partitions = (bytes.len() - CHALLENGE_HEADER) / CHALLENGE_PARTITION;
    let mut r = Reader { bytes };
    check(r.take(4)? == CHALLENGE_MAGIC)?;
    let (node, boot, epoch, flags) = (r.u32()?, r.array::<16>()?, r.u32()?, r.u32()?);
    check(flags <= 7)?;
    let [minute, start_ms, end_ms, observed_ms] = [r.u64()?, r.u64()?, r.u64()?, r.u64()?];
    let (observations, submitted) = (r.u32()?, r.u32()?);
    let mut causes = [0u32; CAUSE_COUNT];
    for cause in &mut causes {
        *cause = r.u32()?;
    }
    let [count, bins_dropped, pad_low, pad_high] = r.array::<4>()?;
    check(pad_low == 0 && pad_high == 0 && usize::from(count) == partitions)?;
    let mut bins = Vec::with_capacity(partitions);
    for _ in 0..partitions {
        bins.push(read_partition(&mut r)?);
    }
    let record = challenge_minutes::Record {
        node,
        boot,
        epoch,
        minute,
        start_ms,
        end_ms,
        observed_ms,
        observations,
        sealed: flags & 1 != 0,
        complete: flags & 2 != 0,
        gap: flags & 4 != 0,
        submitted,
        causes,
        bins,
        bins_dropped,
    };
    validate_challenge(&record)?;
    Ok(record)
}

fn read_partition(r: &mut Reader<'_>) -> Result<Partition, InvalidArchive> {
    let [bin, a, b, c] = r.array::<4>()?;
    check(a == 0 && b == 0 && c == 0)?;
    let (issued, accepted) = (r.u32()?, r.u32()?);
    let mut buckets = [0u32; BUCKET_COUNT];
    for bucket in &mut buckets {
        *bucket = r.u32()?;
    }
    Ok(Partition {
        bin,
        issued,
        accepted,
        buckets,
        missing: r.u32()?,
        invalid: r.u32()?,
        wasm: r.u32()?,
        javascript: r.u32()?,
        unknown_solver: r.u32()?,
    })
}

/// Reads little-endian values from the front of a byte slice; running out of bytes is
/// [`InvalidArchive`].
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], InvalidArchive> {
        let (head, rest) = self.bytes.split_at_checked(length).ok_or(InvalidArchive)?;
        self.bytes = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], InvalidArchive> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| InvalidArchive)
    }

    fn u32(&mut self) -> Result<u32, InvalidArchive> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64, InvalidArchive> {
        self.array().map(u64::from_le_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minute() -> minutes::Record {
        minutes::Record {
            node: 7,
            boot: [b'a'; 16],
            epoch: 1,
            minute: 2,
            utc_start: 119,
            utc_end: 179,
            start_ms: 1000,
            end_ms: 61_000,
            observed_ms: 60_000,
            observations: 240,
            sealed: true,
            complete: true,
            counts: Counts::from_values([u64::MAX; 8]),
            ..minutes::Record::default()
        }
    }

    // Port of minute_archive.zig "minute format preserves maximum counters, rejects
    // reserved bits and validates coverage" (without the SBM1 rows Rust never reads).
    #[test]
    fn minute_format_preserves_maximum_counters_and_rejects_reserved_bits() {
        let mut record = minute();
        let mut encoded = encode_minute(&record).unwrap();
        assert_eq!(encoded.len(), MINUTE_BYTES);
        assert_eq!(decode_minute(&encoded), Ok(record));
        assert_eq!(decode_minute(&encoded[..MINUTE_BYTES - 1]), Err(InvalidArchive));
        encoded[31] = 1;
        assert_eq!(decode_minute(&encoded), Err(InvalidArchive));
        encoded[31] = 0;
        encoded[87] = 1;
        assert_eq!(decode_minute(&encoded), Err(InvalidArchive));
        encoded[87] = 0;
        encoded[0] = b'X';
        assert_eq!(decode_minute(&encoded), Err(InvalidArchive));
        record.rss_last_kib = Some(51_200);
        record.cpu_ms = Some(730);
        let gauged = decode_minute(&encode_minute(&record).unwrap()).unwrap();
        assert_eq!(
            (gauged.rss_last_kib, gauged.rss_max_kib, gauged.cpu_ms),
            (Some(51_200), None, Some(730))
        );
        record.gap = true;
        assert_eq!(encode_minute(&record), Err(InvalidArchive));
        record.complete = false;
        record.observed_ms -= 1;
        assert_eq!(encode_minute(&record), Err(InvalidArchive));
    }

    fn challenge() -> challenge_minutes::Record {
        let mut record = challenge_minutes::Record {
            node: 7,
            boot: [b'a'; 16],
            epoch: 1,
            minute: 2,
            start_ms: 60_000,
            end_ms: 120_000,
            observed_ms: 60_000,
            observations: 240,
            sealed: true,
            complete: true,
            submitted: 9,
            ..challenge_minutes::Record::default()
        };
        record.causes[12] = u32::MAX;
        let first = record.partition(133).unwrap();
        *first = Partition {
            bin: 133,
            issued: 4,
            accepted: 2,
            missing: 1,
            wasm: 2,
            ..Partition::default()
        };
        first.buckets[3] = 1;
        let _ = record.partition(200).unwrap();
        record
    }

    // Port of challenge_archive.zig "challenge minute format round-trips partitions and
    // rejects inconsistent or unsorted ones".
    #[test]
    fn challenge_format_round_trips_partitions_and_rejects_inconsistent_ones() {
        let mut record = challenge();
        let encoded = encode_challenge(&record).unwrap();
        assert_eq!(encoded.len(), CHALLENGE_HEADER + 2 * CHALLENGE_PARTITION);
        assert_eq!(decode_challenge(&encoded), Ok(record.clone()));
        assert_eq!(decode_challenge(&encoded[..encoded.len() - 1]), Err(InvalidArchive));
        let mut padded = encoded.clone();
        padded[CHALLENGE_HEADER + 1] = 1;
        assert_eq!(decode_challenge(&padded), Err(InvalidArchive));
        let mut short = encoded.clone();
        short[124] = 3;
        assert_eq!(decode_challenge(&short), Err(InvalidArchive));
        record.bins[0].wasm = 1;
        assert_eq!(encode_challenge(&record), Err(InvalidArchive));
        record.bins[0].wasm = 2;
        record.bins[1].bin = 100;
        assert_eq!(encode_challenge(&record), Err(InvalidArchive));
        record.bins[1].bin = 200;
        record.gap = true;
        assert_eq!(encode_challenge(&record), Err(InvalidArchive));
    }

    /// A small xorshift generator, so the fuzz test is deterministic and dependency-free.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
        }
    }

    /// Mutated payloads never panic the decoders, and whatever decodes re-encodes to the
    /// same bytes.
    #[test]
    fn fuzz_decoders_round_trip_or_refuse() {
        let seeds = [encode_minute(&minute()).unwrap(), encode_challenge(&challenge()).unwrap()];
        let mut rng = Xorshift(0x0bad_5eed_0013_0040);
        let mut accepted = 0;
        for _ in 0..100_000 {
            let mut bytes = seeds[rng.below(seeds.len())].clone();
            for _ in 0..rng.below(4) {
                match rng.below(4) {
                    _ if bytes.is_empty() => bytes.push(rng.next() as u8),
                    0 => {
                        let at = rng.below(bytes.len());
                        bytes[at] ^= 1 << rng.below(8);
                    }
                    1 => bytes.truncate(rng.below(bytes.len() + 1)),
                    2 => bytes.extend((0..rng.below(200)).map(|_| rng.next() as u8)),
                    _ => {
                        let at = rng.below(bytes.len());
                        bytes[at] = rng.next() as u8;
                    }
                }
            }
            if let Ok(record) = decode_minute(&bytes) {
                assert_eq!(encode_minute(&record).unwrap(), bytes);
                accepted += 1;
            }
            if let Ok(record) = decode_challenge(&bytes) {
                assert_eq!(encode_challenge(&record).unwrap(), bytes);
                accepted += 1;
            }
        }
        assert!(accepted > 0);
    }
}
