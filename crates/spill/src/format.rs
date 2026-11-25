//! The bytes of the file: the header, the geometry and one slot.
//!
//! Everything here works on copies. A slot is read into a `[u8; SLOT_LEN]` and judged
//! there, so no check can be invalidated by a later change of the file.

use sibuna_crypto::wyhash;

/// The shards of a cache. A shard has a sketch and a write counter of its own.
pub const SHARDS: usize = 64;
/// The slots of a bucket.
pub const WAYS: usize = 4;
/// The bytes of one slot.
pub const SLOT_LEN: usize = 64;
/// The longest key.
pub const MAX_KEY: usize = 24;
/// The longest value.
pub const MAX_VALUE: usize = 16;
/// The version of the file format.
pub const VERSION: u32 = 1;
/// The smallest size of a cache: 64 KiB.
pub const MIN_SIZE: u64 = 64 << 10;
/// The largest size of a cache: 64 GiB.
pub const MAX_SIZE: u64 = 64 << 30;

/// The first bytes of every cache file.
pub(crate) const MAGIC: [u8; 8] = *b"SIBSPILL";
/// The bytes of the header that carry meaning.
pub(crate) const HEADER_LEN: usize = 64;
const PAGE: u64 = 4096;
/// Where the write counters of the shards start: the second page.
const STAMPS_START: u64 = PAGE;
/// Where the slots start: after the header page and the page of counters.
pub(crate) const DATA_START: u64 = 2 * PAGE;
/// The bytes that one bucket adds to every shard.
const BUCKET_ROW: u64 = (SHARDS * WAYS * SLOT_LEN) as u64;
pub(crate) const HEADER_SEED: u64 = 0x5349_4253_5049_4c4c;
/// An odd constant that spreads slot numbers over the seeds of their checksums.
const SPREAD: u64 = 0x9e37_79b9_7f4a_7c15;

/// The shape of a cache: how many buckets each shard has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// The buckets of one shard. Never zero.
    pub buckets: u64,
}

impl Geometry {
    /// The largest geometry whose file has at most `size` bytes. `None` when `size` is
    /// below [`MIN_SIZE`] or above [`MAX_SIZE`].
    pub fn for_size(size: u64) -> Option<Self> {
        if !(MIN_SIZE..=MAX_SIZE).contains(&size) {
            return None;
        }
        let buckets = (size - DATA_START) / BUCKET_ROW;
        (buckets > 0).then_some(Self { buckets })
    }

    /// The exact length of the file.
    pub fn file_len(&self) -> u64 {
        DATA_START + self.buckets * BUCKET_ROW
    }

    /// The slots of the whole cache.
    pub fn slot_count(&self) -> u64 {
        self.buckets * (SHARDS * WAYS) as u64
    }

    /// The slots of one shard.
    pub fn shard_slot_count(&self) -> u64 {
        self.buckets * WAYS as u64
    }

    /// The shard and the bucket of a key whose salted hash is `hash`.
    pub(crate) fn place(&self, hash: u64) -> (usize, u64) {
        let shard = (hash & (SHARDS as u64 - 1)) as usize;
        // The other 58 bits scaled to the number of buckets: below `buckets`.
        let bucket = ((u128::from(hash >> 6) * u128::from(self.buckets)) >> 58) as u64;
        (shard, bucket.min(self.buckets - 1))
    }

    /// The number of the slot `way` of `bucket` in `shard`.
    pub(crate) fn slot_index(&self, shard: usize, bucket: u64, way: usize) -> u64 {
        (shard as u64 * self.buckets + bucket) * WAYS as u64 + way as u64
    }

    /// Where the slot number `index` starts in the file.
    pub(crate) fn slot_offset(index: u64) -> u64 {
        DATA_START + index * SLOT_LEN as u64
    }

    /// Where the write counter of `shard` is kept in the file.
    pub(crate) fn stamp_offset(shard: usize) -> u64 {
        STAMPS_START + shard as u64 * 8
    }
}

/// The header of a file that passed its checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub geometry: Geometry,
    pub file_len: u64,
    pub salt: u64,
}

/// What the first bytes of a file say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderState {
    /// The bytes do not start with the magic: the file is not a cache.
    Foreign,
    /// The magic is there and the rest is cut short or fails its checksum.
    Damaged,
    /// A whole header of another version of the format.
    Version(u32),
    /// A whole header of this version.
    Valid(Header),
}

fn u32_at(bytes: &[u8; HEADER_LEN], at: usize) -> u32 {
    let mut field = [0; 4];
    field.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(field)
}

fn u64_at(bytes: &[u8; SLOT_LEN], at: usize) -> u64 {
    let mut field = [0; 8];
    field.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(field)
}

/// The header of a new file of `geometry` with the given `salt`, created at `now`.
pub(crate) fn write_header(geometry: Geometry, salt: u64, now: u64) -> [u8; HEADER_LEN] {
    let mut bytes = [0; HEADER_LEN];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..12].copy_from_slice(&VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&(SLOT_LEN as u32).to_le_bytes());
    bytes[16..20].copy_from_slice(&(SHARDS as u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&(WAYS as u32).to_le_bytes());
    bytes[24..32].copy_from_slice(&geometry.buckets.to_le_bytes());
    bytes[32..40].copy_from_slice(&geometry.file_len().to_le_bytes());
    bytes[40..48].copy_from_slice(&salt.to_le_bytes());
    bytes[48..56].copy_from_slice(&now.to_le_bytes());
    let check = wyhash::hash(HEADER_SEED, &bytes[..56]);
    bytes[56..].copy_from_slice(&check.to_le_bytes());
    bytes
}

/// Judges the first bytes of a file. `bytes` may be shorter than a header.
pub(crate) fn read_header(bytes: &[u8]) -> HeaderState {
    if !bytes.starts_with(&MAGIC) {
        return HeaderState::Foreign;
    }
    let Some(header) = bytes.first_chunk::<HEADER_LEN>() else {
        return HeaderState::Damaged;
    };
    if wyhash::hash(HEADER_SEED, &header[..56]) != u64_at(header, 56) {
        return HeaderState::Damaged;
    }
    let version = u32_at(header, 8);
    if version != VERSION {
        return HeaderState::Version(version);
    }
    let shape = [u32_at(header, 12), u32_at(header, 16), u32_at(header, 20)];
    let buckets = u64_at(header, 24);
    if shape != [SLOT_LEN as u32, SHARDS as u32, WAYS as u32] || buckets == 0 {
        return HeaderState::Damaged;
    }
    let geometry = Geometry { buckets };
    HeaderState::Valid(Header { geometry, file_len: u64_at(header, 32), salt: u64_at(header, 40) })
}

/// What one slot holds at a given time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotState {
    /// Never written, or cleared.
    Empty,
    /// The bytes do not pass their checks. They are free space.
    Corrupt,
    /// A whole entry whose time has passed. It is free space.
    Expired,
    /// A whole entry that may be used.
    Live(Entry),
}

/// An entry that passed every check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub key: [u8; MAX_KEY],
    pub key_len: u8,
    pub value: [u8; MAX_VALUE],
    pub value_len: u8,
    pub expires: u64,
    pub stamp: u32,
}

impl Entry {
    pub fn key(&self) -> &[u8] {
        self.key.get(..usize::from(self.key_len)).unwrap_or(&[])
    }
}

/// The seed of the checksum of slot number `index` in a file of `salt`.
fn slot_seed(salt: u64, index: u64) -> u64 {
    salt ^ index.wrapping_add(1).wrapping_mul(SPREAD)
}

/// The bytes of a slot that holds `key` and `value` until `expires`.
///
/// The caller has checked the lengths: a longer key or value is cut, which no caller
/// relies on.
pub(crate) fn write_slot(
    key: &[u8],
    value: &[u8],
    expires: u64,
    stamp: u32,
    salt: u64,
    index: u64,
) -> [u8; SLOT_LEN] {
    let key = key.get(..MAX_KEY).unwrap_or(key);
    let value = value.get(..MAX_VALUE).unwrap_or(value);
    let mut bytes = [0; SLOT_LEN];
    bytes[8..16].copy_from_slice(&expires.to_le_bytes());
    bytes[16..20].copy_from_slice(&stamp.to_le_bytes());
    bytes[20] = key.len() as u8;
    bytes[21] = value.len() as u8;
    bytes[24..24 + key.len()].copy_from_slice(key);
    bytes[48..48 + value.len()].copy_from_slice(value);
    let check = wyhash::hash(slot_seed(salt, index), &bytes[8..]);
    bytes[..8].copy_from_slice(&check.to_le_bytes());
    bytes
}

/// Judges the copy `bytes` of slot number `index` at the time `now`.
///
/// A slot is live only when its lengths are in range, its padding is zero, its checksum
/// belongs to this file and this slot, and its expiry lies after `now` and at most
/// `max_ttl` after it.
pub(crate) fn read_slot(
    bytes: &[u8; SLOT_LEN],
    salt: u64,
    index: u64,
    now: u64,
    max_ttl: u64,
) -> SlotState {
    let expires = u64_at(bytes, 8);
    if expires == 0 {
        return SlotState::Empty;
    }
    let (key_len, value_len) = (bytes[20], bytes[21]);
    let lengths = (1..=MAX_KEY).contains(&usize::from(key_len))
        && usize::from(value_len) <= MAX_VALUE
        && bytes[22..24] == [0, 0];
    if !lengths {
        return SlotState::Corrupt;
    }
    let padded = bytes[24 + usize::from(key_len)..48].iter().all(|&byte| byte == 0)
        && bytes[48 + usize::from(value_len)..].iter().all(|&byte| byte == 0);
    if !padded || wyhash::hash(slot_seed(salt, index), &bytes[8..]) != u64_at(bytes, 0) {
        return SlotState::Corrupt;
    }
    if expires <= now {
        return SlotState::Expired;
    }
    if expires > now.saturating_add(max_ttl) {
        return SlotState::Corrupt;
    }
    let mut entry =
        Entry { key: [0; MAX_KEY], key_len, value: [0; MAX_VALUE], value_len, expires, stamp: 0 };
    entry.key.copy_from_slice(&bytes[24..48]);
    entry.value.copy_from_slice(&bytes[48..]);
    let mut stamp = [0; 4];
    stamp.copy_from_slice(&bytes[16..20]);
    entry.stamp = u32::from_le_bytes(stamp);
    SlotState::Live(entry)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn the_geometry_fits_the_size_and_places_every_hash_inside() {
        assert_eq!(Geometry::for_size(MIN_SIZE - 1), None);
        assert_eq!(Geometry::for_size(MAX_SIZE + 1), None);
        let small = Geometry::for_size(MIN_SIZE).unwrap();
        assert_eq!(small.buckets, 3);
        assert_eq!(small.file_len(), 8192 + 3 * 16384);
        assert!(small.file_len() <= MIN_SIZE);
        let large = Geometry::for_size(MAX_SIZE).unwrap();
        assert!(large.file_len() <= MAX_SIZE && MAX_SIZE - large.file_len() < 16384);
        for geometry in [small, Geometry { buckets: 1 }, Geometry { buckets: 1000 }, large] {
            for hash in [0, 1, 63, 64, u64::MAX, u64::MAX - 63, 0x1234_5678_9abc_def0] {
                let (shard, bucket) = geometry.place(hash);
                assert!(shard < SHARDS && bucket < geometry.buckets);
                let index = geometry.slot_index(shard, bucket, WAYS - 1);
                assert!(index < geometry.slot_count());
                let end = Geometry::slot_offset(index) + SLOT_LEN as u64;
                assert!(end <= geometry.file_len());
            }
        }
        // The last slot ends where the file ends.
        let last = large.slot_index(SHARDS - 1, large.buckets - 1, WAYS - 1);
        assert_eq!(Geometry::slot_offset(last) + SLOT_LEN as u64, large.file_len());
    }

    #[test]
    fn a_header_is_read_back_and_every_damage_is_named() {
        let geometry = Geometry { buckets: 7 };
        let header = write_header(geometry, 99, 1_000);
        let valid = Header { geometry, file_len: geometry.file_len(), salt: 99 };
        assert_eq!(read_header(&header), HeaderState::Valid(valid));
        assert_eq!(read_header(&header[..63]), HeaderState::Damaged);
        assert_eq!(read_header(&header[..8]), HeaderState::Damaged);
        assert_eq!(read_header(&header[..7]), HeaderState::Foreign);
        assert_eq!(read_header(&[]), HeaderState::Foreign);
        assert_eq!(read_header(&[0; 64]), HeaderState::Foreign);
        assert_eq!(
            read_header(b"SQLite format 3\0 and more bytes follow here"),
            HeaderState::Foreign
        );
        // Every single flipped bit after the magic is found.
        for bit in 64..HEADER_LEN * 8 {
            let mut bad = header;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(read_header(&bad), HeaderState::Damaged, "bit {bit}");
        }
        // Another version with a right checksum is named as a version.
        let mut next = header;
        next[8..12].copy_from_slice(&2u32.to_le_bytes());
        let check = wyhash::hash(HEADER_SEED, &next[..56]);
        next[56..].copy_from_slice(&check.to_le_bytes());
        assert_eq!(read_header(&next), HeaderState::Version(2));
    }

    #[test]
    fn a_slot_is_read_back_only_at_its_place_in_its_file_and_in_its_time() {
        let slot = write_slot(b"client", b"srv", 500, 7, 42, 9);
        let SlotState::Live(entry) = read_slot(&slot, 42, 9, 100, 1_000) else {
            panic!("the slot is live");
        };
        assert_eq!(
            (entry.key(), entry.value_len, entry.expires, entry.stamp),
            (&b"client"[..], 3, 500, 7)
        );
        assert_eq!(&entry.value[..3], b"srv");
        assert_eq!(read_slot(&slot, 42, 9, 500, 1_000), SlotState::Expired);
        assert_eq!(read_slot(&slot, 42, 9, 499, 1), SlotState::Live(entry));
        // The expiry lies further ahead than any hint may live.
        assert_eq!(read_slot(&slot, 42, 9, 100, 399), SlotState::Corrupt);
        // Another slot, another file.
        assert_eq!(read_slot(&slot, 42, 10, 100, 1_000), SlotState::Corrupt);
        assert_eq!(read_slot(&slot, 43, 9, 100, 1_000), SlotState::Corrupt);
        assert_eq!(read_slot(&[0; SLOT_LEN], 42, 9, 100, 1_000), SlotState::Empty);
    }

    #[test]
    fn every_flipped_bit_of_a_slot_is_found() {
        let slot = write_slot(&[7; MAX_KEY], &[9; MAX_VALUE], 500, u32::MAX, 42, 0);
        assert!(matches!(read_slot(&slot, 42, 0, 100, 1_000), SlotState::Live(_)));
        for bit in 0..SLOT_LEN * 8 {
            let mut bad = slot;
            bad[bit / 8] ^= 1 << (bit % 8);
            let state = read_slot(&bad, 42, 0, 100, 1_000);
            assert!(!matches!(state, SlotState::Live(_)), "bit {bit}: {state:?}");
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_are_almost_never_live() {
        let mut state = 0x1234_5678_u64;
        let mut live = 0;
        for round in 0..200_000u64 {
            let mut bytes = [0; SLOT_LEN];
            for chunk in bytes.as_chunks_mut::<8>().0 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *chunk = (state ^ (state >> 29)).to_le_bytes();
            }
            // Half of the rounds have lengths in range, so that the checksum decides.
            if round % 2 == 0 {
                bytes[20] = 1 + (bytes[20] % MAX_KEY as u8);
                bytes[21] %= MAX_VALUE as u8 + 1;
                bytes[22..24].fill(0);
                let (key, value) = (usize::from(bytes[20]), usize::from(bytes[21]));
                bytes[24 + key..48].fill(0);
                bytes[48 + value..].fill(0);
            }
            if matches!(read_slot(&bytes, 1, round, 0, u64::MAX), SlotState::Live(_)) {
                live += 1;
            }
        }
        assert_eq!(live, 0);
    }
}
