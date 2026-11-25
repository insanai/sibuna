#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::Put;
use crate::format::{DATA_START, HEADER_SEED, SLOT_LEN};

const NOW: u64 = 1_000_000;
const LATER: u64 = NOW + 600;
const OPTIONS: Options = Options { size: 1 << 20, max_ttl: 3_600 };

/// A directory of its own for one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-spill-{}-{serial}", std::process::id());
        let path = std::env::temp_dir().join(name);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("hints.spill")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn key(number: u32) -> [u8; 8] {
    let mut bytes = *b"key-0000";
    bytes[4..].copy_from_slice(&number.to_le_bytes());
    bytes
}

/// Opens the cache, stores 1,000 hints and closes it.
fn seed(path: &Path) {
    let (mut cache, report) = load_cache(path, &OPTIONS, NOW).unwrap();
    assert_eq!(report.outcome, Outcome::Created);
    for number in 0..200 {
        assert_eq!(cache.put(&key(number), b"server", LATER, NOW), Put::Stored);
    }
    cache.flush().unwrap();
}

fn kept(cache: &mut Cache) -> usize {
    (0..200).filter(|&number| cache.get(&key(number), NOW).is_some()).count()
}

/// Overwrites `bytes` at `offset` of the closed file.
fn patch(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
}

fn reopen(path: &Path) -> (Cache, Report) {
    load_cache(path, &OPTIONS, NOW).unwrap()
}

#[test]
fn hints_survive_closing_and_opening_the_file() {
    let scratch = Scratch::new();
    seed(&scratch.file());
    let (mut cache, report) = reopen(&scratch.file());
    assert_eq!(report.outcome, Outcome::Reused);
    assert!(report.persistent && cache.is_persistent());
    assert_eq!(report.slots, cache.slot_count());
    assert_eq!(kept(&mut cache), 200);
    let hint = cache.get(&key(7), NOW).unwrap();
    assert_eq!((hint.value(), hint.expires), (&b"server"[..], LATER));
    // The file has exactly the length of its geometry and no neighbour is left behind.
    let len = fs::metadata(scratch.file()).unwrap().len();
    assert_eq!(len, Geometry::for_size(OPTIONS.size).unwrap().file_len());
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 1);
    // After their time the hints are gone, whatever the file says.
    assert_eq!(cache.get(&key(7), LATER), None);
}

#[cfg(unix)]
#[test]
fn the_file_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    seed(&scratch.file());
    let mode = fs::metadata(scratch.file()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_damaged_header_discards_the_whole_file() {
    let scratch = Scratch::new();
    seed(&scratch.file());
    // One byte of the salt.
    patch(&scratch.file(), 41, &[0xff]);
    let (mut cache, report) = reopen(&scratch.file());
    assert_eq!(report.outcome, Outcome::Discarded(Reason::Header));
    assert_eq!(kept(&mut cache), 0);
    assert_eq!(cache.put(&key(1), b"server", LATER, NOW), Put::Stored);
    drop(cache);
    assert_eq!(reopen(&scratch.file()).1.outcome, Outcome::Reused);
}

#[test]
fn another_version_discards_the_whole_file() {
    let scratch = Scratch::new();
    seed(&scratch.file());
    let mut header = [0; HEADER_LEN];
    File::open(scratch.file()).unwrap().read_exact(&mut header).unwrap();
    header[8..12].copy_from_slice(&7u32.to_le_bytes());
    let check = sibuna_crypto::wyhash::hash(HEADER_SEED, &header[..56]);
    header[56..].copy_from_slice(&check.to_le_bytes());
    patch(&scratch.file(), 0, &header);
    let (mut cache, report) = reopen(&scratch.file());
    assert_eq!(report.outcome, Outcome::Discarded(Reason::Version(7)));
    assert_eq!(kept(&mut cache), 0);
}

#[test]
fn a_truncated_or_grown_file_is_discarded() {
    let scratch = Scratch::new();
    let whole = Geometry::for_size(OPTIONS.size).unwrap().file_len();
    for len in [whole - 1, whole - SLOT_LEN as u64, DATA_START, 4096, 64, whole + 1] {
        seed(&scratch.file());
        OpenOptions::new().write(true).open(scratch.file()).unwrap().set_len(len).unwrap();
        let (mut cache, report) = reopen(&scratch.file());
        assert_eq!(report.outcome, Outcome::Discarded(Reason::Length { found: len }), "{len}");
        assert_eq!(kept(&mut cache), 0);
        assert_eq!(fs::metadata(scratch.file()).unwrap().len(), whole);
        drop(cache);
        fs::remove_file(scratch.file()).unwrap();
    }
    // Cut inside the header: the magic is there and the rest is not.
    seed(&scratch.file());
    OpenOptions::new().write(true).open(scratch.file()).unwrap().set_len(40).unwrap();
    assert_eq!(reopen(&scratch.file()).1.outcome, Outcome::Discarded(Reason::Header));
}

#[test]
fn a_file_of_another_size_is_discarded() {
    let scratch = Scratch::new();
    seed(&scratch.file());
    let larger = Options { size: 2 << 20, ..OPTIONS };
    let (mut cache, report) = load_cache(&scratch.file(), &larger, NOW).unwrap();
    let was = Geometry::for_size(OPTIONS.size).unwrap().file_len();
    assert_eq!(report.outcome, Outcome::Discarded(Reason::Size { found: was }));
    assert_eq!(kept(&mut cache), 0);
    assert_eq!(report.slots, Geometry::for_size(2 << 20).unwrap().slot_count());
    drop(cache);
    // A size that gives the same number of buckets is the same file.
    let again = Options { size: (2 << 20) + 100, ..OPTIONS };
    assert_eq!(load_cache(&scratch.file(), &again, NOW).unwrap().1.outcome, Outcome::Reused);
}

#[test]
fn a_file_that_is_not_a_cache_is_refused_and_left_alone() {
    let scratch = Scratch::new();
    for content in [&b"important notes, not a cache"[..], &[0; 8192], b"SIBS"] {
        fs::write(scratch.file(), content).unwrap();
        let error = load_cache(&scratch.file(), &OPTIONS, NOW).err().unwrap();
        assert_eq!(error.code, "SPILL002");
        assert!(error.to_string().contains("Hint: Name another path"), "{error}");
        assert_eq!(fs::read(scratch.file()).unwrap(), content);
    }
    // An empty file holds nothing to lose.
    fs::write(scratch.file(), b"").unwrap();
    assert_eq!(reopen(&scratch.file()).1.outcome, Outcome::Created);
}

#[test]
fn a_second_opener_finds_the_cache_in_use() {
    let scratch = Scratch::new();
    let (first, _) = reopen(&scratch.file());
    let error = load_cache(&scratch.file(), &OPTIONS, NOW).err().unwrap();
    assert!(error.is_busy(), "{error}");
    drop(first);
    assert_eq!(reopen(&scratch.file()).1.outcome, Outcome::Reused);
}

#[test]
fn a_size_out_of_range_and_a_missing_directory_are_named() {
    let scratch = Scratch::new();
    for size in [0, crate::MIN_SIZE - 1, crate::MAX_SIZE + 1, u64::MAX] {
        let error = load_cache(&scratch.file(), &Options { size, ..OPTIONS }, NOW).err().unwrap();
        assert_eq!(error.code, "SPILL001");
    }
    assert!(!scratch.file().exists());
    let nowhere = scratch.0.join("missing").join("hints.spill");
    let error = load_cache(&nowhere, &OPTIONS, NOW).err().unwrap();
    assert_eq!(error.code, "SPILL004");
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn damaged_slots_cost_their_hints_and_no_others() {
    let scratch = Scratch::new();
    seed(&scratch.file());
    let whole = Geometry::for_size(OPTIONS.size).unwrap().file_len();
    // Noise over the second half of the slots.
    let middle = DATA_START + (whole - DATA_START) / 2;
    let noise: Vec<u8> = (0..whole - middle).map(|at| (at * 31 % 251) as u8 | 1).collect();
    patch(&scratch.file(), middle, &noise);
    let (mut cache, report) = reopen(&scratch.file());
    assert_eq!(report.outcome, Outcome::Reused);
    let survivors = kept(&mut cache);
    // The keys spread evenly, so about half of them lay in the damaged half.
    assert!((60..140).contains(&survivors), "{survivors}");
    assert!(cache.counters().corrupt > 0);
    // Every surviving hint still has its value.
    for number in 0..200 {
        if let Some(hint) = cache.get(&key(number), NOW) {
            assert_eq!(hint.value(), b"server");
        }
    }
    // The cleared slots take hints again.
    for number in 0..200 {
        cache.put(&key(number), b"server", LATER, NOW);
    }
    assert_eq!(kept(&mut cache), 200);
}

#[test]
fn a_slot_that_was_half_written_is_not_trusted() {
    let scratch = Scratch::new();
    let (mut cache, _) = reopen(&scratch.file());
    assert_eq!(cache.put(b"client", b"server-a", LATER, NOW), Put::Stored);
    drop(cache);
    // Find the slot, then write a part of what an update would have written: a new
    // expiry over the old checksum, key and value.
    let bytes = fs::read(scratch.file()).unwrap();
    let data = &bytes[DATA_START as usize..];
    let slot = data.chunks(SLOT_LEN).position(|slot| slot[8..16] != [0; 8]).unwrap();
    let offset = DATA_START + (slot * SLOT_LEN) as u64;
    patch(&scratch.file(), offset + 8, &(LATER + 60).to_le_bytes());
    let (mut cache, report) = reopen(&scratch.file());
    assert_eq!(report.outcome, Outcome::Reused);
    assert_eq!(cache.get(b"client", NOW), None);
    assert_eq!(cache.counters().corrupt, 1);
}

#[test]
fn a_cache_in_memory_works_and_says_that_it_does_not_persist() {
    let mut cache = load_memory_cache(&OPTIONS).unwrap();
    assert!(!cache.is_persistent());
    assert_eq!(cache.put(b"client", b"server", LATER, NOW), Put::Stored);
    assert!(cache.get(b"client", NOW).is_some());
    assert!(cache.flush().is_ok());
    assert!(load_memory_cache(&Options { size: 1, ..OPTIONS }).is_err());
}

#[cfg(unix)]
#[test]
fn creating_the_cache_preserves_an_existing_sibling_and_its_target() {
    let scratch = Scratch::new();
    let precious = scratch.0.join("precious");
    fs::write(&precious, b"keep me").unwrap();
    let sibling = scratch.0.join("hints.spill.tmp");
    std::os::unix::fs::symlink(&precious, &sibling).unwrap();
    let (_cache, report) = load_cache(&scratch.file(), &OPTIONS, NOW).unwrap();
    assert_eq!(report.outcome, Outcome::Created);
    assert_eq!(fs::read(&precious).unwrap(), b"keep me");
    assert!(fs::symlink_metadata(scratch.file()).unwrap().file_type().is_file());
    assert_eq!(fs::read_link(&sibling).unwrap(), precious);
}

#[cfg(unix)]
#[test]
fn a_lock_on_a_file_that_lost_its_name_does_not_open_the_cache() {
    let scratch = Scratch::new();
    seed(&scratch.file());
    // We open the file, and before we lock it another process puts a new file there.
    let stale = open_private(&scratch.file(), false).unwrap();
    fs::rename(scratch.file(), scratch.0.join("moved")).unwrap();
    fs::write(scratch.file(), b"").unwrap();
    let stale = lock(&scratch.file(), stale).unwrap();
    assert!(!names(&scratch.file(), &stale));
    assert!(names(&scratch.0.join("moved"), &stale));
}
