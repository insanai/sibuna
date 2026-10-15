//! Deterministic fuzzing of the CSV loader, the snapshot decoder, the storage row decoder
//! and the address parser.
//!
//! A xorshift generator builds valid inputs and mutates them (bit flips, structural bytes,
//! truncation, duplication, splicing). Every input must be handled without a panic, and:
//!
//! - the loader gives the same result for any chunking, agrees with a naive reference
//!   loader, and every generation it accepts survives the snapshot and storage formats;
//! - an accepted snapshot re-encodes to exactly its own bytes (the encoding is canonical)
//!   and never holds more ranges than its payload can describe;
//! - accepted storage rows re-encode to their own bytes, refused rows append nothing, and
//!   the batch check agrees with a naive reference;
//! - an accepted address text formats and parses back to the same address.

// Test helpers outside #[test] functions fail loudly on unexpected errors.
#![allow(clippy::unwrap_used)]

mod common;

use common::XorShift;
use sibuna_crypto::sha256::Sha256;
use sibuna_geoip::{
    Country, Database, LoadError, Loader, MAX_LINE, Provenance, Provider, Range, RangeError,
    Version, address, country, range, snapshot, wire,
};

const ITERATIONS: usize = 100_000;

/// Bytes that change the structure of the inputs when they replace or join others.
const STRUCTURAL: &[u8] = b",\n\r\":.0129afZZUS ";

fn mutate(rng: &mut XorShift, input: &mut Vec<u8>, other: &[u8]) {
    let length = input.len();
    match rng.below(7) {
        0 if length > 0 => {
            let at = rng.below(length as u64) as usize;
            input[at] ^= 1 << rng.below(8);
        }
        1 if length > 0 => {
            let at = rng.below(length as u64) as usize;
            input[at] = STRUCTURAL[rng.below(STRUCTURAL.len() as u64) as usize];
        }
        2 => input.truncate(rng.below(length as u64 + 1) as usize),
        3 if length > 0 => {
            let start = rng.below(length as u64) as usize;
            let end = start + rng.below((length - start) as u64 + 1) as usize;
            let piece = input[start..end].to_vec();
            let at = rng.below(length as u64 + 1) as usize;
            input.splice(at..at, piece);
        }
        4 => {
            let cut = rng.below(length as u64 + 1) as usize;
            let from = rng.below(other.len() as u64 + 1) as usize;
            input.truncate(cut);
            input.extend_from_slice(&other[from..]);
        }
        5 => {
            let at = rng.below(length as u64 + 1) as usize;
            let byte = STRUCTURAL[rng.below(STRUCTURAL.len() as u64) as usize];
            input.insert(at, byte);
        }
        _ if length > 0 => {
            let at = rng.below(length as u64) as usize;
            input.remove(at);
        }
        _ => {}
    }
}

fn random_country(rng: &mut XorShift) -> Country {
    if rng.below(20) == 0 {
        return Country::UNKNOWN;
    }
    country::nth(rng.below(country::COUNT as u64) as usize).unwrap()
}

/// A valid-looking CSV of a few rows of both families, sometimes quoted or with CRLF.
fn random_csv(rng: &mut XorShift) -> Vec<u8> {
    let mut out = String::new();
    let mut v4 = 0x0100_0000u32 + rng.below(1 << 20) as u32;
    let mut v6 = (0x2001_0200u128 << 96) + (u128::from(rng.next()) << 40);
    for _ in 0..1 + rng.below(5) {
        let code = random_country(rng);
        let (first, last) = if rng.below(2) == 0 {
            let first = v4 + rng.below(3) as u32;
            let last = first + rng.below(300) as u32;
            v4 = last + 1;
            (address::from_ipv4(first), address::from_ipv4(last))
        } else {
            let first = v6 + u128::from(rng.below(3));
            let last = first + (u128::from(rng.next()) >> rng.below(64));
            v6 = last + 1;
            (first, last)
        };
        let (a, b) = (address::to_ip(first), address::to_ip(last));
        if rng.below(8) == 0 {
            out.push_str(&format!("\"{a}\",\"{b}\",\"{code}\"\r\n"));
        } else {
            out.push_str(&format!("{a},{b},{code}\n"));
        }
    }
    if rng.below(4) == 0 {
        out.pop();
    }
    out.into_bytes()
}

/// The loader's rules written as plainly as possible over the whole input at once.
fn reference_load(csv: &[u8]) -> Result<Vec<Range>, LoadError> {
    let mut lines: Vec<&[u8]> = csv.split(|&byte| byte == b'\n').collect();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    let (mut last_v4, mut last_v6) = (None, None);
    let mut kept = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let row_error = |error| LoadError::Row { error, file: 0, line: index as u64 + 1 };
        if line.len() > MAX_LINE {
            return Err(row_error(RangeError::InvalidRow));
        }
        let parsed = range::parse_row(line).map_err(row_error)?;
        let last = if address::is_mapped(parsed.first) { &mut last_v4 } else { &mut last_v6 };
        if matches!(*last, Some(previous) if parsed.first <= previous) {
            return Err(row_error(RangeError::Overlap));
        }
        *last = Some(parsed.last);
        if !parsed.country.is_unknown() {
            kept.push(parsed);
        }
    }
    if kept.is_empty() {
        return Err(LoadError::NoRanges);
    }
    kept.sort_by_key(|value| value.first);
    for pair in kept.windows(2) {
        if pair[1].first <= pair[0].last {
            return Err(LoadError::Ranges(RangeError::Overlap));
        }
    }
    Ok(kept)
}

fn load_in_chunks(rng: &mut XorShift, csv: &[u8]) -> Result<Database, LoadError> {
    let mut loader = Loader::new();
    let mut rest = csv;
    while !rest.is_empty() {
        let size = (1 + rng.below(64) as usize).min(rest.len());
        let (chunk, after) = rest.split_at(size);
        loader.feed(chunk)?;
        rest = after;
    }
    loader.end_file()?;
    loader.finish(Provider::Dbip, "2026-09")
}

/// Every accepted generation survives the snapshot and the storage formats unchanged.
fn check_generation(db: &Database) {
    let ranges: Vec<Range> = db.ranges().collect();
    range::check_sorted(&ranges).unwrap();
    for value in &ranges {
        for ip in [value.first, value.last] {
            let expected = address::is_public(ip).then_some(value.country);
            assert_eq!(db.lookup(ip), expected);
        }
    }
    let bytes = snapshot::encode(db).unwrap();
    let decoded = snapshot::decode(&bytes).unwrap();
    assert_eq!(&decoded, db);
    assert_eq!(snapshot::encode(&decoded).unwrap(), bytes);
    let mut restored = Vec::new();
    let mut batch = [0u8; wire::BATCH_BYTES];
    for chunk in ranges.chunks(wire::BATCH_ROWS) {
        let length = wire::encode_batch(chunk, &mut batch).unwrap();
        assert!(wire::is_valid_batch(&batch[..length]));
        wire::decode_rows(&mut restored, ranges.len(), &batch[..length]).unwrap();
    }
    assert_eq!(restored, ranges);
    assert_eq!(&Database::from_ranges(&restored, *db.provenance()).unwrap(), db);
}

#[test]
fn csv_loader_survives_mutation_and_agrees_with_the_reference() {
    let mut rng = XorShift(0x1234_5678_9abc_def1);
    let fixtures: [&[u8]; 2] = [
        include_bytes!("../testdata/user-country-ipv4.csv"),
        include_bytes!("../testdata/user-country-ipv6.csv"),
    ];
    let mut accepted = 0;
    for iteration in 0..ITERATIONS {
        let mut input = if iteration % 50 == 0 {
            fixtures[iteration / 50 % 2].to_vec()
        } else {
            random_csv(&mut rng)
        };
        let other = random_csv(&mut rng);
        for _ in 0..rng.below(4) {
            mutate(&mut rng, &mut input, &other);
        }
        if input.is_empty() {
            continue;
        }
        let whole = Database::from_csv(Provider::Dbip, "2026-09", &input);
        let chunked = load_in_chunks(&mut rng, &input);
        assert_eq!(whole, chunked, "{:?}", String::from_utf8_lossy(&input));
        match (&whole, reference_load(&input)) {
            (Ok(db), Ok(ranges)) => {
                assert_eq!(db.ranges().collect::<Vec<_>>(), ranges);
                assert_eq!(db.digest(), &Sha256::digest(&input));
                if iteration % 4 == 0 {
                    check_generation(db);
                }
                accepted += 1;
            }
            (Err(error), Err(expected)) => assert_eq!(*error, expected),
            (got, want) => panic!("{got:?} against {want:?} for {input:?}"),
        }
    }
    // The mutations must leave a fair share of inputs valid, or the test proves little.
    assert!(accepted > ITERATIONS / 5, "{accepted}");
}

/// A valid generation of a few ranges in all three width classes, often adjacent.
fn random_database(rng: &mut XorShift) -> Database {
    let mut ranges = Vec::new();
    let mut cursor = if rng.below(2) == 0 {
        address::from_ipv4(rng.below(1 << 31) as u32)
    } else {
        0x2001_0200u128 << 96
    };
    for _ in 0..1 + rng.below(6) {
        let gap = if rng.below(2) == 0 { 0 } else { u128::from(rng.below(1000)) };
        let first = cursor + gap;
        let last = match rng.below(3) {
            0 => first + u128::from(rng.below(256)),
            1 => (first | u128::from(u64::MAX)) + (u128::from(rng.below(4)) << 64),
            _ => first + (u128::from(rng.next()) << rng.below(48)),
        };
        let country = country::nth(rng.below(country::COUNT as u64) as usize).unwrap();
        ranges.push(Range { first, last, country });
        cursor = last + 1;
    }
    let provider = if rng.below(2) == 0 { Provider::Dbip } else { Provider::UserCountry };
    let version = if provider == Provider::Dbip { "2026-09" } else { "2026-09-09" };
    let provenance = Provenance {
        provider,
        version: Version::new(version).unwrap(),
        digest: Sha256::digest(&rng.next().to_be_bytes()),
        file_digests: [[7; 32], [9; 32]],
    };
    Database::from_ranges(&ranges, provenance).unwrap()
}

fn reseal(bytes: &mut [u8]) {
    if bytes.len() < snapshot::HEADER_BYTES {
        return;
    }
    let length = (bytes.len() - snapshot::HEADER_BYTES) as u32;
    bytes[24..28].copy_from_slice(&length.to_be_bytes());
    let digest = Sha256::digest(&bytes[snapshot::HEADER_BYTES..]);
    bytes[124..156].copy_from_slice(&digest);
}

#[test]
fn snapshot_decoder_accepts_only_canonical_bytes() {
    let mut rng = XorShift(0x0bad_cafe_f00d_0001);
    let mut accepted = 0;
    for _ in 0..ITERATIONS {
        let db = random_database(&mut rng);
        let valid = snapshot::encode(&db).unwrap();
        assert_eq!(snapshot::decode(&valid).as_ref(), Ok(&db));
        let other = snapshot::encode(&random_database(&mut rng)).unwrap();
        let mut input = valid.clone();
        for _ in 0..1 + rng.below(3) {
            mutate(&mut rng, &mut input, &other);
        }
        // Most mutations would only fail the payload digest; reseal to reach the rows.
        if rng.below(4) != 0 {
            reseal(&mut input);
        }
        if let Ok(decoded) = snapshot::decode(&input) {
            assert_eq!(snapshot::encode(&decoded).unwrap(), input);
            let payload = input.len() - snapshot::HEADER_BYTES;
            assert!(decoded.range_count() <= payload / 7);
            accepted += 1;
        }
    }
    assert!(accepted > 1000, "{accepted}");
}

/// The batch rules written plainly over byte slices.
fn reference_valid_batch(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || bytes.len() > wire::BATCH_BYTES
        || !bytes.len().is_multiple_of(wire::ROW_BYTES)
    {
        return false;
    }
    let rows: Vec<&[u8]> = bytes.chunks(wire::ROW_BYTES).collect();
    rows.iter().enumerate().all(|(index, row)| {
        row[..16] <= row[16..32]
            && country::is_valid(&row[32..34])
            && (index == 0 || row[..16] > rows[index - 1][16..32])
    })
}

#[test]
fn storage_rows_round_trip_or_append_nothing() {
    let mut rng = XorShift(0x5eed_5eed_0000_0003);
    let mut accepted = 0;
    for _ in 0..ITERATIONS {
        let db = random_database(&mut rng);
        let ranges: Vec<Range> = db.ranges().collect();
        let mut batch = [0u8; wire::BATCH_BYTES];
        let length = wire::encode_batch(&ranges, &mut batch).unwrap();
        let mut input = batch[..length].to_vec();
        let other: Vec<u8> = input.iter().rev().copied().collect();
        for _ in 0..rng.below(3) {
            mutate(&mut rng, &mut input, &other);
        }
        let mut decoded = vec![Range { first: 0, last: 0, country: ranges[0].country }];
        let bound = 1 + rng.below(8) as usize;
        let result = wire::decode_rows(&mut decoded, bound, &input);
        assert_eq!(wire::is_valid_batch(&input), reference_valid_batch(&input));
        match result {
            Ok(()) => {
                let rows: Vec<u8> = decoded[1..].iter().flat_map(wire::encode_row).collect();
                assert_eq!(rows, input);
                assert!(decoded.len() <= bound);
                assert!(wire::is_valid_batch(&input) || input.len() > wire::BATCH_BYTES);
                accepted += 1;
            }
            Err(_) => assert_eq!(decoded.len(), 1),
        }
    }
    assert!(accepted > 1000, "{accepted}");
}

#[test]
fn accepted_addresses_format_and_parse_back() {
    let vectors = include_str!("../testdata/address-vectors.txt");
    let texts: Vec<&str> =
        vectors.lines().filter_map(|line| line.split_once('\t')).map(|p| p.1).collect();
    let mut rng = XorShift(0xadd2_e550_0000_0004);
    for _ in 0..ITERATIONS {
        let mut input = texts[rng.below(texts.len() as u64) as usize].as_bytes().to_vec();
        let other = texts[rng.below(texts.len() as u64) as usize].as_bytes();
        for _ in 0..rng.below(3) {
            mutate(&mut rng, &mut input, other);
        }
        if let Ok(ip) = address::parse_bytes(&input) {
            let text = address::to_ip(ip).to_string();
            assert_eq!(address::parse(&text), Ok(ip), "{text}");
        }
    }
}
