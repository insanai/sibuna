use super::*;
use crate::{Database, Loader, gzip};
use std::sync::atomic::AtomicBool;

const V4: &[u8] = include_bytes!("../../testdata/user-country-ipv4.csv");
const V6: &[u8] = include_bytes!("../../testdata/user-country-ipv6.csv");
const GZ: &[u8] = include_bytes!("../../testdata/countries.csv.gz");
/// Written by the Zig 0.16 `tools/geoip_snapshot.zig` from the two CSV fixtures:
/// `--provider user-country --version 2026-09-09 ipv4.csv ipv6.csv --snapshot-out ...`.
const ZIG_USER_COUNTRY: &[u8] = include_bytes!("../../testdata/user-country.sbgeoip");
/// Written by the same tool: `--provider dbip --version 2026-09 countries.csv.gz ...`.
const ZIG_DBIP: &[u8] = include_bytes!("../../testdata/dbip.sbgeoip");

fn user_country() -> Database {
    let mut loader = Loader::new();
    loader.feed(V4).unwrap();
    loader.end_file().unwrap();
    loader.feed(V6).unwrap();
    loader.end_file().unwrap();
    loader.finish(Provider::UserCountry, "2026-09-09").unwrap()
}

/// Recomputes the payload digest and length after a test edits the payload.
fn reseal(bytes: &mut [u8]) {
    let length = (bytes.len() - HEADER_BYTES) as u32;
    bytes[24..28].copy_from_slice(&length.to_be_bytes());
    let digest = Sha256::digest(&bytes[HEADER_BYTES..]);
    bytes[124..156].copy_from_slice(&digest);
}

#[test]
fn snapshot_round_trips_mixed_width_classes_and_adjacency() {
    let csv = b"1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n1.0.8.0,1.0.15.255,CN\n\
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP\n\
2001:201::,2001:201:ffff:ffff:ffff:ffff:ffff:ffff,SG\n\
2001:218:4000:5::,2001:218:4000:5:7fff:ffff:ffff:ffff,JP\n\
2001:218:4000:5:8000::,2001:218:4000:5:ffff:ffff:ffff:ffff,HK\n";
    let original = Database::from_csv(Provider::UserCountry, "2026-09-09", csv).unwrap();
    let bytes = encode(&original).unwrap();
    let expected = HEADER_BYTES
        + (1 + 4 + 4 + 2)
        + (1 + 4 + 2)
        + (1 + 4 + 4 + 2)
        + (1 + 8 + 8 + 2)
        + (1 + 8 + 2)
        + (1 + 16 + 16 + 2)
        + (1 + 16 + 2);
    assert_eq!(bytes.len(), expected);
    let restored = decode(&bytes).unwrap();
    assert_eq!(restored, original);
    assert_eq!(restored.digest(), original.digest());
    assert_eq!(restored.version().as_str(), "2026-09-09");
    assert_eq!(restored.provider(), Provider::UserCountry);
    assert_eq!(restored.lookup_text("2001:218:4000:5:9000::1").unwrap().as_str(), "HK");
    assert_eq!(peek(&bytes).unwrap().rows, 7);
}

#[test]
fn snapshot_decoder_rejects_corruption_truncation_and_non_canonical_rows() {
    let original = Database::from_csv(Provider::Dbip, "2026-09", b"1.0.0.0,1.0.0.255,AU\n");
    let original = original.unwrap();
    let bytes = encode(&original).unwrap();
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    let mut flipped = bytes.clone();
    flipped[HEADER_BYTES + 3] ^= 1;
    assert_eq!(decode(&flipped), Err(SnapshotError::PayloadDigest));
    let mut bad_magic = bytes.clone();
    bad_magic[0] = b'X';
    assert_eq!(peek(&bad_magic), Err(SnapshotError::Magic));
    // A mapped IPv4 range written with the full width class is not canonical.
    let range = original.range(0).unwrap();
    let mut full = bytes[..HEADER_BYTES].to_vec();
    full.push(2);
    full.extend_from_slice(&range.first.to_be_bytes());
    full.extend_from_slice(&range.last.to_be_bytes());
    full.extend_from_slice(b"AU");
    reseal(&mut full);
    let defect = RowDefect::NotCanonical;
    assert_eq!(decode(&full), Err(SnapshotError::Row { index: 0, defect }));
}

#[test]
fn rust_encoder_writes_the_zig_fixtures_byte_for_byte() {
    assert_eq!(encode(&user_country()).unwrap(), ZIG_USER_COUNTRY);
    let stopping = AtomicBool::new(false);
    let dbip = gzip::decode(Provider::Dbip, "2026-09", GZ, &stopping).unwrap();
    assert_eq!(encode(&dbip).unwrap(), ZIG_DBIP);
    assert_eq!(decode(ZIG_USER_COUNTRY).unwrap(), user_country());
    assert_eq!(decode(ZIG_DBIP).unwrap(), dbip);
    let header = peek(ZIG_USER_COUNTRY).unwrap();
    assert_eq!(header.rows, 25);
    assert_eq!(header.provenance.file_digests[1], Sha256::digest(V6));
}

#[test]
fn empty_embedded_bytes_mean_no_generation() {
    assert_eq!(load_embedded(b""), Ok(None));
    assert_eq!(load_embedded(b"junk"), Err(SnapshotError::Size));
    assert_eq!(load_embedded(ZIG_DBIP).unwrap().unwrap().range_count(), 2);
}

#[test]
fn header_fields_are_canonical() {
    let cases: [(usize, u8, SnapshotError); 9] = [
        (8, 3, SnapshotError::Provider),
        (9, 1, SnapshotError::Reserved),
        (10, b'1', SnapshotError::Version),
        (19, b'1', SnapshotError::Reserved),
        (23, 0, SnapshotError::RowCount),
        (27, 1, SnapshotError::PayloadLength),
        (100, 1, SnapshotError::Reserved),
        (156, 2, SnapshotError::FileCount),
        (159, 1, SnapshotError::Reserved),
    ];
    for (offset, value, error) in cases {
        let mut bytes = ZIG_DBIP.to_vec();
        bytes[offset] = value;
        assert_eq!(peek(&bytes), Err(error), "offset {offset}");
    }
    let mut empty_version = ZIG_DBIP.to_vec();
    empty_version[10..20].fill(0);
    assert_eq!(peek(&empty_version), Err(SnapshotError::Version));
    let mut long = ZIG_DBIP.to_vec();
    long.resize(MAX_BYTES + 1, 0);
    assert_eq!(peek(&long), Err(SnapshotError::Size));
}

#[test]
fn payload_rows_are_refused_with_their_defect() {
    let base = ZIG_DBIP[..HEADER_BYTES].to_vec();
    let row = |payload: &[u8], rows: u32| {
        let mut bytes = base.clone();
        bytes[20..24].copy_from_slice(&rows.to_be_bytes());
        bytes.extend_from_slice(payload);
        reseal(&mut bytes);
        decode(&bytes)
    };
    let defect = |index, defect| Err(SnapshotError::Row { index, defect });
    assert_eq!(row(&[3, 1, 0, 0, 0, 1, 0, 0, 1, b'U', b'S'], 1), defect(0, RowDefect::Tag));
    assert_eq!(row(&[4, 1, 0, 0, 0, 1, 0, 0, 1, b'U', b'S'], 1), defect(0, RowDefect::Tag));
    assert_eq!(row(&[0x80, 1, 0, 0, 1, b'U', b'S'], 1), defect(0, RowDefect::Adjacency));
    assert_eq!(row(&[0, 1, 0, 0, 0, 1, 0, 0, 1, b'U'], 1), defect(0, RowDefect::Truncated));
    assert_eq!(row(&[0, 1, 0, 0, 9, 1, 0, 0, 1, b'U', b'S'], 1), defect(0, RowDefect::Unordered));
    assert_eq!(row(&[0, 1, 0, 0, 0, 1, 0, 0, 1, b'Z', b'Z'], 1), defect(0, RowDefect::Country));
    let two = [0, 1, 0, 0, 0, 1, 0, 0, 9, b'U', b'S', 0, 1, 0, 0, 9, 1, 0, 0, 10, b'D', b'E'];
    assert_eq!(row(&two, 2), defect(1, RowDefect::Overlap));
    let adjacent =
        [0, 1, 0, 0, 0, 1, 0, 0, 9, b'U', b'S', 0, 1, 0, 0, 10, 1, 0, 0, 11, b'D', b'E'];
    assert_eq!(row(&adjacent, 2), defect(1, RowDefect::NotCanonical));
    let ok = [0, 1, 0, 0, 0, 1, 0, 0, 9, b'U', b'S', 0x80, 1, 0, 0, 11, b'D', b'E'];
    assert_eq!(row(&ok, 2).unwrap().range_count(), 2);
    let mut trailing = ok.to_vec();
    trailing.push(0);
    assert_eq!(row(&trailing, 2), Err(SnapshotError::TrailingBytes));
    // A claimed row count far above what the payload can hold fails without a large array.
    assert_eq!(row(&ok, 1 << 20), defect(2, RowDefect::Truncated));
}
