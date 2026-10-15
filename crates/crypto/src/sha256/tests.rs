use super::*;
use crate::test_util::{hex_array, pattern};

type CompressFn = fn(&mut State, &[Block]);

/// The implementations this CPU can run, each called directly rather than through dispatch.
fn implementations() -> std::vec::Vec<(&'static str, CompressFn)> {
    let mut list: std::vec::Vec<(&'static str, CompressFn)> =
        std::vec![("portable", portable::compress), ("dispatched", compress),];
    #[cfg(target_arch = "x86_64")]
    if x86::ShaNi::detect().is_some() {
        list.push(("sha-ni", |state, blocks| {
            x86::ShaNi::detect().unwrap().compress(state, blocks)
        }));
    }
    #[cfg(target_arch = "aarch64")]
    if aarch64::Sha2::detect().is_some() {
        list.push(("armv8", |state, blocks| {
            aarch64::Sha2::detect().unwrap().compress(state, blocks)
        }));
    }
    list
}

/// Hashes `data` with `compress`, feeding it in pieces of `piece` bytes.
fn digest_with(data: &[u8], piece: usize, compress: CompressFn) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in data.chunks(piece.max(1)) {
        hasher.update_with(chunk, compress);
    }
    hasher.finalize_with(compress)
}

/// FIPS 180-4 example vectors (NIST CSRC "SHA256.pdf" and "SHA2_Additional.pdf"),
/// confirmed with Zig 0.16 `std.crypto.hash.sha2.Sha256`.
const VECTORS: [(&str, &str); 4] = [
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
         hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ),
];

#[test]
fn fips_vectors_on_every_implementation() {
    for (name, compress) in implementations() {
        for (input, expected) in VECTORS {
            for piece in [1, 3, 63, 64, 65, 1000] {
                let digest = digest_with(input.as_bytes(), piece, compress);
                assert_eq!(digest, hex_array(expected), "{name} {input:?} piece {piece}");
            }
        }
    }
    for (input, expected) in VECTORS {
        assert_eq!(Sha256::digest(input.as_bytes()), hex_array(expected));
    }
}

#[test]
fn one_million_a_on_every_implementation() {
    let data = [b'a'; 1_000_000];
    let expected = hex_array("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    for (name, compress) in implementations() {
        assert_eq!(digest_with(&data, 1000, compress), expected, "{name}");
        assert_eq!(digest_with(&data, data.len(), compress), expected, "{name}");
    }
}

#[test]
fn implementations_agree_on_every_length_and_split() {
    let data = pattern(600);
    let list = implementations();
    for len in 0..=data.len() {
        let reference = digest_with(&data[..len], len, portable::compress);
        for (name, compress) in &list {
            for piece in [1, 7, 55, 56, 64, 129] {
                let digest = digest_with(&data[..len], piece, *compress);
                assert_eq!(digest, reference, "{name} length {len} piece {piece}");
            }
        }
    }
}

#[test]
fn cloned_hasher_continues_independently() {
    let mut base = Sha256::new();
    base.update(b"statement prefix that spans more than one block of sixty-four bytes...");
    let mut left = base.clone();
    let mut right = base.clone();
    left.update(b"left");
    right.update(b"right");
    let full = |suffix: &[u8]| {
        let mut message = std::vec::Vec::from(
            &b"statement prefix that spans more than one block of sixty-four bytes..."[..],
        );
        message.extend_from_slice(suffix);
        Sha256::digest(&message)
    };
    assert_eq!(left.finalize(), full(b"left"));
    assert_eq!(right.finalize(), full(b"right"));
    assert_eq!(Sha256::default().finalize(), Sha256::digest(b""));
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[test]
fn detection_matches_the_cpu() {
    let expected = std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("sse2")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1");
    assert_eq!(x86::ShaNi::detect().is_some(), expected);
    assert_eq!(x86::ShaNi::detect().is_some(), expected, "cached answer");
    let name = implementation();
    assert_eq!(name == "x86-64 SHA-NI", expected, "{name}");
}

/// Measures throughput of each implementation. Run with
/// `cargo test --release -p sibuna-crypto -- --ignored --nocapture sha256_throughput`.
#[test]
#[ignore = "benchmark; run explicitly in release mode"]
fn sha256_throughput() {
    use std::hint::black_box;
    use std::time::Instant;
    let message = [0x5au8; 64];
    let large = pattern(1 << 20);
    for (name, compress) in implementations() {
        let rounds = 1_000_000;
        let start = Instant::now();
        for _ in 0..rounds {
            black_box(digest_with(black_box(&message), 64, compress));
        }
        let per_hash = start.elapsed().as_nanos() as f64 / f64::from(rounds);
        let repeats = 200;
        let start = Instant::now();
        for _ in 0..repeats {
            black_box(digest_with(black_box(&large), large.len(), compress));
        }
        let seconds = start.elapsed().as_secs_f64();
        let mib_per_second = f64::from(repeats) / seconds;
        std::println!(
            "sha256 {name:>10}: 64-byte message {per_hash:7.1} ns/hash ({:6.2} M hash/s), \
             1 MiB {mib_per_second:7.1} MiB/s",
            1000.0 / per_hash
        );
    }
}

#[cfg(all(not(feature = "std"), target_arch = "x86_64"))]
#[test]
fn compile_time_selection_follows_target_features() {
    let expected = cfg!(all(
        target_feature = "sha",
        target_feature = "sse2",
        target_feature = "ssse3",
        target_feature = "sse4.1"
    ));
    assert_eq!(implementation() == "x86-64 SHA-NI", expected);
}
