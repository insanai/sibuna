//! Cross-implementation vectors: values produced by the Zig 0.16 implementation
//! (`libs/challenge` and `libs/crypto` of the Zig repository, run with `zig run`), and the
//! checks that Rust produces the same bytes and accepts what Zig minted.
//!
//! The ignored test `write_rust_vectors_for_zig` writes values that Rust minted from other
//! inputs as a Zig source file; a Zig program then verifies them with the Zig coordinator.
//! Together they show that a Zig node and a Rust node sharing a seed interoperate
//! (SID 0010, acceptance criterion 2).

use core::num::NonZeroU32;
use std::fmt::Write as _;
use std::string::String;

use sibuna_crypto::ed25519::SigningKey;
use sibuna_encoding::hex;
use sibuna_pow::hashcash;
use sibuna_pow::posw::{self, Params, Workspace};

use crate::token::{Payload, WorkLevel, ed25519, mac};
use crate::{
    Adaptive, AdaptiveConfig, Algorithm, ChallengeSpec, Coordinator, Keys, Options, Requirement,
    Seed, Solution, TokenScheme, fingerprint_keyed, fingerprint_unkeyed, rule_hash,
};

// The constants below were printed by the Zig 0.16 program `vectors.zig` (Zig sources of
// `libs/challenge` and `libs/crypto`). Seed 0x42 repeated is the benchmark's seed.
const KEY_TOKEN: &str = "2f74369a2b4713cd7e223a7ff60a4294c37701d77eb5015180c63681cfa4668c";
const KEY_CHALLENGE: &str = "c86fb38b279f8519ff94bc159e78a863f1d1ff36f5c85dcc975cbf22873839ae";
const KEY_ED25519_SEED: &str = "07160a32f4ca36efd62ec612358e48c96734248fbe30b3d27e8618dc9a1b1d82";
const KEY_FINGERPRINT: &str = "3f86517ca8abb348d3965fa85104d2452db7e2aa03e178b98e388ed4583ae8df";
const KEY_REQUIREMENT: &str = "4e90153a91e0a65616bdfcd31670ccf53bb15bcdf304c6b52382cf526e17f4f8";
const FP_KEYED: u64 = 0x11287316a64e9ec5;
const FP_AB_C: u64 = 0x9b910060f360d037;
const FP_A_BC: u64 = 0x710523eda1359521;
const FP_EMPTY: u64 = 0x2c1f265d2b67213f;
const FP_UNKEYED: u64 = 0x5b448d48778fe60e;
const RULE_GPTBOT: u64 = 0x2ecb32658218839a;
const RULE_EMPTY: u64 = 0x696a60b92fc98b15;
const RULE_DEFAULT: u64 = 0xc5c754ae4a407849;
const FP3: u64 = 0x03768e9a335b7e30;
const MAC_TOKEN: &str =
    "AgETAAAAAAAAAAAAZVPxAAAAAABlU_8QLssyZYIYg5oDdo6aM1t-MH8Fx44U2tU6_SaaTaRQckQ";
const ED_PUBLIC_7: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const ED_TOKEN: &str = concat!(
    "AgAMAAAAAAAAAAAAZVPxAAAAAABlU_8QAAAAAAAAEjRbRI1Id4_mDrzOTUBcLnVtwlfZ5",
    "M2G-an6J16DX61tMGCBz8MFxov_pUACz6XmK6S__n8pykefw0G2NEviPuJNVgnECnL__gI"
);
const BENCH_FP: u64 = 0x1603f10ebd2d28c7;
const BENCH_MAC_TOKEN: &str =
    "AgAQAAAAAAAAAAAAZtwXoAAAAABm3DPAAAAAAAAAAAEWA_EOvS0ox9oHhfBKPCv6nVT8P8vWOiE";
const BENCH_ED_PUBLIC: &str = "856ab553b429093296588309b7d454fe1e632fa37000e362abd1becb15d6f0ab";
const BENCH_ED_TOKEN: &str = concat!(
    "AgAQAAAAAAAAAAAAZtwXoAAAAABm3DPAAAAAAAAAAAEWA_EOvS0ox4XHLQ0YAWP8OR303",
    "Pw0nrHU7rtOLF127auhRTCjTTRknWmdN1n3Mb83PIcWm935DC6aAU5sOgHn5XUcNmnVgww"
);
const KEY_CHALLENGE_NODE7: &str =
    "7abc68fa1c2ad697ef164f5b7d8b8b46a0857784ad66586986982608149ce2ec";
const A_ID1: &str = "AQAKAADxU2UAAAAAxZ5OphZzKBH0yMJKNj3PTpqDGIJlMssuVS47S0ql6rs7ezFGviwDPQ";
const A_ID2: &str = "AQAKAAHxU2UAAAAAxZ5OphZzKBH0qxrb8qcRxgAAAAAAAAAA9HGGTvY2WkR6xAxlXuaeZQ";
const A_NONCE1: u64 = 0x0000000000000130;
const A_TOKEN1: &str =
    "AgAKAAAAAAAAAAAAZVPxBQAAAABlU_8VLssyZYIYg5oRKHMWpk6exb-U8AbMt-E5MvPQ3h02K9E";
const A_TICKET_POSW: &str = "AQETDADxU2UAAAAAxZ5OphZzKBHt_gAAAAAAALuPAWX0tfJP936RXVvbUq8";
const A_TICKET_HASHCASH: &str = "AQD_EADxU2UAAAAAxZ5OphZzKBEBAAAAAAAAALnku7AdXMD53hix1tjJkgg";
const B_ID: &str = "AQEIBgDxU2UAAAAAxZ5OphZzKBH_oy7LQ6otmAEAAAAAAAAAnME2W7M6U8cwNJG2t8gsSA";
const B_TOKEN: &str = concat!(
    "AgELAAAAAAAAAAAAZVPxAQAAAABlU_8RAAAAAAAAAAERKHMWpk6exb3LJXb5Yu_wK30U7",
    "-iCheKlcdgiDjd_8HqkaDlsaElXdqn_Jyfj3WletgnlPGqlvqrJbebWEHlWPHmYOCDnQAA"
);
const C_ID: &str = "AQENCAHxU2UAAAAAxZ5OphZzKBEk15qYs5z5dgAAAAAAAAAAMZIChV4v5ZibMopuPWI0hg";
const C_DIFFICULTY: u8 = 13;
const ADAPTIVE_TRACE: [(u64, u32); 40] = [
    (4970, 2),
    (5438, 2),
    (161, 0),
    (213, 0),
    (156, 0),
    (11701, 3),
    (20295, 4),
    (11547, 3),
    (6001, 2),
    (5584, 2),
    (149, 0),
    (196, 0),
    (222, 0),
    (11750, 3),
    (20396, 4),
    (6826, 2),
    (5578, 2),
    (199, 0),
    (173, 0),
    (199, 0),
    (8917, 3),
    (18271, 4),
    (11834, 3),
    (5956, 2),
    (5608, 2),
    (181, 0),
    (157, 0),
    (154, 0),
    (11699, 3),
    (20294, 4),
    (6904, 2),
    (5547, 2),
    (187, 0),
    (180, 0),
    (173, 0),
    (11649, 3),
    (20256, 4),
    (11465, 3),
    (5935, 2),
    (5518, 2),
];

const SEED: [u8; 32] = [0x42; 32];
const NOW: u64 = 1_700_000_000;
const IP: &[u8] = b"203.0.113.9";
const UA: &[u8] = b"Mozilla/5.0";

fn node(id: u32) -> Option<NonZeroU32> {
    NonZeroU32::new(id)
}

/// Coordinator A of the Zig program: Hashcash at 10 bits, node 7, MAC tokens.
fn coordinator_a() -> Coordinator {
    let options = Options {
        default_spec: ChallengeSpec {
            algorithm: Algorithm::Hashcash,
            difficulty: 10,
            ..Default::default()
        },
        challenge_ttl: 600,
        token_ttl: 3600,
        token_scheme: TokenScheme::Mac,
        node: node(7),
        ..Default::default()
    };
    Coordinator::new(&Seed::new(SEED), options)
}

/// Coordinator B of the Zig program: PoSW at 11 bits with 6 openings, Ed25519 tokens.
fn coordinator_b() -> Coordinator {
    let options = Options {
        default_spec: ChallengeSpec {
            algorithm: Algorithm::Posw,
            difficulty: 11,
            posw_challenges: 6,
        },
        challenge_ttl: 600,
        token_ttl: 3600,
        token_scheme: TokenScheme::Ed25519,
        ..Default::default()
    };
    Coordinator::new(&Seed::new(SEED), options)
}

#[test]
fn key_schedule_and_node_binding_match_zig() {
    let mut keys = Keys::derive(&Seed::new(SEED));
    assert_eq!(hex::encode(&keys.token), KEY_TOKEN);
    assert_eq!(hex::encode(&keys.challenge), KEY_CHALLENGE);
    assert_eq!(hex::encode(&keys.ed25519_seed), KEY_ED25519_SEED);
    assert_eq!(hex::encode(&keys.fingerprint), KEY_FINGERPRINT);
    assert_eq!(hex::encode(&keys.requirement), KEY_REQUIREMENT);
    keys.bind_node(NonZeroU32::new(7).unwrap());
    assert_eq!(hex::encode(&keys.challenge), KEY_CHALLENGE_NODE7);
}

#[test]
fn fingerprints_and_rule_hashes_match_zig() {
    let keys = Keys::derive(&Seed::new(SEED));
    assert_eq!(fingerprint_keyed(&keys.fingerprint, IP, UA), FP_KEYED);
    assert_eq!(coordinator_a().fingerprint(IP, UA), FP_KEYED);
    let k3 = [3u8; 32];
    assert_eq!(fingerprint_keyed(&k3, b"ab", b"c"), FP_AB_C);
    assert_eq!(fingerprint_keyed(&k3, b"a", b"bc"), FP_A_BC);
    assert_eq!(fingerprint_keyed(&k3, b"", b""), FP_EMPTY);
    assert_eq!(fingerprint_keyed(&k3, b"192.168.1.100", b"Mozilla/5.0"), FP3);
    assert_eq!(fingerprint_unkeyed(b"192.168.1.100", b"Mozilla/5.0"), FP_UNKEYED);
    assert_eq!(rule_hash("bot/gptbot"), RULE_GPTBOT);
    assert_eq!(rule_hash(""), RULE_EMPTY);
    assert_eq!(rule_hash("default"), RULE_DEFAULT);
}

#[test]
fn both_token_formats_match_zig_bytes() {
    let mac_payload = Payload {
        timestamp: NOW,
        expiry: NOW + 3600,
        rule_hash: RULE_GPTBOT,
        client_fingerprint: FP3,
        work: WorkLevel { algorithm: 1, bits: 19 },
    };
    assert_eq!(mac::mint(&[3; 32], &mac_payload).as_str(), MAC_TOKEN);
    assert_eq!(mac::verify(&[3; 32], MAC_TOKEN.as_bytes(), NOW, Some(FP3)), Ok(mac_payload));

    let key_pair = SigningKey::from_seed(&[7; 32]);
    assert_eq!(hex::encode(&key_pair.verifying_key().to_bytes()), ED_PUBLIC_7);
    let ed_payload = Payload {
        timestamp: NOW,
        expiry: NOW + 3600,
        rule_hash: 0x1234,
        client_fingerprint: FP_UNKEYED,
        work: WorkLevel { algorithm: 0, bits: 12 },
    };
    assert_eq!(ed25519::mint(&key_pair, &ed_payload).as_str(), ED_TOKEN);
    let public = key_pair.verifying_key();
    assert_eq!(
        ed25519::verify(&public, ED_TOKEN.as_bytes(), NOW, Some(FP_UNKEYED)),
        Ok(ed_payload)
    );
}

#[test]
fn benchmark_tokens_match_zig_bytes() {
    let keys = Keys::derive(&Seed::new(SEED));
    let now = 1_725_700_000;
    let fp = fingerprint_keyed(&keys.fingerprint, b"203.0.113.195", b"Chrome/128");
    assert_eq!(fp, BENCH_FP);
    let payload = Payload {
        timestamp: now,
        expiry: now + 7200,
        rule_hash: 1,
        client_fingerprint: fp,
        work: WorkLevel { algorithm: 0, bits: 16 },
    };
    assert_eq!(mac::mint(&keys.token, &payload).as_str(), BENCH_MAC_TOKEN);
    let key_pair = SigningKey::from_seed(&keys.ed25519_seed);
    assert_eq!(hex::encode(&key_pair.verifying_key().to_bytes()), BENCH_ED_PUBLIC);
    assert_eq!(ed25519::mint(&key_pair, &payload).as_str(), BENCH_ED_TOKEN);
}

#[test]
fn coordinator_a_issues_and_mints_what_zig_issued_and_minted() {
    let coord = coordinator_a();
    let ch1 = coord.create_challenge_with_spec(IP, UA, NOW, coord.default_spec(), RULE_GPTBOT);
    assert_eq!(ch1.id.as_str(), A_ID1);
    assert_eq!(coord.create_challenge(IP, UA, NOW + 1).id.as_str(), A_ID2);
    let nonce = hashcash::solve_bits(ch1.id.as_bytes(), 10, 10_000_000).unwrap();
    assert_eq!(nonce, A_NONCE1);
    let verified =
        coord.verify_and_mint(ch1.id.as_bytes(), Solution::Nonce(nonce), IP, UA, NOW + 5);
    assert_eq!(verified.unwrap().token.as_str(), A_TOKEN1);

    let posw = Requirement {
        spec: ChallengeSpec { algorithm: Algorithm::Posw, difficulty: 19, posw_challenges: 12 },
        rule_hash: 0xfeed,
    };
    assert_eq!(coord.requirement_ticket(posw, IP, UA, NOW).as_str(), A_TICKET_POSW);
    let hashcash = Requirement {
        spec: ChallengeSpec {
            algorithm: Algorithm::Hashcash,
            difficulty: 300,
            posw_challenges: 16,
        },
        rule_hash: 1,
    };
    assert_eq!(coord.requirement_ticket(hashcash, IP, UA, NOW).as_str(), A_TICKET_HASHCASH);
}

#[test]
fn rust_accepts_what_the_zig_coordinator_issued_and_minted() {
    // A fresh Rust node with the same seed and node id: Zig's identifier verifies here.
    let coord = coordinator_a();
    let verified = coord
        .verify_and_mint(A_ID1.as_bytes(), Solution::Nonce(A_NONCE1), IP, UA, NOW + 5)
        .unwrap();
    assert_eq!(verified.token.as_str(), A_TOKEN1);
    assert_eq!((verified.algorithm, verified.difficulty), (Algorithm::Hashcash, 10));
    let session = coord.verify_cookie(A_TOKEN1.as_bytes(), IP, UA, NOW + 10).unwrap();
    assert_eq!(session.rule_hash, RULE_GPTBOT);
    assert_eq!(session.work, WorkLevel { algorithm: 0, bits: 10 });
    // Tickets and tokens are cluster-wide: an unbound node with the seed honours them too.
    let other = coordinator_b();
    assert!(
        mac::verify(&Keys::derive(&Seed::new(SEED)).token, A_TOKEN1.as_bytes(), NOW, None).is_ok()
    );
    let posw = other.open_ticket(A_TICKET_POSW.as_bytes(), IP, UA, NOW + 1).unwrap();
    assert_eq!(
        posw.spec,
        ChallengeSpec { algorithm: Algorithm::Posw, difficulty: 19, posw_challenges: 12 }
    );
    assert_eq!(posw.rule_hash, 0xfeed);
    let hashcash = coord.open_ticket(A_TICKET_HASHCASH.as_bytes(), IP, UA, NOW).unwrap();
    assert_eq!(hashcash.spec.difficulty, 255);
    // But the identifier is bound to node 7.
    assert_eq!(
        other.verify_and_mint(A_ID1.as_bytes(), Solution::Nonce(A_NONCE1), IP, UA, NOW),
        Err(crate::VerifyError::InvalidChallengeTag)
    );
}

#[test]
fn coordinator_b_posw_and_ed25519_match_zig() {
    let coord = coordinator_b();
    let ch = coord.create_challenge_with_spec(IP, UA, NOW, coord.default_spec(), 1);
    assert_eq!(ch.id.as_str(), B_ID);
    let mut ws = Box::new(Workspace::new());
    let params = Params { depth: ch.difficulty, challenges: ch.challenges };
    let proof = posw::solve(ch.id.as_bytes(), params, &mut ws).unwrap();
    let verified = coord.verify_and_mint(B_ID.as_bytes(), Solution::Proof(proof), IP, UA, NOW + 1);
    assert_eq!(verified.unwrap().token.as_str(), B_TOKEN);
    let session = coordinator_b().verify_cookie(B_TOKEN.as_bytes(), IP, UA, NOW + 2).unwrap();
    assert_eq!(session.work, WorkLevel { algorithm: 1, bits: 11 });
}

#[test]
fn the_adaptive_bump_enters_the_identifier_as_in_zig() {
    let options = Options {
        default_spec: ChallengeSpec {
            algorithm: Algorithm::Posw,
            difficulty: 14,
            posw_challenges: 8,
        },
        challenge_ttl: 300,
        token_ttl: 86_400,
        ..Default::default()
    };
    let coord = Coordinator::new(&Seed::new(SEED), options);
    for _ in 0..500 {
        coord.create_challenge(IP, UA, NOW);
    }
    let ch = coord.create_challenge(IP, UA, NOW + 1);
    assert_eq!(coord.adaptive().bump(), 2);
    assert_eq!(coord.adaptive().rate_256(), 32_000);
    assert_eq!(ch.difficulty, C_DIFFICULTY);
    assert_eq!(ch.id.as_str(), C_ID);
}

#[test]
fn adaptive_trace_matches_zig() {
    let ctl =
        Adaptive::new(AdaptiveConfig { baseline_per_second: 10, max_bump: 6, alpha_256: 64 });
    let mut t = 0u64;
    let mut trace = Vec::new();
    for step in 0..8000u64 {
        let mut delta = (step * 7919) % 97;
        match (step / 500) % 3 {
            1 => delta *= 40,
            2 => delta /= 8,
            _ => {}
        }
        t += delta;
        ctl.observe(t);
        if step % 200 == 199 {
            trace.push((ctl.rate_256(), ctl.bump()));
        }
    }
    assert_eq!(trace, ADAPTIVE_TRACE);
}

/// Writes values Rust minted from inputs the Zig program never used, as a Zig source file
/// for the Zig verifier. Run with
/// `SIBUNA_INTEROP_OUT=<dir>/interop_data.zig cargo test -p sibuna-challenge -- --ignored
/// write_rust_vectors_for_zig`.
#[test]
#[ignore = "writes a file for the Zig cross-check; run explicitly"]
fn write_rust_vectors_for_zig() {
    let path = std::env::var("SIBUNA_INTEROP_OUT").expect("set SIBUNA_INTEROP_OUT");
    let (ip, ua, now) = (&b"198.51.100.23"[..], &b"curl/8.5.0"[..], 1_760_000_000u64);
    let rule = rule_hash("waf:sqli");
    let mut out = String::new();
    let mut line =
        |name: &str, value: &str| writeln!(out, "pub const {name} = \"{value}\";").unwrap();

    // Hashcash on node 7 with MAC tokens: one Rust node issues, another Rust node verifies.
    let options = Options {
        default_spec: ChallengeSpec {
            algorithm: Algorithm::Hashcash,
            difficulty: 12,
            ..Default::default()
        },
        challenge_ttl: 600,
        token_ttl: 3600,
        node: node(7),
        ..Default::default()
    };
    let issuer = Coordinator::new(&Seed::new(SEED), options);
    let ch = issuer.create_challenge_with_spec(ip, ua, now, issuer.default_spec(), rule);
    let nonce = hashcash::solve_bits(ch.id.as_bytes(), 12, 1 << 32).unwrap();
    let verifier = Coordinator::new(&Seed::new(SEED), options);
    let token = verifier
        .verify_and_mint(ch.id.as_bytes(), Solution::Nonce(nonce), ip, ua, now + 3)
        .unwrap()
        .token;
    line("R_ID", ch.id.as_str());
    line("R_NONCE", &nonce.to_string());
    line("R_TOKEN", token.as_str());
    let requirement = Requirement {
        spec: ChallengeSpec { algorithm: Algorithm::Posw, difficulty: 21, posw_challenges: 9 },
        rule_hash: 0xabcdef,
    };
    line("R_TICKET", issuer.requirement_ticket(requirement, ip, ua, now).as_str());

    // PoSW without node binding, Ed25519 tokens.
    let options = Options {
        default_spec: ChallengeSpec {
            algorithm: Algorithm::Posw,
            difficulty: 12,
            posw_challenges: 5,
        },
        challenge_ttl: 600,
        token_ttl: 7200,
        token_scheme: TokenScheme::Ed25519,
        ..Default::default()
    };
    let issuer = Coordinator::new(&Seed::new(SEED), options);
    let ch = issuer.create_challenge_with_spec(ip, ua, now, issuer.default_spec(), rule);
    let mut ws = Box::new(Workspace::new());
    let params = Params { depth: ch.difficulty, challenges: ch.challenges };
    let proof = posw::solve(ch.id.as_bytes(), params, &mut ws).unwrap();
    let verifier = Coordinator::new(&Seed::new(SEED), options);
    let token = verifier
        .verify_and_mint(ch.id.as_bytes(), Solution::Proof(proof), ip, ua, now + 4)
        .unwrap()
        .token;
    line("R_ED_ID", ch.id.as_str());
    line("R_ED_PROOF_HEX", &hex::encode(proof));
    line("R_ED_TOKEN", token.as_str());
    std::fs::write(path, out).unwrap();
}
