//! Deterministic fuzzing of everything a client sends back: challenge identifiers,
//! requirement tickets and session cookies.
//!
//! Genuine values are mutated by bit flips, truncation, duplication, splicing of two genuine
//! values, substitution of base64 characters (which usually still decodes, so the tag is
//! what refuses it) and random text. The invariants: nothing panics, and a value is accepted
//! (past the tag or signature) only when it is byte for byte one the coordinator issued.
//! `cargo test` runs 100,000 identifiers, tickets and MAC cookies each and 5,000 Ed25519
//! cookies; `fuzz_heavy` runs ten times as many (40 times as many Ed25519 cookies).

use std::collections::HashSet;
use std::vec::Vec;

use crate::{
    Algorithm, ChallengeSpec, Coordinator, Options, Requirement, Seed, Solution, TokenScheme,
    VerifyError,
};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const IP: &[u8] = b"192.0.2.44";
const UA: &[u8] = b"fuzz/1.0";
const NOW: u64 = 1_700_000_000;

/// Marsaglia's xorshift64: small, fast and reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A value in `0..n`; `n` must not be zero.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Returns a mutation of a random pool member, sometimes spliced with another one.
fn mutate(rng: &mut XorShift, pool: &[Vec<u8>]) -> Vec<u8> {
    let mut value = pool[rng.below(pool.len())].clone();
    let other = &pool[rng.below(pool.len())];
    match rng.below(8) {
        0 => {
            for _ in 0..=rng.below(3) {
                let at = rng.below(value.len());
                value[at] ^= 1 << rng.below(8);
            }
        }
        1 => value.truncate(rng.below(value.len())),
        2 => {
            let from = rng.below(value.len());
            let to = from + rng.below(value.len() - from);
            let copy = value[from..to].to_vec();
            let at = rng.below(value.len());
            value.splice(at..at, copy);
        }
        3 => {
            let cut = rng.below(value.len().min(other.len()));
            value.truncate(cut);
            value.extend_from_slice(&other[cut..]);
        }
        4 | 5 => {
            for _ in 0..=rng.below(2) {
                let at = rng.below(value.len());
                value[at] = ALPHABET[rng.below(64)];
            }
        }
        6 => value.iter_mut().for_each(|c| *c = ALPHABET[rng.below(64)]),
        _ => {
            let len = rng.below(160);
            value = (0..len).map(|_| rng.next() as u8).collect();
        }
    }
    value
}

fn coordinator(scheme: TokenScheme) -> Coordinator {
    let options = Options {
        default_spec: ChallengeSpec {
            algorithm: Algorithm::Hashcash,
            difficulty: 1,
            ..Default::default()
        },
        token_scheme: scheme,
        ..Default::default()
    };
    Coordinator::new(&Seed::new([0x24; 32]), options)
}

fn fuzz_identifiers(rng: &mut XorShift, iterations: usize) {
    let coord = coordinator(TokenScheme::Mac);
    let posw = ChallengeSpec { algorithm: Algorithm::Posw, difficulty: 9, posw_challenges: 2 };
    let pool: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            let spec = if i % 2 == 0 { coord.default_spec() } else { posw };
            coord.create_challenge_with_spec(IP, UA, NOW, spec, i).id.as_bytes().to_vec()
        })
        .collect();
    let genuine: HashSet<&[u8]> = pool.iter().map(Vec::as_slice).collect();
    for _ in 0..iterations {
        let input = mutate(rng, &pool);
        let solution = Solution::Nonce(rng.next());
        let result = coord.verify_and_mint(&input, solution, IP, UA, NOW);
        let refused_unread = matches!(
            result,
            Err(VerifyError::MalformedChallenge | VerifyError::InvalidChallengeTag)
        );
        assert!(refused_unread || genuine.contains(input.as_slice()), "accepted {input:?}");
    }
}

fn fuzz_tickets(rng: &mut XorShift, iterations: usize) {
    let coord = coordinator(TokenScheme::Mac);
    let pool: Vec<Vec<u8>> = (0..8u32)
        .map(|i| {
            let spec = ChallengeSpec { difficulty: 8 + i, ..Default::default() };
            let requirement = Requirement { spec, rule_hash: u64::from(i) };
            coord.requirement_ticket(requirement, IP, UA, NOW).as_bytes().to_vec()
        })
        .collect();
    let genuine: HashSet<&[u8]> = pool.iter().map(Vec::as_slice).collect();
    let mut opened = 0;
    for _ in 0..iterations {
        let input = mutate(rng, &pool);
        if coord.open_ticket(&input, IP, UA, NOW).is_some() {
            assert!(genuine.contains(input.as_slice()), "opened {input:?}");
            opened += 1;
        }
    }
    assert!(opened > 0, "no genuine ticket survived the mutations");
}

fn fuzz_cookies(rng: &mut XorShift, scheme: TokenScheme, iterations: usize) {
    let coord = coordinator(scheme);
    let pool: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            let ch = coord.create_challenge_with_spec(IP, UA, NOW + i, coord.default_spec(), i);
            let nonce = sibuna_pow::hashcash::solve_bits(ch.id.as_bytes(), 1, 1 << 20).unwrap();
            let minted =
                coord.verify_and_mint(ch.id.as_bytes(), Solution::Nonce(nonce), IP, UA, NOW);
            minted.unwrap().token.as_str().as_bytes().to_vec()
        })
        .collect();
    let genuine: HashSet<&[u8]> = pool.iter().map(Vec::as_slice).collect();
    let mut accepted = 0;
    for _ in 0..iterations {
        let input = mutate(rng, &pool);
        if coord.verify_cookie(&input, IP, UA, NOW).is_ok() {
            assert!(genuine.contains(input.as_slice()), "accepted {input:?}");
            accepted += 1;
        }
    }
    assert!(accepted > 0, "no genuine cookie survived the mutations");
}

/// 305,000 inputs. Ed25519 verification is slow without optimisation, so its share
/// is small here; `fuzz_heavy` gives it a full run.
#[test]
fn mutated_values_never_panic_and_only_genuine_ones_pass() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    fuzz_identifiers(&mut rng, 100_000);
    fuzz_tickets(&mut rng, 100_000);
    fuzz_cookies(&mut rng, TokenScheme::Mac, 100_000);
    fuzz_cookies(&mut rng, TokenScheme::Ed25519, 5_000);
}

#[test]
#[ignore = "heavy fuzz run; use --release"]
fn fuzz_heavy() {
    let mut rng = XorShift(0xD1B5_4A32_D192_ED03);
    fuzz_identifiers(&mut rng, 1_000_000);
    fuzz_tickets(&mut rng, 1_000_000);
    fuzz_cookies(&mut rng, TokenScheme::Mac, 1_000_000);
    fuzz_cookies(&mut rng, TokenScheme::Ed25519, 200_000);
}
