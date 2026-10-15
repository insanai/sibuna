//! Deterministic fuzzing of the verifiers.
//!
//! The PoSW verifier sees 100,000 inputs made from genuine proofs by bit flips, truncation,
//! duplication, splicing, label swaps and random bytes, together with mutated statements
//! and parameters. The invariant: it never panics, and it accepts exactly the genuine
//! (statement, parameters, proof) triples. Hashcash verification is checked against a naive
//! reference on 100,000 random nonces and difficulties. The prover is round-tripped through
//! the verifier on random statements and parameters.

use std::vec::Vec;

use sibuna_crypto::sha256::Sha256;

use crate::hashcash;
use crate::posw::{self, LABEL_LEN, Params};
use crate::test_util::XorShift;

const ITERATIONS: usize = 100_000;

/// A statement, its parameters and a genuine proof.
struct Genuine {
    chi: Vec<u8>,
    params: Params,
    proof: Vec<u8>,
}

fn genuine_proofs() -> Vec<Genuine> {
    let mut ws = posw::tests::workspace();
    [(&b"fuzz-a"[..], 4, 2), (b"fuzz-b", 5, 1), (b"", 4, 1), (b"fuzz-d", 4, 3)]
        .into_iter()
        .map(|(chi, depth, challenges)| {
            let params = Params { depth, challenges };
            let proof = posw::solve(chi, params, &mut ws).unwrap().to_vec();
            Genuine { chi: chi.to_vec(), params, proof }
        })
        .collect()
}

/// Mutates `proof` in one of several ways, drawing `donor` bytes from another proof.
fn mutate_proof(rng: &mut XorShift, proof: &mut Vec<u8>, donor: &[u8]) {
    match rng.below(7) {
        0 => {
            for _ in 0..=rng.below(3) {
                let at = rng.below(proof.len());
                proof[at] ^= 1 << rng.below(8);
            }
        }
        1 => proof.truncate(rng.below(proof.len())),
        2 => {
            let from = rng.below(proof.len());
            let to = from + rng.below(proof.len() - from);
            let copy = proof[from..to].to_vec();
            let at = rng.below(proof.len());
            proof.splice(at..at, copy);
        }
        3 => {
            let cut = rng.below(proof.len().min(donor.len()));
            proof.truncate(cut);
            proof.extend_from_slice(&donor[cut..]);
        }
        4 => {
            let labels = proof.len() / LABEL_LEN;
            let (a, b) = (rng.below(labels) * LABEL_LEN, rng.below(labels) * LABEL_LEN);
            for i in 0..LABEL_LEN {
                proof.swap(a + i, b + i);
            }
        }
        5 => proof.iter_mut().for_each(|b| *b = rng.next() as u8),
        _ => {
            let at = rng.below(proof.len());
            proof.truncate(at);
        }
    }
}

/// Mutates the statement or the parameters, or leaves both alone.
fn mutate_context(rng: &mut XorShift, chi: &mut Vec<u8>, params: &mut Params) {
    match rng.below(6) {
        0 => params.depth = rng.next() as u8,
        1 => params.challenges = rng.next() as u8,
        2 => params.depth = params.depth.wrapping_add(1),
        3 if !chi.is_empty() => {
            let at = rng.below(chi.len());
            chi[at] ^= 1 << rng.below(8);
        }
        4 => chi.push(rng.next() as u8),
        _ => {}
    }
}

#[test]
fn posw_verifier_accepts_only_genuine_proofs() {
    let genuine = genuine_proofs();
    let mut rng = XorShift::new(0x005e_ed0f_9057);
    let mut accepted = 0;
    for _ in 0..ITERATIONS {
        let base = &genuine[rng.below(genuine.len())];
        let donor = &genuine[rng.below(genuine.len())].proof;
        let (mut chi, mut params, mut proof) = (base.chi.clone(), base.params, base.proof.clone());
        if rng.below(4) == 0 {
            mutate_context(&mut rng, &mut chi, &mut params);
        } else {
            mutate_proof(&mut rng, &mut proof, donor);
        }
        let is_genuine =
            genuine.iter().any(|g| g.chi == chi && g.params == params && g.proof == proof);
        assert_eq!(posw::verify(&chi, params, &proof), is_genuine, "{params:?}");
        accepted += usize::from(is_genuine);
    }
    // Some mutations are identities (for example an unchanged context); they must verify.
    assert!(accepted > 0);
}

/// The leading zero bits of `digest`, one bit at a time.
fn naive_leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut zeros = 0;
    for bit in 0..256 {
        if digest[bit / 8] & (0x80 >> (bit % 8)) != 0 {
            break;
        }
        zeros += 1;
    }
    zeros
}

#[test]
fn hashcash_agrees_with_a_naive_reference() {
    let mut rng = XorShift::new(0xa11ce);
    let challenges: [&[u8]; 4] = [
        b"",
        b"short",
        b"AQEQEAAAAAAAAAAAsibuna-benchmark-challenge-identifier-0000000000000",
        &[0; 200],
    ];
    for _ in 0..ITERATIONS {
        let challenge = challenges[rng.below(challenges.len())];
        // Mostly small nonces and difficulties, so some trials succeed.
        let nonce = if rng.below(2) == 0 { rng.next() } else { rng.next() % 100_000 };
        let bits = match rng.below(4) {
            0 => rng.next() as u32,
            1 => rng.below(300) as u32,
            _ => rng.below(12) as u32,
        };
        let mut message = challenge.to_vec();
        message.extend_from_slice(std::format!(":{nonce}").as_bytes());
        let digest = Sha256::digest(&message);
        assert_eq!(hashcash::digest(challenge, nonce), digest);
        let zeros = naive_leading_zero_bits(&digest);
        assert_eq!(hashcash::leading_zero_bits(&digest), zeros);
        assert_eq!(hashcash::verify_bits(challenge, nonce, bits), zeros >= bits);
        assert_eq!(
            hashcash::verify_hex(challenge, nonce, bits),
            u64::from(zeros) >= 4 * u64::from(bits)
        );
    }
}

#[test]
fn prover_round_trips_through_the_verifier() {
    let mut rng = XorShift::new(0xc0ffee);
    let mut ws = posw::tests::workspace();
    for _ in 0..200 {
        let chi: Vec<u8> = (0..rng.below(80)).map(|_| rng.next() as u8).collect();
        let params = Params { depth: rng.next() as u8, challenges: rng.next() as u8 };
        // Keep valid depths small so the test stays fast; invalid ones must fail cleanly.
        let params = if rng.below(4) == 0 && !params.is_valid() {
            params
        } else {
            Params { depth: 4 + rng.below(5) as u8, challenges: 1 + rng.below(32) as u8 }
        };
        match posw::solve(&chi, params, &mut ws) {
            Ok(proof) => {
                assert!(params.is_valid());
                assert!(posw::verify(&chi, params, proof));
            }
            Err(err) => {
                assert_eq!(params.validate(), Err(err));
            }
        }
    }
}
