use std::boxed::Box;
use std::vec;
use std::vec::Vec;

use super::*;
use crate::test_util::to_hex;

/// Reference labelling straight from the DAG definition, memoised over a fully
/// materialised table. It shares no code with the sibling-stack prover, so it
/// cross-checks it.
struct Reference {
    base: Sha256,
    n: u8,
    labels: Vec<Option<Label>>,
}

impl Reference {
    fn label(&mut self, depth: u8, index: u32) -> Label {
        let slot = (1usize << depth) - 1 + index as usize;
        if let Some(label) = self.labels[slot] {
            return label;
        }
        let mut hasher = node_hasher(&self.base, depth, index);
        if depth == self.n {
            for d in 1..=self.n {
                if turns_right(index, self.n, d) {
                    let parent = self.label(d, (index >> (self.n - d)) ^ 1);
                    hasher.update(&parent);
                }
            }
        } else {
            let left = self.label(depth + 1, index * 2);
            let right = self.label(depth + 1, index * 2 + 1);
            hasher.update(&left);
            hasher.update(&right);
        }
        let label = hasher.finalize();
        self.labels[slot] = Some(label);
        label
    }
}

fn reference_root(chi: &[u8], n: u8) -> Label {
    let node_count = (1usize << (n + 1)) - 1;
    let mut reference = Reference { base: base_hasher(chi), n, labels: vec![None; node_count] };
    reference.label(0, 0)
}

pub(crate) fn workspace() -> Box<Workspace> {
    Box::new(Workspace::new())
}

#[test]
fn prover_matches_the_reference_labelling_and_verifies() {
    let mut ws = workspace();
    let chi = b"0123456789abcdef0123456789abcdef";
    for params in [Params { depth: 6, challenges: 4 }, Params { depth: 12, challenges: 8 }] {
        let proof = solve(chi, params, &mut ws).unwrap();
        assert_eq!(proof.len(), params.proof_size());
        let root = reference_root(chi, params.depth);
        assert_eq!(&proof[..LABEL_LEN], &root);
        assert!(verify(chi, params, proof));
    }
}

#[test]
fn rejects_tampering_wrong_statement_and_wrong_parameters() {
    let mut ws = workspace();
    let chi = b"sibuna-posw-statement";
    let params = Params { depth: 11, challenges: 6 };
    let proof = solve(chi, params, &mut ws).unwrap().to_vec();
    assert!(verify(chi, params, &proof));
    assert!(!verify(b"other-statement", params, &proof));
    assert!(!verify(chi, Params { depth: 12, challenges: 6 }, &proof));
    assert!(!verify(chi, Params { depth: 11, challenges: 5 }, &proof));

    let mut copy = proof.clone();
    copy[LABEL_LEN + 40] ^= 0x01;
    assert!(!verify(chi, params, &copy));
    copy[LABEL_LEN + 40] ^= 0x01;
    copy[3] ^= 0x80;
    assert!(!verify(chi, params, &copy));
    assert_eq!(
        solve(chi, Params { depth: 2, challenges: 1 }, &mut ws),
        Err(ParamsError::Depth(2))
    );
}

/// SHA-256 of whole proofs produced by the Zig 0.16 prover (`solve` in
/// `libs/crypto/src/posw.zig`), and one proof in full. Depths above 10 exercise the
/// capture pass; depths up to 10 open from the retained levels alone.
#[test]
fn proofs_are_byte_identical_to_zig() {
    const CHI32: &[u8] = b"0123456789abcdef0123456789abcdef";
    const BENCH: &[u8] = b"AQEQEAAAAAAAAAAAsibuna-benchmark-challenge-identifier-0000000000000";
    let cases: [(&[u8], u8, u8, usize, &str); 8] = [
        (CHI32, 4, 1, 192, "f063fffe7112c6bbd5cd4d94794353f955ee4787b6a994fdb737d7d8fb104c79"),
        (CHI32, 4, 3, 512, "c94b5f7fbf7a07ab9ff91583968c251090ae44ff1155910a6d6ed9540ee2f094"),
        (
            b"sibuna-posw-statement",
            11,
            6,
            2336,
            "dbaea7ccd81bac54737969f5472677d1c01ecb199788c753c2cd19f79e01cbc8",
        ),
        (CHI32, 12, 8, 3360, "8ab8ab0bfd84f90cc12cc9211b68034c1022525cc6336c606d13575252056bcc"),
        (BENCH, 13, 16, 7200, "5c971b092f327627eacc2f910d452f1c581e79ce2361915b8c3de74201bcabee"),
        (b"", 10, 32, 11296, "5992515f726543c685745ba5a0070d43b23a1916e250ad54d9741500c5be0003"),
        (b"x", 14, 2, 992, "8a08c111c2cda3309a4267351dc8cbe8a74f2eff8c67dcc6c3251af07a0cbd9f"),
        (
            b"wasm-entry-posw-challenge",
            8,
            4,
            1184,
            "f94b06621684be1a8bf9d392be985e005e4f0fdadf4492edbfa3153937972706",
        ),
    ];
    let mut ws = workspace();
    for (chi, depth, challenges, len, sha) in cases {
        let params = Params { depth, challenges };
        let proof = solve(chi, params, &mut ws).unwrap();
        assert_eq!(proof.len(), len);
        assert_eq!(to_hex(&Sha256::digest(proof)), sha, "depth {depth} challenges {challenges}");
        assert!(verify(chi, params, proof));
    }
    let proof = solve(CHI32, Params { depth: 4, challenges: 1 }, &mut ws).unwrap();
    assert_eq!(
        to_hex(proof),
        "e5a0e29e3b0f44e0ba3246c9222d976c438295e50fb30d70d48629ddb4c43aa8\
         bbc17a877f673caf53e136723b16adfcb300e5d01b9badb73c9dd9883306162c\
         4a1ca0bc682febc642bd1de3a3ee925b2e01311e7b0ff7f1488a9d815e4cb272\
         ca1fea5d1813a6b98668d94b5fbc07503dc965779b88886cc614f9357885b608\
         c30f928d54f0b1e0893efd061187a5c91f8b8fd0ab2879d3f8b0f9f225b9f5e9\
         c8f2ef29722c0b986d86b5558dace033e7e18cdc96a277927a2121a0c9038a21"
    );
}

/// Challenged leaves computed by Zig 0.16 `challengeLeaf("chi", [7] ** 32, i, n)`.
#[test]
fn challenge_leaves_match_zig() {
    let phi = [7u8; LABEL_LEN];
    assert_eq!(challenge_leaf(b"chi", &phi, 0, 24), 4_652_321);
    assert_eq!(challenge_leaf(b"chi", &phi, 31, 4), 7);
    // Out-of-range depths do not panic.
    assert_eq!(challenge_leaf(b"chi", &phi, 0, 0), 0);
    let _ = challenge_leaf(b"chi", &phi, 0, 32);
    let _ = challenge_leaf(b"chi", &phi, 0, 255);
}

#[test]
fn params_sizes_and_validation() {
    let params = Params { depth: 13, challenges: 16 };
    assert!(params.is_valid());
    assert_eq!(params.leaf_count(), 8192);
    assert_eq!(params.opening_size(), 14 * 32);
    assert_eq!(params.proof_size(), 32 + 16 * 14 * 32);
    let largest = Params { depth: MAX_DEPTH, challenges: MAX_CHALLENGES };
    assert_eq!(largest.proof_size(), MAX_PROOF_SIZE);
    assert_eq!(Workspace::new().proof_buffer().len(), MAX_PROOF_SIZE);
    assert_eq!(Params { depth: 3, challenges: 1 }.validate(), Err(ParamsError::Depth(3)));
    assert_eq!(Params { depth: 25, challenges: 1 }.validate(), Err(ParamsError::Depth(25)));
    assert_eq!(Params { depth: 4, challenges: 0 }.validate(), Err(ParamsError::Challenges(0)));
    assert_eq!(Params { depth: 24, challenges: 33 }.validate(), Err(ParamsError::Challenges(33)));
    assert!(Params { depth: 4, challenges: 1 }.is_valid());
    assert!(Params { depth: 24, challenges: 32 }.is_valid());
    assert_eq!(Params { depth: 255, challenges: 255 }.leaf_count(), u32::MAX);
    assert_eq!(
        std::format!("{}", ParamsError::Depth(2)),
        "proof depth 2 is outside the accepted range 4 to 24"
    );
    assert_eq!(
        std::format!("{}", ParamsError::Challenges(40)),
        "40 challenges is outside the accepted range 1 to 32"
    );
}

#[test]
fn workspace_reuse_does_not_leak_between_proofs() {
    let mut ws = workspace();
    let params = Params { depth: 11, challenges: 3 };
    let first = solve(b"a", params, &mut ws).unwrap().to_vec();
    solve(b"b", Params { depth: 14, challenges: 32 }, &mut ws).unwrap();
    assert_eq!(solve(b"a", params, &mut ws).unwrap(), &first[..]);
    let mut fresh = workspace();
    assert_eq!(solve(b"a", params, &mut fresh).unwrap(), &first[..]);
}

#[test]
fn verify_rejects_malformed_proofs_without_panicking() {
    let params = Params { depth: 4, challenges: 2 };
    assert!(!verify(b"x", params, &[]));
    assert!(!verify(b"x", params, &[0; 1]));
    assert!(!verify(b"x", params, &vec![0; params.proof_size()]));
    assert!(!verify(b"x", params, &vec![0; params.proof_size() + 1]));
    assert!(!verify(b"x", Params { depth: 0, challenges: 0 }, &[0; 32]));
    assert!(!verify(b"x", Params { depth: 255, challenges: 255 }, &[0; 32]));
}
