use rustls::crypto::ring::kx_group::X25519;
use rustls::{NamedGroup, ProtocolVersion};

use super::*;

const CLIENT_SHARE: usize = ENCAPSULATION_KEY_LEN + X25519_LEN;
const SERVER_SHARE: usize = CIPHERTEXT_LEN + X25519_LEN;

#[test]
fn a_client_and_a_server_agree_on_a_secret_of_both_halves() {
    let client = X25519MLKEM768.start().unwrap();
    assert_eq!(client.group(), NamedGroup::X25519MLKEM768);
    assert_eq!(client.pub_key().len(), CLIENT_SHARE);
    let server = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
    assert_eq!(server.group, NamedGroup::X25519MLKEM768);
    assert_eq!(server.pub_key.len(), SERVER_SHARE);
    let secret = client.complete(&server.pub_key).unwrap();
    assert_eq!(secret.secret_bytes().len(), 64);
    assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
}

#[test]
fn each_exchange_draws_fresh_keys() {
    let first = X25519MLKEM768.start().unwrap();
    let second = X25519MLKEM768.start().unwrap();
    assert_ne!(first.pub_key(), second.pub_key());
    let a = X25519MLKEM768.start_and_complete(first.pub_key()).unwrap();
    let b = X25519MLKEM768.start_and_complete(first.pub_key()).unwrap();
    assert_ne!(a.pub_key, b.pub_key);
    assert_ne!(a.secret.secret_bytes(), b.secret.secret_bytes());
}

#[test]
fn the_classical_component_is_the_tail_of_the_share_and_completes_alone() {
    let client = X25519MLKEM768.start().unwrap();
    let (group, component) = client.hybrid_component().unwrap();
    assert_eq!(group, NamedGroup::X25519);
    assert_eq!(component, &client.pub_key()[ENCAPSULATION_KEY_LEN..]);
    // A server without the hybrid group answers the X25519 share alone.
    let server = X25519.start_and_complete(component).unwrap();
    let secret = client.complete_hybrid_component(&server.pub_key).unwrap();
    assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
}

#[test]
fn shares_of_the_wrong_length_are_refused() {
    let client = X25519MLKEM768.start().unwrap();
    let share = client.pub_key();
    for bad in [&share[..0], &share[..CLIENT_SHARE - 1], &[share, &[0]].concat()[..]] {
        let refused = X25519MLKEM768.start_and_complete(bad).err();
        assert_eq!(refused, Some(INVALID_KEY_SHARE), "client share of {} bytes", bad.len());
    }
    let server = X25519MLKEM768.start_and_complete(share).unwrap();
    let short = &server.pub_key[..SERVER_SHARE - 1];
    assert_eq!(client.complete(short).err(), Some(INVALID_KEY_SHARE));
}

#[test]
fn an_encapsulation_key_that_fails_the_modulus_check_is_refused() {
    let client = X25519MLKEM768.start().unwrap();
    let mut share = client.pub_key().to_vec();
    // The first two 12-bit coefficients become 4095, which is not below q = 3329.
    share[..3].copy_from_slice(&[0xff, 0xff, 0xff]);
    assert_eq!(X25519MLKEM768.start_and_complete(&share).err(), Some(INVALID_KEY_SHARE));
}

#[test]
fn a_forged_ciphertext_gives_a_different_secret_not_an_error() {
    let client = X25519MLKEM768.start().unwrap();
    let mut server = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
    server.pub_key[0] ^= 1;
    let secret = client.complete(&server.pub_key).unwrap();
    assert_ne!(secret.secret_bytes(), server.secret.secret_bytes());
}

#[test]
fn the_kem_groups_are_for_tls_1_3_only() {
    for group in [X25519MLKEM768, MLKEM768] {
        assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!group.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(group.ffdhe_group().is_none());
    }
}

#[test]
fn the_provider_offers_the_hybrid_group_first_and_keeps_ring_otherwise() {
    let ours = provider();
    let ring = rustls::crypto::ring::default_provider();
    let names: Vec<_> = ours.kx_groups.iter().map(|group| group.name()).collect();
    assert_eq!(
        names,
        [
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1
        ]
    );
    let suites =
        |p: &CryptoProvider| p.cipher_suites.iter().map(|s| s.suite()).collect::<Vec<_>>();
    assert_eq!(suites(&ours), suites(&ring));
}

#[test]
fn the_layout_splits_what_it_joined_in_either_order() {
    for post_quantum_first in [true, false] {
        let layout = HybridLayout {
            classical_share_len: 2,
            post_quantum_client_share_len: 3,
            post_quantum_server_share_len: 4,
            post_quantum_first,
        };
        let joined = layout.concat(&[1, 2, 3], &[8, 9]);
        let halves = (&[1u8, 2, 3][..], &[8u8, 9][..]);
        assert_eq!(layout.split_client_share(&joined), Some(halves));
        assert_eq!(layout.split_server_share(&joined), None);
        let joined = layout.concat(&[1, 2, 3, 4], &[8, 9]);
        let halves = (&[1u8, 2, 3, 4][..], &[8u8, 9][..]);
        assert_eq!(layout.split_server_share(&joined), Some(halves));
    }
}

/// The CPU time of one exchange on each side, hybrid against X25519 alone (SID 0035,
/// Measurement). Run with `cargo test --release -p sibuna-tls cost_of -- --ignored`.
#[test]
#[ignore = "a measurement, not a check"]
fn cost_of_an_exchange_on_each_side() {
    const ROUNDS: u32 = 2000;
    for group in [X25519MLKEM768, X25519] {
        let mut client_time = std::time::Duration::ZERO;
        let mut server_time = std::time::Duration::ZERO;
        for _ in 0..ROUNDS {
            let started = std::time::Instant::now();
            let client = group.start().unwrap();
            client_time += started.elapsed();
            let started = std::time::Instant::now();
            let server = group.start_and_complete(client.pub_key()).unwrap();
            server_time += started.elapsed();
            let started = std::time::Instant::now();
            client.complete(&server.pub_key).unwrap();
            client_time += started.elapsed();
        }
        let name = group.name();
        let client = client_time / ROUNDS;
        let server = server_time / ROUNDS;
        eprintln!("{name:?}: client {client:?}, server {server:?}");
    }
}
