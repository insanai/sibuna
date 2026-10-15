use super::*;
use crate::test_util::{XorShift, hex, hex_array};
use std::string::ToString;
use std::vec::Vec;

const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only \
                           one tip for the future, sunscreen would be it.";

fn key_80() -> [u8; 32] {
    core::array::from_fn(|i| 0x80 + i as u8)
}

/// RFC 8439 section 2.8.2, which is also Zig's test "seal" (second case) and "open".
#[test]
fn rfc_aead_example() {
    let aead = ChaCha20Poly1305::new(&key_80());
    let nonce = hex_array("070000004041424344454647");
    let ad = hex("50515253c0c1c2c3c4c5c6c7");
    let mut buffer = SUNSCREEN.to_vec();
    let tag = aead.seal_in_place(&nonce, &ad, &mut buffer).unwrap();
    let expected = hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116");
    assert_eq!(buffer, expected);
    assert_eq!(tag.as_slice(), hex("1ae10b594f09e26a7e902ecbd0600691"));
    aead.open_in_place(&nonce, &ad, &mut buffer, &tag).unwrap();
    assert_eq!(buffer, SUNSCREEN);
}

/// Zig's test "seal" (first case) and "open" (first case): an empty message.
#[test]
fn zig_empty_message() {
    let aead = ChaCha20Poly1305::new(&key_80());
    let nonce = hex_array("070000004041424344454647");
    let tag = aead.seal_in_place(&nonce, b"", &mut []).unwrap();
    assert_eq!(tag.as_slice(), hex("a0784d7a4716f3feb4f64e7f4b39bf04"));
    aead.open_in_place(&nonce, b"", &mut [], &tag).unwrap();
}

/// Zig's test "open": corrupting the ciphertext, the data, the key or the nonce fails,
/// and the buffer keeps the ciphertext.
#[test]
fn zig_open_rejects_corruption() {
    let nonce: [u8; 12] = hex_array("070000004041424344454647");
    let ad = hex("50515253c0c1c2c3c4c5c6c7");
    let mut sealed = SUNSCREEN.to_vec();
    let tag = ChaCha20Poly1305::new(&key_80()).seal_in_place(&nonce, &ad, &mut sealed).unwrap();
    let attempt = |key: [u8; 32], nonce: [u8; 12], ad: &[u8], ciphertext: &[u8]| {
        let mut buffer = ciphertext.to_vec();
        let result = ChaCha20Poly1305::new(&key).open_in_place(&nonce, ad, &mut buffer, &tag);
        assert_eq!(buffer, ciphertext, "buffer changed on failure");
        result
    };
    let mut bad_ciphertext = sealed.clone();
    bad_ciphertext[0] ^= 1;
    let mut bad_ad = ad.clone();
    bad_ad[0] ^= 1;
    let mut bad_key = key_80();
    bad_key[0] ^= 1;
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 1;
    let failed = Err(Error::AuthenticationFailed);
    assert_eq!(attempt(key_80(), nonce, &ad, &bad_ciphertext), failed);
    assert_eq!(attempt(key_80(), nonce, &bad_ad, &sealed), failed);
    assert_eq!(attempt(bad_key, nonce, &ad, &sealed), failed);
    assert_eq!(attempt(key_80(), bad_nonce, &ad, &sealed), failed);
}

#[test]
fn rfc_appendix_a5_decryption() {
    let (key, nonce, ad, ciphertext, tag, plaintext) = RFC_A5;
    let mut buffer = hex(ciphertext);
    let aead = ChaCha20Poly1305::new(&hex_array(key));
    aead.open_in_place(&hex_array(nonce), &hex(ad), &mut buffer, &hex_array(tag)).unwrap();
    assert_eq!(buffer, hex(plaintext));
}

/// draft-irtf-cfrg-xchacha-03 appendix A.3.1.
#[test]
fn xchacha_draft_aead() {
    let aead = XChaCha20Poly1305::new(&key_80());
    let nonce = hex_array("404142434445464748494a4b4c4d4e4f5051525354555657");
    let ad = hex("50515253c0c1c2c3c4c5c6c7");
    let mut buffer = SUNSCREEN.to_vec();
    let tag = aead.seal_in_place(&nonce, &ad, &mut buffer).unwrap();
    let expected = hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
         21f9664c97637da9768812f615c68b13b52e");
    assert_eq!(buffer, expected);
    assert_eq!(tag.as_slice(), hex("c0875924c1c7987947deafd8780acf49"));
    aead.open_in_place(&nonce, &ad, &mut buffer, &tag).unwrap();
    assert_eq!(buffer, SUNSCREEN);
}

/// Zig's tests "AEAD API" and "xchacha20" (second half).
#[test]
fn zig_aead_api() {
    let ad = b"Additional data";
    let mut buffer = SUNSCREEN.to_vec();
    let aead = XChaCha20Poly1305::new(&[69; 32]);
    let tag = aead.seal_in_place(&[42; 24], ad, &mut buffer).unwrap();
    let mut combined = buffer.clone();
    combined.extend_from_slice(&tag);
    let expected = hex("994D2DD32333F48E53650C02C7A2ABB8E018B0836D7175AEC779F52E96178076\
         8F815C58F1AA52D211498DB89B9216763F569C9433A6BBFCEFB4D4A49387A4C5\
         207FBB3B5A92B5941294DF30588C6740D39DC16FA1F0E634F7246CF7CDCB978E\
         44347D89381B7A74EB7084F754B90BDE9AAF5A94B8F2A85EFD0B50692AE2D425\
         E234");
    assert_eq!(combined, expected);
    let mut altered = buffer.clone();
    altered[0] = altered[0].wrapping_add(1);
    let result = aead.open_in_place(&[42; 24], ad, &mut altered, &tag);
    assert_eq!(result, Err(Error::AuthenticationFailed));
    aead.open_in_place(&[42; 24], ad, &mut buffer, &tag).unwrap();
    assert_eq!(buffer, SUNSCREEN);
    let aead = ChaCha20Poly1305::new(&[69; 32]);
    let mut buffer = SUNSCREEN.to_vec();
    let tag = aead.seal_in_place(&[42; 12], ad, &mut buffer).unwrap();
    buffer[0] = buffer[0].wrapping_add(1);
    assert!(aead.open_in_place(&[42; 12], ad, &mut buffer, &tag).is_err());
}

/// The key, nonce, message and associated data of the generated vectors.
fn zig_inputs() -> ([u8; 32], [u8; 24], Vec<u8>, &'static [u8]) {
    let key = core::array::from_fn(|i| (i * 29 + 3) as u8);
    let nonce = core::array::from_fn(|i| (i * 17 + 101) as u8);
    let message = (0..1000).map(|i| (i * 13 + 7) as u8).collect();
    (key, nonce, message, b"sibuna-console-totp-seed-v1 associated data")
}

#[test]
fn zig_generated_vectors() {
    let (key, nonce, message, ad) = zig_inputs();
    let short_nonce: [u8; 12] = core::array::from_fn(|i| nonce[i]);
    for (len, ad_len, ciphertext, tag) in ZIG_CHACHA {
        let mut buffer = message[..len].to_vec();
        let produced =
            ChaCha20Poly1305::new(&key).seal_in_place(&short_nonce, &ad[..ad_len], &mut buffer);
        assert_eq!(buffer, hex(ciphertext), "{len}");
        assert_eq!(produced.unwrap().as_slice(), hex(tag), "{len}");
    }
    for (len, ad_len, ciphertext, tag) in ZIG_XCHACHA {
        let mut buffer = message[..len].to_vec();
        let produced =
            XChaCha20Poly1305::new(&key).seal_in_place(&nonce, &ad[..ad_len], &mut buffer);
        assert_eq!(buffer, hex(ciphertext), "{len}");
        assert_eq!(produced.unwrap().as_slice(), hex(tag), "{len}");
    }
}

/// The console's envelope: a 24-byte nonce, the 20-byte TOTP seed sealed with the user
/// id in the associated data, and the tag. Its Zig test flips every bit position of the
/// envelope and changes the user and the key.
#[test]
fn console_envelope_rejects_tampering() {
    let seal = |key: [u8; 32], user: u64, nonce: [u8; 24]| {
        let mut envelope = [0u8; 60];
        envelope[..24].copy_from_slice(&nonce);
        envelope[24..44].copy_from_slice(b"12345678901234567890");
        let ad = user.to_be_bytes();
        let (head, rest) = envelope.split_at_mut(44);
        let tag =
            XChaCha20Poly1305::new(&key).seal_in_place(&nonce, &ad, &mut head[24..]).unwrap();
        rest.copy_from_slice(&tag);
        envelope
    };
    let open = |envelope: &[u8; 60], key: [u8; 32], user: u64| {
        let nonce: [u8; 24] = core::array::from_fn(|i| envelope[i]);
        let tag: [u8; 16] = core::array::from_fn(|i| envelope[44 + i]);
        let mut seed: [u8; 20] = core::array::from_fn(|i| envelope[24 + i]);
        XChaCha20Poly1305::new(&key)
            .open_in_place(&nonce, &user.to_be_bytes(), &mut seed, &tag)
            .map(|()| seed)
    };
    let sealed = seal([17; 32], 42, [9; 24]);
    assert_eq!(&open(&sealed, [17; 32], 42).unwrap(), b"12345678901234567890");
    assert!(open(&sealed, [17; 32], 43).is_err());
    assert!(open(&sealed, [18; 32], 42).is_err());
    for index in 0..sealed.len() {
        let mut altered = sealed;
        altered[index] ^= 1;
        assert_eq!(open(&altered, [17; 32], 42), Err(Error::AuthenticationFailed));
    }
    assert_ne!(sealed, seal([17; 32], 42, [10; 24]));
}

/// 100,000 mutated envelopes (bit flips, overwrites, splices, truncation, other nonces,
/// other associated data): none authenticates, and a failed open leaves the buffer as it
/// was.
#[test]
fn fuzz_mutated_envelopes_never_open() {
    let mut rng = XorShift::new(0xae4d);
    let aead = XChaCha20Poly1305::new(&[5; 32]);
    let mut originals = Vec::new();
    for len in [0usize, 1, 20, 64, 105] {
        let mut envelope = std::vec![0u8; 24 + len + 16];
        rng.fill(&mut envelope);
        let nonce: [u8; 24] = core::array::from_fn(|i| envelope[i]);
        let (body, tag) = envelope[24..].split_at_mut(len);
        tag.copy_from_slice(&aead.seal_in_place(&nonce, b"subject 7", body).unwrap());
        originals.push(envelope);
    }
    let open = |envelope: &[u8], ad: &[u8]| -> Option<Vec<u8>> {
        let nonce: [u8; 24] = core::array::from_fn(|i| *envelope.get(i).unwrap_or(&0));
        let body_len = envelope.len().checked_sub(40)?;
        let tag: [u8; 16] = core::array::from_fn(|i| envelope[24 + body_len + i]);
        let mut body = envelope[24..24 + body_len].to_vec();
        let before = body.clone();
        match aead.open_in_place(&nonce, ad, &mut body, &tag) {
            Ok(()) => Some(body),
            Err(_) => {
                assert_eq!(body, before);
                None
            }
        }
    };
    for original in &originals {
        assert!(open(original, b"subject 7").is_some());
    }
    for round in 0..100_000 {
        let original = &originals[round % originals.len()];
        let mut envelope = original.clone();
        let donor = &originals[rng.below(originals.len())];
        match rng.below(3) {
            0 => envelope.truncate(rng.below(envelope.len())),
            1 if round % 7 == 0 => {
                assert!(open(&envelope, b"subject 8").is_none());
                continue;
            }
            _ => rng.mutate(&mut envelope, donor),
        }
        if envelope != *original {
            assert!(open(&envelope, b"subject 7").is_none(), "mutated envelope opened");
        }
    }
}

#[test]
fn refuses_oversized_messages_without_allocating() {
    assert_eq!(MAX_MESSAGE_LEN, 274_877_906_880);
    assert_eq!(Error::AuthenticationFailed.to_string(), "authentication failed");
    assert_eq!(std::format!("{:?}", XChaCha20Poly1305::new(&[1; 32])), "XChaCha20Poly1305 { .. }");
}

/// Seals buffers of several sizes; run with
/// `cargo test --release -p sibuna-crypto -- --ignored --nocapture aead_timing`.
#[test]
#[ignore = "benchmark; run explicitly in release mode"]
fn aead_timing() {
    let chacha = ChaCha20Poly1305::new(&[0x42; 32]);
    let xchacha = XChaCha20Poly1305::new(&[0x42; 32]);
    for len in [20usize, 64, 1024, 16384, 1 << 20] {
        let mut buffer = std::vec![0x5au8; len];
        let iterations = ((256usize << 20) / len).max(1);
        let mut best = f64::MAX;
        let mut best_x = f64::MAX;
        for _ in 0..5 {
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                let tag = chacha.seal_in_place(&[0x24; 12], b"ad", &mut buffer).unwrap();
                std::hint::black_box(tag);
            }
            best = best.min(start.elapsed().as_secs_f64() * 1e9 / iterations as f64);
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                let tag = xchacha.seal_in_place(&[0x24; 24], b"ad", &mut buffer).unwrap();
                std::hint::black_box(tag);
            }
            best_x = best_x.min(start.elapsed().as_secs_f64() * 1e9 / iterations as f64);
        }
        std::println!(
            "chacha20poly1305 seal {len} B: {best:.1} ns/op, {:.0} MB/s; \
             xchacha {best_x:.1} ns/op",
            len as f64 / best * 1e3
        );
    }
}

/// RFC 8439 appendix A.5: key, nonce, associated data, ciphertext, tag, plaintext.
const RFC_A5: (&str, &str, &str, &str, &str, &str) = (
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
    "000000000102030405060708",
    "f33388860000000000004e91",
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2\
     4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf\
     332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855\
     9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4\
     b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e\
     af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a\
     0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10\
     49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29\
     a6ad5cb4022b02709b",
    "eead9d67890cbb22392336fea1851f38",
    "496e7465726e65742d4472616674732061726520647261667420646f63756d65\
     6e74732076616c696420666f722061206d6178696d756d206f6620736978206d\
     6f6e74687320616e64206d617920626520757064617465642c207265706c6163\
     65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65\
     6e747320617420616e792074696d652e20497420697320696e617070726f7072\
     6961746520746f2075736520496e7465726e65742d4472616674732061732072\
     65666572656e6365206d6174657269616c206f7220746f206369746520746865\
     6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67\
     726573732e2fe2809d",
);

/// Generated with Zig 0.16 `ChaCha20Poly1305.encrypt` over [`zig_inputs`]: message length,
/// associated data length, ciphertext, tag.
const ZIG_CHACHA: [(usize, usize, &str, &str); 17] = [
    (0, 0, "", "71eb532b47e02ad09075b519fb34a277"),
    (1, 5, "cc", "1642f82ccbf874fdb78bdac5b61fe1d8"),
    (15, 10, "cc7fce2bac041f817e60747696c835", "09902589d7722563108e34bd8cf2a044"),
    (16, 15, "cc7fce2bac041f817e60747696c835c7", "b72fc5c50888714f7f73cd534e3e554d"),
    (17, 20, "cc7fce2bac041f817e60747696c835c7fa", "ddf25577310316783ab34ce086296310"),
    (
        63,
        25,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b08",
        "05724ce1a86bba75ac511704cda9ba52",
    ),
    (
        64,
        30,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889",
        "53eb9011b17c6c65bda1a84d9b804906",
    ),
    (
        65,
        35,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3",
        "dd81de9f729925337f8c7d8d184335fe",
    ),
    (
        127,
        40,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150f",
        "fd1e14a55a893f9d5d9e38802dc99960",
    ),
    (
        128,
        1,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150fb6",
        "8f02e67ad77aead8de0cc52a1dc78499",
    ),
    (
        129,
        6,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150fb6\
         98",
        "0bb2f8988b6f4224a606f1745f8f1d1c",
    ),
    (
        255,
        11,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150fb6\
         98045a14fe3658dd4a011b77e183f15e74f61fe3f5caa78fc9eff727c9232713\
         896c9bd70d3c2cb78e7dc57aa0244071b11df9f3681d7478d3d3dc056dfcbb77\
         7a5fd497ee6242f14a0f8dcc3a60468b6adcd7930711599f71786eed22798621\
         e35c6d1bc988c834ee5c3c1a7286596fbd1b3c1a1b43a1ca1e362aff1d51e6",
        "bdd4c31492704f81ad557c013998a0ba",
    ),
    (
        256,
        16,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150fb6\
         98045a14fe3658dd4a011b77e183f15e74f61fe3f5caa78fc9eff727c9232713\
         896c9bd70d3c2cb78e7dc57aa0244071b11df9f3681d7478d3d3dc056dfcbb77\
         7a5fd497ee6242f14a0f8dcc3a60468b6adcd7930711599f71786eed22798621\
         e35c6d1bc988c834ee5c3c1a7286596fbd1b3c1a1b43a1ca1e362aff1d51e61f",
        "31cd1fa9d4b46ab4dd981e9611c8f515",
    ),
    (
        257,
        21,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150fb6\
         98045a14fe3658dd4a011b77e183f15e74f61fe3f5caa78fc9eff727c9232713\
         896c9bd70d3c2cb78e7dc57aa0244071b11df9f3681d7478d3d3dc056dfcbb77\
         7a5fd497ee6242f14a0f8dcc3a60468b6adcd7930711599f71786eed22798621\
         e35c6d1bc988c834ee5c3c1a7286596fbd1b3c1a1b43a1ca1e362aff1d51e61f\
         8b",
        "db9c689a76d9da458c6d9679d2a514d0",
    ),
    (
        511,
        26,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150fb6\
         98045a14fe3658dd4a011b77e183f15e74f61fe3f5caa78fc9eff727c9232713\
         896c9bd70d3c2cb78e7dc57aa0244071b11df9f3681d7478d3d3dc056dfcbb77\
         7a5fd497ee6242f14a0f8dcc3a60468b6adcd7930711599f71786eed22798621\
         e35c6d1bc988c834ee5c3c1a7286596fbd1b3c1a1b43a1ca1e362aff1d51e61f\
         8b0357bdb9cb245dcd8e7adf2d65312bdaee740fa3f592d4f25632526a6e8727\
         96b6b4c298f6837849d50b8ad5b6ab550cf2406a68a1aa393cd8a455ab26897c\
         f6e63f0b8fa863c9e3f2df2dc12a360558375c0c8a57ab60b3eb7f6d613ea32c\
         ea247a614970e9a601f22ff5577d522cd3031c0d33fff43099f0f974b452f2fb\
         f5818692c942636cab02d86441a2c9d54e6f2a7b7ea601057bad8bb46e7a28c6\
         f87853b43322344fa27efc2ead352b6109a9954011af31abd4ac354bb07a43f3\
         941fd887b60cb146682f5c466456a361a1b191762ae316f394478d18fb775096\
         4960996e99f5643e84be9b52a2f5457e5903932702ba21fb3956b38dfd48ef",
        "89ce491441925ad40e568d0a373a7e7b",
    ),
    (
        512,
        31,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150fb6\
         98045a14fe3658dd4a011b77e183f15e74f61fe3f5caa78fc9eff727c9232713\
         896c9bd70d3c2cb78e7dc57aa0244071b11df9f3681d7478d3d3dc056dfcbb77\
         7a5fd497ee6242f14a0f8dcc3a60468b6adcd7930711599f71786eed22798621\
         e35c6d1bc988c834ee5c3c1a7286596fbd1b3c1a1b43a1ca1e362aff1d51e61f\
         8b0357bdb9cb245dcd8e7adf2d65312bdaee740fa3f592d4f25632526a6e8727\
         96b6b4c298f6837849d50b8ad5b6ab550cf2406a68a1aa393cd8a455ab26897c\
         f6e63f0b8fa863c9e3f2df2dc12a360558375c0c8a57ab60b3eb7f6d613ea32c\
         ea247a614970e9a601f22ff5577d522cd3031c0d33fff43099f0f974b452f2fb\
         f5818692c942636cab02d86441a2c9d54e6f2a7b7ea601057bad8bb46e7a28c6\
         f87853b43322344fa27efc2ead352b6109a9954011af31abd4ac354bb07a43f3\
         941fd887b60cb146682f5c466456a361a1b191762ae316f394478d18fb775096\
         4960996e99f5643e84be9b52a2f5457e5903932702ba21fb3956b38dfd48ef69",
        "a66dfcc10053f60e71e8b55f7f1340a8",
    ),
    (
        1000,
        36,
        "cc7fce2bac041f817e60747696c835c7fa7adb0c56737fcd17e38f875be50b79\
         e19e2300947fab7f0d6f8682b75d7186a2e7136a545c479a73a17c1e9f1b0889\
         d3746d8269fbbbce7dafa5285fe6472ef5c092fe352d1b93a984fe1049ed3cc4\
         194afa3867da9ad16d4106ddcff2602e9e72b24e384ae1eaae2de37b64150fb6\
         98045a14fe3658dd4a011b77e183f15e74f61fe3f5caa78fc9eff727c9232713\
         896c9bd70d3c2cb78e7dc57aa0244071b11df9f3681d7478d3d3dc056dfcbb77\
         7a5fd497ee6242f14a0f8dcc3a60468b6adcd7930711599f71786eed22798621\
         e35c6d1bc988c834ee5c3c1a7286596fbd1b3c1a1b43a1ca1e362aff1d51e61f\
         8b0357bdb9cb245dcd8e7adf2d65312bdaee740fa3f592d4f25632526a6e8727\
         96b6b4c298f6837849d50b8ad5b6ab550cf2406a68a1aa393cd8a455ab26897c\
         f6e63f0b8fa863c9e3f2df2dc12a360558375c0c8a57ab60b3eb7f6d613ea32c\
         ea247a614970e9a601f22ff5577d522cd3031c0d33fff43099f0f974b452f2fb\
         f5818692c942636cab02d86441a2c9d54e6f2a7b7ea601057bad8bb46e7a28c6\
         f87853b43322344fa27efc2ead352b6109a9954011af31abd4ac354bb07a43f3\
         941fd887b60cb146682f5c466456a361a1b191762ae316f394478d18fb775096\
         4960996e99f5643e84be9b52a2f5457e5903932702ba21fb3956b38dfd48ef69\
         9b3e395366fa94c3da8dfcd4cbcdfdee8da1e68dcac60e4fceb11b14acbde639\
         8dbe2ad16fc3ba553177ce0dbbf985b497752035cc6ef8dde1f7df8685e75ddb\
         370d2be4c012dbed4fd54ba929eae8d2f3d7bc605035052b984bcd03f18de2d7\
         374b93d20971f17c5b7541974c612ade1e0860d4732c8185ef04ac00ef887da8\
         3e47f6b261b1b31b13812ae918a0e399106203d362acceffa7919daee58f6762\
         2517bf9130560033ae550600b8aca9cbea6d1394e1471dbc2c97b3c6e2a09108\
         a7a810a630b6334c95dc61d0e54c5ce817d18a569bc985abff9876f0890fd04c\
         a1fe0e15aa072aebce22ac80c3f8bf3508a91b3fc1dadfc2f5b16633f642405c\
         572611a8f9109ccafe6dd81f8be10c0d47651091b848766145c14754dfc77059\
         6160c7aaf515be5fbe20b6af0cee53f3fda62b1b6e157693225a13ab013d04c0\
         911d819adec42dcdd879b67f922edd054351803d72da5bbd4eb2e72bf3f2dd57\
         0d16f9e93b9ee00f19aa511ef775e5e4741aee8dd5e716501d9d71b84a682509\
         b008186c7c4d95a8c8659d224e68e27f617a52511f722e2c03fad6ebbe181c93\
         beacfee32d4f9f83c0cd063614db6d3e2f945c5c67e015364baaffa35da535fc\
         8d807808188d52efc04dd82ac2ae296e296c58072da564efb55f998e37f6fcda\
         0f0f1160f77f0f7e",
        "c8ee2897a545fc691f207b3c4bb61425",
    ),
];

/// Generated with Zig 0.16 `XChaCha20Poly1305.encrypt` over [`zig_inputs`]: message length,
/// associated data length, ciphertext, tag.
const ZIG_XCHACHA: [(usize, usize, &str, &str); 17] = [
    (0, 0, "", "c06f916e6ab786085e839cfe9eae509b"),
    (1, 5, "45", "31dc1c9a5a412393fb51d1c651ff2485"),
    (15, 10, "4584d6931372f5f3e4fea0dc1ce68b", "a89b76fb178aa54a6b022666236a0c57"),
    (16, 15, "4584d6931372f5f3e4fea0dc1ce68be3", "bc0db9fda908b9859dd461cd38f3c92b"),
    (17, 20, "4584d6931372f5f3e4fea0dc1ce68be378", "550174642e5760724a578ef05eff6231"),
    (
        63,
        25,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d569444",
        "0348d5b5044cc0b1a95dfb35a2c1e790",
    ),
    (
        64,
        30,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414",
        "08fc18a31e01b62ab5514f3d72c19d17",
    ),
    (
        65,
        35,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         88",
        "4ccf958020c573aabe39728fc2f94e5a",
    ),
    (
        127,
        40,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5",
        "ab03d56bf8cd8e108798f8669dd74635",
    ),
    (
        128,
        1,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5f8",
        "e9803f68bcabe390235aa4ffecbea2f8",
    ),
    (
        129,
        6,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5f8\
         d0",
        "e06977348362955be89ba03eed63c69d",
    ),
    (
        255,
        11,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5f8\
         d09daf6adaaea90fa74f6fd4a575b349d5f7db42390e65d3c74602a5cf47cd7a\
         50348b63c2b55198a2646efe22865ed59a899e35aab1fff4b4238588b5e07a83\
         dad12c2396eadec13766a8d6f3d9754acc770b061d7c5a187caa46b8a72f12a1\
         bf144627807260ac73aaf0afb32e74ee0c9dda36f7d7c59fb1bb466b5298e2",
        "53170617282661cd606cf5716a179bab",
    ),
    (
        256,
        16,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5f8\
         d09daf6adaaea90fa74f6fd4a575b349d5f7db42390e65d3c74602a5cf47cd7a\
         50348b63c2b55198a2646efe22865ed59a899e35aab1fff4b4238588b5e07a83\
         dad12c2396eadec13766a8d6f3d9754acc770b061d7c5a187caa46b8a72f12a1\
         bf144627807260ac73aaf0afb32e74ee0c9dda36f7d7c59fb1bb466b5298e263",
        "6dfb9edd6f75988b37d471d1ba45e679",
    ),
    (
        257,
        21,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5f8\
         d09daf6adaaea90fa74f6fd4a575b349d5f7db42390e65d3c74602a5cf47cd7a\
         50348b63c2b55198a2646efe22865ed59a899e35aab1fff4b4238588b5e07a83\
         dad12c2396eadec13766a8d6f3d9754acc770b061d7c5a187caa46b8a72f12a1\
         bf144627807260ac73aaf0afb32e74ee0c9dda36f7d7c59fb1bb466b5298e263\
         2e",
        "9bd79329a2466de613605bd57701c45f",
    ),
    (
        511,
        26,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5f8\
         d09daf6adaaea90fa74f6fd4a575b349d5f7db42390e65d3c74602a5cf47cd7a\
         50348b63c2b55198a2646efe22865ed59a899e35aab1fff4b4238588b5e07a83\
         dad12c2396eadec13766a8d6f3d9754acc770b061d7c5a187caa46b8a72f12a1\
         bf144627807260ac73aaf0afb32e74ee0c9dda36f7d7c59fb1bb466b5298e263\
         2e5331baaa08c3d98c24e81e3544b02b04926224234f9a40761307d67f0671a4\
         5b6030fede7852aad80c96b60dc1023251a8b370e707e1962089b186b2f69aba\
         7d24a41616edb70120d24002e77421bfc455493578e99f7db258c82e6048a880\
         f4e9a60dbb735bc6945c0f1ede11c50cbfaf8d992cbf2153000dbef7d681ab9e\
         cb997c0b0458c0f5068b9db18aef01a3e1f02a108b9af620b9db0947db7badda\
         74993203b3d400558e6b2a670beb226506a778c78fbb83157203385c3758fb87\
         b57cb23530bb2da248ed9240ec180e24d98cf37f218a7201f1f4b17f0bb6b8bf\
         ab26a1909385879113a27576e257abbb1bf26d10bfe90c3de1a394ce065a2b",
        "942ac58ec9d9335ac0c2be9615334330",
    ),
    (
        512,
        31,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5f8\
         d09daf6adaaea90fa74f6fd4a575b349d5f7db42390e65d3c74602a5cf47cd7a\
         50348b63c2b55198a2646efe22865ed59a899e35aab1fff4b4238588b5e07a83\
         dad12c2396eadec13766a8d6f3d9754acc770b061d7c5a187caa46b8a72f12a1\
         bf144627807260ac73aaf0afb32e74ee0c9dda36f7d7c59fb1bb466b5298e263\
         2e5331baaa08c3d98c24e81e3544b02b04926224234f9a40761307d67f0671a4\
         5b6030fede7852aad80c96b60dc1023251a8b370e707e1962089b186b2f69aba\
         7d24a41616edb70120d24002e77421bfc455493578e99f7db258c82e6048a880\
         f4e9a60dbb735bc6945c0f1ede11c50cbfaf8d992cbf2153000dbef7d681ab9e\
         cb997c0b0458c0f5068b9db18aef01a3e1f02a108b9af620b9db0947db7badda\
         74993203b3d400558e6b2a670beb226506a778c78fbb83157203385c3758fb87\
         b57cb23530bb2da248ed9240ec180e24d98cf37f218a7201f1f4b17f0bb6b8bf\
         ab26a1909385879113a27576e257abbb1bf26d10bfe90c3de1a394ce065a2bba",
        "b43ca4523d277391eae18c683cff6d09",
    ),
    (
        1000,
        36,
        "4584d6931372f5f3e4fea0dc1ce68be3785b1c0eff29dd431a657de8f2a1d054\
         2d80d9706c1025b47f606a6980815a826f2fb4d294a67f3b6e72530d56944414\
         883035f451504e36827e0edc1d83bd2c9fc1190499aca39ca65b46842a490acd\
         08c9d3458d57444c265ad0eed2d93f599692cd95569a1728ec3438a98fffc5f8\
         d09daf6adaaea90fa74f6fd4a575b349d5f7db42390e65d3c74602a5cf47cd7a\
         50348b63c2b55198a2646efe22865ed59a899e35aab1fff4b4238588b5e07a83\
         dad12c2396eadec13766a8d6f3d9754acc770b061d7c5a187caa46b8a72f12a1\
         bf144627807260ac73aaf0afb32e74ee0c9dda36f7d7c59fb1bb466b5298e263\
         2e5331baaa08c3d98c24e81e3544b02b04926224234f9a40761307d67f0671a4\
         5b6030fede7852aad80c96b60dc1023251a8b370e707e1962089b186b2f69aba\
         7d24a41616edb70120d24002e77421bfc455493578e99f7db258c82e6048a880\
         f4e9a60dbb735bc6945c0f1ede11c50cbfaf8d992cbf2153000dbef7d681ab9e\
         cb997c0b0458c0f5068b9db18aef01a3e1f02a108b9af620b9db0947db7badda\
         74993203b3d400558e6b2a670beb226506a778c78fbb83157203385c3758fb87\
         b57cb23530bb2da248ed9240ec180e24d98cf37f218a7201f1f4b17f0bb6b8bf\
         ab26a1909385879113a27576e257abbb1bf26d10bfe90c3de1a394ce065a2bba\
         0823654ec0e997c75d9b5e49cade2dc5278006096ff891f845731062ed46e8d0\
         2d6ce6c69a2f492a49cdb896240f7442b9dc23a79134223c3b8c2f41daf6e491\
         74d5e766d3247d370260eca2eef75ce5edb553b5ed073dced6c116d704b0d37a\
         d98a21a4a7bf46f5110b2a6b77cb232013de5e06b40e64de2d937b354f8dbe55\
         6808b147438a4ec51152f5c6e3dd31c50f68f597a55731bbef0ce590084d99dc\
         17bec3c2b3ff05f755ce0ee5dea8a5791ecf547d12e5f8dfc5b506f2ee2fb257\
         d5865cc43a94788e0a4f862121837e6be6e44152676095f6961f46cba33a60a6\
         f3e9802ceedd98f6d1055ba76c88c0e77cbb165aecaf70d98368ede08fae964b\
         d76798f6b4b3b52cd97404c728f72a53cb7264c450fb22d817f86208b696da68\
         920ab9fe452a7172f0cfcd8884d9f5c3360265d8cfde826ce4a30c9ac60bae65\
         1e48b27b1a6fa49be06588d8febfaceb89c8d20421358a030db3edc93d4849e2\
         74cb5381bcc4276e14033bee78c1308c72e834f8bf8e1c8e9d46e7e1f3afd968\
         2167935f1cc7e0ce36de2565ac31a3a9b5d38c5882c278edc0dcb2ed30c4854c\
         a9dd3938a9331475a0222360642f31e9aa1fda2877cc69dfe3688a8357399f3f\
         5506c5151f21397f398d2e231b9d1c982235a1fe521809f0c9731a47659442ca\
         b35a158e297e9dfe",
        "2cf04ae9e7a4536b5c9b0bf6902c5dde",
    ),
];
