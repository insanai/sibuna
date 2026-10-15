use super::*;
use crate::sha512::Sha512;
use crate::test_util::{hex, hex_array};

/// RFC 8032 section 7.1: secret key (seed), public key, message, signature. Also produced
/// by Zig 0.16 `Ed25519.KeyPair.generateDeterministic` and `sign`.
const RFC_8032: [(&str, &str, &str, &str); 3] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
         18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

fn check_sign_and_verify(seed: &str, public_key: &str, message: &[u8], signature: &str) {
    let key = SigningKey::from_seed(&hex_array(seed));
    assert_eq!(key.verifying_key().to_bytes(), hex_array::<32>(public_key));
    let produced = key.sign(message);
    assert_eq!(produced.to_bytes(), hex_array::<64>(signature));
    let verifying_key = VerifyingKey::from_bytes(&hex_array(public_key)).unwrap();
    assert_eq!(verifying_key, key.verifying_key());
    verifying_key.verify(message, &Signature::from_bytes(&hex_array(signature))).unwrap();
}

#[test]
fn rfc_8032_vectors() {
    for (seed, public_key, message, signature) in RFC_8032 {
        check_sign_and_verify(seed, public_key, &hex(message), signature);
    }
}

#[test]
fn rfc_8032_sha_abc() {
    check_sign_and_verify(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        &Sha512::digest(b"abc"),
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
         09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    );
}

/// The 40-byte message signed in the Zig-generated vectors: byte `i` is `3i + 1`, the size
/// of a session token payload.
fn token_sized_message() -> [u8; 40] {
    core::array::from_fn(|i| (3 * i + 1) as u8)
}

/// Generated with Zig 0.16 `Ed25519.KeyPair.generateDeterministic([fill] ** 32)` and
/// `sign(message, null)`. The seed [7; 32] is the one Zig's token tests use.
#[test]
fn zig_generated_vectors() {
    let cases = [
        (
            7u8,
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
            "0c06fccf9df9993c624a5e0c1f50f4550afa0105d83d078354d0f1670f93ab53\
             1fa78b6ba1cbeddffd6d1439c792b8d45fdd9af7bb778359ecd5b7ccc4c59b06",
        ),
        (
            9u8,
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
            "6aba5e6fc6c5107ea826318858070bb0e992ec6f9cf3ddf04e3f1b8691b3e4be\
             08b27868584e7ea0447ad5ccfe51952787b20f23ef4c70fff6d05c73d2f7ef0c",
        ),
    ];
    for (fill, public_key, signature) in cases {
        let seed = std::format!("{fill:02x}").repeat(32);
        check_sign_and_verify(&seed, public_key, &token_sized_message(), signature);
    }
}

/// Zig 0.16 std tests "key pair creation" and "signature".
#[test]
fn zig_key_pair_and_signature() {
    let key = SigningKey::from_seed(&hex_array(
        "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166",
    ));
    assert_eq!(
        key.verifying_key().to_bytes(),
        hex_array::<32>("2d6f7455d97b4a3a10d7293909d1a4f2058cb9a370e43fa8154bb280db839083")
    );
    let signature = key.sign(b"test");
    assert_eq!(
        signature.to_bytes(),
        hex_array::<64>(
            "10a442b4a80cc4225b154f43bef28d2472ca80221951262eb8e0df9091575e26\
             87cc486e77263c3418c757522d54f84b0359236abbbd4acd20dc297fdca66808"
        )
    );
    key.verifying_key().verify(b"test", &signature).unwrap();
    assert_eq!(
        key.verifying_key().verify(b"TEST", &signature),
        Err(SignatureError::VerificationFailed)
    );
}

/// Zig 0.16 std test "test vectors": edge cases from "Taming the many EdDSAs" (Chalkias,
/// Garillot and Nikolaenko, 2020). `None` means the signature is accepted.
const EDGE_CASES: [(&str, &str, &str, Option<SignatureError>); 12] = [
    (
        "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a\
         0000000000000000000000000000000000000000000000000000000000000000",
        Some(SignatureError::WeakPublicKey),
    ),
    (
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43\
         a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        Some(SignatureError::WeakPublicKey),
    ),
    (
        "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa\
         8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        None, // small-order R is accepted
    ),
    (
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f\
         87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        None, // mixed orders
    ),
    (
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512\
         5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        None, // cofactored verification
    ),
    (
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7\
         e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        None, // cofactored verification
    ),
    (
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e\
         547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        Some(SignatureError::NonCanonical), // S > L
    ),
    (
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942\
         7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        Some(SignatureError::NonCanonical), // S >> L
    ),
    (
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        Some(SignatureError::IdentityElement), // non-canonical R
    ),
    (
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        Some(SignatureError::IdentityElement), // non-canonical R
    ),
    (
        "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc\
         a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        Some(SignatureError::IdentityElement), // small-order A
    ),
    (
        "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc\
         a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        Some(SignatureError::IdentityElement), // small-order A
    ),
];

#[test]
fn zig_edge_cases() {
    for (i, (message, public_key, signature, expected)) in EDGE_CASES.into_iter().enumerate() {
        let result = VerifyingKey::from_bytes(&hex_array(public_key)).and_then(|key| {
            key.verify(&hex(message), &Signature::from_bytes(&hex_array(signature)))
        });
        assert_eq!(result.err(), expected, "case {i}");
    }
}

/// Zig 0.16 std test "cofactored vs cofactorless verification": a signature only the
/// cofactored equation accepts. Zig's `verify` (the one Sibuna uses) accepts it.
#[test]
fn cofactored_verification_accepts() {
    let key = VerifyingKey::from_bytes(&hex_array(
        "86e72f5c2a7215151059aa151c0ee6f8e2155d301402f35d7498f078629a8f79",
    ))
    .unwrap();
    let signature = Signature::from_bytes(&hex_array(
        "fa9dde274f4820efb19a890f8ba2d8791710a4303ceef4aedf9dddc4e81a1f11\
         701a598b9a02ae60505dd0c2938a1a0c2d6ffd4676cfb49125b19e9cb358da06",
    ));
    key.verify(&hex("65643235353139766563746f72732033"), &signature).unwrap();
}

/// Points of small order from Zig's edwards25519 "packing/unpacking" test, plus the
/// encodings of p and p + 1, which are not canonical.
#[test]
fn small_order_public_keys_are_rejected() {
    let cases = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            SignatureError::WeakPublicKey,
        ),
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            SignatureError::IdentityElement,
        ),
        (
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            SignatureError::WeakPublicKey,
        ),
        (
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            SignatureError::WeakPublicKey,
        ),
        (
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            SignatureError::IdentityElement,
        ),
        (
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            SignatureError::NonCanonical,
        ),
        (
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            SignatureError::NonCanonical,
        ),
    ];
    for (encoding, expected) in cases {
        assert_eq!(
            VerifyingKey::from_bytes(&hex_array(encoding)).err(),
            Some(expected),
            "{encoding}"
        );
    }
}

#[test]
fn off_curve_encodings_are_rejected() {
    // y = 2 is not the y-coordinate of any point.
    let mut encoding = [0u8; 32];
    encoding[0] = 2;
    assert_eq!(VerifyingKey::from_bytes(&encoding).err(), Some(SignatureError::InvalidEncoding));
}

/// Zig's edwards25519 "packing/unpacking" and "implicit reduction of invalid scalars".
#[test]
fn zig_base_point_multiples() {
    let mut s = [0u8; 32];
    s[0] = 170;
    assert_eq!(
        Point::mul_base(&s).encode(),
        hex_array::<32>("074bc7e0fcbd587fdbc0969444245fadc562809c8f6e97e949af62484b5b81a6")
    );
    let mut s = [0u8; 32];
    s[31] = 255;
    assert_eq!(
        Point::mul_base(&s).encode(),
        hex_array::<32>("339f189ecc5fbebe9895345c72dc07bda6e615f8a40e768441b6f529cd6c671a")
    );
}

#[test]
fn tampering_is_detected() {
    let key = SigningKey::from_seed(&[7; 32]);
    let message = token_sized_message();
    let signature = key.sign(&message);
    let verifying_key = key.verifying_key();
    for bit in 0..message.len() * 8 {
        let mut altered = message;
        altered[bit / 8] ^= 1 << (bit % 8);
        assert!(verifying_key.verify(&altered, &signature).is_err(), "message bit {bit}");
    }
    for bit in 0..SIGNATURE_LEN * 8 {
        let mut altered = signature.to_bytes();
        altered[bit / 8] ^= 1 << (bit % 8);
        let result = verifying_key.verify(&message, &Signature::from_bytes(&altered));
        assert!(result.is_err(), "signature bit {bit}");
    }
    let other = SigningKey::from_seed(&[9; 32]).verifying_key();
    assert_eq!(other.verify(&message, &signature), Err(SignatureError::VerificationFailed));
}

#[test]
fn signatures_round_trip_through_bytes() {
    let key = SigningKey::from_seed(&[1; 32]);
    let signature = key.sign(b"payload");
    assert_eq!(Signature::from_bytes(&signature.to_bytes()), signature);
    let restored = VerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    restored.verify(b"payload", &signature).unwrap();
    let debug = std::format!("{key:?}");
    assert!(debug.starts_with("SigningKey"), "{debug}");
    assert_eq!(
        std::format!("{}", SignatureError::WeakPublicKey),
        "the public key has small order"
    );
}

/// Mutates valid (message, signature) pairs and checks that verification never panics and
/// accepts only the unmodified pair. Also feeds mutated public keys to `from_bytes`.
fn fuzz_verification(cases: usize) {
    let mut rng = crate::test_util::XorShift::new(0xed25_5190_f022);
    let keys = [SigningKey::from_seed(&[7; 32]), SigningKey::from_seed(&[9; 32])];
    let message = token_sized_message();
    let originals = [keys[0].sign(&message), keys[1].sign(&message)];
    for _ in 0..cases {
        let which = rng.below(2);
        let verifying_key = keys[which].verifying_key();
        let mut signature = originals[which].to_bytes();
        let mut altered_message = message;
        match rng.below(3) {
            0 => rng.mutate(&mut signature, &originals[1 - which].to_bytes()),
            1 => rng.mutate(&mut altered_message, &signature),
            _ => {
                let mut key_bytes = verifying_key.to_bytes();
                rng.mutate(&mut key_bytes, &signature);
                if let Ok(key) = VerifyingKey::from_bytes(&key_bytes) {
                    assert_eq!(key.to_bytes(), key_bytes);
                    let result = key.verify(&message, &Signature::from_bytes(&signature));
                    assert_eq!(result.is_ok(), key_bytes == verifying_key.to_bytes());
                }
                continue;
            }
        }
        let result = verifying_key.verify(&altered_message, &Signature::from_bytes(&signature));
        let unchanged = signature == originals[which].to_bytes() && altered_message == message;
        assert_eq!(result.is_ok(), unchanged, "{result:?}");
    }
}

#[test]
fn fuzz_signature_verification() {
    fuzz_verification(300);
}

#[test]
#[ignore = "long fuzz run; use --release"]
fn fuzz_signature_verification_long() {
    fuzz_verification(100_000);
}
