use super::*;
use crate::chacha20::ChaCha20;
use crate::test_util::{XorShift, hex, hex_array};

/// RFC 8439 section 2.5.2, which is also Zig's test "rfc7439 vector1".
#[test]
fn rfc_example() {
    let key = hex_array("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let tag = mac(&key, b"Cryptographic Forum Research Group");
    assert_eq!(tag.as_slice(), hex("a8061dc1305136c6c22b8baf0c0127a9"));
}

/// Zig's test "requiring a final reduction".
#[test]
fn zig_final_reduction() {
    let key = [
        190, 63, 95, 57, 155, 103, 77, 170, 7, 98, 106, 44, 117, 186, 90, 185, 109, 118, 184, 24,
        69, 41, 166, 243, 119, 132, 151, 61, 52, 43, 64, 250,
    ];
    let message = [
        253, 193, 249, 146, 70, 6, 214, 226, 131, 213, 241, 116, 20, 24, 210, 224, 65, 151, 255,
        104, 133,
    ];
    let expected = [25, 13, 249, 42, 164, 57, 99, 60, 149, 181, 74, 74, 13, 63, 121, 6];
    assert_eq!(mac(&key, &message), expected);
}

#[test]
fn rfc_appendix_a3() {
    for (number, (key, message, tag)) in RFC_A3.into_iter().enumerate() {
        assert_eq!(mac(&hex_array(key), &hex(message)).as_slice(), hex(tag), "#{}", number + 1);
    }
}

/// RFC 8439 section 2.6.2 and appendix A.4: the one-time key is the first half of
/// keystream block 0.
#[test]
fn rfc_key_generation() {
    let cases = RFC_A4.into_iter().chain([(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "000000000001020304050607",
        "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646",
    )]);
    for (key, nonce, expected) in cases {
        let block = ChaCha20::new(&hex_array(key), &hex_array(nonce), 0).keystream_block();
        assert_eq!(block.unwrap()[..32], hex(expected));
    }
}

/// Splitting the input arbitrarily gives the one-shot tag.
#[test]
fn streaming_matches_one_shot() {
    let mut rng = XorShift::new(1305);
    let mut data = std::vec![0u8; 700];
    for _ in 0..300 {
        rng.fill(&mut data);
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let len = rng.below(data.len());
        let expected = mac(&key, &data[..len]);
        let mut state = Poly1305::new(&key);
        let mut rest = &data[..len];
        while !rest.is_empty() {
            let take = rng.below(rest.len().min(40) + 1);
            state.update(&rest[..take]);
            rest = &rest[take..];
        }
        assert_eq!(state.finalize(), expected);
    }
    assert_eq!(std::format!("{:?}", Poly1305::new(&[0; 32])), "Poly1305 { .. }");
}

/// Edge values of the accumulator: all-ones keys and blocks, against a naive
/// implementation over u128 pairs.
#[test]
fn matches_naive_reference() {
    let mut rng = XorShift::new(0x5eed);
    for round in 0..2000 {
        let mut key = [0u8; 32];
        let mut message = std::vec![0u8; rng.below(80)];
        if round % 3 == 0 {
            key.fill(0xff);
            message.fill(0xff);
        } else {
            rng.fill(&mut key);
            rng.fill(&mut message);
        }
        assert_eq!(mac(&key, &message), naive(&key, &message), "round {round}");
    }
}

/// A 192-bit number as little-endian words, for the naive reference.
type Wide = [u64; 3];

fn wide_add(a: Wide, b: Wide) -> Wide {
    let (s0, c0) = a[0].overflowing_add(b[0]);
    let (s1, c1) = a[1].overflowing_add(b[1]);
    let (s1, c2) = s1.overflowing_add(u64::from(c0));
    [s0, s1, a[2] + b[2] + u64::from(c1 | c2)]
}

fn wide_sub(a: Wide, b: Wide) -> Wide {
    let (d0, b0) = a[0].overflowing_sub(b[0]);
    let (d1, b1) = a[1].overflowing_sub(b[1]);
    let (d1, b2) = d1.overflowing_sub(u64::from(b0));
    [d0, d1, a[2] - b[2] - u64::from(b1 | b2)]
}

fn wide_at_least(a: Wide, b: Wide) -> bool {
    (a[2], a[1], a[0]) >= (b[2], b[1], b[0])
}

const P: Wide = [0xffff_ffff_ffff_fffb, u64::MAX, 3];

fn add_mod(a: Wide, b: Wide) -> Wide {
    let sum = wide_add(a, b);
    if wide_at_least(sum, P) { wide_sub(sum, P) } else { sum }
}

/// `a * b mod p` by double-and-add over the 130 bits of `b`.
fn mul_mod(a: Wide, b: Wide) -> Wide {
    let mut result = [0; 3];
    for bit in (0..130).rev() {
        result = add_mod(result, result);
        if b[bit / 64] >> (bit % 64) & 1 == 1 {
            result = add_mod(result, a);
        }
    }
    result
}

/// Poly1305 straight from the definition: h = (h + n) * r mod p per block, tag =
/// (h + s) mod 2^128.
fn naive(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let word = |at: usize| u64::from_le_bytes(core::array::from_fn(|i| key[at + i]));
    let r = [word(0) & 0x0fff_fffc_0fff_ffff, word(8) & 0x0fff_fffc_0fff_fffc, 0];
    let mut h: Wide = [0; 3];
    for chunk in message.chunks(16) {
        let mut block = [0u8; 24];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;
        let n: Wide = core::array::from_fn(|i| {
            u64::from_le_bytes(core::array::from_fn(|j| block[8 * i + j]))
        });
        h = mul_mod(add_mod(h, n), r);
    }
    let (t0, carry) = h[0].overflowing_add(word(16));
    let t1 = h[1].wrapping_add(word(24)).wrapping_add(u64::from(carry));
    let mut tag = [0u8; 16];
    tag[..8].copy_from_slice(&t0.to_le_bytes());
    tag[8..].copy_from_slice(&t1.to_le_bytes());
    tag
}

/// RFC 8439 appendix A.3: key (r then s), message, tag.
const RFC_A3: [(&str, &str, &str); 11] = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
    ),
    (
        "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e\
         6465642062792074686520436f6e7472696275746f7220666f72207075626c69\
         636174696f6e20617320616c6c206f722070617274206f6620616e2049455446\
         20496e7465726e65742d4472616674206f722052464320616e6420616e792073\
         746174656d656e74206d6164652077697468696e2074686520636f6e74657874\
         206f6620616e204945544620616374697669747920697320636f6e7369646572\
         656420616e20224945544620436f6e747269627574696f6e222e205375636820\
         73746174656d656e747320696e636c756465206f72616c2073746174656d656e\
         747320696e20494554462073657373696f6e732c2061732077656c6c20617320\
         7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361\
         74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c\
         207768696368206172652061646472657373656420746f",
        "36e5f6b5c5e06070f0efca96227a863e",
    ),
    (
        "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e\
         6465642062792074686520436f6e7472696275746f7220666f72207075626c69\
         636174696f6e20617320616c6c206f722070617274206f6620616e2049455446\
         20496e7465726e65742d4472616674206f722052464320616e6420616e792073\
         746174656d656e74206d6164652077697468696e2074686520636f6e74657874\
         206f6620616e204945544620616374697669747920697320636f6e7369646572\
         656420616e20224945544620436f6e747269627574696f6e222e205375636820\
         73746174656d656e747320696e636c756465206f72616c2073746174656d656e\
         747320696e20494554462073657373696f6e732c2061732077656c6c20617320\
         7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361\
         74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c\
         207768696368206172652061646472657373656420746f",
        "f3477e7cd95417af89a6b8794c310cf0",
    ),
    (
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f\
         7665730a446964206779726520616e642067696d626c6520696e207468652077\
         6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665\
         732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        "4541669a7eaaee61e708dc7cbcc5eb62",
    ),
    (
        "0200000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "03000000000000000000000000000000",
    ),
    (
        "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
        "02000000000000000000000000000000",
        "03000000000000000000000000000000",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff\
         11000000000000000000000000000000",
        "05000000000000000000000000000000",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe\
         01010101010101010101010101010101",
        "00000000000000000000000000000000",
    ),
    (
        "0200000000000000000000000000000000000000000000000000000000000000",
        "fdffffffffffffffffffffffffffffff",
        "faffffffffffffffffffffffffffffff",
    ),
    (
        "0100000000000000040000000000000000000000000000000000000000000000",
        "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000\
         0000000000000000000000000000000001000000000000000000000000000000",
        "14000000000000005500000000000000",
    ),
    (
        "0100000000000000040000000000000000000000000000000000000000000000",
        "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000\
         00000000000000000000000000000000",
        "13000000000000000000000000000000",
    ),
];

/// RFC 8439 appendix A.4: ChaCha20 key, nonce, Poly1305 one-time key.
const RFC_A4: [(&str, &str, &str); 3] = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000002",
        "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739",
    ),
    (
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "000000000000000000000002",
        "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae",
    ),
];
