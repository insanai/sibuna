use super::*;
use crate::test_util::{XorShift, hex, hex_array};
use std::vec::Vec;

const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only \
                           one tip for the future, sunscreen would be it.";

const DHOLE: &[u8] = b"The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, \
                       red dog, and whistling dog. It is about the size of a German shepherd \
                       but looks more like a long-legged fox. This highly elusive and skilled \
                       jumper is classified with wolves, coyotes, jackals, and foxes in the \
                       taxonomic family Canidae.";

fn key_0_to_31() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

fn encrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    apply_keystream(key, nonce, counter, &mut out).unwrap();
    out
}

/// RFC 8439 section 2.1.1.
#[test]
fn rfc_quarter_round() {
    let mut x = [0u32; 16];
    x[..4].copy_from_slice(&[0x1111_1111, 0x0102_0304, 0x9b8d_6f43, 0x0123_4567]);
    quarter_round(&mut x, 0, 1, 2, 3);
    assert_eq!(x[..4], [0xea2a_92f4, 0xcb1c_f8ce, 0x4581_472e, 0x5881_c4bb]);
}

/// RFC 8439 section 2.2.1: QUARTERROUND(2, 7, 8, 13) on a whole state.
#[test]
fn rfc_quarter_round_on_state() {
    let mut x = [
        0x8795_31e0,
        0xc5ec_f37d,
        0x5164_61b1,
        0xc9a6_2f8a,
        0x44c2_0ef3,
        0x3390_af7f,
        0xd9fc_690b,
        0x2a5f_714c,
        0x5337_2767,
        0xb00a_5631,
        0x974c_541a,
        0x359e_9963,
        0x5c97_1061,
        0x3d63_1689,
        0x2098_d9d6,
        0x91db_d320,
    ];
    let mut expected = x;
    expected[2] = 0xbdb8_86dc;
    expected[7] = 0xcfac_afd2;
    expected[8] = 0xe46b_ea80;
    expected[13] = 0xccc0_7c79;
    quarter_round(&mut x, 2, 7, 8, 13);
    assert_eq!(x, expected);
}

/// RFC 8439 section 2.3.2.
#[test]
fn rfc_block_function() {
    let nonce = hex_array("000000090000004a00000000");
    let block = ChaCha20::new(&key_0_to_31(), &nonce, 1).keystream_block().unwrap();
    let expected = hex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
         d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    assert_eq!(block.as_slice(), expected);
}

/// RFC 8439 section 2.4.2, which is also Zig's test "test vector sunscreen".
#[test]
fn rfc_sunscreen() {
    let nonce = hex_array("000000000000004a00000000");
    let ciphertext = encrypt(&key_0_to_31(), &nonce, 1, SUNSCREEN);
    let expected = hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
         f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
         07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
         5af90bbf74a35be6b40b8eedf2785e42874d");
    assert_eq!(ciphertext, expected);
    assert_eq!(encrypt(&key_0_to_31(), &nonce, 1, &ciphertext), SUNSCREEN);
}

/// Zig's tests "test vector 1" to "test vector 5" use the original ChaCha20 with a 64-bit
/// counter and nonce. With counter 0 and fewer than 2^32 blocks it equals RFC 8439
/// ChaCha20 with four zero bytes before the nonce.
#[test]
fn zig_original_chacha_vectors() {
    let zero_key = [0u8; 32];
    let mut one_key = [0u8; 32];
    one_key[31] = 1;
    let cases: [([u8; 32], [u8; 8], &str); 4] = [
        (
            zero_key,
            [0; 8],
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        ),
        (
            one_key,
            [0; 8],
            "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41\
             bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963",
        ),
        (
            zero_key,
            [0, 0, 0, 0, 0, 0, 0, 1],
            "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031\
             e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3",
        ),
        (
            zero_key,
            [1, 0, 0, 0, 0, 0, 0, 0],
            "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32\
             111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b",
        ),
    ];
    for (key, short_nonce, expected) in cases {
        let expected = hex(expected);
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&short_nonce);
        assert_eq!(encrypt(&key, &nonce, 0, &std::vec![0; expected.len()]), expected);
    }
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let expected = hex("f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c1\
         34a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a\
         38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd\
         9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c7\
         9db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025\
         d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d7\
         0eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2\
         ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9");
    assert_eq!(encrypt(&key_0_to_31(), &nonce, 0, &[0; 256]), expected);
}

#[test]
fn rfc_appendix_a1_block_functions() {
    for (key, nonce, counter, expected) in RFC_A1 {
        let block = ChaCha20::new(&hex_array(key), &hex_array(nonce), counter);
        assert_eq!(block.clone().keystream_block().unwrap().as_slice(), hex(expected));
    }
}

#[test]
fn rfc_appendix_a2_encryption() {
    for (key, nonce, counter, plaintext, ciphertext) in RFC_A2 {
        let produced = encrypt(&hex_array(key), &hex_array(nonce), counter, &hex(plaintext));
        assert_eq!(produced, hex(ciphertext));
    }
}

/// draft-irtf-cfrg-xchacha-03 section 2.2.1.
#[test]
fn xchacha_draft_hchacha20() {
    let input = hex_array("000000090000004a0000000031415927");
    let expected = hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    assert_eq!(hchacha20(&key_0_to_31(), &input).as_slice(), expected);
}

#[test]
fn xchacha_draft_a321() {
    let [key, nonce, keystream, ciphertext] = XCHACHA_A321;
    let (key, nonce) = (hex_array(key), hex_array(nonce));
    let mut zeros = std::vec![0u8; DHOLE.len()];
    apply_xchacha20_keystream(&key, &nonce, 0, &mut zeros).unwrap();
    assert_eq!(zeros, hex(keystream));
    let mut data = DHOLE.to_vec();
    apply_xchacha20_keystream(&key, &nonce, 0, &mut data).unwrap();
    assert_eq!(data, hex(ciphertext));
}

/// Zig's test "xchacha20", first half.
#[test]
fn zig_xchacha20() {
    let mut data = SUNSCREEN.to_vec();
    apply_xchacha20_keystream(&[69; 32], &[42; 24], 0, &mut data).unwrap();
    let expected = hex("E0A1BCF939654AFDBDC1746EC49832647C19D891F0D1A81FC0C1703B4514BDEA\
         584B512F6908C2C5E9DD18D5CBC1805DE5803FE3B9CA5F193FB8359E91FAB0C3\
         BB40309A292EB1CF49685C65C4A3ADF4F11DB0CD2B6B67FBC174BC2E860E8F76\
         9FD3565BBFAD1C845E05A0FED9BE167C240D");
    assert_eq!(data, expected);
}

/// The four-block path and the one-block path agree, for any length and any split into
/// whole-block calls.
#[test]
fn four_block_path_matches_single_blocks() {
    let mut rng = XorShift::new(0xc4ac4a);
    let key: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
    let nonce = [9u8; 12];
    for _ in 0..200 {
        let len = rng.below(1100);
        let counter = rng.next_u64() as u32 & 0xffff;
        let mut data = std::vec![0u8; len];
        rng.fill(&mut data);
        let mut expected = data.clone();
        let mut single = ChaCha20::new(&key, &nonce, counter);
        for chunk in expected.chunks_mut(BLOCK_LEN) {
            single.apply_keystream(chunk).unwrap();
        }
        let mut cipher = ChaCha20::new(&key, &nonce, counter);
        let mut rest = data.as_mut_slice();
        while !rest.is_empty() {
            let take = (BLOCK_LEN * (1 + rng.below(6))).min(rest.len());
            let (head, tail) = rest.split_at_mut(take);
            cipher.apply_keystream(head).unwrap();
            rest = tail;
        }
        assert_eq!(data, expected, "length {len}");
    }
}

#[test]
fn refuses_to_wrap_the_counter() {
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let mut data = [0u8; 4 * BLOCK_LEN];
    assert!(apply_keystream(&key, &nonce, u32::MAX - 3, &mut data).is_ok());
    let mut data = [7u8; 4 * BLOCK_LEN + 1];
    assert_eq!(
        apply_keystream(&key, &nonce, u32::MAX - 3, &mut data),
        Err(Error::CounterOverflow)
    );
    assert!(data.iter().all(|&b| b == 7));
    let mut cipher = ChaCha20::new(&key, &nonce, u32::MAX);
    assert!(cipher.keystream_block().is_ok());
    assert_eq!(cipher.keystream_block(), Err(Error::CounterOverflow));
    assert!(cipher.apply_keystream(&mut []).is_ok());
    assert_eq!(std::format!("{cipher:?}"), "ChaCha20 { counter: 0, .. }");
}

/// Encrypts 1 MiB in place; run with
/// `cargo test --release -p sibuna-crypto -- --ignored --nocapture chacha20_timing`.
#[test]
#[ignore = "benchmark; run explicitly in release mode"]
fn chacha20_timing() {
    let mut data = std::vec![0x5au8; 1 << 20];
    let mut best = f64::MAX;
    for _ in 0..20 {
        let start = std::time::Instant::now();
        apply_keystream(&[0x42; 32], &[0x24; 12], 1, &mut data).unwrap();
        best = best.min(start.elapsed().as_secs_f64());
    }
    std::println!("chacha20 1 MiB: {:.0} MB/s", data.len() as f64 / best / 1e6);
}

/// RFC 8439 appendix A.1: key, nonce, counter, keystream block.
const RFC_A1: [(&str, &str, u32, &str); 5] = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        0,
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
         da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        1,
        "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
         29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000000",
        1,
        "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a\
         8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
    ),
    (
        "00ff000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        2,
        "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca\
         13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000002",
        0,
        "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7\
         8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
    ),
];

/// RFC 8439 appendix A.2: key, nonce, counter, plaintext, ciphertext.
const RFC_A2: [(&str, &str, u32, &str, &str); 3] = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        0,
        "0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
         da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000002",
        1,
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
        "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec\
         2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d\
         4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950\
         42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a\
         d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d\
         c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b\
         0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c\
         cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b\
         c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f\
         5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6\
         98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab\
         7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
    ),
    (
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "000000000000000000000002",
        42,
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f\
         7665730a446964206779726520616e642067696d626c6520696e207468652077\
         6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665\
         732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf\
         166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb\
         f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77\
         04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
    ),
];

/// draft-irtf-cfrg-xchacha-03 appendix A.3.2.1: key, nonce, keystream and ciphertext
/// at counter 0 for [`DHOLE`].
const XCHACHA_A321: [&str; 4] = [
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    "404142434445464748494a4b4c4d4e4f5051525354555658",
    "1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9a\
     adec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d\
     29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4\
     cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25\
     5e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe46221\
     5cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf60\
     7cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd\
     241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290f\
     a0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00\
     b3df507ca8c924f7017b7e712d15a2eb",
    "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9\
     8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d\
     4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da\
     ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744\
     3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240\
     7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c\
     09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae\
     577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c\
     cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663\
     93b93111c1a55dd7421a10184974c7c5",
];
