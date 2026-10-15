use super::*;
use crate::test_util::hex;
use std::string::ToString;
use std::vec::Vec;

fn params(mode: Mode, time_cost: u32, memory_kib: u32, parallelism: u32) -> Params {
    Params { mode, time_cost, memory_kib, parallelism }
}

fn derive(params: &Params, password: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut workspace = std::vec![Block::ZERO; block_count(params).unwrap()];
    let mut out = std::vec![0u8; len];
    derive_key(params, password, salt, &mut workspace, &mut out).unwrap();
    out
}

/// RFC 9106 section 5 test vectors, which are also Zig's tests "argon2d", "argon2i" and
/// "argon2id" (Zig 0.16 skips the first; it computes the same value).
#[test]
fn rfc_9106_vectors() {
    let cases = [
        (Mode::Argon2d, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"),
        (Mode::Argon2i, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"),
        (Mode::Argon2id, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
    ];
    for (mode, expected) in cases {
        let params = params(mode, 3, 32, 4);
        let mut workspace = std::vec![Block::ZERO; 32];
        let mut out = [0u8; 32];
        derive_key_with_secret(
            &params,
            &[0x01; 32],
            &[0x02; 16],
            &[0x03; 8],
            &[0x04; 12],
            &mut workspace,
            &mut out,
        )
        .unwrap();
        assert_eq!(out.as_slice(), hex(expected), "{mode:?}");
    }
}

#[test]
fn zig_password_somesalt() {
    for (mode, time_cost, memory_kib, parallelism, expected) in PASSWORD_SOMESALT {
        let params = params(mode, time_cost, memory_kib, parallelism);
        assert_eq!(derive(&params, b"password", b"somesalt", 24), hex(expected), "{params:?}");
    }
}

#[test]
fn zig_output_lengths() {
    let params = params(Mode::Argon2id, 3, 32, 4);
    for (len, expected) in OUTPUT_LENGTHS {
        assert_eq!(derive(&params, b"testpass", b"saltsalt", len), hex(expected), "{len}");
    }
}

#[test]
fn block_count_rounds_memory() {
    assert_eq!(block_count(&Params::default()), Ok(19456));
    assert_eq!(block_count(&params(Mode::Argon2id, 1, 1000, 3)), Ok(996));
    assert_eq!(block_count(&params(Mode::Argon2id, 1, 8, 1)), Ok(8));
    assert_eq!(block_count(&params(Mode::Argon2id, 1, 7, 1)), Err(Error::WeakParameters));
    assert_eq!(block_count(&params(Mode::Argon2id, 0, 8, 1)), Err(Error::WeakParameters));
    assert_eq!(block_count(&params(Mode::Argon2id, 1, 8, 0)), Err(Error::WeakParameters));
    let too_wide = params(Mode::Argon2id, 1, u32::MAX, MAX_PARALLELISM + 1);
    assert_eq!(block_count(&too_wide), Err(Error::WeakParameters));
    let widest = params(Mode::Argon2id, 1, u32::MAX, MAX_PARALLELISM);
    assert_eq!(block_count(&widest), Ok(u32::MAX as usize / (4 * 0xff_ffff) * 4 * 0xff_ffff));
}

#[test]
fn rejects_invalid_inputs_before_using_memory() {
    let params = params(Mode::Argon2id, 1, 8, 1);
    let mut workspace = std::vec![Block::ZERO; 8];
    let mut out = [0u8; 32];
    let run = |salt: &[u8], out: &mut [u8], workspace: &mut [Block]| {
        derive_key(&params, b"pw", salt, workspace, out)
    };
    assert_eq!(run(b"short", &mut out, &mut workspace), Err(Error::WeakParameters));
    assert_eq!(run(b"saltsalt", &mut out[..3], &mut workspace), Err(Error::WeakParameters));
    assert_eq!(run(b"saltsalt", &mut out, &mut workspace[..7]), Err(Error::WorkspaceTooSmall));
    assert!(run(b"saltsalt", &mut out, &mut workspace).is_ok());
    assert_eq!(Error::WorkspaceTooSmall.to_string(), "Argon2 workspace has too few blocks");
}

#[test]
fn larger_workspace_gives_same_result_and_is_wiped() {
    let params = params(Mode::Argon2id, 2, 64, 2);
    let expected = derive(&params, b"password", b"somesalt", 32);
    let mut workspace = std::vec![Block::ZERO; 100];
    workspace.iter_mut().for_each(|block| block.0.fill(0xdead_beef));
    let mut out = [0u8; 32];
    derive_key(&params, b"password", b"somesalt", &mut workspace, &mut out).unwrap();
    assert_eq!(out.as_slice(), expected);
    assert!(workspace[..64].iter().all(|block| block.0.iter().all(|&w| w == 0)));
    assert!(workspace[64..].iter().all(|block| block.0.iter().all(|&w| w == 0xdead_beef)));
}

#[test]
fn mode_names() {
    for mode in [Mode::Argon2d, Mode::Argon2i, Mode::Argon2id] {
        assert_eq!(Mode::from_name(mode.name().as_bytes()), Some(mode));
    }
    assert_eq!(Mode::from_name(b"argon2"), None);
}

/// Argon2id with the console's parameters. Run with
/// `cargo test --release -p sibuna-crypto -- --ignored --nocapture argon2_timing`.
/// Zig 0.16 `argon2.kdf` with the same parameters took 25.4 ms on the reference host.
#[test]
#[ignore = "benchmark; run explicitly in release mode"]
fn argon2_timing() {
    let params = Params::default();
    let mut workspace = std::vec![Block::ZERO; block_count(&params).unwrap()];
    let mut out = [0u8; 32];
    let mut samples = [0f64; 7];
    for sample in &mut samples {
        let start = std::time::Instant::now();
        derive_key(&params, b"a long passphrase", &[7; 32], &mut workspace, &mut out).unwrap();
        *sample = start.elapsed().as_secs_f64() * 1e3;
    }
    samples.sort_by(f64::total_cmp);
    std::println!(
        "argon2id m=19456 t=2 p=1: median {:.2} ms, min {:.2} ms",
        samples[3],
        samples[0]
    );
}

/// `password`, `somesalt`, 24-byte output: the vectors of Zig's "kdf" test (from Go's
/// x/crypto/argon2), plus three more parameter sets, all computed with Zig 0.16
/// `argon2.kdf`. Columns: mode, t, m, p, output.
const PASSWORD_SOMESALT: [(Mode, u32, u32, u32, &str); 33] = [
    (Mode::Argon2i, 1, 64, 1, "b9c401d1844a67d50eae3967dc28870b22e508092e861a37"),
    (Mode::Argon2d, 1, 64, 1, "8727405fd07c32c78d64f547f24150d3f2e703a89f981a19"),
    (Mode::Argon2id, 1, 64, 1, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"),
    (Mode::Argon2i, 2, 64, 1, "8cf3d8f76a6617afe35fac48eb0b7433a9a670ca4a07ed64"),
    (Mode::Argon2d, 2, 64, 1, "3be9ec79a69b75d3752acb59a1fbb8b295a46529c48fbb75"),
    (Mode::Argon2id, 2, 64, 1, "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"),
    (Mode::Argon2i, 2, 64, 2, "2089f3e78a799720f80af806553128f29b132cafe40d059f"),
    (Mode::Argon2d, 2, 64, 2, "68e2462c98b8bc6bb60ec68db418ae2c9ed24fc6748a40e9"),
    (Mode::Argon2id, 2, 64, 2, "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"),
    (Mode::Argon2i, 3, 256, 2, "f5bbf5d4c3836af13193053155b73ec7476a6a2eb93fd5e6"),
    (Mode::Argon2d, 3, 256, 2, "f4f0669218eaf3641f39cc97efb915721102f4b128211ef2"),
    (Mode::Argon2id, 3, 256, 2, "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b"),
    (Mode::Argon2i, 4, 256, 4, "f7dbbacbf16999e3700817a7e06f65a8db2e9fa9504ede4c"),
    (Mode::Argon2d, 4, 256, 4, "ea2970501cf49faa5ba1d2e6370204e9b57ca90a8fea937b"),
    (Mode::Argon2id, 4, 256, 4, "fbd40d5a8cb92f88c20bda4b3cdb1f9d5af1efa937032410"),
    (Mode::Argon2i, 4, 256, 8, "15d3c398364e53f68fd12d19baf3f21432d964254fe27467"),
    (Mode::Argon2d, 4, 256, 8, "23c9adc06f06e21e4612c1466a1be02627690932b02c0df0"),
    (Mode::Argon2id, 4, 256, 8, "f22802f8ca47be93f9954e4ce20c1e944e938fbd4a125d9d"),
    (Mode::Argon2i, 2, 64, 3, "5cab452fe6b8479c8661def8cd703b611a3905a6d5477fe6"),
    (Mode::Argon2d, 2, 64, 3, "22474a423bda2ccd36ec9afd5119e5c8949798cadf659f51"),
    (Mode::Argon2id, 2, 64, 3, "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079"),
    (Mode::Argon2i, 3, 256, 6, "ebc8f91964abd8ceab49a12963b0a9e57d635bfa2aad2884"),
    (Mode::Argon2d, 3, 256, 6, "1dd7202fd68da6675f769f4034b7a1db30d8785331954117"),
    (Mode::Argon2id, 3, 256, 6, "424436b6ee22a66b04b9d0cf78f190305c5c166bae8baa09"),
    (Mode::Argon2i, 1, 8, 1, "aeb3f43823a7c2e3f734272633ef6388502902ce1f30310e"),
    (Mode::Argon2d, 1, 8, 1, "c3591aef7e2806a47f5070e4b0052be0dc64d95f11580660"),
    (Mode::Argon2id, 1, 8, 1, "0b66c95f90bc503132840eade592ec0235342f52206e5cec"),
    (Mode::Argon2i, 1, 1000, 3, "7e27bcdfcd05e116681c472b0a1950fcc4e1755df9b6f87e"),
    (Mode::Argon2d, 1, 1000, 3, "48855f9ed2365e6ac0ccd4eb9fa026e4e968198a520f1e35"),
    (Mode::Argon2id, 1, 1000, 3, "f29d22f87d3ce26ef64453927991e700dfa7609f07ee17d0"),
    (Mode::Argon2i, 2, 2048, 1, "0da918ef577936b2dd3f22ab637e1e43ff5680b6cfe00a10"),
    (Mode::Argon2d, 2, 2048, 1, "1abcf39bad541b0de448bfc2e961f905659ceb3ecce63bd8"),
    (Mode::Argon2id, 2, 2048, 1, "95e6ae29fc17e15e1f69d69d5f4acec6a1df974368f284ac"),
];

/// Zig's "kdf derived key length" test made concrete: `testpass`, `saltsalt`, Argon2id,
/// t = 3, m = 32, p = 4, output lengths across the boundaries of H'. Computed with Zig
/// 0.16 `argon2.kdf`.
const OUTPUT_LENGTHS: [(usize, &str); 12] = [
    (4, "ef59899f"),
    (31, "d31adfd2f536c24f94d81ab8ceca2f6c4c3361fd26ae387627724f5a5d39c5"),
    (32, "240816fb9031cdd67cffa756d283e2fb87c90f9adbbbcd1213116c3a4195bd9b"),
    (
        33,
        "9138fd542abaea31d827bd2669dccfc05936ec0712606609a36a2f9203bd0de1\
         39",
    ),
    (
        63,
        "12f506ac46a1411565b7cee724ed9939a516044b2da2856fd79328aa5b4c226f\
         a7e4055ac04df1e96346642e0de92a0186f1855310ad192fb219ed3f88ac72",
    ),
    (
        64,
        "13db741b98f10bd199f825643df09d4a767d87c410e56acdc082b86b83fe8100\
         05aeb1051b17e5aa322e1bd170c0afc3d80295315363a421267150c5adf45a3e",
    ),
    (
        65,
        "b768d02fa91e5f45670ced5881dbdd835e9000236efbcef4e68b41560b7dafb4\
         a8f8dae74b5e5674ccefe76dea58a7d0c59ecdbe8845d33e655ac66d969167fc\
         83",
    ),
    (
        77,
        "3e81383a5d0ed0e84ead4c837073131c726c57ed3b9521ce229fd4fbc1daf40f\
         9ba86ffe03047017d6a463e374b6b924f83edc3312e2924ece5af99f495fb2dd\
         37bf84077294faa2be1ba17d06",
    ),
    (
        111,
        "dddf61d303e9c3737845cc4843a216ec457cb0eb419c303a063d35e274d0b1b9\
         3ee522879842198826eadca535cacd138abd38a95bcf0a4490ff68c82370ce62\
         dd03783e6adb148f8434cdb408cfba25d5b998b56a8fe07ce482568ed4db74a8\
         55f6f02228407852588e87a812e812",
    ),
    (
        128,
        "480fcb5859bb8250a5ffb10fcfd676d8378748adebd7b73f34a0e0191fd66c6d\
         4abe42c44ea29396f37c81e3a1f943e4e41fac1f4bdb3882a8e466bdff224dec\
         b681d64c8479d1affc21c07de3bb0b6a35085a1921c50f44567ad3eb5c301856\
         61db48650edbdd717644a5e3f0d079d510ec3ded8f16217e263a6548ea9dbd90",
    ),
    (
        129,
        "9fef114cfedd3caf92e233b7357e67991bf08d3de794673eaa45ca7a7c01f008\
         03b7207a1cbbe9d38b8e4a9b9a238327d43b7204978b688d5055bb850409c7ff\
         1c32b41d8bbf522f069c639be33430eccc061e6f889ed40170b38d387b227c39\
         e1b876b0538947cf5a0cd66efff54ff824890614390f4a78976352de665b0fdc\
         70",
    ),
    (
        200,
        "ee8ca84429e8e3dafb990c8655844c417510b305c5fcbe5184cdec792938ed34\
         bfa61dca5db1ab71b32930565b9d1751979caa72ee1be791d63dd2aab46d9f80\
         9efe3acaf112e4b1561c6d7ba3b50a831335637d0744958197fa712655f814e4\
         30683838a47515c586acc2e42f0bb7363c1eb0104cfa819cf432df2f5f9ad36e\
         46ffe3d39f0812a68c563bd994e753cd4db0c57de105629d49e1be7695aff758\
         bc0984bce62015663544dd4ff55cfac78847ea0e0b7c2ab956e235cb1f7394c1\
         84f0808729c4fbc4",
    ),
];
