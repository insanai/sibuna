use super::super::{SALT_LEN, block_count};
use super::*;
use crate::test_util::{XorShift, hex};
use std::string::String;
use std::vec::Vec;

/// A workspace for `params`.
fn workspace_for(params: &Params) -> Vec<Block> {
    std::vec![Block::ZERO; block_count(params).unwrap()]
}

/// Generous maxima for the tests: the largest costs used below.
const TEST_LIMITS: Limits = Limits { max_memory_kib: 19456, max_time_cost: 3, max_parallelism: 4 };

/// Password, mode, t, m, p and PHC string.
type Deterministic = (&'static [u8], Mode, u32, u32, u32, &'static str);

/// PHC strings made with Zig 0.16 `argon2.kdf` and `phc_format.serialize` exactly as
/// `strHash` does, with a deterministic salt: byte `j` of the salt of entry `i` is
/// `7j + 13i`. Columns: password, mode, t, m, p, string.
const ZIG_DETERMINISTIC: [Deterministic; 4] = [
    (
        b"a long passphrase",
        Mode::Argon2id,
        2,
        19456,
        1,
        "$argon2id$v=19$m=19456,t=2,p=1$AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK+2vcTL0tk\
         $aEtjqpExGIseRRLxpGVhQeAjg2Ilq0ycanua7tsV2Ng",
    ),
    (
        b"correct horse battery staple",
        Mode::Argon2i,
        3,
        32,
        4,
        "$argon2i$v=19$m=32,t=3,p=4$DRQbIikwNz5FTFNaYWhvdn2Ei5KZoKeutbzDytHY3+Y\
         $eFV1B1bTmLhYR49uUqMkxx2mJfiXiS5sm2hBvfL7gF8",
    ),
    (
        b"",
        Mode::Argon2d,
        1,
        64,
        2,
        "$argon2d$v=19$m=64,t=1,p=2$GiEoLzY9REtSWWBnbnV8g4qRmJ+mrbS7wsnQ197l7PM\
         $5WhGHUZFIThOPdIOSV8h0obi/F+lfsLcg9LzuSvxYdE",
    ),
    (
        b"p\x00ss\xffword",
        Mode::Argon2id,
        2,
        19456,
        1,
        "$argon2id$v=19$m=19456,t=2,p=1$Jy41PENKUVhfZm10e4KJkJeepayzusHIz9bd5Ovy+QA\
         $vvWDKXuK0n6E+GkkUiIGRmZ0t7cnNtUQf8Om7dO3D/E",
    ),
];

/// Strings from Zig 0.16 `argon2.strHash` with its own random salt, as the Zig console
/// stored them.
const ZIG_STRHASH: [(&[u8], &str); 2] = [
    (
        b"a long passphrase",
        "$argon2id$v=19$m=19456,t=2,p=1$vPNc9xsOC2mflKWwPjvxI06jaPiRxDUBX4SEa/laedI\
         $rnO11PcfBn6xp+30IQVETymoQLAAOWo0CbGGYNUZar4",
    ),
    (
        b"another passphrase!",
        "$argon2id$v=19$m=19456,t=2,p=1$GFtVL2jV1fV6P9G0HqaEjVpttm0O6a0wLAslThH6D5A\
         $IhFHQUuNFTO02/Fv7fLtmix+vjhx7VUPI8hEiNkbaeQ",
    ),
];

/// Strings made by [`hash_phc`] (printed by `print_rust_made`) and accepted, with a wrong
/// password refused, by Zig 0.16 `argon2.strVerify` in a Zig program.
const RUST_MADE: [(&[u8], &str); 2] = [
    (
        b"rust made this",
        "$argon2id$v=19$m=19456,t=2,p=1$ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoM\
         $hGKJoreYmVsxdqpjrYO54bq4HbmwPqKqPP2WdOq/Wqk",
    ),
    (
        b"small parameters",
        "$argon2i$v=19$m=32,t=3,p=4$ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoM\
         $lMcmIp3uS81aklBYdWevAEtT14+CbDYKiCNH4GQaLJg",
    ),
];

fn deterministic_salt(i: usize) -> [u8; SALT_LEN] {
    core::array::from_fn(|j| (j * 7 + i * 13) as u8)
}

#[test]
fn rust_strings_match_zig() {
    for (i, (password, mode, time_cost, memory_kib, parallelism, expected)) in
        ZIG_DETERMINISTIC.into_iter().enumerate()
    {
        let params = Params { mode, time_cost, memory_kib, parallelism };
        let mut workspace = workspace_for(&params);
        let mut out = [0u8; PHC_MAX_LEN];
        let text = hash_phc(&params, password, &deterministic_salt(i), &mut workspace, &mut out);
        assert_eq!(text.unwrap(), expected);
    }
}

#[test]
fn zig_strings_verify() {
    let mut workspace = workspace_for(&Params::default());
    let strings = ZIG_DETERMINISTIC
        .iter()
        .map(|entry| (entry.0, entry.5))
        .chain(ZIG_STRHASH)
        .chain(RUST_MADE);
    for (password, text) in strings {
        verify_phc(text.as_bytes(), password, &TEST_LIMITS, &mut workspace).unwrap();
        let wrong = verify_phc(text.as_bytes(), b"wrong", &TEST_LIMITS, &mut workspace);
        assert_eq!(wrong, Err(Error::VerificationFailed), "{text}");
    }
}

/// Prints the strings of [`RUST_MADE`]; run with `--ignored --nocapture` to regenerate
/// them for the Zig cross-check.
#[test]
#[ignore = "generator for the Zig cross-check"]
fn print_rust_made() {
    let salt: [u8; SALT_LEN] = core::array::from_fn(|j| 100 + j as u8);
    let cases = [
        (&b"rust made this"[..], Params::default()),
        (
            b"small parameters",
            Params { mode: Mode::Argon2i, time_cost: 3, memory_kib: 32, parallelism: 4 },
        ),
    ];
    for (password, params) in cases {
        let mut workspace = workspace_for(&params);
        let mut out = [0u8; PHC_MAX_LEN];
        let text = hash_phc(&params, password, &salt, &mut workspace, &mut out).unwrap();
        std::println!("{text}");
    }
}

/// Zig's "phc format hasher" and "password hash and password verify" tests.
#[test]
fn zig_round_trip() {
    let params = Params { mode: Mode::Argon2id, time_cost: 3, memory_kib: 32, parallelism: 4 };
    let mut workspace = workspace_for(&params);
    let mut out = [0u8; 128];
    let text = hash_phc(&params, b"testpass", &[0x5a; SALT_LEN], &mut workspace, &mut out)
        .unwrap()
        .as_bytes()
        .to_vec();
    verify_phc(&text, b"testpass", &TEST_LIMITS, &mut workspace).unwrap();
}

/// The console's test "Argon2id fixed workspace verifies and refuses unsafe PHC
/// parameters", with the parameter maxima now enforced by the verifier itself.
#[test]
fn console_workspace_and_maxima() {
    let mut workspace = workspace_for(&Params::default());
    let mut out = [0u8; 255];
    let salt = [0x11; SALT_LEN];
    let text = hash_phc(&Params::default(), b"a long passphrase", &salt, &mut workspace, &mut out)
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(text.starts_with(b"$argon2id$v=19$m=19456,t=2,p=1$"));
    let limits = Limits::default();
    verify_phc(&text, b"a long passphrase", &limits, &mut workspace).unwrap();
    assert_eq!(
        verify_phc(&text, b"wrong", &limits, &mut workspace),
        Err(Error::VerificationFailed)
    );
    let huge = b"$argon2id$v=19$m=99999999,t=2,p=1$invalid$invalid";
    assert!(verify_phc(huge, b"anything", &limits, &mut workspace).is_err());
    let huge = b"$argon2id$v=19$m=99999999,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2g";
    assert_eq!(verify_phc(huge, b"x", &limits, &mut workspace), Err(Error::LimitExceeded));
    let slow = b"$argon2id$v=19$m=19456,t=3,p=1$c29tZXNhbHQ$aGFzaGhhc2g";
    assert_eq!(verify_phc(slow, b"x", &limits, &mut workspace), Err(Error::LimitExceeded));
    let wide = b"$argon2id$v=19$m=19456,t=2,p=2$c29tZXNhbHQ$aGFzaGhhc2g";
    assert_eq!(verify_phc(wide, b"x", &limits, &mut workspace), Err(Error::LimitExceeded));
}

#[test]
fn verification_errors_follow_zig_order() {
    let mut workspace = std::vec![Block::ZERO; 64];
    let limits = Limits { max_memory_kib: 1 << 20, max_time_cost: 8, max_parallelism: 8 };
    let check = |text: &str, workspace: &mut Vec<Block>| {
        verify_phc(text.as_bytes(), b"pw", &limits, workspace)
    };
    let cases = [
        ("", Error::InvalidEncoding),
        ("$scrypt$v=19$m=32,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2g", Error::UnsupportedAlgorithm),
        ("$argon2id$v=16$m=32,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2g", Error::InvalidEncoding),
        ("$argon2id$v=19$m=32,t=0,p=4$c29tZXNhbHQ$aGFzaGhhc2g", Error::WeakParameters),
        ("$argon2id$v=19$m=31,t=1,p=4$c29tZXNhbHQ$aGFzaGhhc2g", Error::WeakParameters),
        ("$argon2id$v=19$m=32,t=1,p=4$c2FsdA$aGFzaGhhc2g", Error::WeakParameters),
        ("$argon2id$v=19$m=32,t=1,p=4$c29tZXNhbHQ$aGFz", Error::WeakParameters),
        ("$argon2id$v=19$m=128,t=1,p=4$c29tZXNhbHQ$aGFzaGhhc2g", Error::WorkspaceTooSmall),
        ("$argon2id$v=19$m=32,t=1,p=4$c29tZXNhbHQ$aGFzaGhhc2g", Error::VerificationFailed),
        // Zig panicked on this one.
        ("$argon2id$v=19$alg_version=19,m=32,t=1,p=4$c29tZXNhbHQ$aGFzaA", Error::InvalidEncoding),
    ];
    for (text, expected) in cases {
        assert_eq!(check(text, &mut workspace), Err(expected), "{text}");
    }
}

/// The Argon2-shaped input of Zig's "phc format - encoding/decoding" test: its `key`
/// parameter is not a field of Argon2's result type, so Zig's Argon2 verifier rejects it.
/// The other inputs of that test use scrypt's result type.
#[test]
fn zig_phc_format_inputs() {
    let text = b"$argon2id$v=19$key=a2V5,m=4096,t=0,p=1$X1NhbHQAAAAAAAAAAAAAAA\
                 $bWh++MKN1OiFHKgIWTLvIi1iHicmHH7+Fv3K88ifFfI";
    assert_eq!(PhcHash::parse(text).unwrap_err(), Error::InvalidEncoding);
    // "phc format - empty input string" and "hash without salt".
    assert_eq!(PhcHash::parse(b"").unwrap_err(), Error::InvalidEncoding);
    assert_eq!(PhcHash::parse(b"$scrypt").unwrap_err(), Error::InvalidEncoding);
}

#[test]
fn parses_quirks_like_zig() {
    let parsed = PhcHash::parse(
        b"$argon2id$v=19$alg_id=argon2d,m=1_9_456,t=0002,p=1,junk$c2FsdHNhbHQ$aGFzaA$x$y",
    )
    .unwrap();
    assert_eq!(
        parsed.params,
        Params { mode: Mode::Argon2d, time_cost: 2, memory_kib: 19456, parallelism: 1 }
    );
    assert_eq!(parsed.version, Some(19));
    assert_eq!(parsed.salt(), b"saltsalt");
    assert_eq!(parsed.hash(), b"hash");
    let no_version = PhcHash::parse(b"$argon2i$m=32,t=3,p=4$c29tZXNhbHQ$aGFzaA").unwrap();
    assert_eq!(no_version.version, None);
    assert!(std::format!("{no_version:?}").contains("salt_len: 8"));
    // Repeated parameters count towards the six required fields.
    let repeated = PhcHash::parse(b"$argon2id$v=19$m=32,m=32,m=32$c2FsdHNhbHQ$aGFzaA").unwrap();
    assert_eq!(repeated.params.time_cost, 0);
    for bad in [
        &b"$argon2id$v=19$m=_32,t=3,p=4$c2FsdHNhbHQ$aGFzaA"[..],
        b"$argon2id$v=19$m=32_,t=3,p=4$c2FsdHNhbHQ$aGFzaA",
        b"$argon2id$v=19$m=+32,t=3,p=4$c2FsdHNhbHQ$aGFzaA",
        b"$argon2id$v=19$m=32,t=3,p=16777216$c2FsdHNhbHQ$aGFzaA",
        b"$argon2id$v=19$m=4294967296,t=3,p=4$c2FsdHNhbHQ$aGFzaA",
        b"$argon2id$v=19$m=32,t=3,p=4$c2FsdHNhbHR$aGFzaA",
        b"$argon2id$v=19$m=32,t=3,p=4$c2FsdHNhbHQ=$aGFzaA",
        b"$argon2id$v=19$m=32,t=3,p=4$c$aGFzaA",
        b"argon2id$v=19$m=32,t=3,p=4$c2FsdHNhbHQ$aGFzaA",
    ] {
        assert_eq!(PhcHash::parse(bad).unwrap_err(), Error::InvalidEncoding, "{bad:?}");
    }
    let long_salt = std::format!("$argon2id$v=19$m=32,t=3,p=4${}$aGFzaA", "A".repeat(88));
    assert_eq!(PhcHash::parse(long_salt.as_bytes()).unwrap_err(), Error::InvalidEncoding);
    let max_salt = std::format!("$argon2id$v=19$m=32,t=3,p=4${}$aGFzaA", "A".repeat(86));
    assert_eq!(PhcHash::parse(max_salt.as_bytes()).unwrap().salt(), [0u8; 64]);
}

#[test]
fn hash_phc_checks_buffer_and_salt() {
    let params = Params { mode: Mode::Argon2id, time_cost: 1, memory_kib: 8, parallelism: 1 };
    let mut workspace = workspace_for(&params);
    let mut short = [0u8; 40];
    let result = hash_phc(&params, b"pw", &[1; 16], &mut workspace, &mut short);
    assert_eq!(result.unwrap_err(), Error::BufferTooSmall);
    let mut out = [0u8; PHC_MAX_LEN];
    let result = hash_phc(&params, b"pw", &[1; 65], &mut workspace, &mut out);
    assert_eq!(result.unwrap_err(), Error::InvalidEncoding);
    let result = hash_phc(&params, b"pw", &[1; 7], &mut workspace, &mut out);
    assert_eq!(result.unwrap_err(), Error::WeakParameters);
    let widest = Params {
        mode: Mode::Argon2id,
        time_cost: u32::MAX,
        memory_kib: u32::MAX,
        parallelism: MAX_PARALLELISM,
    };
    let len = write_phc(&mut Writer { out: &mut [], len: 0 }, &widest, &[0; 64], &[0; 32]);
    assert_eq!(len, PHC_MAX_LEN);
}

#[test]
fn base64_round_trips() {
    let mut rng = XorShift::new(64);
    for len in 0..=MAX_PHC_BINARY_LEN {
        let mut bytes = std::vec![0u8; len];
        rng.fill(&mut bytes);
        let mut text = [0u8; 100];
        let mut writer = Writer { out: &mut text, len: 0 };
        writer.push_base64(&bytes);
        let encoded_length = writer.len;
        assert_eq!(encoded_length, encoded_len(len));
        assert_eq!(decode_base64(&text[..encoded_length]).unwrap().as_slice(), bytes);
    }
}

/// Formats a parse result as the Zig corpus generator does.
fn describe(text: &[u8]) -> String {
    match parse_fields(text) {
        Err(_) => "err".into(),
        Ok(fields) => {
            let version = fields.version.map_or("-".into(), |v| std::format!("{v}"));
            std::format!(
                "ok {} {} {} {} {} {} {}",
                hex_string(fields.algorithm),
                version,
                fields.memory_kib,
                fields.time_cost,
                fields.parallelism,
                hex_string(fields.salt.as_slice()),
                hex_string(fields.hash.as_slice()),
            )
        }
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| std::format!("{b:02x}")).collect()
}

/// Checks every line `hex(input) TAB result` of a corpus made by the Zig 0.16 program
/// `gen_phc.zig`, which runs `phc_format.deserialize` with Argon2's result type.
fn check_corpus(corpus: &str) -> usize {
    let mut count = 0;
    for line in corpus.lines() {
        let (input, expected) = line.split_once('\t').unwrap();
        let input = hex(input);
        assert_eq!(describe(&input), expected, "input {:?}", String::from_utf8_lossy(&input));
        count += 1;
    }
    count
}

/// 300 mutated strings and Zig's verdicts on them.
#[test]
fn agrees_with_zig_on_corpus() {
    assert_eq!(check_corpus(include_str!("zig_corpus.txt")), 300);
}

/// The same check on a large corpus: set `SIBUNA_PHC_CORPUS` to a file made with
/// `gen_phc 200000 <seed>`.
#[test]
#[ignore = "needs a corpus file generated with Zig"]
fn agrees_with_zig_on_large_corpus() {
    let path = std::env::var("SIBUNA_PHC_CORPUS").unwrap();
    let corpus = std::fs::read_to_string(path).unwrap();
    let count = check_corpus(&corpus);
    std::println!("{count} strings agree with Zig");
}

/// Mutates `data` as the fuzzers of this crate do, plus truncation and duplication.
fn mutate(rng: &mut XorShift, data: &mut Vec<u8>, donor: &[u8]) {
    match rng.below(4) {
        0 => data.truncate(rng.below(data.len() + 1)),
        1 if !data.is_empty() => {
            let at = rng.below(data.len());
            let piece: Vec<u8> = data[at..].iter().take(1 + rng.below(12)).copied().collect();
            let to = rng.below(data.len() + 1);
            data.splice(to..to, piece);
        }
        2 => {
            let to = rng.below(data.len() + 1);
            let byte = b"$,=_0123456789vmtp"[rng.below(18)];
            data.insert(to, byte);
        }
        _ => rng.mutate(data, donor),
    }
}

/// 100,000 mutated strings: parsing never panics, decoded values stay within bounds, a
/// string over the maxima is refused before the workspace is touched, and only a full
/// evaluation (a match or a mismatch) uses the workspace, which is wiped afterwards.
#[test]
fn fuzz_parse_and_verify() {
    let mut rng = XorShift::new(0x9e37_79b9);
    let seeds: Vec<&[u8]> = ZIG_DETERMINISTIC
        .iter()
        .map(|entry| entry.5.as_bytes())
        .chain([&b"$argon2id$v=19$m=16,t=1,p=2$c29tZXNhbHQ$aGFzaGhhc2g"[..]])
        .collect();
    let limits = Limits { max_memory_kib: 64, max_time_cost: 2, max_parallelism: 4 };
    let mut workspace = std::vec![Block::ZERO; 64];
    let mut evaluations = 0;
    for round in 0..100_000 {
        let mut text = seeds[round % seeds.len()].to_vec();
        for _ in 0..1 + rng.below(3) {
            let donor = seeds[rng.below(seeds.len())];
            mutate(&mut rng, &mut text, donor);
        }
        if let Ok(parsed) = PhcHash::parse(&text) {
            assert!(parsed.salt().len() <= 64 && parsed.hash().len() <= 64);
            assert!(parsed.params.parallelism <= MAX_PARALLELISM);
        }
        if evaluations >= 500 {
            continue;
        }
        workspace.iter_mut().for_each(|block| block.0.fill(0x5a5a));
        let result = verify_phc(&text, b"pw", &limits, &mut workspace);
        let touched = workspace.iter().any(|block| block.0.iter().any(|&w| w != 0x5a5a));
        match result {
            Ok(()) | Err(Error::VerificationFailed) => {
                evaluations += 1;
                assert!(
                    workspace.iter().all(|block| block.0.iter().all(|&w| w == 0x5a5a || w == 0))
                );
            }
            Err(_) => assert!(!touched, "refused string used memory: {text:?}"),
        }
    }
    assert!(evaluations > 0);
}
