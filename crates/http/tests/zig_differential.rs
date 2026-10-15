//! The Rust parser must reach the verdict of the Zig 0.16 parser on every vector of
//! `data/zig_parser_vectors.txt`, and parse the same fields from the requests both accept,
//! except for the request-targets the port refuses on purpose ([`ALLOWED_REFUSALS`]).

use std::fmt::Write;

const VECTORS: &str = include_str!("data/zig_parser_vectors.txt");

/// Reverses the escaping of the vector file: `\r`, `\n`, `\t` and `\xHH`.
fn unescape(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        match bytes[index + 1] {
            b'r' => out.push(b'\r'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'x' => {
                let hex = std::str::from_utf8(&bytes[index + 2..index + 4]).expect("ASCII escape");
                out.push(u8::from_str_radix(hex, 16).expect("hexadecimal escape"));
                index += 2;
            }
            other => panic!("unknown escape {}", other as char),
        }
        index += 2;
    }
    out
}

fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &byte in bytes {
        match byte {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..0x7f if byte != b'\\' => out.push(byte as char),
            _ => write!(out, "\\x{byte:02x}").expect("writing to a String"),
        }
    }
    out
}

fn verdict(data: &[u8]) -> String {
    let request = match sibuna_http::parse_request(data) {
        Ok(request) => request,
        Err(error) => return format!("err\t{error:?}"),
    };
    let mut fnv = 0xcbf2_9ce4_8422_2325u64;
    for header in request.headers() {
        let line = [header.name, b":", header.value, b"\n"].concat();
        for byte in line {
            fnv = (fnv ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!(
        "ok\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{fnv:016x}",
        escape(request.method_text),
        escape(request.path),
        escape(request.query),
        std::str::from_utf8(request.version.as_bytes()).expect("ASCII version"),
        request.header_count,
        u8::from(request.chunked),
        request.body.len(),
    )
}

/// The kinds of request-target the Zig parser accepted and the port refuses on purpose with
/// `UnsupportedTargetForm`: Sibuna is a reverse proxy, so it accepts only origin-form, and
/// `*` for `OPTIONS` (SID 0009, revision of 2026-10-15). Each kind carries the number of
/// vectors of that kind, so the allow-list cannot grow unnoticed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefusedForm {
    /// `scheme://authority/path`: addresses a forward proxy, and policy would otherwise
    /// match the whole URL while the origin routes on its path.
    Absolute,
    /// `*` with a method other than exactly `OPTIONS` (methods are case-sensitive): RFC 9112
    /// section 3.2.4 allows asterisk-form for `OPTIONS` only.
    Asterisk,
    /// Any other target that does not start with `/` (authority-form such as `a:80`, or a
    /// bare word): it names no origin path at all.
    Other,
}

const ALLOWED_REFUSALS: [(RefusedForm, usize); 3] =
    [(RefusedForm::Absolute, 64), (RefusedForm::Asterisk, 4), (RefusedForm::Other, 7)];

/// Classifies a vector the Zig parser accepted, from its verdict fields: the method and the
/// escaped path.
fn refusal(zig_verdict: &str) -> Option<RefusedForm> {
    let fields: Vec<&str> = zig_verdict.split('\t').collect();
    let (method, path) = (fields[1], fields[2]);
    if path.starts_with('/') || (path == "*" && method == "OPTIONS") {
        return None;
    }
    Some(if path.contains("://") {
        RefusedForm::Absolute
    } else if path == "*" {
        RefusedForm::Asterisk
    } else {
        RefusedForm::Other
    })
}

#[test]
fn rust_and_zig_parsers_agree_on_every_vector() {
    let mut count = 0;
    let mut accepted = 0;
    let mut refused = [0usize; 3];
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let (input, expected) = line.split_once('\t').unwrap();
        let data = unescape(input);
        assert_eq!(escape(&data), input, "the escaping round-trips");
        let actual = verdict(&data);
        count += 1;
        accepted += usize::from(expected.starts_with("ok"));
        if actual == expected {
            continue;
        }
        let kind = expected.starts_with("ok").then(|| refusal(expected)).flatten();
        assert_eq!(actual, "err\tUnsupportedTargetForm", "request {input}");
        let kind = kind.unwrap_or_else(|| panic!("not an allowed refusal: {input} {expected}"));
        refused[ALLOWED_REFUSALS.iter().position(|(allowed, _)| *allowed == kind).unwrap()] += 1;
    }
    assert_eq!(count, 3821);
    assert!(accepted > 700);
    for ((kind, expected), seen) in ALLOWED_REFUSALS.iter().zip(refused) {
        assert_eq!(seen, *expected, "{kind:?}");
    }
}
