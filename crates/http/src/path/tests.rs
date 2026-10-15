//! Tests of the normal form: the bypass spellings of the security review, RFC 3986
//! examples, and a deterministic fuzz run against a naive reference.

use super::*;
use crate::test_util::{Rng, mutate};

fn normal(raw: &[u8]) -> Result<String, PathError> {
    let mut out = vec![0u8; raw.len()];
    normalize_path(raw, &mut out).map(str::to_owned)
}

#[test]
fn every_spelling_of_a_protected_path_has_one_normal_form() {
    let same: [&[u8]; 8] = [
        b"/admin/x",
        b"//admin/x",
        b"/./admin/x",
        b"/%61dmin/x",
        b"/%61%64%6D%69%6e/x",
        b"/public/../admin/x",
        b"/admin/./x",
        b"///admin//x",
    ];
    for raw in same {
        assert_eq!(normal(raw).as_deref(), Ok("/admin/x"), "{:?}", String::from_utf8_lossy(raw));
    }
    assert_eq!(normal(b"//login").as_deref(), Ok("/login"));
    // Matching is case-sensitive, as for most origins.
    assert_eq!(normal(b"/ADMIN/x").as_deref(), Ok("/ADMIN/x"));
}

#[test]
fn ambiguous_spellings_are_refused() {
    let refused: [(&[u8], PathError); 20] = [
        (b"/admin%2fx", PathError::EncodedSeparator),
        (b"/admin%2Fx", PathError::EncodedSeparator),
        (b"/admin%5cx", PathError::EncodedSeparator),
        (b"/admin%00", PathError::EncodedNul),
        (b"/admin;x/y", PathError::Parameter),
        (b"/.well-known/..;x/admin", PathError::Parameter),
        (b"/a;jsessionid=1", PathError::Parameter),
        (b"/admin\\x", PathError::Backslash),
        (b"/a%2", PathError::InvalidEscape),
        (b"/a%zz", PathError::InvalidEscape),
        (b"/a%", PathError::InvalidEscape),
        (b"/a#b", PathError::InvalidByte),
        (b"/a?b", PathError::InvalidByte),
        (b"/a b", PathError::InvalidByte),
        (b"/caf\xc3\xa9", PathError::InvalidByte),
        (b"/..", PathError::AboveRoot),
        (b"/a/../..", PathError::AboveRoot),
        (b"/%2e%2e/admin", PathError::AboveRoot),
        (b"http://a/admin/x", PathError::NotOriginForm),
        (b"", PathError::NotOriginForm),
    ];
    for (raw, error) in refused {
        assert_eq!(normal(raw), Err(error), "{:?}", String::from_utf8_lossy(raw));
    }
    assert_eq!(normalize_path(b"/abc", &mut [0u8; 3]), Err(PathError::TooLong));
}

#[test]
fn escapes_dots_and_slashes_follow_rfc_3986() {
    let cases: [(&[u8], &str); 16] = [
        (b"/", "/"),
        (b"//", "/"),
        (b"*", "*"),
        (b"/a/", "/a/"),
        (b"/a/.", "/a/"),
        (b"/a/..", "/"),
        (b"/a//b//", "/a/b/"),
        (b"/a/b/c/./../../g", "/a/g"),
        (b"/mid/content=5/../6", "/mid/6"),
        (b"/x/%2E%2e/admin", "/admin"),
        (b"/%7euser", "/~user"),
        (b"/caf%c3%a9", "/caf%C3%A9"),
        (b"/a%20b%3bc%2a", "/a%20b%3Bc%2A"),
        (b"/...", "/..."),
        (b"/.a/..b/", "/.a/..b/"),
        (b"/a:b@c!$&'()*+,=", "/a:b@c!$&'()*+,="),
    ];
    for (raw, expected) in cases {
        assert_eq!(normal(raw).as_deref(), Ok(expected), "{:?}", String::from_utf8_lossy(raw));
        assert!(is_normal_path(expected.as_bytes()), "{expected}");
    }
    assert!(!is_normal_path(b"/a/./b") && !is_normal_path(b"//a") && !is_normal_path(b"a"));
    assert!(!is_normal_path(b"/%41") && !is_normal_path(b"/%3b") && !is_normal_path(b"/%2F"));
}

/// The normal form computed the obvious way: decode every segment into a vector, then
/// resolve the segments on a stack.
fn reference(raw: &[u8]) -> Result<Vec<u8>, PathError> {
    if raw == b"*" {
        return Ok(raw.to_vec());
    }
    let rest = raw.strip_prefix(b"/").ok_or(PathError::NotOriginForm)?;
    let parts: Vec<&[u8]> = rest.split(|&c| c == b'/').collect();
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut trailing = true;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let decoded = reference_decode(part)?;
        if decoded == b"." {
            trailing = true;
        } else if decoded == b".." {
            stack.pop().ok_or(PathError::AboveRoot)?;
            trailing = true;
        } else {
            stack.push(decoded);
            trailing = index + 1 < parts.len();
        }
    }
    let mut out = b"/".to_vec();
    out.extend(stack.join(&b'/'));
    if trailing && !stack.is_empty() {
        out.push(b'/');
    }
    Ok(out)
}

fn reference_decode(part: &[u8]) -> Result<Vec<u8>, PathError> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < part.len() {
        let c = part[index];
        index += 1;
        match c {
            b'%' => {
                let digits = part.get(index..index + 2).ok_or(PathError::InvalidEscape)?;
                let text = std::str::from_utf8(digits).map_err(|_| PathError::InvalidEscape)?;
                if !text.bytes().all(|d| d.is_ascii_hexdigit()) {
                    return Err(PathError::InvalidEscape);
                }
                let value = u8::from_str_radix(text, 16).map_err(|_| PathError::InvalidEscape)?;
                index += 2;
                match value {
                    0 => return Err(PathError::EncodedNul),
                    b'/' | b'\\' => return Err(PathError::EncodedSeparator),
                    v if v.is_ascii_alphanumeric() || b"-._~".contains(&v) => out.push(v),
                    _ => out.extend(format!("%{}", text.to_ascii_uppercase()).bytes()),
                }
            }
            b'\\' => return Err(PathError::Backslash),
            b';' => return Err(PathError::Parameter),
            b'#' | b'?' => return Err(PathError::InvalidByte),
            0x21..=0x7e => out.push(c),
            _ => return Err(PathError::InvalidByte),
        }
    }
    Ok(out)
}

/// Checks one input against the reference and the properties of the normal form.
fn check(raw: &[u8]) -> bool {
    let mut out = vec![0u8; raw.len()];
    let result = normalize_path(raw, &mut out).map(|path| path.as_bytes().to_vec());
    assert_eq!(result, reference(raw), "{:?}", String::from_utf8_lossy(raw));
    assert_eq!(is_normal_path(raw), result.as_deref() == Ok(raw));
    let Ok(path) = result else { return false };
    assert!(path.len() <= raw.len());
    assert!(path == b"*" || path.first() == Some(&b'/'));
    // Idempotent, and never above the root: no dot segment survives.
    assert!(is_normal_path(&path));
    assert_eq!(normal(&path).map(String::into_bytes), Ok(path.clone()));
    assert!(path.split(|&c| c == b'/').all(|segment| segment != b"." && segment != b".."));
    if let Some(short) = raw.len().checked_sub(1) {
        assert_eq!(normalize_path(raw, &mut vec![0u8; short]), Err(PathError::TooLong));
    }
    true
}

const PIECES: [&[u8]; 30] = [
    b"/", b"/", b"/", b".", b".", b"..", b"%", b"2", b"e", b"E", b"f", b"F", b"5", b"c", b"0",
    b"a", b"A", b";", b"\\", b"#", b"~", b"%2e", b"%2E", b"%2f", b"%5C", b"%00", b"%41", b"%7e",
    b"%25", b"\x80",
];

const CORPUS: [&[u8]; 8] = [
    b"/admin/x",
    b"//admin/x",
    b"/./admin/%2e%2E/x",
    b"/%61dmin/x?",
    b"/admin;x/y",
    b"/.well-known/..;x/admin",
    b"/a/b/c/./../../g/",
    b"*",
];

#[test]
fn random_paths_agree_with_the_reference_and_stay_normal() {
    let mut rng = Rng::new(0x9a7b_0001);
    let mut accepted = 0;
    let mut input = Vec::new();
    for round in 0..150_000 {
        input.clear();
        if round % 2 == 0 {
            input.push(b'/');
            for _ in 0..rng.at_most(24) {
                input.extend_from_slice(rng.pick(&PIECES));
            }
        } else {
            input.extend_from_slice(rng.pick(&CORPUS));
            for _ in 0..1 + rng.below(3) {
                let other = *rng.pick(&CORPUS);
                mutate(&mut rng, &mut input, other);
            }
        }
        accepted += usize::from(check(&input));
    }
    assert!(accepted > 20_000, "{accepted} accepted");
}

#[test]
#[ignore = "long fuzz run; use --release -- --ignored"]
fn random_paths_agree_with_the_reference_long() {
    let mut rng = Rng::new(0x9a7b_0002);
    let mut input = Vec::new();
    for _ in 0..5_000_000 {
        input.clear();
        input.push(b'/');
        for _ in 0..rng.at_most(64) {
            input.extend_from_slice(rng.pick(&PIECES));
        }
        check(&input);
    }
}
