//! Parser fuzzing: random and mutated snippets never panic, and the compiler agrees with
//! a naive reference implementation of the Zig rules.

#![allow(clippy::unwrap_used)]

extern crate std;

use super::*;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use std::string::String as StdString;

/// Valid snippets to mutate.
const CORPUS: [&str; 6] = [
    include_str!("../../tests/data/snippets/field.html"),
    include_str!("../../tests/data/snippets/audit-detail.html"),
    include_str!("../../tests/data/snippets/globe-mode.html"),
    include_str!("../../tests/data/snippets/notification-form.html"),
    "<p>{{ a }}{{b}}{{\tc_1\n}}</p>",
    "\u{4e16}{{ x }}\u{e9}{{ x }}",
];

/// Fragments spliced in to reach every check.
const FRAGMENTS: [&str; 16] = [
    "{{", "}}", "{%", "{#", "{", "}", " ", "\n", "\r", "\t", "name", "1", "-", "self", "\u{e9}",
    "{{ v }}",
];

/// A xorshift64 generator: deterministic and dependency-free.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
    }
}

/// Applies one random mutation to `bytes`.
fn mutate(random: &mut XorShift, bytes: &mut Vec<u8>) {
    let at = random.below(bytes.len() + 1);
    match random.below(6) {
        0 if !bytes.is_empty() => {
            let index = random.below(bytes.len());
            bytes[index] ^= 1 << random.below(8);
        }
        1 => bytes.truncate(at),
        2 => {
            let end = (at + random.below(64)).min(bytes.len());
            let copy = bytes[at..end].to_vec();
            bytes.splice(at..at, copy);
        }
        3 => {
            let other = CORPUS[random.below(CORPUS.len())].as_bytes();
            let from = random.below(other.len());
            let end = (from + random.below(200)).min(other.len());
            bytes.splice(at..at, other[from..end].iter().copied());
        }
        4 if bytes.len() < 40_000 => {
            let copy = bytes.clone();
            bytes.extend_from_slice(&copy);
        }
        _ => {
            let fragment = FRAGMENTS[random.below(FRAGMENTS.len())].as_bytes();
            bytes.splice(at..at, fragment.iter().copied());
        }
    }
}

/// The Zig rules, written plainly: the code of the first failing check, if any.
fn reference_check(source: &str) -> Option<&'static str> {
    if source.len() > 32 * 1024 {
        return Some("HTML001");
    }
    if source.contains("{%") || source.contains("{#") {
        return Some("HTML002");
    }
    let mut rest = source;
    let mut count = 0;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Some("HTML003");
        };
        let name = after[..end].trim_matches(NAME_PADDING);
        let valid = !name.is_empty()
            && name.bytes().enumerate().all(|(i, b)| {
                b.is_ascii_alphabetic() || b == b'_' || (i != 0 && b.is_ascii_digit())
            });
        if !valid || ["_", "self", "Self", "super", "crate"].contains(&name) {
            return Some("HTML006");
        }
        count += 1;
        if count > 128 {
            return Some("HTML005");
        }
        rest = &after[end + 2..];
    }
    None
}

/// The output of the reference renderer when each value is its own name in brackets.
fn reference_render(source: &str) -> StdString {
    let mut out = StdString::new();
    let mut rest = source;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}").unwrap();
        out.push_str(&format!("[{}]", after[..end].trim_matches(NAME_PADDING)));
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

fn check_accepted(template: &Template, round: usize) {
    assert!(template.placeholder_count() <= PLACEHOLDER_LIMIT);
    assert!(template.field_count() <= template.placeholder_count());
    let labels: Vec<StdString> = template.field_names().map(|name| format!("[{name}]")).collect();
    let values: Vec<(&str, &dyn Value)> =
        template.field_names().zip(labels.iter()).map(|(n, l)| (n, l as &dyn Value)).collect();
    let mut out = StdString::new();
    template.render(&mut out, &values).unwrap();
    assert_eq!(out, reference_render(template.source()));
    if round.is_multiple_of(16) {
        assert!(crate::generate(core::slice::from_ref(template)).is_ascii());
    }
}

fn check_rejected(diagnostic: &Diagnostic, source: &str) {
    assert_eq!(Some(diagnostic.code()), reference_check(source), "{source:?}");
    let location = diagnostic.location.as_ref().unwrap();
    assert!(location.line >= 1 && location.column >= 1);
    let shown = location.excerpt.chars().count();
    assert!(shown <= 72 + 6);
    assert!(location.carets >= 1 && location.caret + location.carets <= shown + 1);
    let text = diagnostic.to_string();
    assert!(text.starts_with("-- ") && text.ends_with('\n'));
    assert!(text.contains(diagnostic.code()));
}

#[test]
fn fuzz_compile_agrees_with_the_reference_and_never_panics() {
    let mut random = XorShift(0x2545_f491_4f6c_dd1d);
    let mut bytes = Vec::new();
    let (mut accepted, mut rejected) = (0, 0);
    for round in 0..100_000 {
        if round % 8 == 0 || bytes.len() > 48_000 {
            bytes = CORPUS[random.below(CORPUS.len())].as_bytes().to_vec();
        }
        for _ in 0..=random.below(3) {
            mutate(&mut random, &mut bytes);
        }
        let source = StdString::from_utf8_lossy(&bytes).to_string();
        match compile("fuzz.html", &source) {
            Ok(template) => {
                assert_eq!(reference_check(&source), None, "{source:?}");
                check_accepted(&template, round);
                accepted += 1;
            }
            Err(diagnostic) => {
                check_rejected(&diagnostic, &source);
                rejected += 1;
            }
        }
    }
    // Both outcomes must be common, or the fuzzer is not exploring.
    assert!(accepted > 10_000 && rejected > 10_000, "{accepted} accepted, {rejected} rejected");
}

#[test]
fn fuzz_random_bytes_never_panic() {
    let mut random = XorShift(0xdead_beef_cafe_f00d);
    let alphabet = b"{}%# \n\ra_1-<>&\"'";
    for _ in 0..100_000 {
        let length = random.below(48);
        let bytes: Vec<u8> = (0..length).map(|_| alphabet[random.below(alphabet.len())]).collect();
        let source = core::str::from_utf8(&bytes).unwrap();
        let result = compile("random.html", source);
        assert_eq!(result.as_ref().err().map(Diagnostic::code), reference_check(source));
    }
}
