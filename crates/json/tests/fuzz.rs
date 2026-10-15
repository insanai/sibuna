//! Deterministic fuzzing of the parser and writer.
//!
//! A xorshift generator produces valid documents and mutates them and the conformance
//! corpus (bit flips, structural bytes, truncation, duplication, splicing, deep nesting).
//! Every input must parse without panicking, errors must point inside the input, accepted
//! values must respect the limits they were parsed with, the limits must reject exactly the
//! values that break them, and writing an accepted value must give text that parses back
//! to the same value and writes back to the same bytes.

mod corpus;

use sibuna_json::{ErrorKind, Limits, Value, parse_with_limits};

/// Marsaglia's xorshift64: small, fast and reproducible from its seed.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }

    fn pick<'t, T>(&mut self, items: &'t [T]) -> &'t T {
        &items[self.below(items.len())]
    }
}

const WHITESPACE: &[&str] = &["", "", " ", "\n", "\t", "\r\n  "];
const NUMBERS: &[&str] = &[
    "0",
    "-0",
    "7",
    "-12",
    "3.25",
    "1e3",
    "-2.5E-3",
    "1E+2",
    "18446744073709551615",
    "-9223372036854775808",
    "123456789012345678901234567890",
    "0.000001",
    "1e400",
];
const STRING_PIECES: &[&str] = &[
    "a",
    "word",
    " ",
    "\\n",
    "\\t",
    "\\\"",
    "\\\\",
    "\\/",
    "\\u00e9",
    "\\u0000",
    "\\ud83d\\ude00",
    "\u{e9}",
    "\u{4e16}",
    "\u{1f600}",
    "/*",
    "{",
    "]",
];

/// Appends a random valid document of nesting depth at most `depth_left`.
fn generate(rng: &mut XorShift, out: &mut String, depth_left: usize) {
    out.push_str(rng.pick(WHITESPACE));
    let choice = if depth_left == 0 { rng.below(4) } else { rng.below(8) };
    match choice {
        0 => out.push_str(rng.pick(&["null", "true", "false"])),
        1 => out.push_str(rng.pick(NUMBERS)),
        2 | 3 => generate_string(rng, out, ""),
        4 | 5 => {
            out.push('[');
            for i in 0..rng.below(5) {
                if i > 0 {
                    out.push(',');
                }
                generate(rng, out, depth_left - 1);
            }
            out.push(']');
        }
        _ => {
            out.push('{');
            for i in 0..rng.below(5) {
                if i > 0 {
                    out.push(',');
                }
                // Distinct suffixes keep keys unique however the pieces decode.
                generate_string(rng, out, &format!("#{i}"));
                out.push(':');
                generate(rng, out, depth_left - 1);
            }
            out.push('}');
        }
    }
    out.push_str(rng.pick(WHITESPACE));
}

fn generate_string(rng: &mut XorShift, out: &mut String, suffix: &str) {
    out.push('"');
    for _ in 0..rng.below(5) {
        out.push_str(rng.pick(STRING_PIECES));
    }
    out.push_str(suffix);
    out.push('"');
}

/// Applies one to three random edits.
fn mutate(rng: &mut XorShift, input: &mut Vec<u8>, other: &[u8]) {
    const INTERESTING: &[u8] = b"{}[],:\"\\u0-e.+ \n\t\x00\x1f\x7f\xff\xc3\xed";
    for _ in 0..1 + rng.below(3) {
        let at = rng.below(input.len() + 1);
        match rng.below(7) {
            0 if at < input.len() => input[at] ^= 1 << rng.below(8),
            1 if at < input.len() => input[at] = *rng.pick(INTERESTING),
            2 => input.truncate(at),
            3 => {
                let end = at + rng.below(input.len() - at + 1);
                let copy = input[at..end].to_vec();
                input.splice(at..at, copy);
            }
            4 => {
                let from = rng.below(other.len() + 1);
                input.truncate(at);
                input.extend_from_slice(&other[from..]);
            }
            5 => {
                let depth = rng.below(80);
                let (open, close) = if rng.below(2) == 0 { ("[", "]") } else { ("{\"k\":", "}") };
                let mut wrapped = open.repeat(depth).into_bytes();
                wrapped.extend_from_slice(input);
                wrapped.extend_from_slice(close.repeat(depth).as_bytes());
                *input = wrapped;
            }
            _ => input.insert(at, *rng.pick(INTERESTING)),
        }
    }
}

/// What a value costs in terms of the limits: nesting depth, value count and the longest
/// string or key.
#[derive(Default)]
struct Cost {
    depth: usize,
    values: usize,
    longest_string: usize,
}

fn cost(value: &Value<'_>, depth: usize, total: &mut Cost) {
    total.values += 1;
    match value {
        Value::String(text) => total.longest_string = total.longest_string.max(text.len()),
        Value::Array(items) => {
            total.depth = total.depth.max(depth + 1);
            for item in items {
                cost(item, depth + 1, total);
            }
        }
        Value::Object(object) => {
            total.depth = total.depth.max(depth + 1);
            for (key, item) in object {
                total.longest_string = total.longest_string.max(key.len());
                cost(item, depth + 1, total);
            }
        }
        _ => {}
    }
}

const TIGHT: Limits =
    Limits { max_input_bytes: 2048, max_depth: 6, max_values: 64, max_string_bytes: 16 };

/// Checks every invariant for one input.
fn check(input: &[u8]) {
    let default = Limits::default();
    let result = parse_with_limits(input, &default);
    let tight = parse_with_limits(input, &TIGHT);
    for error in [result.as_ref().err(), tight.as_ref().err()].into_iter().flatten() {
        assert!(error.offset <= input.len().max(TIGHT.max_input_bytes), "{error:?}");
        assert!(error.line >= 1 && error.column >= 1);
    }
    let Ok(value) = result else {
        assert!(tight.is_err(), "tight limits accepted what the defaults rejected");
        return;
    };
    let mut total = Cost::default();
    cost(&value, 0, &mut total);
    assert!(total.depth <= default.max_depth && total.values <= default.max_values);
    let fits = input.len() <= TIGHT.max_input_bytes
        && total.depth <= TIGHT.max_depth
        && total.values <= TIGHT.max_values
        && total.longest_string <= TIGHT.max_string_bytes;
    match tight {
        Ok(tight_value) => {
            assert!(fits, "tight limits accepted a value that breaks them");
            assert_eq!(tight_value, value);
        }
        Err(error) => {
            assert!(!fits, "tight limits rejected a fitting value: {error:?}");
            let limit_kinds = [
                ErrorKind::InputTooLarge,
                ErrorKind::DepthLimit,
                ErrorKind::ValueLimit,
                ErrorKind::StringTooLong,
            ];
            assert!(limit_kinds.contains(&error.kind), "{error:?}");
        }
    }
    let written = value.to_string();
    let reparsed = parse_with_limits(written.as_bytes(), &default)
        .unwrap_or_else(|e| panic!("written text {written:?} does not parse: {e}"));
    assert_eq!(reparsed, value);
    assert_eq!(reparsed.to_string(), written);
}

fn run(seed: u64, rounds: usize) {
    let mut rng = XorShift(seed);
    let corpus: Vec<&[u8]> =
        corpus::ACCEPT.iter().chain(corpus::REJECT).map(|(_, input)| *input).collect();
    let mut text = String::new();
    for round in 0..rounds {
        text.clear();
        generate(&mut rng, &mut text, 1 + round % 6);
        let valid = parse_with_limits(text.as_bytes(), &Limits::default());
        assert!(valid.is_ok(), "generated {text:?} rejected: {valid:?}");
        check(text.as_bytes());
        let mut input =
            if round % 4 == 0 { rng.pick(&corpus).to_vec() } else { text.clone().into_bytes() };
        let other = *rng.pick(&corpus);
        mutate(&mut rng, &mut input, other);
        check(&input);
    }
}

// 100,000 rounds of two documents each: a generated valid one and a mutation of it or of
// the corpus.
#[test]
fn mutated_documents_keep_every_invariant() {
    run(0x9E37_79B9_7F4A_7C15, 100_000);
}

#[test]
#[ignore = "heavy fuzz run; use `cargo test --release -- --ignored`"]
fn mutated_documents_keep_every_invariant_long() {
    for seed in 1..=20 {
        run(seed * 0x2545_F491_4F6C_DD1D, 500_000);
    }
}

// Nesting far past the limit, closed or not, fails with the depth error and no recursion.
#[test]
fn hostile_nesting_is_rejected_at_the_limit() {
    for depth in [65usize, 1_000, 100_000] {
        for (open, close) in [("[", "]"), ("{\"a\":", "}")] {
            let unclosed = open.repeat(depth);
            let closed = format!("{unclosed}0{}", close.repeat(depth));
            for input in [unclosed, closed] {
                let error = parse_with_limits(input.as_bytes(), &Limits::default()).unwrap_err();
                assert_eq!(error.kind, ErrorKind::DepthLimit);
            }
        }
    }
}
