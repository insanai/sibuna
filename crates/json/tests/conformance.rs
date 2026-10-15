//! JSONTestSuite-style conformance cases, written by hand (see `corpus/mod.rs`).

mod corpus;

use corpus::{ACCEPT, REJECT};
use sibuna_json::{Error, ErrorKind, Limits, Value, parse, parse_with_limits};

#[test]
fn accepts_every_y_and_accepted_i_case() {
    for (name, input) in ACCEPT {
        if let Err(error) = parse(input) {
            panic!("{name} rejected: {error}");
        }
    }
}

#[test]
fn rejects_every_n_and_rejected_i_case() {
    for (name, input) in REJECT {
        if let Ok(value) = parse(input) {
            panic!("{name} accepted as {value:?}");
        }
    }
}

// JSONTestSuite counts duplicate keys as valid JSON (`y_object_duplicated_key`); Zig's
// default parse options, and therefore Sibuna, reject them.
#[test]
fn rejects_duplicated_keys_by_design() {
    for input in [&b"{\"a\":\"b\",\"a\":\"c\"}"[..], b"{\"a\":\"b\",\"a\":\"b\"}"] {
        assert_eq!(parse(input).unwrap_err().kind, ErrorKind::DuplicateKey);
    }
}

// `n_structure_100000_opening_arrays` and `i_structure_500_nested_arrays`: the depth limit
// rejects both, without recursion, where Zig accepted the second.
#[test]
fn deep_nesting_hits_the_depth_limit() {
    let open = "[".repeat(100_000);
    assert_eq!(parse(open.as_bytes()).unwrap_err().kind, ErrorKind::DepthLimit);
    let nested = format!("{}{}", "[".repeat(500), "]".repeat(500));
    assert_eq!(parse(nested.as_bytes()).unwrap_err().kind, ErrorKind::DepthLimit);
    let limits = Limits { max_depth: 500, ..Limits::default() };
    assert!(parse_with_limits(nested.as_bytes(), &limits).is_ok());
}

// Writing an accepted document and parsing the output gives the same value, and writing
// that value again gives the same bytes.
#[test]
fn writer_output_round_trips() {
    for (name, input) in ACCEPT {
        let value = parse(input).unwrap();
        let written = value.to_string();
        let reparsed = parse(written.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(reparsed, value, "{name}");
        assert_eq!(reparsed.to_string(), written, "{name}");
        assert!(!written.contains(' ') || written.contains('"'), "{name}: {written}");
    }
}

#[test]
fn round_trip_preserves_every_code_point_class() {
    let text: String = [
        '\u{0}',
        '\u{1f}',
        '"',
        '\\',
        '/',
        '\u{7f}',
        '\u{80}',
        '\u{7ff}',
        '\u{800}',
        '\u{ffff}',
        '\u{10000}',
        '\u{10ffff}',
        '\u{2028}',
    ]
    .iter()
    .collect();
    let mut written = String::new();
    sibuna_json::write_string(&mut written, &text).unwrap();
    assert_eq!(parse(written.as_bytes()).unwrap(), Value::String(text.into()));
}

#[test]
fn errors_display_their_location() {
    let error: Error = parse(b"{\n  \"a\": [1,]\n}").unwrap_err();
    assert_eq!(error.kind, ErrorKind::ExpectedValue);
    assert_eq!(error.to_string(), "a value was expected here (line 2, column 11)");
}
