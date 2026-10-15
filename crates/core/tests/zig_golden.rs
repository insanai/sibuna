//! Byte-for-byte agreement with the Zig daemon.
//!
//! `data/zig_golden.txt` was produced by a small Zig 0.16 program that imported the Zig
//! daemon's `libs/core/src` files and printed their output for fixed inputs: diagnostics,
//! every `explainError` text, the Prometheus exposition, redacted request and response
//! heads, and the `INVALID COMMAND LINE` report of `apps/sibuna/src/main.zig`. Each line
//! is a record: a tag, then tab-separated fields escaped with `\n`, `\r`, `\t`, `\\` and
//! `\xNN`.

use sibuna_core::errors::{ErrorKind, explain_name};
use sibuna_core::incident_heads::{
    Extra, REQUEST_BYTES, RESPONSE_BYTES, RequestLine, request_head, response_head,
};
use sibuna_core::{Config, Counter, Metrics, diagnostic};

const GOLDEN: &str = include_str!("data/zig_golden.txt");

fn unescape(field: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bytes = field.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            out.push(byte);
            continue;
        }
        match bytes.next() {
            Some(b'n') => out.push(b'\n'),
            Some(b'r') => out.push(b'\r'),
            Some(b't') => out.push(b'\t'),
            Some(b'\\') => out.push(b'\\'),
            Some(b'x') => {
                let hex: String = bytes.by_ref().take(2).map(char::from).collect();
                out.push(u8::from_str_radix(&hex, 16).expect("two hex digits"));
            }
            other => panic!("bad escape {other:?} in {field}"),
        }
    }
    out
}

fn records(tag: &str) -> Vec<Vec<Vec<u8>>> {
    let records: Vec<Vec<Vec<u8>>> = GOLDEN
        .lines()
        .filter_map(|line| line.strip_prefix(tag)?.strip_prefix('\t'))
        .map(|rest| rest.split('\t').map(unescape).collect())
        .collect();
    assert!(!records.is_empty(), "no {tag} records");
    records
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("UTF-8 field")
}

#[test]
fn diagnostics_match_zig() {
    for record in records("diagnostic") {
        let [title, message, hint, expected] = &record[..] else { panic!("{record:?}") };
        let mut out = String::new();
        diagnostic::render(&mut out, text(title), text(message), text(hint)).unwrap();
        assert_eq!(out.as_bytes(), &expected[..]);
    }
}

#[test]
fn explanations_match_zig() {
    let records = records("explain");
    assert_eq!(records.len(), ErrorKind::ALL.len());
    for record in records {
        let [name, expected] = &record[..] else { panic!("{record:?}") };
        assert_eq!(explain_name(text(name)).as_bytes(), &expected[..], "{}", text(name));
    }
}

#[test]
fn prometheus_matches_zig() {
    let [record] = &records("prometheus")[..] else { panic!("one prometheus record") };
    let metrics = Metrics::default();
    // The generator stored 1, then v * 7 + 3 for each next counter, and u64::MAX last.
    // The port's security counters follow Zig's; the Zig counters keep their exposition.
    let mut value: u64 = 1;
    let counters = metrics.counters();
    let zig_counters = &counters[..sibuna_core::metrics::ZIG_COUNTER_COUNT];
    for (_, counter) in zig_counters {
        counter.add(value);
        value = value * 7 + 3;
    }
    let last: &Counter = zig_counters[zig_counters.len() - 1].1;
    last.add(u64::MAX - last.value());
    let mut out = String::new();
    metrics.write_prometheus(&mut out).unwrap();
    let zig_lines = 2 * sibuna_core::metrics::ZIG_COUNTER_COUNT;
    let end = out.match_indices('\n').nth(zig_lines - 1).map_or(out.len(), |(at, _)| at + 1);
    assert_eq!(&out.as_bytes()[..end], &record[0][..]);
    assert!(out[end..].starts_with("# TYPE sibuna_bans_refused_total counter\n"));
}

#[test]
fn request_heads_match_zig() {
    let mut extra = Extra::default();
    extra.add("X-Trace-Id").unwrap();
    extra.add("X-Session-Id").unwrap();
    for record in records("request") {
        let [truncated, expected, method, path, query, headers @ ..] = &record[..] else {
            panic!("{record:?}")
        };
        let line = RequestLine { method, path, query, version: b"HTTP/1.1" };
        let pairs = headers.as_chunks::<2>().0.iter().map(|[name, value]| (&name[..], &value[..]));
        let mut out = [0; REQUEST_BYTES];
        let head = request_head(&line, pairs, &extra, &mut out);
        assert_eq!(&out[..head.len], &expected[..]);
        assert_eq!(head.truncated, truncated == b"true");
    }
}

#[test]
fn response_heads_match_zig() {
    let mut extra = Extra::default();
    extra.add("X-Trace-Id").unwrap();
    for record in records("response") {
        let [truncated, expected, raw] = &record[..] else { panic!("{record:?}") };
        let mut out = [0; RESPONSE_BYTES];
        let head = response_head(raw, &extra, &mut out);
        assert_eq!(&out[..head.len], &expected[..], "{}", String::from_utf8_lossy(raw));
        assert_eq!(head.truncated, truncated == b"true");
    }
}

#[test]
fn invalid_command_line_reports_match_zig() {
    for record in records("arguments") {
        let [expected, args @ ..] = &record[..] else { panic!("{record:?}") };
        let args: Vec<&str> = args.iter().map(|arg| text(arg)).collect();
        let error = Config::parse_args(&args).unwrap_err();
        assert_eq!(error.to_string(), text(expected), "{args:?}");
    }
}
