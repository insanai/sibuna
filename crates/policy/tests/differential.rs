//! Differential test against the Zig 0.16 policy library.
//!
//! `tests/data/differential/reference.zig` generated `expected.txt` from the inputs in the
//! same directory: requests built from `fragments.txt` by a seeded generator and evaluated
//! by the default engine, the gate profile, the sample `policy.json` (with its rule
//! matches) and both WAF paths; payloads inspected every way and embedded; mutated policy
//! files loaded with their diagnostics; mutated management documents parsed. This test
//! generates the same inputs, prints the same lines and requires them to be equal. Each
//! line carries a digest of its input, so a generator mismatch is told apart from an
//! engine mismatch. The lines in [`DELIBERATE`] differ on purpose and must keep differing;
//! every other line must be equal.
// Test helpers outside `#[test]` functions: a malformed data file should panic loudly.
#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;

use sibuna_crypto::wyhash;
use sibuna_policy::inspection::{self, Mode, Modes};
use sibuna_policy::waf::{self, AttackCategory, Violation};
use sibuna_policy::{
    Action, Algorithm, Decision, Diagnostic, Engine, Header, RequestView, RuleMatches, embedding,
    management,
};

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/differential/");
/// Counts of generated requests, policy files and documents in `expected.txt`. A larger
/// run against a locally generated reference can be checked by setting
/// `SIBUNA_DIFFERENTIAL=<expected file>,<requests>,<policies>,<documents>`.
const COUNTS: (u64, u64, u64) = (2000, 1200, 500);
const FILLER: &[u8] = b"the quick brown fox jumps over the lazy dog, and the form holds a note. ";
const ALPHABET: &[u8] = b"{}[]\",:0123456789 truefalsnul-.eE\\aAzZ/_x\xc3\xa9\xff\x01";
const TOKENS: [&str; 26] = [
    "\"name\":\"x\",",
    "\"bogus\":1,",
    "null",
    "\"DENY\"",
    "\"WEIGH\"",
    "1e3",
    "\"10.0.0.0/33\"",
    "-1",
    "\"1_0\"",
    "[1,2]",
    "{}",
    "\"rules\":[],",
    "\"weight\":5,",
    "\"action\":\"ALLOW\",",
    "\"path\":\"/x\",",
    "\"cidrs\":[\"1.2.3.4\"],",
    "\"limits\":{\"rate\":1,\"window_seconds\":1},",
    "\"challenge\":{\"difficulty\":8},",
    "\"headers\":{\"A\":\"b\"},",
    "\"inspection\":{\"sqli\":1},",
    "\\u0041",
    "\"\\ud800\"",
    "0.5",
    "\"audit\"",
    "true",
    "\"posw\"",
];

/// Lines where the Rust engine deliberately differs from the Zig reference, by reason (the
/// `waf` and `body_fields` module docs and SID 0004 record each change). Every other change
/// of the WAF since the reference keeps these inputs' lines equal.
const DELIBERATE: [(&str, &[&str]); 2] = [
    (
        "a text body under a binary Content-Type is inspected; Zig skipped every body of a \
         declared binary type",
        &[
            "R5", "R7", "R9", "R58", "R70", "R150", "R176", "R200", "R231", "R251", "R300",
            "R455", "R473", "R477", "R489", "R552", "R558", "R576", "R635", "R683", "R687",
            "R689", "R692", "R707", "R726", "R745", "R759", "R775", "R828", "R829", "R858",
            "R862", "R863", "R895", "R948", "R982", "R997", "R1053", "R1084", "R1154", "R1185",
            "R1192", "R1196", "R1207", "R1226", "R1240", "R1249", "R1255", "R1304", "R1323",
            "R1328", "R1329", "R1346", "R1389", "R1412", "R1424", "R1437", "R1448", "R1477",
            "R1506", "R1508", "R1528", "R1609", "R1638", "R1649", "R1654", "R1680", "R1697",
            "R1708", "R1731", "R1749", "R1792", "R1836", "R1844", "R1912", "R1914", "R1931",
            "R1944", "R1947", "R1987", "R1990",
        ],
    ),
    (
        "a decoded line feed (%0a, %250a) before a command is command injection; Zig folded \
         it into a space before the detector saw it",
        &["R321", "R945", "R1581", "P42.2", "P42.3"],
    ),
];

/// True when `line` starts with the identifier of a [`DELIBERATE`] line.
fn is_deliberate(line: &str) -> bool {
    let id = line.split_once(' ').map_or(line, |(id, _)| id);
    DELIBERATE.iter().any(|(_, ids)| ids.contains(&id))
}

/// Removes the [`DELIBERATE`] lines from both outputs after checking that each still
/// differs from its reference, so a stale entry is noticed.
fn remove_deliberate(expected_text: &str, actual: &mut Vec<String>) -> String {
    let expected: Vec<&str> = expected_text.lines().filter(|line| is_deliberate(line)).collect();
    let deliberate: Vec<&String> = actual.iter().filter(|line| is_deliberate(line)).collect();
    let count: usize = DELIBERATE.iter().map(|(_, ids)| ids.len()).sum();
    assert_eq!((expected.len(), deliberate.len()), (count, count), "a listed line is missing");
    for (zig, rust) in expected.iter().zip(&deliberate) {
        assert_ne!(zig, rust, "a deliberate difference no longer occurs; remove it from the list");
    }
    actual.retain(|line| !is_deliberate(line));
    expected_text.split_inclusive('\n').filter(|line| !is_deliberate(line)).collect()
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DATA}{name}")).unwrap()
}

#[derive(Default)]
struct Fragments {
    ips: Vec<Vec<u8>>,
    paths: Vec<Vec<u8>>,
    queries: Vec<Vec<u8>>,
    user_agents: Vec<Vec<u8>>,
    header_names: Vec<Vec<u8>>,
    header_values: Vec<Vec<u8>>,
    content_types: Vec<Vec<u8>>,
    bodies: Vec<Vec<u8>>,
    payloads: Vec<Vec<u8>>,
}

fn unescape(line: &[u8]) -> Vec<u8> {
    if line == b"(empty)" {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < line.len() {
        if line[i] != b'\\' || i + 1 >= line.len() {
            out.push(line[i]);
            i += 1;
            continue;
        }
        i += 1;
        match line[i] {
            b'r' => out.push(b'\r'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'\\' => out.push(b'\\'),
            b'x' => {
                let hex = std::str::from_utf8(&line[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 2;
            }
            other => out.extend_from_slice(&[b'\\', other]),
        }
        i += 1;
    }
    out
}

fn fragments() -> Fragments {
    let text = read("fragments.txt");
    let mut result = Fragments::default();
    let mut current: Option<&mut Vec<Vec<u8>>> = None;
    for line in text.split(|&b| b == b'\n').filter(|line| !line.is_empty()) {
        if line[0] == b'[' && line[line.len() - 1] == b']' {
            current = Some(match &line[1..line.len() - 1] {
                b"ips" => &mut result.ips,
                b"paths" => &mut result.paths,
                b"queries" => &mut result.queries,
                b"user_agents" => &mut result.user_agents,
                b"header_names" => &mut result.header_names,
                b"header_values" => &mut result.header_values,
                b"content_types" => &mut result.content_types,
                b"bodies" => &mut result.bodies,
                _ => &mut result.payloads,
            });
            continue;
        }
        current.as_mut().unwrap().push(unescape(line));
    }
    result
}

fn splitmix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

struct Rng(u64);

impl Rng {
    fn new(index: u64, salt: u64) -> Rng {
        Rng(splitmix(index.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ salt) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, list: &'a [Vec<u8>]) -> &'a [u8] {
        &list[self.below(list.len())]
    }
}

fn transform(text: &[u8], kind: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, &c) in text.iter().enumerate() {
        match kind {
            1 => out.push(c.to_ascii_uppercase()),
            2 | 3 if !c.is_ascii_alphanumeric() => {
                out.extend_from_slice(if kind == 3 { b"%25" } else { b"%" });
                let hex = b"0123456789ABCDEF";
                out.extend_from_slice(&[hex[usize::from(c >> 4)], hex[usize::from(c & 15)]]);
            }
            4 if c == b' ' => out.extend_from_slice(b"/**/"),
            5 => out.push(if c == b' ' { b'+' } else { c }),
            6 => out.push(if index % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }),
            7 if c == b' ' => out.extend_from_slice(b"  \t"),
            _ => out.push(c),
        }
    }
    out
}

fn field(rng: &mut Rng, list: &[Vec<u8>], fragments: &Fragments, inject: usize) -> Vec<u8> {
    let mut text = rng.pick(list).to_vec();
    if rng.below(inject) == 0 {
        text.extend_from_slice(rng.pick(&fragments.payloads));
    }
    transform(&text, rng.below(24))
}

struct Request {
    path: Vec<u8>,
    query: Vec<u8>,
    ip: Vec<u8>,
    user_agent: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

impl Request {
    fn generate(index: u64, f: &Fragments) -> Request {
        let mut rng = Rng::new(index, 1);
        let path = field(&mut rng, &f.paths, f, 12);
        let query = field(&mut rng, &f.queries, f, 6);
        let ip = rng.pick(&f.ips).to_vec();
        let user_agent = field(&mut rng, &f.user_agents, f, 16);
        let mut headers = Vec::new();
        for _ in 0..rng.below(4) {
            let name = rng.pick(&f.header_names).to_vec();
            headers.push((name, field(&mut rng, &f.header_values, f, 8)));
        }
        let content_type = rng.pick(&f.content_types);
        if content_type != b"(none)" {
            headers.push((b"Content-Type".to_vec(), content_type.to_vec()));
        }
        let mut body = field(&mut rng, &f.bodies, f, 5);
        if rng.below(8) == 0 {
            let mut long = Vec::new();
            while long.len() < 8200 {
                long.extend_from_slice(FILLER);
            }
            long.extend_from_slice(&body);
            body = long;
        }
        Request { path, query, ip, user_agent, headers, body }
    }

    fn digest(&self) -> u64 {
        let mut bytes = Vec::new();
        for part in [&self.path, &self.query, &self.ip, &self.user_agent] {
            bytes.extend_from_slice(part);
            bytes.push(0);
        }
        for (name, value) in &self.headers {
            bytes.extend_from_slice(name);
            bytes.push(1);
            bytes.extend_from_slice(value);
            bytes.push(0);
        }
        bytes.push(2);
        bytes.extend_from_slice(&self.body);
        wyhash::hash(0, &bytes)
    }
}

fn letter(action: Action) -> char {
    match action {
        Action::Allow => 'a',
        Action::Deny => 'd',
        Action::Challenge => 'c',
        Action::Weigh => 'w',
    }
}

fn decision(out: &mut String, d: &Decision<'_>) {
    let algorithm = match d.algorithm {
        Some(Algorithm::Hashcash) => 'h',
        Some(Algorithm::Posw) => 'p',
        None => '-',
    };
    let _ = write!(
        out,
        "{}:{}:{}:{}:{}:{}:",
        letter(d.action),
        d.rule_name,
        d.difficulty,
        algorithm,
        d.score,
        d.audited
    );
    match d.limits {
        Some(l) => write!(out, "{}/{}/{}", l.rate, l.window_seconds, l.ban_seconds),
        None => write!(out, "-"),
    }
    .unwrap();
    let _ = write!(out, ":{:x}", d.limit_scope);
}

fn violation(out: &mut String, found: Option<Violation>) {
    match found {
        Some(hit) => write!(out, "{}:{}", hit.category.name(), hit.pattern),
        None => write!(out, "-"),
    }
    .unwrap();
}

const MIXED: Modes = Modes {
    path_traversal: Mode::Audit,
    sqli: Mode::Enforce,
    xss: Mode::Audit,
    rce: Mode::Disabled,
};

fn request_lines(f: &Fragments, requests: u64, out: &mut Vec<String>) {
    let default_engine = Engine::new(16);
    let mut gate = Engine::new(16);
    gate.waf_enabled = false;
    let sample = Engine::load_json(&read("policy.json"), 16).unwrap();
    for index in 0..requests {
        let request = Request::generate(index, f);
        let headers: Vec<Header<'_>> =
            request.headers.iter().map(|(name, value)| Header { name, value }).collect();
        let view = RequestView {
            path: &request.path,
            query: &request.query,
            client_ip: &request.ip,
            client_address: sibuna_cidr::parse_ip(&request.ip).ok(),
            user_agent: &request.user_agent,
            headers: &headers,
            body: &request.body,
        };
        let mut line = format!("R{index} {:016x} ", request.digest());
        decision(&mut line, &default_engine.evaluate(&view));
        line.push_str(" | ");
        decision(&mut line, &gate.evaluate(&view));
        line.push_str(" | ");
        let mut matches = RuleMatches::new();
        let observed = sample.evaluate_with_matches(&view, &mut matches);
        assert_eq!(observed, sample.evaluate(&view));
        decision(&mut line, &observed);
        let bits = matches.iter().fold(0u128, |bits, index| bits | (1 << index));
        let _ = write!(line, " {bits:x} | ");
        violation(&mut line, waf::inspect_request(default_engine.signatures(), &view));
        line.push_str(" | ");
        let findings = inspection::inspect(default_engine.signatures(), MIXED, &view);
        violation(&mut line, findings.denied);
        let _ = write!(line, "/{}", findings.audited);
        out.push(line);
    }
}

fn payload_lines(f: &Fragments, out: &mut Vec<String>) {
    let signatures = waf::Signatures::new();
    for (index, payload) in f.payloads.iter().enumerate() {
        for kind in [0, 2, 3, 4] {
            let text = transform(payload, kind);
            let mut line = format!("P{index}.{kind} ");
            violation(&mut line, waf::inspect_text_with(&signatures, &text));
            line.push_str(" | ");
            violation(&mut line, waf::inspect_text(&text));
            line.push_str(" |");
            for category in AttackCategory::ALL {
                line.push(' ');
                violation(&mut line, waf::inspect_category(&signatures, category, &text));
            }
            let vector = embedding::embed(&text);
            let _ = write!(line, " | {:016x}", wyhash::hash(0, &embedding::to_bytes(&vector)));
            out.push(line);
        }
    }
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut text = base.to_vec();
    for _ in 0..1 + rng.below(3) {
        let op = rng.below(6);
        let pos = rng.below(text.len() + 1);
        match op {
            0 => {
                let byte = ALPHABET[rng.below(ALPHABET.len())];
                if !text.is_empty() {
                    let at = pos.min(text.len() - 1);
                    text[at] = byte;
                }
            }
            1 if pos < text.len() => {
                text.remove(pos);
            }
            1 => {}
            2 => text.insert(pos, ALPHABET[rng.below(ALPHABET.len())]),
            3 => {
                if rng.below(2) == 0 {
                    text.truncate(pos);
                }
            }
            4 => {
                let start = rng.below(text.len() + 1);
                let end = (start + rng.below(16)).min(text.len());
                let copy = text[start..end].to_vec();
                text.splice(pos..pos, copy);
            }
            _ => {
                let token = TOKENS[rng.below(TOKENS.len())].as_bytes();
                text.splice(pos..pos, token.iter().copied());
            }
        }
    }
    text
}

fn lines_of(name: &str) -> Vec<Vec<u8>> {
    read(name).split(|&b| b == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec).collect()
}

fn mode_letter(mode: Mode) -> char {
    match mode {
        Mode::Disabled => 'd',
        Mode::Audit => 'a',
        Mode::Enforce => 'e',
    }
}

fn loader_lines(policies: u64, out: &mut Vec<String>) {
    let bases = lines_of("policies.txt");
    let probe_headers =
        [Header { name: b"X-A", value: b"v1" }, Header { name: b"X-B", value: b"xx" }];
    let probe = RequestView {
        headers: &probe_headers,
        ..RequestView::new(b"/api/checkout/pay", b"10.1.2.3", b"curl/8.0")
    };
    for index in 0..policies {
        let mut rng = Rng::new(index, 2);
        let base = &bases[rng.below(bases.len())];
        let text = mutate(&mut rng, base);
        let mut line = format!("L{index} {:016x} ", wyhash::hash(0, &text));
        let mut engine = Engine::new(16);
        let mut diagnostic = Diagnostic::default();
        if let Err(error) = engine.apply_json(&text, &mut diagnostic) {
            let title = error.explain().title;
            let _ = write!(
                line,
                "err {} {title} {}|{}|{}",
                error.name(),
                diagnostic.rule,
                diagnostic.field,
                diagnostic.value
            );
            out.push(line);
            continue;
        }
        let (m, t) = (engine.inspection_modes, engine.thresholds);
        let _ = write!(
            line,
            "ok {} {} {} {}{}{}{} {}/{}/{} ",
            engine.rule_count(),
            letter(engine.default_action),
            engine.waf_enabled,
            mode_letter(m.path_traversal),
            mode_letter(m.sqli),
            mode_letter(m.xss),
            mode_letter(m.rce),
            t.challenge_at,
            t.deny_at,
            t.bits_step
        );
        decision(&mut line, &engine.evaluate(&probe));
        out.push(line);
    }
}

fn document_lines(documents: u64, out: &mut Vec<String>) {
    let bases = lines_of("documents.txt");
    for index in 0..documents {
        let mut rng = Rng::new(index, 3);
        let base = &bases[rng.below(bases.len())];
        let text = mutate(&mut rng, base);
        let mut line = format!("M{index} {:016x} ", wyhash::hash(0, &text));
        match management::parse(&text) {
            Err(error) => {
                let _ = write!(line, "err {}", error.name());
            }
            Ok(document) => {
                let r = &document.rule;
                let algorithm = match r.algorithm {
                    Some(Algorithm::Hashcash) => 'h',
                    Some(Algorithm::Posw) => 'p',
                    None => '-',
                };
                let _ = write!(
                    line,
                    "ok {}|{}|{}|{}|{}|{}|{}|{}|{}|{}|",
                    document.id,
                    r.name,
                    letter(r.action),
                    document.priority,
                    document.enabled,
                    r.path_pattern.as_deref().unwrap_or("-"),
                    r.ua_pattern.as_deref().unwrap_or("-"),
                    r.difficulty.unwrap_or(0),
                    algorithm,
                    r.weight
                );
                match r.limits {
                    Some(l) => write!(line, "{}/{}/{}", l.rate, l.window_seconds, l.ban_seconds),
                    None => write!(line, "-"),
                }
                .unwrap();
                let _ =
                    write!(line, "|{}|{}|{:x}", r.headers.len(), r.cidrs.len(), r.limit_identity);
            }
        }
        out.push(line);
    }
}

#[test]
fn rust_engine_prints_the_zig_reference_lines() {
    let (expected_text, (requests, policies, documents)) =
        match std::env::var("SIBUNA_DIFFERENTIAL") {
            Ok(spec) => {
                let parts: Vec<&str> = spec.split(',').collect();
                let count = |i: usize| parts[i].parse::<u64>().unwrap();
                (std::fs::read_to_string(parts[0]).unwrap(), (count(1), count(2), count(3)))
            }
            Err(_) => (String::from_utf8(read("expected.txt")).unwrap(), COUNTS),
        };
    let f = fragments();
    let mut actual = Vec::new();
    request_lines(&f, requests, &mut actual);
    payload_lines(&f, &mut actual);
    loader_lines(policies, &mut actual);
    document_lines(documents, &mut actual);
    let expected_text = remove_deliberate(&expected_text, &mut actual);
    // Diagnostic values may hold a decoded newline, so the texts are compared whole; the
    // line view only locates a difference.
    let mut actual_text = actual.join("\n");
    actual_text.push('\n');
    if actual_text == expected_text {
        return;
    }
    let differing =
        expected_text.lines().zip(actual_text.lines()).enumerate().filter(|(_, (e, a))| e != a);
    for (index, (expected, actual)) in differing.take(20) {
        eprintln!("line {index}\n  zig:  {expected}\n  rust: {actual}");
    }
    panic!("the Rust lines differ from the Zig reference");
}
