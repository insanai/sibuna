//! Timing tests that reproduce the policy workloads of the Zig benchmark
//! (`benchmarks/benchmark.zig`) with the same inputs and the same method: an untimed warm-up,
//! seven timed batches, and the median batch divided by the iteration count.
//!
//! Run with `cargo test --release -p sibuna-policy --test timing -- --ignored --nocapture`.
// The timing tests exist to print their measurements.
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use std::hint::black_box;
use std::time::Instant;

use sibuna_cidr::PrefixTrie;
use sibuna_patterns::{Automaton, Options};
use sibuna_policy::bots::{AI_SCRAPERS, SCRAPER_LIBRARIES, SEARCH_CRAWLERS};
use sibuna_policy::{Action, Engine, Header, Mode, Modes, RequestView};

const BATCHES: usize = 7;

/// Returns the median nanoseconds per operation of `body(iterations)`.
fn measure(iterations: u64, mut body: impl FnMut(u64) -> u64) -> f64 {
    black_box(body(iterations.min(1000)));
    let mut samples = [0f64; BATCHES];
    let mut sink = 0u64;
    for sample in &mut samples {
        let start = Instant::now();
        sink = sink.wrapping_add(body(iterations));
        *sample = start.elapsed().as_nanos() as f64;
    }
    black_box(sink);
    samples.sort_by(f64::total_cmp);
    samples[BATCHES / 2] / iterations as f64
}

fn report(subsystem: &str, workload: &str, rust: f64, zig: f64) {
    println!("{subsystem:<14} {workload:<36} rust {rust:>10.1} ns/op   zig {zig:>10.1} ns/op");
}

/// The benchmark's browser request, as the HTTP parser hands it over.
const UA: &[u8] = b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/128.0 Safari/537.36";
const HEADERS: [Header<'static>; 6] = [
    Header { name: b"Host", value: b"example.com" },
    Header { name: b"User-Agent", value: UA },
    Header {
        name: b"Accept",
        value: b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    Header { name: b"Accept-Language", value: b"en-US,en;q=0.5" },
    Header { name: b"Accept-Encoding", value: b"gzip, deflate, br" },
    Header { name: b"Cookie", value: b"__sibuna_token=v1_YWJjZGVmZ2hpams; session=xyz123" },
];

fn browser_request() -> RequestView<'static> {
    RequestView {
        path: b"/api/v1/data",
        query: b"page=2",
        client_ip: b"203.0.113.7",
        client_address: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7))),
        user_agent: UA,
        headers: &HEADERS,
        body: b"",
    }
}

fn classify(engine: &Engine, iterations: u64) -> u64 {
    let request = browser_request();
    let mut sum = 0u64;
    for _ in 0..iterations {
        let decision = black_box(engine).evaluate(black_box(&request));
        sum = sum.wrapping_add(decision.action as u64);
    }
    sum
}

#[test]
#[ignore]
fn policy_engine_browser_request() {
    let mut engine = Engine::new(16);
    report(
        "policy_engine",
        "browser_request_full_classification",
        measure(100_000, |n| classify(&engine, n)),
        1258.2,
    );
    engine.waf_enabled = false;
    report(
        "policy_engine",
        "browser_request_gate_profile",
        measure(100_000, |n| classify(&engine, n)),
        178.7,
    );
}

fn body_scan(engine: &Engine, body: &[u8], iterations: u64) -> u64 {
    let request =
        RequestView { body, ..RequestView::new(b"/submit", b"203.0.113.7", b"Mozilla/5.0") };
    let mut sum = 0u64;
    for _ in 0..iterations {
        let decision = black_box(engine).evaluate(black_box(&request));
        sum = sum.wrapping_add(decision.action as u64);
    }
    sum
}

#[test]
#[ignore]
fn waf_inspect_8kb_body() {
    let filler = b"the quick brown fox jumps over the lazy dog, and the form holds a note. ";
    let body: Vec<u8> = (0..8192).map(|i| filler[i % filler.len()]).collect();
    let mut engine = Engine::new(16);
    report(
        "waf_inspect",
        "8kb_body_semantic_scan",
        measure(5_000, |n| body_scan(&engine, &body, n)),
        18_689.1,
    );
    engine.inspection_modes = Modes { sqli: Mode::Audit, ..Modes::default() };
    let mixed = measure(5_000, |n| body_scan(&engine, &body, n));
    report("waf_inspect", "8kb_body_sqli_audit_other_enforce", mixed, 104_667.2);
}

const TEST_UAS: [&[u8]; 6] = [
    b"Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    b"Mozilla/5.0 AppleWebKit/537.36 (compatible; ClaudeBot/1.0)",
    b"Mozilla/5.0 (Linux; Android 10) Bytespider; spider-feedback@bytedance",
    b"python-requests/2.31.0",
    b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/128.0.0.0",
    b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Safari/604.1",
];

#[test]
#[ignore]
fn bot_matcher_forty_signatures() {
    let names = AI_SCRAPERS.iter().chain(&SCRAPER_LIBRARIES).chain(&SEARCH_CRAWLERS);
    let options = Options { ascii_case_insensitive: true, ..Options::default() };
    let automaton =
        Automaton::from_patterns(options, names.map(|name| (name.as_bytes(), 0))).unwrap();
    let rust = measure(200_000, |iterations| {
        let mut hits = 0;
        for i in 0..iterations as usize {
            hits += u64::from(
                black_box(&automaton).find_first(TEST_UAS[i % TEST_UAS.len()]).is_some(),
            );
        }
        hits
    });
    report("bot_matcher", "aho_corasick_40_signatures", rust, 71.6);
}

#[test]
#[ignore]
fn ip_filter_cidr_classification() {
    let mut trie = PrefixTrie::new();
    for cidr in [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "54.239.0.0/16",
        "35.184.0.0/13",
        "2001:db8::/32",
        "2a02:1234::/32",
        "2606:4700::/32",
    ] {
        trie.insert_cidr(cidr.as_bytes(), Action::Deny).unwrap();
    }
    let ips4: [&[u8]; 6] =
        [b"192.168.1.50", b"10.200.1.1", b"172.20.5.10", b"54.239.10.20", b"8.8.8.8", b"1.1.1.1"];
    let ips6: [&[u8]; 6] = [
        b"2001:db8::1",
        b"2001:db8:1::5",
        b"2a02:1234::9",
        b"fe80::1",
        b"::1",
        b"2606:4700::1111",
    ];
    for (workload, ips, zig) in
        [("ipv4_cidr_classification", ips4, 44.9), ("ipv6_cidr_classification", ips6, 87.6)]
    {
        let rust = measure(200_000, |iterations| {
            let mut found = 0u64;
            for i in 0..iterations as usize {
                if let Some(action) = black_box(&trie).lookup_str(ips[i % ips.len()]) {
                    found = found.wrapping_add(*action as u64);
                }
            }
            found
        });
        report("ip_filter", workload, rust, zig);
    }
}

#[test]
#[ignore]
fn engine_heap_size() {
    let engine = Engine::new(16);
    println!("engine heap bytes: {}", engine.heap_bytes());
    println!("engine value bytes: {}", size_of::<Engine>());
}
