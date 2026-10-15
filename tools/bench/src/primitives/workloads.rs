//! The sixteen workloads of the Zig benchmark (`benchmarks/benchmark.zig`), with the same
//! inputs, iteration counts and order, measured through the public APIs of the Rust crates.

use std::hint::black_box;

use sibuna_challenge::token::{Payload, WorkLevel, ed25519, mac};
use sibuna_challenge::{Keys, Seed, fingerprint_keyed};
use sibuna_cidr::PrefixTrie;
use sibuna_crypto::ed25519::SigningKey;
use sibuna_crypto::wyhash;
use sibuna_patterns::{Automaton, Options};
use sibuna_policy::bots::{AI_SCRAPERS, SCRAPER_LIBRARIES, SEARCH_CRAWLERS};
use sibuna_policy::{Action, Engine, Header, Mode, Modes, RequestView};
use sibuna_pow::{hashcash, posw};
use sibuna_store::limiter::{DEFAULT_SCOPE, Limits, RateLimiter};
use sibuna_store::placement::{ClientHash, ClientHasher};
use sibuna_store::spent::{SpentSet, Tag};

use super::{Run, Sizes, measure};

/// The challenge of the proof-of-work rows.
const CHALLENGE: &[u8] = b"AQEQEAAAAAAAAAAAsibuna-benchmark-challenge-identifier-0000000000000";

/// The User-Agents of the bot matcher rows.
const TEST_UAS: [&[u8]; 6] = [
    b"Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    b"Mozilla/5.0 AppleWebKit/537.36 (compatible; ClaudeBot/1.0)",
    b"Mozilla/5.0 (Linux; Android 10) Bytespider; spider-feedback@bytedance",
    b"python-requests/2.31.0",
    b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/128.0.0.0",
    b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Safari/604.1",
];

/// The client addresses of the IPv4 filter and rate limiter rows.
const TEST_IPS: [&[u8]; 6] =
    [b"192.168.1.50", b"10.200.1.1", b"172.20.5.10", b"54.239.10.20", b"8.8.8.8", b"1.1.1.1"];

/// The client addresses of the IPv6 filter row.
const TEST_IPS6: [&[u8]; 6] =
    [b"2001:db8::1", b"2001:db8:1::5", b"2a02:1234::9", b"fe80::1", b"::1", b"2606:4700::1111"];

/// The request of the HTTP parser and policy engine rows.
const RAW_REQUEST: &[u8] = b"GET /api/v1/data?page=2 HTTP/1.1\r\nHost: example.com\r\n\
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/128.0 Safari/537.36\r\n\
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
    Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\n\
    Cookie: __sibuna_token=v1_YWJjZGVmZ2hpams; session=xyz123\r\n\r\n";

/// Runs every workload in the order of the Zig benchmark and returns the rows and the sizes
/// of the engine and its tables.
pub fn run_all() -> (Vec<Run>, Sizes) {
    let mut runs = Vec::with_capacity(16);
    proof_of_work(&mut runs);
    let bot_table_bytes = bot_matcher(&mut runs);
    ip_filter(&mut runs);
    tokens(&mut runs);
    state(&mut runs);
    let mut sizes = http_and_policy(&mut runs);
    sizes.bot_table_bytes = bot_table_bytes;
    (runs, sizes)
}

fn proof_of_work(runs: &mut Vec<Run>) {
    let nonce = hashcash::solve_bits(CHALLENGE, 16, 1 << 32);
    let nonce = nonce.unwrap_or_else(|| unreachable!("the fixed challenge has a 16-bit nonce"));
    let timing = measure(
        200_000,
        || (),
        |(), n| {
            let mut ok = 0;
            for _ in 0..n {
                ok += u64::from(hashcash::verify_bits(black_box(CHALLENGE), black_box(nonce), 16));
            }
            ok
        },
    );
    runs.push(Run::new("pow_verify", "hashcash_16_bits", timing));

    let mut workspace = Box::new(posw::Workspace::new());
    let params = posw::Params { depth: 13, challenges: 16 };
    let proof = posw::solve(CHALLENGE, params, &mut workspace);
    let proof = proof.unwrap_or_else(|_| unreachable!("depth 13 with 16 openings is valid"));
    let timing = measure(
        20_000,
        || (),
        |(), n| {
            let mut ok = 0;
            for _ in 0..n {
                ok += u64::from(posw::verify(
                    black_box(CHALLENGE),
                    black_box(params),
                    black_box(proof),
                ));
            }
            ok
        },
    );
    runs.push(Run::new("pow_verify", "posw_depth13_t16", timing));
}

/// The 40 signatures of the bot matcher rows, in the Zig order.
fn signatures() -> impl Iterator<Item = &'static str> {
    AI_SCRAPERS.iter().chain(&SCRAPER_LIBRARIES).chain(&SEARCH_CRAWLERS).copied()
}

/// Measures both bot matcher rows and returns the automaton's table size in bytes.
fn bot_matcher(runs: &mut Vec<Run>) -> usize {
    let options = Options { ascii_case_insensitive: true, ..Options::default() };
    let automaton = Automaton::from_patterns(options, signatures().map(|s| (s.as_bytes(), 0)));
    let automaton =
        automaton.unwrap_or_else(|e| unreachable!("the built-in signatures compile: {e}"));
    let timing = measure(
        200_000,
        || (),
        |(), n| {
            let mut hits = 0;
            for i in 0..n as usize {
                hits += u64::from(
                    black_box(&automaton).find_first(TEST_UAS[i % TEST_UAS.len()]).is_some(),
                );
            }
            hits
        },
    );
    runs.push(Run::new("bot_matcher", "aho_corasick_40_signatures", timing));

    let patterns: Vec<&[u8]> = signatures().map(str::as_bytes).collect();
    let timing = measure(
        200_000,
        || (),
        |(), n| {
            let mut hits = 0;
            for i in 0..n as usize {
                let ua = TEST_UAS[i % TEST_UAS.len()];
                let found = black_box(&patterns).iter().any(|p| find_ignore_case(ua, p).is_some());
                hits += u64::from(found);
            }
            hits
        },
    );
    let mut naive = Run::new("bot_matcher", "sequential_substring_40_signatures", timing);
    naive.implementation = "sibuna-naive".to_owned();
    runs.push(naive);
    automaton.heap_bytes()
}

/// Zig 0.16 `std.ascii.findIgnoreCase`: Boyer-Moore-Horspool for haystacks of at least 52
/// bytes and needles longer than four, a linear scan otherwise. The naive bot matcher row
/// uses it so that both implementations do the same work.
fn find_ignore_case(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    if needle.is_empty() {
        return Some(0);
    }
    let end = haystack.len() - needle.len();
    if haystack.len() < 52 || needle.len() <= 4 {
        return (0..=end).find(|&i| haystack[i..i + needle.len()].eq_ignore_ascii_case(needle));
    }
    let mut skip = [needle.len(); 256];
    for (i, &byte) in needle[..needle.len() - 1].iter().enumerate() {
        skip[usize::from(byte.to_ascii_lowercase())] = needle.len() - 1 - i;
    }
    let mut i = 0;
    while i <= end {
        if haystack[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(i);
        }
        i += skip[usize::from(haystack[i + needle.len() - 1].to_ascii_lowercase())];
    }
    None
}

fn ip_filter(runs: &mut Vec<Run>) {
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
        let inserted = trie.insert_cidr(cidr.as_bytes(), Action::Deny);
        inserted.unwrap_or_else(|e| unreachable!("{cidr} is a valid prefix: {e}"));
    }
    for (workload, ips) in
        [("ipv4_cidr_classification", TEST_IPS), ("ipv6_cidr_classification", TEST_IPS6)]
    {
        let timing = measure(
            200_000,
            || (),
            |(), n| {
                let mut found = 0u64;
                for i in 0..n as usize {
                    if let Some(action) = black_box(&trie).lookup_str(ips[i % ips.len()]) {
                        found = found.wrapping_add(*action as u64);
                    }
                }
                found
            },
        );
        runs.push(Run::new("ip_filter", workload, timing));
    }
}

fn tokens(runs: &mut Vec<Run>) {
    let keys = Keys::derive(&Seed::new([0x42; 32]));
    let now = 1_725_700_000;
    let fp = fingerprint_keyed(&keys.fingerprint, b"203.0.113.195", b"Chrome/128");
    let payload = Payload {
        timestamp: now,
        expiry: now + 7200,
        rule_hash: 1,
        client_fingerprint: fp,
        work: WorkLevel { algorithm: 0, bits: 16 },
    };
    let token = mac::mint(&keys.token, &payload);
    let timing = measure(
        200_000,
        || (),
        |(), n| {
            let mut sum = 0u64;
            for _ in 0..n {
                let verified = mac::verify(
                    black_box(&keys.token),
                    black_box(token.as_bytes()),
                    now,
                    Some(fp),
                );
                sum = sum.wrapping_add(verified.map_or(0, |p| p.expiry));
            }
            sum
        },
    );
    runs.push(Run::new("token_auth", "blake3_mac_token", timing));

    let key_pair = SigningKey::from_seed(&keys.ed25519_seed);
    let public = key_pair.verifying_key();
    let token = ed25519::mint(&key_pair, &payload);
    let timing = measure(
        10_000,
        || (),
        |(), n| {
            let mut sum = 0u64;
            for _ in 0..n {
                let verified = ed25519::verify(
                    black_box(&public),
                    black_box(token.as_bytes()),
                    now,
                    Some(fp),
                );
                sum = sum.wrapping_add(verified.map_or(0, |p| p.expiry));
            }
            sum
        },
    );
    runs.push(Run::new("token_auth", "ed25519_compact_token", timing));
}

/// The spent-set tag of operation `i`: two Wyhash values of its native-endian bytes.
fn spent_tag(i: u64) -> Tag {
    let mut tag = [0; 16];
    tag[..8].copy_from_slice(&wyhash::hash(1, &i.to_ne_bytes()).to_le_bytes());
    tag[8..].copy_from_slice(&wyhash::hash(2, &i.to_ne_bytes()).to_le_bytes());
    tag
}

fn state(runs: &mut Vec<Run>) {
    let timing = measure(
        40_000,
        || Box::new(SpentSet::new()),
        |set, n| {
            let mut spent = 0;
            for i in 0..n {
                let tag = spent_tag(i);
                let inserted = set.mark_spent(&tag, 200_000, 100);
                assert!(inserted.is_ok(), "spent benchmark insertion failed");
                spent += u64::from(set.is_spent(&tag, 150));
            }
            spent
        },
    );
    runs.push(Run::new("challenge_store", "robin_hood_spend_and_lookup", timing));

    let limits = Limits { rate: 100, window_ms: 10_000 };
    let timing = measure(
        200_000,
        || Box::new(RateLimiter::new()),
        |limiter, n| {
            let mut limited = 0;
            for i in 0..n {
                let ip = TEST_IPS[(i % TEST_IPS.len() as u64) as usize];
                limited += u64::from(limiter.check(ip, 10_000 + i, limits).limited);
            }
            limited
        },
    );
    runs.push(Run::new("rate_limiter", "gcra_check", timing));

    let timing = measure(
        200_000,
        || Box::new(RateLimiter::new()),
        |limiter, n| {
            let mut limited = 0;
            let count = TEST_IPS.len() as u64;
            for i in 0..n {
                let ip = TEST_IPS[(i % count) as usize];
                let result = limiter.check_scoped(ip, 1 + (i / count) % 4, 10_000 + i, limits);
                limited += u64::from(result.limited);
            }
            limited
        },
    );
    runs.push(Run::new("rate_limiter", "gcra_four_rule_scopes", timing));
    hashed_gcra(runs, limits);
}

/// The rows above measure the byte API Zig has (hashing each address); the daemon hashes a
/// client once per request and passes the hash (`check_hashed`), measured here with hashes
/// computed before the loop.
fn hashed_gcra(runs: &mut Vec<Run>, limits: Limits) {
    let hasher = ClientHasher::new();
    let hashes: Vec<ClientHash> = TEST_IPS.iter().map(|ip| hasher.hash(ip)).collect();
    let count = hashes.len() as u64;
    let timing = measure(
        200_000,
        || Box::new(RateLimiter::new()),
        |limiter, n| {
            let mut limited = 0;
            for i in 0..n {
                let client = hashes[(i % count) as usize];
                let result = limiter.check_hashed(client, DEFAULT_SCOPE, 10_000 + i, limits);
                limited += u64::from(result.limited);
            }
            limited
        },
    );
    runs.push(Run::new("rate_limiter", "gcra_check_hashed", timing));

    let timing = measure(
        200_000,
        || Box::new(RateLimiter::new()),
        |limiter, n| {
            let mut limited = 0;
            for i in 0..n {
                let client = hashes[(i % count) as usize];
                let scope = 1 + (i / count) % 4;
                limited +=
                    u64::from(limiter.check_hashed(client, scope, 10_000 + i, limits).limited);
            }
            limited
        },
    );
    runs.push(Run::new("rate_limiter", "gcra_four_rule_scopes_hashed", timing));
}

fn http_and_policy(runs: &mut Vec<Run>) -> Sizes {
    let timing = measure(
        200_000,
        || (),
        |(), n| {
            let mut total = 0u64;
            for _ in 0..n {
                let Ok(request) = sibuna_http::parse_request(black_box(RAW_REQUEST)) else {
                    continue;
                };
                if let Some(cookie) = request.cookie(b"__sibuna_token") {
                    total = total.wrapping_add(cookie.len() as u64);
                }
            }
            total
        },
    );
    runs.push(Run::new("http_parser", "zero_copy_request_and_cookie", timing));

    let request = sibuna_http::parse_request(RAW_REQUEST);
    let request = request.unwrap_or_else(|e| unreachable!("the fixed request parses: {e:?}"));
    let headers: Vec<Header<'_>> =
        request.headers().iter().map(|h| Header { name: h.name, value: h.value }).collect();
    // The engine parses the client address itself (`client_address: None`), as the Zig
    // engine parsed the text inside `evaluateRequest`, so both rows do the same work.
    let user_agent = request.header(b"user-agent").unwrap_or_default();
    let view = RequestView {
        query: request.query,
        headers: &headers,
        client_address: None,
        ..RequestView::new(request.path, b"203.0.113.7", user_agent)
    };
    let mut engine = Engine::new(16);
    let sizes = Sizes {
        engine_bytes: size_of::<Engine>() + engine.heap_bytes(),
        bot_table_bytes: 0,
        waf_table_bytes: engine.signatures().heap_bytes(),
    };
    let classify = |engine: &Engine, view: &RequestView<'_>, n: u64| {
        let mut sum = 0u64;
        for _ in 0..n {
            let decision = black_box(engine).evaluate(black_box(view));
            sum = sum.wrapping_add(decision.action as u64);
        }
        sum
    };
    let timing = measure(100_000, || (), |(), n| classify(&engine, &view, n));
    runs.push(Run::new("policy_engine", "browser_request_full_classification", timing));
    engine.waf_enabled = false;
    let timing = measure(100_000, || (), |(), n| classify(&engine, &view, n));
    runs.push(Run::new("policy_engine", "browser_request_gate_profile", timing));
    engine.waf_enabled = true;

    let filler = b"the quick brown fox jumps over the lazy dog, and the form holds a note. ";
    let body: Vec<u8> = (0..8192).map(|i| filler[i % filler.len()]).collect();
    let scan = RequestView {
        body: &body,
        ..RequestView::new(b"/submit", b"203.0.113.7", b"Mozilla/5.0")
    };
    let timing = measure(5_000, || (), |(), n| classify(&engine, &scan, n));
    let mut row = Run::new("waf_inspect", "8kb_body_semantic_scan", timing);
    row.bytes_per_op = body.len() as u64;
    runs.push(row);
    engine.inspection_modes = Modes { sqli: Mode::Audit, ..Modes::default() };
    let timing = measure(5_000, || (), |(), n| classify(&engine, &scan, n));
    let mut row = Run::new("waf_inspect", "8kb_body_sqli_audit_other_enforce", timing);
    row.bytes_per_op = body.len() as u64;
    runs.push(row);
    sizes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_ignore_case_agrees_with_a_naive_search() {
        let haystack = b"Mozilla/5.0 (Linux; Android 10) Bytespider; spider-feedback@bytedance";
        for needle in
            [&b"bytespider"[..], b"BYTEDANCE", b"spider-feedback", b"moz", b"absent", b"", b"e"]
        {
            let naive = (0..=haystack.len().saturating_sub(needle.len()))
                .find(|&i| haystack[i..i + needle.len()].eq_ignore_ascii_case(needle));
            assert_eq!(find_ignore_case(haystack, needle), naive, "{needle:?}");
        }
        assert_eq!(find_ignore_case(b"ab", b"abc"), None);
    }

    #[test]
    fn spent_tags_differ_per_operation() {
        assert_ne!(spent_tag(0), spent_tag(1));
        assert_eq!(signatures().count(), 40);
    }
}
