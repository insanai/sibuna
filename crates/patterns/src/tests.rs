//! Tests of the whole crate: the Zig suite, capacity limits, and cross-checks of every scan
//! against a naive search.

use crate::{Automaton, BuildError, Builder, Match, Options, PatternId, TagSet};

/// Options of the Zig automaton: always case-insensitive, with a fixed state capacity.
fn zig_options(max_states: usize) -> Options {
    Options { ascii_case_insensitive: true, max_states, max_patterns: max_states }
}

fn name(automaton: &Automaton, found: Option<Match>) -> Option<&str> {
    found.map(|m| std::str::from_utf8(automaton.pattern(m.pattern)).unwrap())
}

/// SplitMix64: a small deterministic generator for the randomised tests.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Returns a value in `0..=max`.
    fn at_most(&mut self, max: usize) -> usize {
        (self.next() % (max as u64 + 1)) as usize
    }

    fn text(&mut self, alphabet: &[u8], max_len: usize) -> Vec<u8> {
        let len = self.at_most(max_len);
        (0..len).map(|_| alphabet[self.at_most(alphabet.len() - 1)]).collect()
    }
}

// Ported from aho_corasick.zig: "tag selection retains overlapping suffix matches and skips
// unselected outputs".
#[test]
fn tag_selection_retains_overlapping_suffix_matches_and_skips_unselected_outputs() {
    let mut builder = Builder::new(zig_options(16));
    builder.add(b"aab", 1).unwrap();
    builder.add(b"ab", 2).unwrap();
    builder.add(b"cd", 3).unwrap();
    let matcher = builder.build();
    assert_eq!(name(&matcher, matcher.find_first_tagged(b"AABcd", 2)), Some("ab"));
    assert_eq!(name(&matcher, matcher.find_first_tagged(b"aabcd", 3)), Some("cd"));
    assert_eq!(matcher.find_first_tagged(b"aabcd", 4), None);
}

// Ported from aho_corasick.zig: "aho corasick matches substrings case-insensitively with
// tags".
#[test]
fn matches_substrings_case_insensitively_with_tags() {
    let mut builder = Builder::new(zig_options(2048));
    builder.add(b"GPTBot", 1).unwrap();
    builder.add(b"ClaudeBot", 1).unwrap();
    builder.add(b"python-requests", 2).unwrap();
    let matcher = builder.build();

    let ua1 = b"Mozilla/5.0 (compatible; gptbot/1.2; +https://openai.com/gptbot)";
    let m1 = matcher.find_first(ua1).unwrap();
    assert_eq!(name(&matcher, Some(m1)), Some("GPTBot"));
    assert_eq!(m1.tag, 1);

    let ua2 = b"Python-Requests/2.28.1";
    assert_eq!(name(&matcher, matcher.find_first(ua2)), Some("python-requests"));
    assert_eq!(matcher.find_first(ua2).unwrap().tag, 2);

    let ua3 = b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
    assert_eq!(matcher.find_first(ua3), None);
}

// Ported from aho_corasick.zig: "aho corasick agrees with naive search on random inputs".
// The Zig test sized the automaton like the bot matcher; any capacity of at least one plus
// the total pattern length behaves the same.
#[test]
fn agrees_with_naive_search_on_random_inputs() {
    let patterns: [&[u8]; 7] = [b"he", b"she", b"his", b"hers", b"bot", b"curl/", b"xyz"];
    let capacity = 1 + patterns.iter().map(|p| p.len()).sum::<usize>();
    let mut builder = Builder::new(zig_options(capacity));
    for pattern in patterns {
        builder.add(pattern, 0).unwrap();
    }
    let matcher = builder.build();
    let mut rng = Rng(42);
    for _ in 0..2000 {
        let text = rng.text(b"hersibotcurl/XYZ ", 48);
        let naive = patterns.iter().any(|p| contains_ignore_case(&text, p));
        assert_eq!(naive, matcher.find_first(&text).is_some(), "text {text:?}");
        assert_eq!(naive, matcher.is_match(&text));
    }
}

fn contains_ignore_case(text: &[u8], pattern: &[u8]) -> bool {
    text.windows(pattern.len()).any(|w| w.eq_ignore_ascii_case(pattern))
}

#[test]
fn capacity_limits_fail_like_zig_and_leave_the_builder_unchanged() {
    let mut builder = Builder::new(zig_options(4));
    assert_eq!(builder.add(b"", 0), Err(BuildError::EmptyPattern));
    assert_eq!(builder.add(b"a", 64), Err(BuildError::TagOutOfRange(64)));
    builder.add(b"abc", 0).unwrap();
    assert_eq!(builder.state_count(), 4);
    assert_eq!(builder.add(b"abd", 0), Err(BuildError::TooManyStates));
    assert_eq!(builder.state_count(), 4);
    // Prefixes of existing patterns need no new state.
    assert_eq!(builder.add(b"AB", 5), Ok(PatternId(1)));
    builder.add(b"a", 6).unwrap();
    builder.add(b"ab", 5).unwrap();
    assert_eq!(builder.add(b"abc", 7), Err(BuildError::TooManyPatterns));
    let matcher = builder.build();
    assert_eq!(matcher.pattern_count(), 4);
    assert_eq!(matcher.find_first(b"xxabd").map(|m| m.tag), Some(6));
    assert_eq!(matcher.all_tags(), TagSet { bits: (1 << 0) | (1 << 5) | (1 << 6) });
}

#[test]
fn empty_automaton_and_empty_haystack_never_match() {
    let empty = Builder::new(Options::default()).build();
    assert_eq!(empty.state_count(), 1);
    assert!(!empty.is_match(b"anything"));
    assert_eq!(empty.find_first(b"anything"), None);
    assert!(empty.tags(b"anything").is_empty());
    assert_eq!(empty.matches(b"anything").count(), 0);
    let some = Automaton::from_patterns(Options::default(), [(&b"a"[..], 1)]).unwrap();
    assert!(!some.is_match(b""));
    assert_eq!(some.matches(b"").count(), 0);
}

#[test]
fn byte_classes_shrink_rows_and_respect_the_case_option() {
    let pairs = [(&b"GET"[..], 0), (&b"get"[..], 1), (&b"\xc3\xa9t\xc3\xa9"[..], 2)];
    let exact = Automaton::from_patterns(Options::default(), pairs).unwrap();
    // G E T g e t 0xc3 0xa9 and one class for every other byte.
    assert_eq!(exact.class_count(), 9);
    assert_eq!(exact.find_first(b"xGeT get").map(|m| m.tag), Some(1));
    assert_eq!(exact.find_first(b"\xc3\x89t\xc3\xa9"), None);
    let options = Options { ascii_case_insensitive: true, ..Options::default() };
    let folded = Automaton::from_patterns(options, pairs).unwrap();
    assert_eq!(folded.class_count(), 6);
    assert!(folded.is_ascii_case_insensitive());
    // Equal under folding: the first added wins, and the iterator reports both.
    assert_eq!(folded.find_first(b"xGeT").map(|m| m.tag), Some(0));
    let all: Vec<u8> = folded.matches(b"gEt").map(|m| m.tag).collect();
    assert_eq!(all, [0, 1]);
    assert_eq!(folded.pattern(PatternId(0)), b"GET");
}

#[test]
fn matches_reports_overlapping_occurrences_in_order() {
    let pairs = [(&b"he"[..], 0), (&b"she"[..], 1), (&b"his"[..], 2), (&b"hers"[..], 3)];
    let matcher = Automaton::from_patterns(Options::default(), pairs).unwrap();
    let found: Vec<(u8, usize, usize)> =
        matcher.matches(b"ushers").map(|m| (m.tag, m.start, m.end)).collect();
    assert_eq!(found, [(1, 1, 4), (0, 2, 4), (3, 2, 6)]);
    assert_eq!(matcher.tags(b"ushers"), TagSet { bits: 0b1011 });
    assert_eq!(matcher.find_first_tagged(b"ushers", 3).map(|m| m.start), Some(2));
}

/// Every occurrence by brute force, in the order `Automaton::matches` promises.
fn naive_matches(patterns: &[(Vec<u8>, u8)], text: &[u8], fold: bool) -> Vec<Match> {
    let equal = |a: &[u8], b: &[u8]| if fold { a.eq_ignore_ascii_case(b) } else { a == b };
    let mut found = Vec::new();
    for end in 1..=text.len() {
        let mut here: Vec<Match> = patterns
            .iter()
            .enumerate()
            .filter(|(_, (p, _))| p.len() <= end && equal(&text[end - p.len()..end], p))
            .map(|(id, (p, tag))| Match {
                pattern: PatternId(id as u32),
                tag: *tag,
                start: end - p.len(),
                end,
            })
            .collect();
        here.sort_by_key(|m| (std::cmp::Reverse(m.end - m.start), m.pattern));
        found.extend(here);
    }
    found
}

fn check_against_naive(automaton: &Automaton, patterns: &[(Vec<u8>, u8)], text: &[u8]) {
    let fold = automaton.is_ascii_case_insensitive();
    let expected = naive_matches(patterns, text, fold);
    let actual: Vec<Match> = automaton.matches(text).collect();
    assert_eq!(actual, expected, "text {text:?} patterns {patterns:?}");
    assert_eq!(automaton.find_first(text), expected.first().copied());
    assert_eq!(automaton.is_match(text), !expected.is_empty());
    let tags = expected.iter().fold(TagSet::EMPTY, |set, m| set | TagSet { bits: 1 << m.tag });
    assert_eq!(automaton.tags(text), tags);
    for tag in 0..5 {
        let first = expected.iter().find(|m| m.tag == tag).copied();
        assert_eq!(automaton.find_first_tagged(text, tag), first);
    }
}

#[test]
fn every_scan_agrees_with_a_naive_search() {
    let mut rng = Rng(7);
    for round in 0..400 {
        let fold = round % 2 == 0;
        let count = 1 + rng.at_most(8);
        let patterns: Vec<(Vec<u8>, u8)> = (0..count)
            .map(|_| {
                let mut pattern = rng.text(b"abAB\xff", 5);
                if pattern.is_empty() {
                    pattern.push(b'a');
                }
                (pattern, rng.at_most(4) as u8)
            })
            .collect();
        let capacity = 1 + patterns.iter().map(|(p, _)| p.len()).sum::<usize>();
        let options =
            Options { ascii_case_insensitive: fold, max_states: capacity, ..Options::default() };
        let pairs = patterns.iter().map(|(p, tag)| (p.as_slice(), *tag));
        let automaton = Automaton::from_patterns(options, pairs).unwrap();
        for _ in 0..20 {
            let text = rng.text(b"abAB\xffc", 40);
            check_against_naive(&automaton, &patterns, &text);
        }
    }
}

/// Signatures for the measurement: the bot list and a sample of the WAF list of Sibuna.
const SIGNATURES: &[&str] = &[
    "GPTBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Claude-Web",
    "anthropic-ai",
    "Bytespider",
    "CCBot",
    "Diffbot",
    "FacebookBot",
    "Google-Extended",
    "PerplexityBot",
    "Omgilibot",
    "Applebot-Extended",
    "Amazonbot",
    "cohere-ai",
    "Timpibot",
    "YouBot",
    "DataForSeoBot",
    "python-requests",
    "aiohttp",
    "httpx",
    "urllib",
    "Scrapy",
    "curl/",
    "Wget/",
    "Go-http-client",
    "Java/",
    "libwww-perl",
    "node-fetch",
    "Axios",
    "PostmanRuntime",
    "HeadlessChrome",
    "PhantomJS",
    "Selenium",
    "Puppeteer",
    "../",
    "..\\",
    "..%2f",
    "%2e%2e",
    "/etc/passwd",
    "/proc/self",
    "win.ini",
    "union select",
    "information_schema",
    "sleep(",
    "benchmark(",
    "into outfile",
    "xp_cmdshell",
    "pg_sleep(",
    "waitfor delay",
    "' or '1'='1",
    "@@version",
    "<script",
    "</script",
    "javascript:",
    "vbscript:",
    "<iframe",
    "document.cookie",
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
    "${jndi:",
    "__import__(",
    "os.system",
    "processbuilder",
];

/// Words of ordinary request text that match none of `SIGNATURES`.
const WORDS: &[&str] = &[
    "Mozilla/5.0",
    "AppleWebKit/537.36",
    "text/html",
    "application/json",
    "the",
    "quick",
    "Accept-Language:",
    "en-US,en;q=0.9",
    "session=abc123",
    "Chrome/128.0.0.0",
    "SELECT",
    "user_id=42",
    "path/to/resource",
    "gzip, deflate",
    "lorem",
    "ipsum",
    "dolor",
    "%20",
];

/// Measures scan throughput over 8 KiB of mixed text with the bot and WAF signature sets.
/// Run with `cargo test -p sibuna-patterns --release -- --ignored --nocapture throughput`.
#[test]
#[ignore = "measurement; run in release mode"]
fn throughput() {
    use std::hint::black_box;
    use std::time::Instant;

    let options = Options { ascii_case_insensitive: true, ..Options::default() };
    let pairs = SIGNATURES.iter().enumerate().map(|(i, s)| (s.as_bytes(), (i % 4) as u8));
    let automaton = Automaton::from_patterns(options, pairs).unwrap();

    let mut rng = Rng(1);
    let mut text = Vec::with_capacity(8192);
    while text.len() < 8192 {
        text.extend_from_slice(WORDS[rng.at_most(WORDS.len() - 1)].as_bytes());
        text.push(b' ');
    }
    text.truncate(8192);
    assert!(!automaton.is_match(&text), "the measurement text must not match");

    let rounds = 20_000;
    let measure = |label: &str, scan: &dyn Fn(&[u8]) -> usize| {
        let start = Instant::now();
        let mut sink = 0;
        for _ in 0..rounds {
            sink += scan(black_box(&text));
        }
        let seconds = start.elapsed().as_secs_f64();
        let megabytes = (rounds * text.len()) as f64 / 1e6;
        println!(
            "{label}: {:.0} MB/s ({:.2} ns/byte)",
            megabytes / seconds,
            seconds * 1e9 / (megabytes * 1e6)
        );
        black_box(sink);
    };
    println!(
        "{} patterns, {} states, {} classes, {} heap bytes",
        automaton.pattern_count(),
        automaton.state_count(),
        automaton.class_count(),
        automaton.heap_bytes()
    );
    measure("is_match", &|t| usize::from(automaton.is_match(t)));
    measure("tags", &|t| automaton.tags(t).bits as usize);
    measure("matches", &|t| automaton.matches(t).count());
}
