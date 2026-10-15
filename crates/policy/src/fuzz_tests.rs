//! Deterministic, dependency-free fuzz tests: a xorshift generator mutates (byte flips,
//! insertions, deletions, truncation, duplication, splicing) seeds of real payloads,
//! requests and policy files. Every input must be handled without a panic, within a work
//! budget proportional to its length, and with the invariants below.

use crate::inspection::{self, Mode, Modes};
use crate::normalizer::{canonicalize, percent_decode};
use crate::rule::Header;
use crate::steps;
use crate::waf::{self, AttackCategory, Signatures};
use crate::{Diagnostic, Engine, RequestView, management, matchers};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const PAYLOADS: [&[u8]; 24] = [
    b"1'/**/UnIoN/**/SeLeCt/**/1",
    b"id=%27%20or%20%271%27=%271",
    b"/api/%252e%252e/%252e%252e/etc/passwd",
    b"<img%20src=x%20onerror=alert(1)>",
    b"<svg/onload=alert(1)>",
    b"x=$(cat /etc/hostname)",
    b"host=a && whoami",
    b"name='x' union all from t--",
    b"I'd select the second option -- it's cheaper",
    b"or 'a or \"b or 1=1",
    b"<a <b <svg <img onx=1",
    b"; ; ;\t\t  ;|| $( ``",
    b"%%%2%25%2525%41+",
    b"/*/*/**/ */ /*",
    b"text/html,application/xml;q=0.9,*/*;q=0.8",
    b"session=abc--def; theme=dark",
    b"\x00\xff\xfe%00",
    b"onboarding=1&alert(true)",
    b"a=1&id=5&type=x",
    b"\"or\" 1 = '1' and 2=2",
    b"${jndi:ldap://x}",
    b"{{7*7}} #{7*7}",
    b"  \t\r\n\x0b\x0c  ",
    b"the quick brown fox jumps over the lazy dog, and the form holds a note. ",
];

const ALPHABET: &[u8] = b"'\"`=<>;|&$%\x00+\t\r\n /*-#()onrmcatidslu0123456789aAzZ.\\_";

fn mutate(rng: &mut Rng, seeds: &[&[u8]], alphabet: &[u8]) -> Vec<u8> {
    let mut text = seeds[rng.below(seeds.len())].to_vec();
    for _ in 0..1 + rng.below(6) {
        let at = rng.below(text.len() + 1);
        match rng.below(7) {
            0 if !text.is_empty() => {
                let at = at.min(text.len() - 1);
                text[at] ^= 1 << rng.below(8);
            }
            1 => text.insert(at, alphabet[rng.below(alphabet.len())]),
            2 if at < text.len() => {
                text.remove(at);
            }
            3 if rng.below(4) == 0 => text.truncate(at),
            4 => {
                let other = seeds[rng.below(seeds.len())];
                let from = rng.below(other.len());
                let end = (from + rng.below(64)).min(other.len());
                text.splice(at..at, other[from..end].iter().copied());
            }
            5 if text.len() < 6000 => {
                // Duplication grows inputs, so super-linear work would show in the budget.
                let copy = text.clone();
                text.splice(at..at, copy);
            }
            _ => {}
        }
    }
    text
}

/// The work budget of one inspection of `len` bytes.
fn budget(len: usize) -> u64 {
    64 * (len as u64 + 1)
}

fn check_text(signatures: &Signatures, text: &[u8], sequential: bool) {
    steps::take();
    let fast = waf::inspect_text_with(signatures, text);
    let categories =
        AttackCategory::ALL.map(|category| waf::inspect_category(signatures, category, text));
    let mut buffer = vec![0u8; text.len()];
    let normalized = canonicalize(text, &mut buffer).len();
    assert!(normalized <= text.len());
    let decoded = percent_decode(text, &mut buffer).len();
    assert!(decoded <= text.len());
    assert!(steps::take() <= 8 * budget(text.len()), "{} bytes", text.len());
    match fast {
        Some(violation) => assert!(categories[violation.category.index()].is_some(), "{text:?}"),
        None => assert!(categories.iter().all(Option::is_none), "{text:?}"),
    }
    if sequential {
        assert_eq!(waf::inspect_text(text).is_some(), fast.is_some(), "{text:?}");
    }
}

#[test]
fn waf_and_normalizer_survive_mutated_payloads() {
    let signatures = Signatures::new();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..200_000 {
        let text = mutate(&mut rng, &PAYLOADS, ALPHABET);
        check_text(&signatures, &text, round % 32 == 0);
    }
}

const BODIES: [&[u8]; 5] = [
    b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\nContent-Type: \
        application/octet-stream\r\n\r\n\x00\r\n--b-fake\r\n\r\n--b\r\nContent-Disposition: \
        form-data; name=\"caption\"\r\n\r\nhello <script>x</script>\r\n--b--\r\n",
    b"--b\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\n1 UNION SELECT x\r\n--b\r\n",
    b"{\"comment\":\"I'd select the second option -- it's cheaper\"}",
    b"cmd=test; /bin/sh&x=1",
    b"\r\n--b--\r\n\r\n\r\n--b\r\n",
];

const CONTENT_TYPES: [&[u8]; 6] = [
    b"multipart/form-data; boundary=b",
    b"multipart/form-data; boundary=\"b\"; charset=x",
    b"application/json",
    b"image/png",
    b"multipart/form-data; boundary=b; boundary=b",
    b"text/plain; q=\"a\\\"b\"",
];

#[test]
fn request_inspection_survives_mutated_bodies_and_headers() {
    let engine = Engine::new(16);
    let mut mixed = Engine::new(16);
    mixed.inspection_modes = Modes { sqli: Mode::Audit, xss: Mode::Disabled, ..Modes::default() };
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..30_000 {
        let body = mutate(&mut rng, &BODIES, ALPHABET);
        let content_type = mutate(&mut rng, &CONTENT_TYPES, b"; =\"\\/abmx-");
        let value = mutate(&mut rng, &PAYLOADS, ALPHABET);
        let headers = [
            Header { name: b"Content-Type", value: &content_type },
            Header { name: b"X-Data", value: &value },
        ];
        let request = RequestView {
            headers: &headers,
            body: &body,
            ..RequestView::new(b"/a", b"1.2.3.4", b"ua")
        };
        steps::take();
        let decision = engine.evaluate(&request);
        let findings = inspection::inspect(engine.signatures(), mixed.inspection_modes, &request);
        let _ = mixed.evaluate(&request);
        let total = body.len().min(8192) + content_type.len() + value.len() + 8;
        assert!(steps::take() <= 24 * budget(total));
        let fields: usize =
            crate::body_fields::Fields::new(&headers, &body).map(<[u8]>::len).sum();
        assert!(fields <= body.len().min(8192));
        assert_eq!(
            decision.rule_name.starts_with("waf:"),
            waf::inspect_request(engine.signatures(), &request).is_some()
        );
        assert_eq!(findings.audited & inspection::bit(AttackCategory::Xss), 0);
    }
}

const POLICY_SEEDS: [&[u8]; 6] = [
    include_bytes!("../tests/data/differential/policy.json"),
    b"{\"default_action\":\"ALLOW\",\"rules\":[{\"name\":\"w\",\"headers\":{\"CF-Worker\":\".*\"}\
        ,\"action\":\"DENY\"},{\"name\":\"c\",\"path\":\"/c/*\",\"action\":\"CHALLENGE\",\"challe\
        nge\":{\"difficulty\":8,\"algorithm\":\"sha256\"}}],\"waf\":false,\"thresholds\":{\"deny_\
        at\":30},\"ip_rules\":{\"2001:db8::/32\":\"DENY\"}}",
    b"{\"inspection\":{\"sqli\":\"audit\",\"xss\":1},\"rules\":[{\"name\":[104,105],\"action\":\"\
        weigh\",\"weight\":\"1_0\",\"limits\":null}]}",
    b"{\"rules\":[{\"name\":\"x\",\"action\":\"deny\",\"limits\":{\"rate\":1e3,\"window_seconds\"\
        :\"60\",\"ban_seconds\":0.0}}]}",
    b"{\"id\":\"a\",\"name\":\"A\",\"action\":\"challenge\",\"headers\":{\"X\":\"y\"},\"cidrs\":\
        [\"::1\"],\"difficulty\":3,\"algorithm\":\"posw\",\"priority\":-1}",
    br#"["\u0041\ud83d\ude00", {"a":[{"b":null}]}, -0.5e+3, true, false, null]"#,
];

#[test]
fn loader_and_management_survive_mutated_documents() {
    let mut rng = Rng(0x6a09_e667_f3bc_c909);
    let alphabet = b"{}[]\",:0123456789 truefalsnul-.eE\\aAzZ/_x\xc3\xa9\xff\x01u";
    // Building the automata dominates a fresh engine; a clone copies them instead.
    let base = Engine::new(16);
    for _ in 0..100_000 {
        let text = mutate(&mut rng, &POLICY_SEEDS, alphabet);
        let mut engine = base.clone();
        let mut diagnostic = Diagnostic::default();
        match engine.apply_json(&text, &mut diagnostic) {
            Ok(()) => {
                assert_eq!(diagnostic, Diagnostic::default());
                assert!(engine.rule_count() <= crate::MAX_RULES);
                let _ = engine.evaluate(&RequestView::new(b"/c/x", b"10.1.2.3", b"curl"));
            }
            Err(error) => assert!(!error.explain().title.is_empty()),
        }
        if let Ok(document) = management::parse(&text) {
            assert!(!document.id.is_empty() && document.rule.headers.len() <= 4);
        }
        let _ = matchers::headers_from_json(&text);
        let _ = matchers::cidrs_from_json(&text);
        let _ = crate::Limits::from_json(&text);
    }
}

#[test]
fn integer_texts_never_panic_and_stay_in_range() {
    let mut rng = Rng(0x510e_527f_ade6_82d1);
    let seeds: [&[u8]; 6] =
        [b"12", b"-0", b"1e3", b"0x1.8p1", b"1_000.5e-1", b"99999999999999999999.0"];
    for _ in 0..100_000 {
        let text = mutate(&mut rng, &seeds, b"0123456789+-_.eEpPxX abcf");
        if let Ok(value) = crate::json::number_for_tests(&text, -1000, 1000) {
            assert!((-1000..=1000).contains(&value), "{text:?}");
        }
    }
}
