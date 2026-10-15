use super::*;

#[test]
fn templates_compile_into_bounded_segments_and_render_escaped_values() {
    let template =
        Template::compile(Kind::Denied, b"<p>Blocked: {{ reason }} ({{ status }})</p>").unwrap();
    assert_eq!(template.segments.len(), 5);
    let values = Values { status: 403, reason: "<waf:sqli>", ..Values::default() };
    let mut out = Vec::new();
    template.write(&mut out, &values).unwrap();
    assert_eq!(out, b"<p>Blocked: &lt;waf:sqli&gt; (403)</p>");
    assert_eq!(template.measure(&values), out.len());
}

#[test]
fn validation_refuses_script_handlers_external_resources_and_misplaced_placeholders() {
    let cases: [(&[u8], PageError); 11] = [
        (b"<ScRiPt>x</script>", PageError::ForbiddenContent),
        (b"<a onclick=\"x\">y</a>", PageError::ForbiddenAttribute),
        (b"<meta http-equiv=\"refresh\">", PageError::ForbiddenAttribute),
        (b"<img src=\"https://evil/x.png\">", PageError::ExternalReference),
        (b"<img src=\"//evil/x.png\">", PageError::ExternalReference),
        (b"<a href=\"javascript:alert(1)\">x</a>", PageError::ForbiddenContent),
        (b"<p style=\"background:url(x)\">", PageError::ForbiddenContent),
        (b"<p>{{ secret }}</p>", PageError::UnknownPlaceholder),
        (b"<p title=\"{{ status }}\">", PageError::PlaceholderInTag),
        (b"<p>{{ challenge }}</p>", PageError::ChallengeSlotForbidden),
        (b"<p>{{ status", PageError::UnknownPlaceholder),
    ];
    for (source, error) in cases {
        assert_eq!(Template::compile(Kind::Denied, source), Err(error), "{source:?}");
    }
    assert_eq!(
        Template::compile(Kind::Challenge, b"<p>no slot</p>"),
        Err(PageError::ChallengeSlotRequired)
    );
    assert!(Template::compile(Kind::Challenge, b"<p>{{ challenge }}</p>").is_ok());
    assert!(
        Template::compile(
            Kind::Denied,
            b"<img src=\"/logo.png\" alt=\"\"><a href=\"#top\">top</a>"
        )
        .is_ok()
    );
    let too_large = vec![b'x'; MAX_BYTES + 1];
    assert_eq!(Template::compile(Kind::Denied, &too_large), Err(PageError::TooLarge));
    let many = "a{{ node }}".repeat(20);
    assert_eq!(Template::compile(Kind::Denied, many.as_bytes()), Err(PageError::TooManySegments));
    assert_eq!(Template::compile(Kind::Denied, b"a\xffb"), Err(PageError::InvalidUtf8));
    assert_eq!(Template::compile(Kind::Denied, b"a\x00b"), Err(PageError::InvalidUtf8));
}

#[test]
fn defaults_compile_for_every_kind_and_mark_themselves_as_not_customized() {
    let pages = Pages::defaults("<html><body>{{ challenge }}</body></html>").unwrap();
    for kind in Kind::ALL {
        let page = pages.page(kind);
        assert!(!page.customized && !page.segments.is_empty() && page.revision == 0);
    }
    let values = Values { status: 429, retry_after: 30, ..Values::default() };
    assert!(pages.page(Kind::RateLimited).measure(&values) > 100);
    assert_eq!(Pages::builtin().page(Kind::Challenge).source(), DEFAULT_CHALLENGE_MINIMAL);
    assert_eq!(Pages::defaults("<p>none</p>"), Err(PageError::ChallengeSlotRequired));
}

#[test]
fn kinds_round_trip_their_names() {
    for kind in Kind::ALL {
        assert_eq!(Kind::parse(kind.name().as_bytes()), Some(kind));
    }
    assert_eq!(Kind::parse(b"Denied"), None);
}

#[test]
fn challenge_slot_is_written_without_escaping() {
    let template = Template::compile(Kind::Challenge, b"<div>{{challenge}}</div>").unwrap();
    let values =
        Values { challenge: "<script src=\"/__sibuna/s.js\"></script>", ..Values::default() };
    let mut out = Vec::new();
    template.write(&mut out, &values).unwrap();
    assert_eq!(out, b"<div><script src=\"/__sibuna/s.js\"></script></div>");
}

/// Deterministic mutation fuzz of the markup validator and the template compiler: no panic,
/// linear work, and every accepted template renders without a placeholder left over.
#[test]
fn markup_validator_survives_mutated_templates() {
    let seeds: [&[u8]; 6] = [
        DEFAULT_DENIED.as_bytes(),
        DEFAULT_CHALLENGE_MINIMAL.as_bytes(),
        b"<p style=\"color:red\" aria-x=\"1\">a</p><style>p{}</style><img src=\"/a\" alt=\"\">",
        b"<button disabled>x</button><br/><a href=\"#x\">y</a>",
        b"<title>t</title><svg viewbox=\"0 0 1 1\"><path d=\"M0\"/></svg>",
        b"<!doctype html><h1 title=\"a > b\">{{ reason }}</h1>",
    ];
    let mut state = 0x6a09_e667_f3bc_c909u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let alphabet = b"<>/\"'= {}-:;&\\#!xa\t\n";
    for round in 0..100_000 {
        let seed = seeds[round % seeds.len()];
        let mut text = seed.to_vec();
        for _ in 0..1 + next() % 4 {
            let at = (next() as usize) % (text.len() + 1);
            match next() % 5 {
                0 if !text.is_empty() => {
                    let at = at.min(text.len() - 1);
                    text[at] = alphabet[(next() as usize) % alphabet.len()];
                }
                1 => text.insert(at, alphabet[(next() as usize) % alphabet.len()]),
                2 if at < text.len() => {
                    text.remove(at);
                }
                3 => text.truncate(at),
                _ => {
                    let other = seeds[(next() as usize) % seeds.len()];
                    let from = (next() as usize) % other.len();
                    text.splice(at..at, other[from..].iter().copied().take(40));
                }
            }
        }
        crate::steps::take();
        let result = Template::compile(Kind::Denied, &text);
        assert!(crate::steps::take() <= 8 * (text.len() as u64 + 1));
        if let Ok(template) = result {
            let mut out = Vec::new();
            template
                .write(&mut out, &Values { reason: "r", request_id: "q", ..Values::default() })
                .unwrap();
            assert_eq!(
                out.len(),
                template.measure(&Values { reason: "r", request_id: "q", ..Values::default() })
            );
            assert!(validate_markup(&text).is_ok());
        }
    }
}
