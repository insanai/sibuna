use super::*;

type Pair<'a> = (&'a [u8], &'a [u8]);

fn request(method: &str, path: &str, query: &str, headers: &[Pair<'_>], extra: &Extra) -> String {
    let line = RequestLine {
        method: method.as_bytes(),
        path: path.as_bytes(),
        query: query.as_bytes(),
        version: b"HTTP/1.1",
    };
    let mut out = [0; REQUEST_BYTES];
    let head = request_head(&line, headers.iter().copied(), extra, &mut out);
    assert!(!head.truncated);
    String::from_utf8(out[..head.len].to_vec()).unwrap()
}

#[test]
fn heads_keep_listed_values_redact_the_rest_and_query_values_and_flag_truncation() {
    let none = Extra::default();
    let headers: [Pair<'_>; 4] = [
        (b"Host", b"app.example"),
        (b"Cookie", b"sid=verysecret"),
        (b"X-Request-Token", b"abc"),
        (b"X-Custom", b"opaque"),
    ];
    let text = request("GET", "/login", "user=alice&token=xyz&flag", &headers, &none);
    assert_eq!(
        text,
        "GET /login?user=[redacted]&token=[redacted]&flag HTTP/1.1\r\n\
         Host: app.example\r\nCookie: [redacted]\r\nX-Request-Token: [redacted]\r\n\
         X-Custom: [redacted]\r\n"
    );
    assert!(!text.contains("verysecret"));

    let mut response = [0; RESPONSE_BYTES];
    let origin = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\nContent-Type: text/html\r\n\r\nbody";
    let tail = response_head(origin, &none, &mut response);
    assert_eq!(
        &response[..tail.len],
        b"HTTP/1.1 200 OK\r\nSet-Cookie: [redacted]\r\nContent-Type: text/html\r\n"
    );

    // A long credential value is redacted before it costs any of the bound, so a raw head
    // wider than the buffer still fits whole; truncation follows redaction, not the input.
    let wide = format!(
        "HTTP/1.1 101 Switching Protocols\r\nSet-Cookie: {}\r\nUpgrade: websocket\r\n\r\n",
        "c".repeat(3000)
    );
    let fits = response_head(wide.as_bytes(), &none, &mut response);
    assert!(!fits.truncated);
    assert_eq!(
        &response[..fits.len],
        b"HTTP/1.1 101 Switching Protocols\r\nSet-Cookie: [redacted]\r\nUpgrade: websocket\r\n"
    );

    let long = [b'a'; 4000];
    let big: [Pair<'_>; 1] = [(b"User-Agent", &long)];
    let line = RequestLine { method: b"GET", path: b"/", query: b"", version: b"HTTP/1.1" };
    let mut out = [0; REQUEST_BYTES];
    let cut = request_head(&line, big, &none, &mut out);
    assert!(cut.truncated && cut.len == REQUEST_BYTES);
}

#[test]
fn operator_additions_keep_values_credential_names_still_lose_them_names_are_checked() {
    let mut extra = Extra::default();
    assert_eq!(extra.add("X-Trace-Id"), Ok(true));
    assert_eq!(extra.add("x-trace-id"), Ok(false));
    assert_eq!(extra.add("Authorization"), Ok(true));
    assert_eq!(extra.add("bad name"), Err(ExtraError::InvalidHeaderName));
    assert_eq!(extra.add(""), Err(ExtraError::InvalidHeaderName));
    assert_eq!(extra.add(&"a".repeat(65)), Err(ExtraError::InvalidHeaderName));
    assert_eq!(extra.len(), 2);

    let mut full = Extra::default();
    for index in 0..MAX_EXTRA {
        assert_eq!(full.add(&format!("X-N{index}")), Ok(true));
    }
    assert_eq!(full.add("X-More"), Err(ExtraError::TooManyHeaders));
    // A duplicate is still recognised when the list is full.
    assert_eq!(full.add("x-n3"), Ok(false));

    let headers: [Pair<'_>; 3] = [
        (b"x-trace-id", b"trace-1"),
        (b"Authorization", b"Bearer topsecret"),
        (b"X-Other", b"hidden"),
    ];
    assert_eq!(
        request("POST", "/api", "", &headers, &extra),
        "POST /api HTTP/1.1\r\nx-trace-id: trace-1\r\n\
         Authorization: [redacted]\r\nX-Other: [redacted]\r\n"
    );
}

#[test]
fn url_bearing_values_lose_userinfo_query_values_and_fragments() {
    let none = Extra::default();
    let headers: [Pair<'_>; 5] = [
        (b"Referer", b"https://u:pw@news.example:8443/story?id=1&k=v#top"),
        (b"Origin", b"https://app.example"),
        (b"Location", b"/next?code=abc"),
        (b"Referer", b"javascript:alert(1)"),
        (b"Referer", b"//alice:password@example.test/path?x=1"),
    ];
    assert_eq!(
        request("GET", "/", "", &headers, &none),
        "GET / HTTP/1.1\r\n\
         Referer: https://[redacted]@news.example:8443/story?id=[redacted]&k=[redacted]\
         #[redacted]\r\nOrigin: https://app.example\r\nLocation: /next?code=[redacted]\r\n\
         Referer: [redacted]\r\nReferer: //[redacted]@example.test/path?x=[redacted]\r\n"
    );
}

#[test]
fn extra_names_iterate_in_insertion_order() {
    let mut extra = Extra::default();
    assert!(extra.is_empty());
    extra.add("X-B").unwrap();
    extra.add("X-A").unwrap();
    assert_eq!(extra.names().collect::<Vec<_>>(), ["X-B", "X-A"]);
    assert_eq!(extra.name(1), Some("X-A"));
    assert_eq!(extra.name(2), None);
    assert_eq!(format!("{extra:?}"), r#"["X-B", "X-A"]"#);
}

#[test]
fn response_states_round_trip_their_codes() {
    for code in 0..=255u8 {
        match ResponseState::from_code(code) {
            Some(state) => assert_eq!(state.code(), code),
            None => assert!(code > 4),
        }
    }
    assert_eq!(ResponseState::default(), ResponseState::Unknown);
}

#[test]
fn secret_names_match_without_case_and_by_mark() {
    for name in SECRET_HEADERS {
        assert!(is_secret_header(name));
        assert!(is_secret_header(&name.to_ascii_uppercase()));
    }
    assert!(is_secret_header(b"X-My-SESSION-Id"));
    assert!(is_secret_header(b"x-apikey2"));
    assert!(!is_secret_header(b"x-api"));
    assert!(!is_secret_header(b""));
    for name in KEPT_HEADERS {
        assert!(!is_secret_header(name.as_bytes()), "{name}");
        assert!(is_valid_name(name.as_bytes()));
    }
}

/// A deterministic xorshift64* generator, so every run fuzzes the same inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a [u8]]) -> &'a [u8] {
        items[self.below(items.len())]
    }
}

/// The byte that marks a credential value. Generated non-credential bytes never hold it.
const MARK: u8 = 0xfe;
const SECRET_VALUE: &[u8] = b"\xfeSECRET-VALUE\xfe";

const NAMES: [&[u8]; 16] = [
    b"Cookie",
    b"set-cookie",
    b"AUTHORIZATION",
    b"X-Api-Key",
    b"X-Session-Id",
    b"x-csrf-token",
    b"Host",
    b"User-Agent",
    b"Referer",
    b"Origin",
    b"Location",
    b"Content-Type",
    b"X-Trace-Id",
    b"X-Custom",
    b"Date",
    b"Accept",
];

const VALUES: [&[u8]; 12] = [
    b"https://u:pw@h.example:8443/a/b?x=1&y=2#frag",
    b"//alice:pw@example.test/p?q",
    b"/next?code=abc&state=1",
    b"javascript:alert('http://x')",
    b"text/html; charset=utf-8",
    b"Mozilla/5.0",
    b"",
    b"?a=1#b",
    b"https://@/",
    b"a@b://c@d/e",
    b"   spaced \t",
    b"\x00\x01\x7f\xff",
];

/// Applies one random mutation: a bit flip, a truncation, a duplication of a span, or a
/// splice from another sample. Never introduces the credential mark.
fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>, donors: &[&[u8]]) {
    match rng.below(4) {
        0 if !bytes.is_empty() => {
            let at = rng.below(bytes.len());
            bytes[at] ^= 1 << rng.below(8);
        }
        1 if !bytes.is_empty() => bytes.truncate(rng.below(bytes.len())),
        2 if !bytes.is_empty() => {
            let start = rng.below(bytes.len());
            let end = start + rng.below(bytes.len() - start + 1);
            let span = bytes[start..end].to_vec();
            let at = rng.below(bytes.len() + 1);
            bytes.splice(at..at, span);
        }
        _ => {
            let donor = rng.pick(donors);
            let at = rng.below(bytes.len() + 1);
            bytes.splice(at..at, donor.iter().copied());
        }
    }
    for byte in bytes.iter_mut().filter(|byte| **byte == MARK) {
        *byte = 0;
    }
}

fn random_bytes(rng: &mut Rng, donors: &[&[u8]]) -> Vec<u8> {
    let mut bytes = rng.pick(donors).to_vec();
    for _ in 0..rng.below(4) {
        mutate(rng, &mut bytes, donors);
    }
    bytes
}

/// The same capture into a buffer large enough for any of these inputs: the bounded head
/// must be its prefix, flagged exactly when it is shorter.
fn assert_prefix_of_unbounded(bounded: &[u8], head: Head, unbounded: &[u8], capacity: usize) {
    assert!(head.len <= capacity);
    assert_eq!(head.truncated, unbounded.len() > capacity);
    assert_eq!(head.len, unbounded.len().min(capacity));
    assert_eq!(&bounded[..head.len], &unbounded[..head.len]);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn random_extra(rng: &mut Rng) -> Extra {
    let mut extra = Extra::default();
    for _ in 0..rng.below(4) {
        let name = rng.pick(&NAMES);
        let _ = extra.add(std::str::from_utf8(name).unwrap());
    }
    extra
}

#[test]
fn fuzz_request_heads_never_leak_credentials_and_stay_bounded() {
    let mut rng = Rng(0x5eed_0001);
    let mut unbounded = vec![0; 64 * 1024];
    for _ in 0..60_000 {
        let extra = random_extra(&mut rng);
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for _ in 0..rng.below(12) {
            let mut name = rng.pick(&NAMES).to_vec();
            if rng.below(4) == 0 {
                mutate(&mut rng, &mut name, &NAMES);
            }
            let value = if is_secret_header(&name) {
                let mut value = random_bytes(&mut rng, &VALUES);
                let at = rng.below(value.len() + 1);
                value.splice(at..at, SECRET_VALUE.iter().copied());
                value
            } else {
                random_bytes(&mut rng, &VALUES)
            };
            headers.push((name, value));
        }
        let path = random_bytes(&mut rng, &[b"/", b"/login", b"/a/b/c"]);
        let query = random_bytes(&mut rng, &[b"", b"a=1&b", b"token=x&&=y"]);
        let line =
            RequestLine { method: b"GET", path: &path, query: &query, version: b"HTTP/1.1" };
        let pairs = || headers.iter().map(|(name, value)| (&name[..], &value[..]));
        let mut out = [0; REQUEST_BYTES];
        let head = request_head(&line, pairs(), &extra, &mut out);
        let mut sink = Sink::new(&mut unbounded);
        sink.put(line.method);
        sink.put(b" ");
        sink.put(line.path);
        if !query.is_empty() {
            sink.put(b"?");
            mask_query(&mut sink, &query);
        }
        sink.put(b" HTTP/1.1\r\n");
        for (name, value) in pairs() {
            field(&mut sink, name, value, &extra);
        }
        assert!(!sink.truncated);
        let written = sink.len;
        let full = &unbounded[..written];
        assert_prefix_of_unbounded(&out, head, full, REQUEST_BYTES);
        assert!(!full.contains(&MARK), "a credential value leaked: {full:?}");
    }
}

#[test]
fn fuzz_response_heads_never_leak_credentials_and_stay_bounded() {
    let mut rng = Rng(0x5eed_0002);
    let mut unbounded = vec![0; 64 * 1024];
    for round in 0..60_000 {
        let extra = random_extra(&mut rng);
        let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..rng.below(12) {
            let mut name = rng.pick(&NAMES).to_vec();
            if rng.below(4) == 0 {
                mutate(&mut rng, &mut name, &NAMES);
            }
            // Keep the line structure: no colon in a name, no line break anywhere.
            name.retain(|byte| !b":\r\n".contains(byte));
            let mut value = random_bytes(&mut rng, &VALUES);
            value.retain(|byte| !b"\r\n".contains(byte));
            if is_secret_header(&name) {
                value.extend_from_slice(SECRET_VALUE);
            }
            raw.extend_from_slice(&name);
            raw.extend_from_slice(b": ");
            raw.extend_from_slice(&value);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\nbody");
        // Odd rounds also break the line structure; they check bounds, not redaction.
        let structured = round % 2 == 0;
        if !structured {
            for _ in 0..1 + rng.below(4) {
                mutate(&mut rng, &mut raw, &VALUES);
            }
        }
        let mut out = [0; RESPONSE_BYTES];
        let head = response_head(&raw, &extra, &mut out);
        let written = capture_unbounded(&raw, &extra, &mut unbounded);
        let full = &unbounded[..written];
        assert_prefix_of_unbounded(&out, head, full, RESPONSE_BYTES);
        if structured {
            assert!(!contains(full, SECRET_VALUE), "a credential value leaked: {raw:?}");
        }
    }
}

/// Runs the response capture into a large buffer and returns the length it wrote.
fn capture_unbounded(raw: &[u8], extra: &Extra, big: &mut [u8]) -> usize {
    let mut sink = Sink::new(big);
    let mut lines = split_crlf(raw);
    if let Some(status) = lines.next() {
        sink.put(status);
        sink.put(b"\r\n");
    }
    for line in lines.take_while(|line| !line.is_empty()) {
        match line.iter().position(|&byte| byte == b':') {
            Some(colon) => {
                field(&mut sink, &line[..colon], trim_blanks(&line[colon + 1..]), extra)
            }
            None => {
                sink.put(line);
                sink.put(b"\r\n");
            }
        }
    }
    assert!(!sink.truncated);
    sink.len
}

#[test]
fn crlf_split_and_trim_follow_zig() {
    let lines: Vec<&[u8]> = split_crlf(b"a\r\n\r\nb\nc\r\n").collect();
    assert_eq!(lines, [&b"a"[..], b"", b"b\nc", b""]);
    assert_eq!(split_crlf(b"").collect::<Vec<_>>(), [&b""[..]]);
    assert_eq!(trim_blanks(b" \t x y \t"), b"x y");
    assert_eq!(trim_blanks(b" \t "), b"");
    assert_eq!(trim_blanks(b""), b"");
}

/// The browser request of the Zig timing program: ten headers, a query, a referer URL and
/// a cookie. Run with `cargo test -p sibuna-core --release -- --ignored --nocapture timing`.
#[test]
#[ignore = "timing measurement; run in release"]
fn request_head_timing() {
    let mut extra = Extra::default();
    extra.add("X-Trace-Id").unwrap();
    let headers: [Pair<'_>; 10] = [
        (b"Host", b"app.example.com"),
        (
            b"User-Agent",
            b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
              Chrome/126.0 Safari/537.36",
        ),
        (b"Accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        (b"Accept-Language", b"en-US,en;q=0.9"),
        (b"Accept-Encoding", b"gzip, deflate, br"),
        (b"Referer", b"https://app.example.com/search?q=shoes&page=2#results"),
        (
            b"Cookie",
            b"__sibuna_token=abcdefghijklmnopqrstuvwxyz0123456789; theme=dark; \
              sid=0123456789abcdef",
        ),
        (b"X-Trace-Id", b"4bf92f3577b34da6a3ce929d0e0e4736"),
        (b"Sec-Fetch-Mode", b"navigate"),
        (b"Connection", b"keep-alive"),
    ];
    let line = RequestLine {
        method: b"GET",
        path: b"/products/shoes/running",
        query: b"color=blue&size=42&ref=home",
        version: b"HTTP/1.1",
    };
    const ITERATIONS: u32 = 2_000_000;
    let mut out = [0; REQUEST_BYTES];
    let mut total = 0;
    let start = std::time::Instant::now();
    for _ in 0..ITERATIONS {
        let headers = std::hint::black_box(&headers);
        total += request_head(&line, headers.iter().copied(), &extra, &mut out).len;
        std::hint::black_box(&out);
    }
    let elapsed = start.elapsed() / ITERATIONS;
    println!("rust request_head: {elapsed:?} per op (len {})", total / ITERATIONS as usize);
}

/// The rules as Zig wrote them: each list compared entry by entry without case.
fn reference_treatment(name: &[u8], extra: &Extra) -> Treatment {
    let listed =
        |list: &[&str]| list.iter().any(|entry| name.eq_ignore_ascii_case(entry.as_bytes()));
    let secret = SECRET_HEADERS.iter().any(|secret| name.eq_ignore_ascii_case(secret))
        || SECRET_MARKS.iter().any(|mark| contains_ignore_case(name, mark));
    if secret || !(listed(&KEPT_HEADERS) || extra.contains(name)) {
        Treatment::Redact
    } else if listed(&["origin", "referer", "location"]) {
        Treatment::MaskUrl
    } else {
        Treatment::Keep
    }
}

#[test]
fn fuzz_name_classification_agrees_with_the_zig_lists() {
    let mut rng = Rng(0x5eed_0004);
    let mut donors: Vec<&[u8]> = NAMES.to_vec();
    donors.extend(SECRET_HEADERS);
    donors.extend(KEPT_HEADERS.iter().map(|name| name.as_bytes()));
    donors.extend(SECRET_MARKS);
    let long = [b'a'; 80];
    donors.push(&long);
    for _ in 0..100_000 {
        let extra = random_extra(&mut rng);
        let mut name = rng.pick(&donors).to_vec();
        for _ in 0..rng.below(3) {
            mutate(&mut rng, &mut name, &donors);
        }
        if rng.below(2) == 0 {
            // Random case changes, which every rule must ignore.
            for byte in &mut name {
                if rng.below(2) == 0 {
                    *byte = byte.to_ascii_uppercase();
                }
            }
        }
        let expected = reference_treatment(&name, &extra);
        assert_eq!(treatment(&name, &extra), expected, "{:?}", String::from_utf8_lossy(&name));
        let secret = SECRET_HEADERS.iter().any(|secret| name.eq_ignore_ascii_case(secret))
            || SECRET_MARKS.iter().any(|mark| contains_ignore_case(&name, mark));
        assert_eq!(is_secret_header(&name), secret);
    }
}

#[test]
fn the_pattern_matchers_spell_the_same_lists() {
    for name in SECRET_HEADERS {
        assert!(is_secret_folded(name));
        assert!(!is_kept_folded(name));
    }
    for name in KEPT_HEADERS {
        assert!(is_kept_folded(name.as_bytes()));
        // The kept list holds no credential name; `treatment` relies on it.
        assert!(!is_secret_folded(name.as_bytes()));
    }
    let urls: Vec<&str> =
        KEPT_HEADERS.into_iter().filter(|name| is_url_folded(name.as_bytes())).collect();
    assert_eq!(urls, ["origin", "referer", "location"]);
}
