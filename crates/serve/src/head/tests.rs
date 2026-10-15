use super::*;
use crate::test_util::{Rng, Trickle, mutate};

const VALID: &[&[u8]] = &[
    b"GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\nCookie: t=xyz\r\n\r\n",
    b"POST /console/api/login HTTP/1.1\r\nHost: c\r\nContent-Length: 5\r\n\
      Expect: 100-continue\r\nContent-Type: application/json\r\n\r\n",
    b"PUT /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
    b"GET /console/ws HTTP/1.1\r\nHost: c\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
      Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
];

#[test]
fn a_head_ends_at_the_first_blank_line() {
    assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r\nrest"), Some(18));
    assert_eq!(head_end(b"GET / HTTP/1.1\n\nrest"), Some(16));
    assert_eq!(head_end(b"\n\n"), Some(2));
    assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r"), None);
    assert_eq!(head_end(b"GET / HTTP/1.1\r\nA: b\r\n"), None);
    assert_eq!(head_end(b""), None);
}

#[test]
fn heads_are_read_across_any_split_and_bounded_by_the_buffer() {
    let mut input = VALID[0].to_vec();
    input.extend_from_slice(b"body");
    for seed in 1..200 {
        let mut trickle = Trickle { bytes: &input, rng: Rng::new(seed) };
        let mut buffer = [0u8; 256];
        let (length, received) = read_head(&mut trickle, &mut buffer).unwrap();
        assert_eq!(length, VALID[0].len());
        assert!(received >= length && received <= input.len());
    }
    let mut buffer = [0u8; 16];
    let mut trickle = Trickle { bytes: VALID[0], rng: Rng::new(7) };
    assert!(matches!(read_head(&mut trickle, &mut buffer), Err(HeadError::TooLarge)));
    let mut trickle = Trickle { bytes: b"GET / HTTP/1.1\r\n", rng: Rng::new(7) };
    let mut buffer = [0u8; 64];
    assert!(matches!(read_head(&mut trickle, &mut buffer), Err(HeadError::Closed)));
    // A head that exactly fills the buffer is complete.
    let exact = VALID[0];
    let mut buffer = vec![0u8; exact.len()];
    let mut trickle = Trickle { bytes: exact, rng: Rng::new(3) };
    assert_eq!(read_head(&mut trickle, &mut buffer).unwrap(), (exact.len(), exact.len()));
}

#[test]
fn heads_are_classified_as_zig_did() {
    let head = parse_head(VALID[1]).unwrap();
    assert_eq!(head.framing, Framing::Length(5));
    assert_eq!(head.expect, Some(&b"100-continue"[..]));
    assert!(head.keep_alive && head.has_body);
    assert_eq!(head.target, b"/console/api/login");
    let head = parse_head(VALID[2]).unwrap();
    assert_eq!(head.framing, Framing::Chunked);
    assert!(head.keep_alive);
    let head = parse_head(b"GET / HTTP/1.0\r\nConnection: anything\r\n\r\n").unwrap();
    assert!(head.keep_alive, "any Connection value but close keeps an HTTP/1.0 connection");
    let head = parse_head(VALID[0]).unwrap();
    assert_eq!(
        (head.target, head.framing, head.has_body),
        (&b"/a?b=1"[..], Framing::Empty, false)
    );
    assert!(!parse_head(VALID[4]).unwrap().keep_alive);
    assert!(!parse_head(b"GET / HTTP/1.0\r\n\r\n").unwrap().keep_alive);
    let refused: &[&[u8]] = &[
        b"BREW /pot HTTP/1.1\r\n\r\n",
        b"get / HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\n\n",
        b"GET / HTTP/1.1\n\n",
        b"GET / HTTP/1.1\r\nHost: a\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET / HTTP/2.0\r\n\r\n",
    ];
    for head in refused {
        assert!(parse_head(head).is_none(), "{}", String::from_utf8_lossy(head));
    }
    for method in METHODS {
        let mut head = method.to_vec();
        head.extend_from_slice(b" / HTTP/1.1\r\n\r\n");
        assert!(parse_head(&head).is_some());
    }
}

/// The naive reading of the end of a head: the first CRLF CRLF or LF LF.
fn reference_end(bytes: &[u8]) -> Option<usize> {
    let crlf = bytes.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    let lf = bytes.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn check_parsed(bytes: &[u8], head: &Head<'_>) {
    let range = bytes.as_ptr_range();
    assert!(range.contains(&head.target.as_ptr()) || head.target.is_empty());
    let request = &head.request;
    let mut rebuilt = request.path.to_vec();
    if head.target.contains(&b'?') {
        rebuilt.push(b'?');
        rebuilt.extend_from_slice(request.query);
    }
    assert_eq!(rebuilt, head.target);
    assert!(METHODS.contains(&request.method_text));
    let closes = request
        .headers()
        .iter()
        .rfind(|h| h.name.eq_ignore_ascii_case(b"connection"))
        .map(|h| h.value.eq_ignore_ascii_case(b"close"));
    let expected = closes.map_or(request.version == Version::Http11, |close| !close);
    assert_eq!(head.keep_alive, expected);
    if let Framing::Length(length) = head.framing {
        assert_eq!(request.content_length(), Some(length));
    }
}

#[test]
fn fuzz_heads_never_panic_and_keep_their_invariants() {
    let mut rng = Rng::new(0x5eed_0001);
    let mut parsed = 0;
    for round in 0..100_000 {
        let mut input = rng.pick(VALID).to_vec();
        let donor = VALID[round % VALID.len()];
        mutate(&mut rng, &mut input, donor);
        assert_eq!(head_end(&input), reference_end(&input));
        let end = head_end(&input).unwrap_or(input.len());
        if let Some(head) = parse_head(&input[..end]) {
            check_parsed(&input[..end], &head);
            parsed += 1;
        }
    }
    assert!(parsed > 10_000, "the mutator should keep many heads valid: {parsed}");
}
