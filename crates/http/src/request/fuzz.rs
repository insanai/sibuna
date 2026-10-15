//! Deterministic fuzzing of the request parser against the reference transcription.

use super::{MAX_HEADERS, ParseError, Request, parse_request, reference};
use crate::test_util::{Rng, mutate, within};

/// Valid requests and smuggling attempts the mutations start from.
const CORPUS: &[&[u8]] = &[
    b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET /api/v1/data?page=2 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 \
      (X11) Chrome/128.0\r\nAccept: text/html,*/*;q=0.8\r\nCookie: __sibuna_token=v1_abc; \
      session=xyz\r\n\r\n",
    b"POST /submit HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
    b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n",
    b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
    b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
    b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
    b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"POST / HTTP/1.1\r\nTransfer-Encoding : chunked\r\n\r\n",
    b"POST / HTTP/1.1\r\nTransfer-Encoding:\x0bchunked\r\n\r\n",
    b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n X-Folded: yes\r\n\r\n",
    b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"POST / HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n",
    b"POST / HTTP/1.1\r\nContent-Length: 1, 1\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n",
    b"GET / HTTP/1.1\nHost: a\n\n",
    b"GET http://a/b?c HTTP/1.0\r\nConnection: keep-alive\r\nAccept: text/html\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
    b"PROPFIND /dav HTTP/1.1\r\nDepth: 1\r\nX-Empty:\r\nX-Tab:\tv\t\r\n\r\n",
];

fn assert_invariants(data: &[u8], request: &Request<'_>) {
    assert!(request.header_count <= MAX_HEADERS);
    let slices = [request.method_text, request.path, request.query, request.body];
    for slice in slices.into_iter().chain(request.headers().iter().flat_map(|h| [h.name, h.value]))
    {
        assert!(within(data, slice), "slice outside the input");
    }
    // The body is exactly what follows the first blank line, or empty at the end.
    let blank = data.windows(4).position(|w| w == b"\r\n\r\n");
    let start = blank.map_or(data.len(), |at| at + 4);
    assert_eq!(request.body.as_ptr(), data[start..].as_ptr());
    assert_eq!(request.body.len(), data.len() - start);
}

/// Parses `data` with both parsers and requires the same verdict and the same fields.
fn check(data: &[u8]) -> Result<(), ParseError> {
    let fast = parse_request(data);
    let slow = reference::parse(data);
    assert_eq!(fast, slow, "input {:?}", String::from_utf8_lossy(data));
    if let Ok(request) = &fast {
        assert_invariants(data, request);
    }
    fast.map(|_| ())
}

fn run(seed: u64, rounds: usize) -> (usize, usize) {
    let mut rng = Rng::new(seed);
    let mut accepted = 0;
    let mut input = Vec::new();
    for _ in 0..rounds {
        input.clear();
        input.extend_from_slice(rng.pick(CORPUS));
        for _ in 0..1 + rng.below(4) {
            let other = *rng.pick(CORPUS);
            mutate(&mut rng, &mut input, other);
        }
        accepted += usize::from(check(&input).is_ok());
    }
    (accepted, rounds - accepted)
}

#[test]
fn every_truncation_of_the_corpus_agrees_with_the_reference() {
    for request in CORPUS {
        for end in 0..=request.len() {
            let _ = check(&request[..end]);
        }
    }
}

#[test]
fn mutated_requests_agree_with_the_reference() {
    let (accepted, rejected) = run(0x5eed_4447, 200_000);
    // Both verdicts must be well represented, or the fuzzer explores only one side.
    assert!(accepted > 20_000 && rejected > 20_000, "{accepted} accepted, {rejected} rejected");
}

#[test]
#[ignore = "long fuzz run; use --release -- --ignored"]
fn mutated_requests_agree_with_the_reference_long() {
    for seed in 1..=20 {
        run(seed, 1_000_000);
    }
}

#[test]
fn many_header_lines_agree_with_the_reference() {
    let mut rng = Rng::new(7);
    for _ in 0..2_000 {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        for _ in 0..rng.below(40) {
            const NAMES: [&[u8]; 4] = [b"X-A", b"Content-Length", b"Transfer-Encoding", b"Host"];
            const VALUES: [&[u8]; 4] = [b"1", b"2", b"chunked", b" a "];
            let name = rng.pick(&NAMES);
            let value = rng.pick(&VALUES);
            raw.extend_from_slice(name);
            raw.extend_from_slice(b": ");
            raw.extend_from_slice(value);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        let _ = check(&raw);
    }
}

/// The Zig `getCookie`, transcribed with plain splitting.
fn reference_cookie<'a>(field: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for pair in field.split(|&c| c == b';') {
        let pair = crate::bytes::trim_space(pair);
        let mut parts = pair.split(|&c| c == b'=');
        if parts.next() == Some(name) {
            return Some(parts.next().unwrap_or(b""));
        }
    }
    None
}

#[test]
fn cookie_lookup_agrees_with_the_reference() {
    let mut rng = Rng::new(0xc00c1e);
    let alphabet = b"ab=; \t";
    let names: [&[u8]; 7] = [b"", b"a", b"b", b"ab", b"a=", b" a", b"=a"];
    for _ in 0..50_000 {
        let field: Vec<u8> = (0..rng.at_most(12)).map(|_| *rng.pick(alphabet)).collect();
        let raw = [&b"GET / HTTP/1.1\r\nCookie: "[..], &field, b"\r\n\r\n"].concat();
        let Ok(request) = parse_request(&raw) else { continue };
        let value = request.header(b"cookie").unwrap_or_default();
        for name in names {
            assert_eq!(request.cookie(name), reference_cookie(value, name), "{field:?} {name:?}");
        }
    }
}
