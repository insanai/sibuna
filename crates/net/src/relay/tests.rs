use std::io::{self, Read};

use super::*;

struct Fixed {
    keep: bool,
    reusable: bool,
    output: Vec<u8>,
}

/// Relays a fixed origin response to an in-memory client, as Zig's `relayFixed` did.
fn relay_fixed(origin: &[u8], keep_alive: bool) -> Result<Fixed, ProxyError> {
    let mut storage = vec![0u8; MAX_RESPONSE_HEAD];
    let mut reader = Reader::new(origin, &mut storage);
    let mut output = Vec::new();
    let mut audit = Audit::default();
    let progress = Progress { activity: None };
    let relayed =
        relay_response(&mut reader, &mut output, false, keep_alive, &mut audit, progress)?;
    Ok(Fixed { keep: relayed.client_keep, reusable: relayed.origin_reusable, output })
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

#[test]
fn framed_origin_responses_are_relayed_exactly_and_keep_the_client_open() {
    let sized = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    let r1 = relay_fixed(sized, true).unwrap();
    assert!(r1.keep);
    assert!(!r1.reusable);
    assert_eq!(
        text(&r1.output),
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello"
    );

    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
        5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n";
    let r2 = relay_fixed(chunked, true).unwrap();
    assert!(r2.keep);
    assert!(r2.reusable);
    assert_eq!(
        text(&r2.output),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n\
         5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n"
    );

    let legacy = b"HTTP/1.0 200 OK\r\nServer: old\r\n\r\nuntil close";
    let r3 = relay_fixed(legacy, true).unwrap();
    assert!(!r3.keep);
    assert!(!r3.reusable);
    assert!(r3.output.ends_with(b"Connection: close\r\n\r\nuntil close"));

    let r4 = relay_fixed(sized, false).unwrap();
    assert!(!r4.keep);

    let truncated = relay_fixed(b"HTTP/1.1 200 OK\r\n", true);
    assert_eq!(truncated.err(), Some(ProxyError::UpstreamReadFailed));
    assert_eq!(relay_fixed(b"", true).err(), Some(ProxyError::UpstreamClosed));
    let bad_chunk = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
    assert_eq!(relay_fixed(bad_chunk, true).err(), Some(ProxyError::UpstreamTruncated));
    // A body shorter than its length is cut after the head: an abort, not a second reply.
    let short = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort";
    assert_eq!(relay_fixed(short, true).err(), Some(ProxyError::UpstreamTruncated));
}

#[test]
fn response_framing_honors_bodyless_replies_and_rejects_ambiguous_origin_headers() {
    let encoded = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(parse_response_head(encoded, true).unwrap().framing, Framing::None);
    let hints = b"HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(parse_response_head(hints, false).unwrap().framing, Framing::None);
    let lengths = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
    assert!(parse_response_head(lengths, false).is_none());
    let nominated = b"HTTP/1.1 200 OK\r\nConnection: Content-Length\r\nContent-Length: 1\r\n\r\n";
    assert!(parse_response_head(nominated, false).is_none());
    let order = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
    assert!(parse_response_head(order, false).is_none());
    let relayed = relay_fixed(
        b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\
          Connection: close, X-Hop\r\nX-Hop: omit\r\nX-App: preserve\r\n\r\n1\r\na\r\n0\r\n\r\n",
        true,
    )
    .unwrap();
    assert!(!relayed.reusable);
    let output = text(&relayed.output);
    assert!(!output.contains("Content-Length"));
    assert!(!output.contains("X-Hop"));
    assert!(output.contains("X-App: preserve"));
}

#[test]
fn informational_heads_are_relayed_and_bounded() {
    let mut origin = Vec::new();
    origin.extend_from_slice(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: <a>\r\n\r\n",
    );
    origin.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    let relayed = relay_fixed(&origin, true).unwrap();
    assert_eq!(
        text(&relayed.output),
        "HTTP/1.1 100 Continue\r\nConnection: keep-alive\r\n\r\n\
         HTTP/1.1 103 Early Hints\r\nLink: <a>\r\nConnection: keep-alive\r\n\r\n\
         HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n"
    );
    let mut many = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(9);
    many.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    assert_eq!(relay_fixed(&many, true).err(), Some(ProxyError::UpstreamReadFailed));
    let unrequested = b"HTTP/1.1 101 Switching Protocols\r\n\r\n";
    assert_eq!(relay_fixed(unrequested, true).err(), Some(ProxyError::UpstreamReadFailed));
}

#[test]
fn audit_sinks_see_the_status_and_raw_head_before_the_relay() {
    let origin = b"HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\nX-A: b\r\n\r\nx";
    let mut storage = vec![0u8; 1024];
    let mut reader = Reader::new(&origin[..], &mut storage);
    let mut status = 0u16;
    let mut captured = Vec::new();
    let mut sink = |head: &[u8]| captured.extend_from_slice(head);
    let mut output = Vec::new();
    {
        let mut audit = Audit {
            response_status: Some(&mut status),
            response_head: Some(&mut sink),
            ..Audit::default()
        };
        let progress = Progress { activity: None };
        relay_response(&mut reader, &mut output, false, true, &mut audit, progress).unwrap();
    }
    assert_eq!(status, 404);
    assert_eq!(captured, &origin[..origin.len() - 1]);
}

#[test]
fn uploads_refresh_activity_per_credit_and_rechunk_per_read() {
    let activity = Activity::new();
    activity.set_timeout_ms(0);
    let progress = Progress { activity: Some(&activity) };
    let body = vec![b'x'; 40_000];
    let mut storage = vec![0u8; 4096];
    let mut source = Reader::new(&body[10..], &mut storage);
    let mut origin = Vec::new();
    relay_body(&body[..10], &mut source, &mut origin, body.len() as u64, progress).unwrap();
    assert_eq!(origin, body);

    let chunked = b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\nT: 1\r\n\r\nNEXT";
    let mut storage = vec![0u8; 64];
    let mut source = Reader::new(Pieces { data: chunked, step: 5 }, &mut storage);
    let mut origin = Vec::new();
    let mut decoder = Decoder::new();
    relay_chunked_body(&mut source, &mut origin, &mut decoder, progress).unwrap();
    // Each read is decoded and re-sent as one canonical chunk; extensions and the trailer
    // stay behind, and so do the bytes after the body.
    let sent = text(&origin);
    assert!(sent.ends_with("\r\n0\r\n\r\n"), "{sent}");
    assert!(!sent.contains("x=y") && !sent.contains("T: 1"));
    let mut copy = origin.clone();
    let mut check = Decoder::new();
    let step = check.decode(&mut copy).unwrap();
    assert!(check.is_done());
    assert_eq!(&copy[..step.output], b"abcde");
    assert!(b"NEXT".starts_with(source.buffered()));

    let mut storage = vec![0u8; 64];
    let mut source = Reader::new(&b"3\r\nabc\r\n2 \r\nde\r\n0\r\n\r\n"[..], &mut storage);
    let mut origin = Vec::new();
    let mut decoder = Decoder::new();
    let result = relay_chunked_body(&mut source, &mut origin, &mut decoder, progress);
    assert_eq!(result, Err(ProxyError::MalformedRequestBody));
    assert!(!origin.ends_with(LAST_CHUNK));
}

/// A source that returns at most `step` bytes per read, as a slow network does.
struct Pieces<'a> {
    data: &'a [u8],
    step: usize,
}

impl Read for Pieces<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.step.min(out.len()).min(self.data.len());
        out[..count].copy_from_slice(&self.data[..count]);
        self.data = &self.data[count..];
        Ok(count)
    }
}

/// A deterministic xorshift generator for the fuzz tests.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

const CHUNKED_SEEDS: [&[u8]; 5] = [
    b"5\r\nhello\r\n0\r\n\r\n",
    b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n",
    b"A\r\n0123456789\r\n+3\r\nabc\r\n1_0 ;x\r\n0123456789abcdef\r\n -0 \r\n\n",
    b"1\r\na\r\n1\r\nb\r\n0\r\nA: 1\r\nB: 2\r\n\r\n",
    b"fffffffffffffffe\r\nab",
];

const ALPHABET: &[u8] = b"\r\n;: \t_+-0123456789abcdefABCDEFxz\x00\x7f";

fn mutate(rng: &mut Rng, seeds: &[&[u8]]) -> Vec<u8> {
    let mut input = seeds[rng.below(seeds.len())].to_vec();
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(input.len() + 1);
        match rng.below(6) {
            0 if !input.is_empty() => {
                let index = at.min(input.len() - 1);
                input[index] ^= 1 << rng.below(8);
            }
            1 => input.insert(at, ALPHABET[rng.below(ALPHABET.len())]),
            2 => input.truncate(at),
            3 => {
                let end = (at + rng.below(16)).min(input.len());
                let piece = input[at..end].to_vec();
                input.splice(at..at, piece);
            }
            4 => {
                let other = seeds[rng.below(seeds.len())];
                let from = rng.below(other.len());
                input.truncate(at);
                input.extend_from_slice(&other[from..]);
            }
            _ => {
                if at < input.len() {
                    input.remove(at);
                }
            }
        }
    }
    input
}

/// A naive reading of a chunked body as `relay_chunked` relays it: the number of bytes
/// relayed when the body is complete, or `None` when the relay must fail. Lines (through LF)
/// must fit `capacity`.
fn reference_chunked(input: &[u8], capacity: usize) -> Option<usize> {
    let mut at = 0;
    let line_end = |at: usize| -> Option<usize> {
        let rest = &input[at..];
        let newline = rest.iter().position(|&byte| byte == b'\n')?;
        (newline < capacity).then_some(at + newline + 1)
    };
    loop {
        let end = line_end(at)?;
        let line = &input[at..end];
        let cut = line.iter().position(|b| b";\r\n".contains(b)).unwrap_or(line.len());
        let digits: Vec<u8> = line[..cut].to_vec();
        let digits = std::str::from_utf8(&digits).ok()?.trim_matches([' ', '\t']);
        let size = naive_zig_hex(digits)?;
        at = end;
        if size == 0 {
            break;
        }
        let data = size.saturating_add(2);
        if data > (input.len() - at) as u64 {
            return None;
        }
        at += data as usize;
    }
    loop {
        let end = line_end(at)?;
        let line = &input[at..end];
        at = end;
        if line == b"\r\n" || line == b"\n" {
            return Some(at);
        }
    }
}

/// Zig's `parseInt(u64, text, 16)`, written with 128-bit arithmetic.
fn naive_zig_hex(text: &str) -> Option<u64> {
    let (negative, digits) = if let Some(rest) = text.strip_prefix('+') {
        (false, rest)
    } else if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text)
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') {
        return None;
    }
    let mut value: u128 = 0;
    for character in digits.chars().filter(|&c| c != '_') {
        value = value * 16 + u128::from(character.to_digit(16)?);
        if value > u128::from(u64::MAX) {
            return None;
        }
    }
    if negative && value != 0 {
        return None;
    }
    Some(value as u64)
}

#[test]
fn fuzz_chunked_response_relay_agrees_with_a_reference() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut storage = vec![0u8; 48];
    for _ in 0..200_000 {
        let input = mutate(&mut rng, &CHUNKED_SEEDS);
        let step = 1 + rng.below(24);
        let mut reader = Reader::new(Pieces { data: &input, step }, &mut storage);
        let mut output = Vec::new();
        let result = relay_chunked(&mut reader, &mut output, Progress { activity: None });
        assert!(input.starts_with(&output), "relayed bytes are a prefix of the input");
        match reference_chunked(&input, 48) {
            Some(length) => {
                assert_eq!(result, Ok(()), "{:?}", String::from_utf8_lossy(&input));
                assert_eq!(output.len(), length);
            }
            None => assert_eq!(result, Err(ProxyError::UpstreamTruncated)),
        }
    }
}

#[test]
fn fuzz_whole_responses_relay_without_panic_and_bounded() {
    let seeds: [&[u8]; 6] = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nServer: old\r\n\r\nuntil close",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        b"HTTP/1.1 304 Not Modified\r\nConnection: close, X\r\nX: y\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: gzip, chunked\r\n\r\n\
          2\r\nab\r\n0\r\n\r\n",
    ];
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut storage = vec![0u8; 256];
    for _ in 0..100_000 {
        let input = mutate(&mut rng, &seeds);
        let mut reader =
            Reader::new(Pieces { data: &input, step: 1 + rng.below(64) }, &mut storage);
        let mut output = Vec::new();
        let mut audit = Audit::default();
        let progress = Progress { activity: None };
        let head_request = rng.below(4) == 0;
        let _ = relay_response(&mut reader, &mut output, head_request, true, &mut audit, progress);
        // Sibuna adds at most one connection field per relayed head.
        assert!(output.len() <= input.len() + 26 * 9);
    }
}

const UPLOAD_SEEDS: [&[u8]; 4] = [
    b"5;sig=\"a;b\"\r\nhello\r\n1\r\n \r\n00D\r\nchunked world\r\n0\r\nX-Checksum: 1\r\n\r\n",
    b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\nGET / HTTP/1.1\r\n",
    b"1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\nT: 1\r\nU: 2\r\n\r\n",
    b"10\r\n0123456789abcdef\r\n0\r\n\r\n",
];

/// Re-chunking a request body per read must never change it: the origin receives canonical
/// chunks that decode to exactly what a one-shot decode of the client's bytes gives, or a
/// body without its last chunk when the client's framing is malformed or incomplete.
#[test]
fn fuzz_rechunked_uploads_agree_with_a_one_shot_decode() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let mut storage = vec![0u8; 64];
    for _ in 0..100_000 {
        let input = mutate(&mut rng, &UPLOAD_SEEDS);
        let mut whole = input.clone();
        let mut reference = Decoder::new();
        let expected = reference.decode(&mut whole).map(|step| whole[..step.output].to_vec());
        let mut source =
            Reader::new(Pieces { data: &input, step: 1 + rng.below(16) }, &mut storage);
        let mut origin = Vec::new();
        let mut decoder = Decoder::new();
        let progress = Progress { activity: None };
        let result = relay_chunked_body(&mut source, &mut origin, &mut decoder, progress);
        let mut sent = origin.clone();
        let mut check = Decoder::new();
        let step = check.decode(&mut sent).expect("Sibuna's own framing is canonical");
        match (&expected, result) {
            (Ok(body), Ok(())) if reference.is_done() => {
                assert!(check.is_done());
                assert_eq!(&sent[..step.output], &body[..]);
            }
            (Ok(_), Err(ProxyError::ClientFailed)) => assert!(!reference.is_done()),
            (Err(_), Err(ProxyError::MalformedRequestBody | ProxyError::ClientFailed)) => {
                assert!(!check.is_done());
            }
            (expected, result) => panic!("{expected:?} {result:?} {:?}", input),
        }
    }
}
