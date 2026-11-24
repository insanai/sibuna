use sibuna_http::parse_request;

use super::*;
use crate::buffered::Reader;
use crate::relay::{Progress, relay_response};

/// A deterministic xorshift generator.
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

const SEEDS: [&[u8]; 9] = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
      5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nServer: old\r\n\r\nuntil close",
    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
    b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 304 Not Modified\r\nConnection: close, X\r\nX: y\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: gzip, chunked\r\n\r\n\
      2\r\nab\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 200 OK\r\n\r\n",
];

const ALPHABET: &[u8] = b"\r\n;: \t_+-0123456789abcdefABCDEFxz\x00\x7f";

fn mutate(rng: &mut Rng) -> Vec<u8> {
    let mut input = SEEDS[rng.below(SEEDS.len())].to_vec();
    for _ in 0..rng.below(4) {
        let at = rng.below(input.len() + 1);
        match rng.below(5) {
            0 if !input.is_empty() => {
                let index = at.min(input.len() - 1);
                input[index] ^= 1 << rng.below(8);
            }
            1 => input.insert(at, ALPHABET[rng.below(ALPHABET.len())]),
            2 => input.truncate(at),
            3 => {
                let other = SEEDS[rng.below(SEEDS.len())];
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

fn outbound(head_request: bool) -> Outbound {
    Outbound {
        handshake: None,
        retryable: true,
        poolable: true,
        buffered: true,
        head_request,
        upload: UploadRelay::Done,
    }
}

/// Feeds `input` in pieces of `step` bytes, as a socket would deliver it, then ends it.
fn run(input: &[u8], step: usize, head_request: bool) -> (Result<Outcome, ProxyError>, Vec<u8>) {
    let mut relay = ResponseRelay::new(&outbound(head_request), true);
    let mut held = Vec::new();
    let mut out = Vec::new();
    for piece in input.chunks(step.max(1)) {
        held.extend_from_slice(piece);
        match relay.feed(&held, &mut out, &mut |_, _| {}) {
            Ok((used, Fed::More)) => drop(held.drain(..used)),
            Ok((_, Fed::Done(outcome))) => return (Ok(outcome), out),
            Ok((_, Fed::Upgraded)) => panic!("no upgrade was offered"),
            Err(error) => return (Err(error), out),
        }
        assert!(held.len() <= MAX_RESPONSE_HEAD, "the relay must bound its unconsumed input");
    }
    (relay.end_of_stream(), out)
}

fn blocking(input: &[u8], head_request: bool) -> (Result<Outcome, ProxyError>, Vec<u8>) {
    let mut storage = vec![0u8; MAX_RESPONSE_HEAD];
    let mut reader = Reader::new(input, &mut storage);
    let mut out = Vec::new();
    let mut audit = Audit::default();
    let progress = Progress { activity: None };
    let relayed = relay_response(&mut reader, &mut out, head_request, true, &mut audit, progress);
    let outcome = relayed.map(|relayed| Outcome {
        client_keep: relayed.client_keep,
        origin_reusable: relayed.origin_reusable,
    });
    (outcome, out)
}

/// Before the final head both relays answer 502; after it both abort.
fn class(error: ProxyError) -> u8 {
    match error {
        ProxyError::UpstreamClosed | ProxyError::UpstreamReadFailed => 1,
        ProxyError::UpstreamTruncated => 2,
        _ => 3,
    }
}

#[test]
fn the_machine_agrees_with_the_blocking_relay_on_mutated_responses() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut finished, mut failed) = (0, 0);
    for _ in 0..150_000 {
        let input = mutate(&mut rng);
        let head_request = rng.below(4) == 0;
        let (expected, expected_out) = blocking(&input, head_request);
        for step in [input.len().max(1), 1 + rng.below(48), 1] {
            let (actual, actual_out) = run(&input, step, head_request);
            match (expected, actual) {
                (Ok(expected), Ok(actual)) => {
                    assert_eq!(expected.client_keep, actual.client_keep, "{input:?}");
                    if step >= input.len() {
                        assert_eq!(expected.origin_reusable, actual.origin_reusable, "{input:?}");
                    } else {
                        // Fed in pieces, the relay cannot see bytes that come later.
                        assert!(actual.origin_reusable || !expected.origin_reusable, "{input:?}");
                    }
                    finished += 1;
                }
                (Err(expected), Err(actual)) => {
                    assert_eq!(class(expected), class(actual), "{input:?}");
                    failed += 1;
                }
                (expected, actual) => panic!("{expected:?} {actual:?} {input:?} step {step}"),
            }
            assert_eq!(expected_out, actual_out, "{input:?} step {step}");
        }
    }
    assert!(finished > 10_000 && failed > 10_000, "{finished} {failed}");
}

fn swap(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    String::from_utf8_lossy(bytes).replace(from, to).into_bytes()
}

const UPGRADE: &[u8] = b"GET /live HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\
    Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
    Sec-WebSocket-Protocol: anahita.live.v1\r\n\r\n";

#[test]
fn an_offered_upgrade_is_encoded_and_its_101_validated() {
    let request = parse_request(UPGRADE).unwrap();
    let mut wire = Vec::new();
    let sent = encode_request(&mut wire, &request, Upload::None, &Audit::default()).unwrap();
    assert!(sent.handshake.is_some() && sent.upload.is_done());
    let text = String::from_utf8(wire).unwrap();
    assert!(text.contains("Sec-WebSocket-Protocol: anahita.live.v1\r\n"), "{text}");
    assert!(text.contains("Upgrade: websocket\r\n"), "{text}");

    let accept = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
        Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
        Sec-WebSocket-Protocol: anahita.live.v1\r\n\r\n\x01\x02hi";
    let mut relay = ResponseRelay::new(&sent, true);
    let mut out = Vec::new();
    let mut seen = 0;
    let (used, fed) = relay.feed(accept, &mut out, &mut |status, _| seen = status).unwrap();
    assert_eq!((fed, seen, relay.status()), (Fed::Upgraded, 101, 101));
    // The first frame stays with the caller: it belongs to the tunnel.
    assert_eq!(&accept[used..], b"\x01\x02hi");
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("Sec-WebSocket-Protocol: anahita.live.v1\r\n"), "{out}");
    assert!(out.ends_with("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"), "{out}");

    // A wrong accept key, or a 101 nobody asked for, is refused before the client sees it.
    let wrong = swap(accept, "s3pP", "XXXX");
    let mut relay = ResponseRelay::new(&sent, true);
    let mut out = Vec::new();
    let refused = relay.feed(&wrong, &mut out, &mut |_, _| {});
    assert_eq!(refused.err(), Some(ProxyError::UpstreamReadFailed));
    assert!(out.is_empty() && !relay.responded());
    let mut relay = ResponseRelay::new(&outbound(false), true);
    let refused = relay.feed(accept, &mut out, &mut |_, _| {});
    assert_eq!(refused.err(), Some(ProxyError::UpstreamReadFailed));

    // The origin may also decline with an ordinary response.
    let declined = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno";
    let mut relay = ResponseRelay::new(&sent, true);
    let mut out = Vec::new();
    let (_, fed) = relay.feed(declined, &mut out, &mut |_, _| {}).unwrap();
    assert_eq!(fed, Fed::Done(Outcome { client_keep: true, origin_reusable: true }));
}

#[test]
fn a_malformed_upgrade_is_refused_before_any_byte_is_encoded_for_the_origin() {
    let head = swap(UPGRADE, "Version: 13", "Version: 12");
    let request = parse_request(&head).unwrap();
    let refused = encode_request(&mut Vec::new(), &request, Upload::None, &Audit::default());
    assert_eq!(refused.err(), Some(ProxyError::InvalidUpgrade));
}

#[test]
fn uploads_pass_a_length_and_rechunk_a_chunked_body_in_any_pieces() {
    let head = b"POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n";
    let mut request = parse_request(head).unwrap();
    request.body = b"0123";
    let mut wire = Vec::new();
    let mut sent =
        encode_request(&mut wire, &request, Upload::Length(10), &Audit::default()).unwrap();
    assert!(!sent.retryable && !sent.poolable && !sent.buffered);
    assert!(wire.ends_with(b"\r\n\r\n0123"));
    // Bytes after the body belong to the next request and stay with the caller.
    let mut rest = b"456789GET".to_vec();
    assert_eq!(sent.upload.feed(&mut rest, &mut wire).unwrap(), 6);
    assert!(sent.upload.is_done() && wire.ends_with(b"0123456789"));

    let body = b"5;x=1\r\nhello\r\n6\r\n world\r\n0\r\nT: 1\r\n\r\nNEXT";
    let mut rng = Rng(7);
    for _ in 0..2_000 {
        let mut upload = UploadRelay::Chunked(Decoder::new());
        let (mut held, mut out, mut at) = (Vec::new(), Vec::new(), 0);
        while !upload.is_done() {
            let end = (at + 1 + rng.below(9)).min(body.len());
            held.extend_from_slice(&body[at..end]);
            at = end;
            let used = upload.feed(&mut held, &mut out).unwrap();
            held.drain(..used);
        }
        let mut check = Decoder::new();
        let step = check.decode(&mut out).unwrap();
        assert!(check.is_done());
        assert_eq!(&out[..step.output], b"hello world");
        held.extend_from_slice(&body[at..]);
        assert_eq!(held, b"NEXT");
    }
    let mut bad = b"zz\r\n".to_vec();
    let mut upload = UploadRelay::Chunked(Decoder::new());
    let refused = upload.feed(&mut bad, &mut Vec::new());
    assert_eq!(refused.err(), Some(ProxyError::MalformedRequestBody));
}
