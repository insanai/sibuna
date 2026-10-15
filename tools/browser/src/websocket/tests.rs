use std::io::{self, Cursor, Read, Write};

use sibuna_http::websocket::{self as ws, FrameError, Opcode, Role};

use super::*;

/// A server frame (unmasked) of any length, built by hand so that it may exceed the 4 KiB
/// bound of `sibuna_http::websocket::encode`.
fn server_frame(opcode: Opcode, fin: bool, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![opcode as u8 | if fin { 0x80 } else { 0 }];
    match payload.len() {
        short @ 0..=125 => frame.push(short as u8),
        medium @ 126..=65535 => {
            frame.push(126);
            frame.extend_from_slice(&(medium as u16).to_be_bytes());
        }
        long => {
            frame.push(127);
            frame.extend_from_slice(&(long as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

/// Feeds `bytes` to a reader in pieces of `step` bytes and collects every message.
fn read_all(bytes: &[u8], step: usize, max: usize) -> Result<Vec<Incoming>, FrameError> {
    let mut reader = MessageReader::new(max, Vec::new());
    let mut messages = Vec::new();
    for piece in bytes.chunks(step) {
        let mut source = Cursor::new(piece);
        // One read takes only part of a long piece; read until the piece is used up.
        while reader.read_from(&mut source).unwrap() > 0 {}
        while let Some(message) = reader.next_message()? {
            messages.push(message);
        }
    }
    Ok(messages)
}

#[test]
fn masks_and_keys_vary() {
    let mut source = MaskSource::new();
    let masks: Vec<[u8; 4]> = (0..16).map(|_| source.mask()).collect();
    assert!(masks.windows(2).any(|pair| pair[0] != pair[1]));
    let key = source.handshake_key();
    assert_eq!(key.len(), 24);
    assert!(ws::decode_key(key.as_bytes()).is_ok());
    assert_ne!(key, source.handshake_key());
}

fn response_for(key: &str) -> String {
    let accept = ws::accept_key(key.as_bytes()).unwrap();
    format!(
        "HTTP/1.1 101 WebSocket Protocol Handshake\r\nUpgrade: WebSocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        std::str::from_utf8(&accept).unwrap()
    )
}

#[test]
fn accepts_a_valid_response_and_refuses_others() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    assert!(check_response(response_for(key).as_bytes(), key).is_ok());
    let wrong_status = response_for(key).replace("101", "400");
    assert!(check_response(wrong_status.as_bytes(), key).is_err());
    let other_key = "AAAAAAAAAAAAAAAAAAAAAA==";
    assert!(check_response(response_for(other_key).as_bytes(), key).is_err());
    let no_upgrade = response_for(key).replace("Upgrade: WebSocket\r\n", "");
    assert!(check_response(no_upgrade.as_bytes(), key).is_err());
}

/// A stream whose reads come from a fixed script and whose writes are recorded.
struct Scripted {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    /// The most bytes one read returns.
    step: usize,
}

impl Scripted {
    fn new(input: Vec<u8>, step: usize) -> Scripted {
        Scripted { input: Cursor::new(input), output: Vec::new(), step }
    }
}

impl Read for Scripted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let limit = self.step.min(buffer.len());
        self.input.read(&mut buffer[..limit])
    }
}

impl Write for Scripted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn handshake_sends_the_request_and_keeps_early_frame_bytes() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let mut input = response_for(key).into_bytes();
    input.extend_from_slice(&server_frame(Opcode::Text, true, b"{}"));
    // Read all at once, the frame arrives with the head and is kept; read byte by byte,
    // the head is found before any frame byte is read.
    let mut stream = Scripted::new(input.clone(), usize::MAX);
    let rest = handshake(&mut stream, "127.0.0.1:9222", "/devtools/browser/x", key).unwrap();
    assert_eq!(rest, server_frame(Opcode::Text, true, b"{}"));
    let mut slow = Scripted::new(input, 1);
    let rest = handshake(&mut slow, "127.0.0.1:9222", "/devtools/browser/x", key).unwrap();
    assert!(rest.is_empty());
    let request = String::from_utf8(stream.output).unwrap();
    assert!(request.starts_with("GET /devtools/browser/x HTTP/1.1\r\n"));
    assert!(request.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
    assert!(request.ends_with("\r\n\r\n"));
}

#[test]
fn handshake_refuses_an_endless_head() {
    let input = format!("HTTP/1.1 101 OK\r\nX: {}", "a".repeat(9000)).into_bytes();
    let mut stream = Scripted::new(input, 100);
    assert!(matches!(
        handshake(&mut stream, "h", "/", "dGhlIHNhbXBsZSBub25jZQ=="),
        Err(Error::Handshake(_))
    ));
}

#[test]
fn decodes_headers_of_every_length_form() {
    let short = server_frame(Opcode::Text, true, b"hi");
    let header = decode_header(&short, 100).unwrap().unwrap();
    assert_eq!(
        (header.fin, header.opcode, header.header_len, header.payload_len),
        (true, Opcode::Text, 2, 2)
    );
    let medium = server_frame(Opcode::Binary, false, &[0; 300]);
    let header = decode_header(&medium, 1000).unwrap().unwrap();
    assert_eq!((header.fin, header.header_len, header.payload_len), (false, 4, 300));
    let long = server_frame(Opcode::Text, true, &[0; 70_000]);
    let header = decode_header(&long, 100_000).unwrap().unwrap();
    assert_eq!((header.header_len, header.payload_len), (10, 70_000));
    assert_eq!(decode_header(&long[..5], 100_000), Ok(None));
    assert_eq!(decode_header(&long, 69_999), Err(FrameError::TooLarge));
    assert_eq!(decode_header(&[], 10), Ok(None));
}

#[test]
fn refuses_malformed_headers() {
    // Reserved bit, reserved opcode, masked server frame.
    assert_eq!(decode_header(&[0xc1, 0x00], 10), Err(FrameError::Protocol));
    assert_eq!(decode_header(&[0x83, 0x00], 10), Err(FrameError::Protocol));
    assert_eq!(decode_header(&[0x81, 0x80, 1, 2, 3, 4], 10), Err(FrameError::Protocol));
    // A fragmented ping, a long close, a non-minimal 16-bit length.
    assert_eq!(decode_header(&[0x09, 0x00], 10), Err(FrameError::Protocol));
    assert_eq!(decode_header(&[0x88, 126, 0, 126], 1000), Err(FrameError::Protocol));
    assert_eq!(decode_header(&[0x81, 126, 0, 5], 1000), Err(FrameError::Protocol));
    // A 64-bit length with the top bit set.
    let mut huge = vec![0x81, 127];
    huge.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(decode_header(&huge, usize::MAX), Err(FrameError::Protocol));
}

#[test]
fn reassembles_large_and_fragmented_messages_from_small_reads() {
    let big = "x".repeat(200_000);
    let mut wire = server_frame(Opcode::Text, true, big.as_bytes());
    wire.extend(server_frame(Opcode::Text, false, b"{\"a\":"));
    wire.extend(server_frame(Opcode::Ping, true, b"p"));
    wire.extend(server_frame(Opcode::Continuation, true, b"1}"));
    wire.extend(server_frame(Opcode::Close, true, &1000u16.to_be_bytes()));
    for step in [1, 7, 4096, wire.len()] {
        let messages = read_all(&wire, step, 1 << 20).unwrap();
        assert_eq!(
            messages,
            vec![
                Incoming::Text(big.clone()),
                Incoming::Ping(b"p".to_vec()),
                Incoming::Text("{\"a\":1}".into()),
                Incoming::Close,
            ]
        );
    }
}

#[test]
fn decodes_frames_written_by_sibuna_http() {
    let mut buffer = [0u8; 64];
    let frame = ws::encode(&mut buffer, Opcode::Text, true, b"hello", Role::Server, None).unwrap();
    assert_eq!(read_all(frame, 3, 100).unwrap(), vec![Incoming::Text("hello".into())]);
}

#[test]
fn refuses_broken_sequences_and_text() {
    let continuation = server_frame(Opcode::Continuation, true, b"a");
    assert_eq!(read_all(&continuation, 64, 100), Err(FrameError::Protocol));
    let mut nested = server_frame(Opcode::Text, false, b"a");
    nested.extend(server_frame(Opcode::Text, true, b"b"));
    assert_eq!(read_all(&nested, 64, 100), Err(FrameError::Protocol));
    let invalid = server_frame(Opcode::Text, true, &[0xff, 0xfe]);
    assert_eq!(read_all(&invalid, 64, 100), Err(FrameError::InvalidUtf8));
    let mut too_long = server_frame(Opcode::Text, false, &[b'a'; 60]);
    too_long.extend(server_frame(Opcode::Continuation, true, &[b'a'; 60]));
    assert_eq!(read_all(&too_long, 64, 100), Err(FrameError::TooLarge));
    let bad_close = server_frame(Opcode::Close, true, &[3]);
    assert_eq!(read_all(&bad_close, 64, 100), Err(FrameError::Protocol));
}

/// Splits a client's wire bytes into (opcode, fin, unmasked payload) triples.
fn client_frames(mut wire: &[u8]) -> Vec<(Opcode, bool, Vec<u8>)> {
    let mut frames = Vec::new();
    while !wire.is_empty() {
        let frame = ws::decode(wire, Role::Server).unwrap().unwrap();
        let key = frame.mask.unwrap();
        let payload = frame.payload.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k).collect();
        frames.push((frame.opcode, frame.fin, payload));
        wire = &wire[frame.consumed..];
    }
    frames
}

#[test]
fn writes_masked_frames_and_fragments_long_text() {
    let mut writer = FrameWriter::new(MaskSource::new());
    let mut wire = Vec::new();
    let text = "y".repeat(MAX_MESSAGE * 2 + 10);
    writer.send_text(&mut wire, &text).unwrap();
    let frames = client_frames(&wire);
    let shape: Vec<(Opcode, bool, usize)> =
        frames.iter().map(|(opcode, fin, payload)| (*opcode, *fin, payload.len())).collect();
    assert_eq!(
        shape,
        vec![
            (Opcode::Text, false, MAX_MESSAGE),
            (Opcode::Continuation, false, MAX_MESSAGE),
            (Opcode::Continuation, true, 10),
        ]
    );
    let joined: Vec<u8> = frames.into_iter().flat_map(|(_, _, payload)| payload).collect();
    assert_eq!(joined, text.as_bytes());

    let mut wire = Vec::new();
    writer.send_text(&mut wire, "").unwrap();
    writer.send_pong(&mut wire, &[7; 200]).unwrap();
    writer.send_close(&mut wire).unwrap();
    let frames = client_frames(&wire);
    assert_eq!(frames[0], (Opcode::Text, true, Vec::new()));
    assert_eq!(frames[1], (Opcode::Pong, true, vec![7; MAX_CONTROL]));
    assert_eq!(frames[2], (Opcode::Close, true, 1000u16.to_be_bytes().to_vec()));
}

/// xorshift64*, for the fuzz test.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

/// Mutates valid wire bytes (bit flips, truncation, duplication, splicing) and checks that
/// the reader never panics and never returns more than its bound.
#[test]
fn fuzz_reader_never_panics_and_stays_bounded() {
    let mut seeds = Vec::new();
    seeds.push(server_frame(Opcode::Text, true, b"{\"id\":1,\"result\":{}}"));
    seeds.push(server_frame(Opcode::Text, true, &[b'z'; 300]));
    let mut fragmented = server_frame(Opcode::Text, false, b"ab");
    fragmented.extend(server_frame(Opcode::Ping, true, b"x"));
    fragmented.extend(server_frame(Opcode::Continuation, true, b"cd"));
    seeds.push(fragmented);
    seeds.push(server_frame(Opcode::Close, true, &1001u16.to_be_bytes()));
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    const BOUND: usize = 512;
    for _ in 0..100_000 {
        let mut input = seeds[rng.below(seeds.len())].clone();
        for _ in 0..1 + rng.below(4) {
            match rng.below(4) {
                0 if !input.is_empty() => {
                    let at = rng.below(input.len());
                    input[at] ^= 1 << rng.below(8);
                }
                1 => input.truncate(rng.below(input.len() + 1)),
                2 => input.extend_from_slice(&input.clone()),
                _ => {
                    let other = &seeds[rng.below(seeds.len())];
                    let cut = rng.below(other.len() + 1);
                    input.extend_from_slice(&other[cut..]);
                }
            }
        }
        if let Ok(messages) = read_all(&input, 1 + rng.below(64), BOUND) {
            for message in messages {
                let size = match message {
                    Incoming::Text(text) => text.len(),
                    Incoming::Binary(bytes) | Incoming::Ping(bytes) => bytes.len(),
                    Incoming::Pong | Incoming::Close => 0,
                };
                assert!(size <= BOUND);
            }
        }
    }
}
