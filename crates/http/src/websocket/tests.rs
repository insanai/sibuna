//! The Zig WebSocket tests (codec, reader and handshake), ported, and new tests of the Rust
//! reader and upgrade check.

use super::*;
use crate::parse_request;

fn decoded(input: &[u8], role: Role) -> Frame<'_> {
    decode(input, role).unwrap().expect("a complete frame")
}

#[test]
fn rfc_masked_hello_vector_and_every_truncated_prefix() {
    let wire = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
    for n in 0..wire.len() {
        assert_eq!(decode(&wire[..n], Role::Server), Ok(None));
    }
    let frame = decoded(&wire, Role::Server);
    let mut receiver = Receiver::new();
    assert_eq!(receiver.accept(&frame), Ok(Event::Text("Hello")));
    assert_eq!(frame.consumed, wire.len());
    assert_eq!(decode(&wire, Role::Client), Err(FrameError::Protocol));
    let mut output = [0u8; 32];
    let mask = Some([0x37, 0xfa, 0x21, 0x3d]);
    let encoded = encode(&mut output, Opcode::Text, true, b"Hello", Role::Client, mask).unwrap();
    assert_eq!(encoded, wire);
}

#[test]
fn fragmented_utf8_survives_interleaved_control_and_arbitrary_frame_boundaries() {
    let mut receiver = Receiver::new();
    let mut wire = [0u8; 32];
    let encoded = encode(&mut wire, Opcode::Text, false, &[0xe2], Role::Server, None).unwrap();
    assert_eq!(receiver.accept(&decoded(encoded, Role::Client)), Ok(Event::Fragment));
    let encoded = encode(&mut wire, Opcode::Ping, true, b"ping", Role::Server, None).unwrap();
    assert_eq!(receiver.accept(&decoded(encoded, Role::Client)), Ok(Event::Ping(b"ping")));
    let encoded =
        encode(&mut wire, Opcode::Continuation, true, &[0x82, 0xac], Role::Server, None).unwrap();
    assert_eq!(receiver.accept(&decoded(encoded, Role::Client)), Ok(Event::Text("\u{20ac}")));
    let encoded = encode(&mut wire, Opcode::Continuation, true, b"", Role::Server, None).unwrap();
    assert_eq!(receiver.accept(&decoded(encoded, Role::Client)), Err(FrameError::Protocol));
}

#[test]
fn reject_malformed_headers_before_payload_allocation() {
    let invalid: [&[u8]; 7] = [
        &[0xc1, 0],           // Reserved bits without negotiated extensions.
        &[0x83, 0],           // Reserved opcode.
        &[0x09, 0],           // Fragmented control.
        &[0x89, 126],         // Oversized control.
        &[0x81, 126, 0, 125], // Non-minimal length.
        &[0x81, 127, 0, 0, 0, 0, 0, 0, 0, 126],
        &[0x81, 127, 0x80, 0, 0, 0, 0, 1, 0, 0],
    ];
    for wire in invalid {
        assert_eq!(decode(wire, Role::Client), Err(FrameError::Protocol), "{wire:?}");
    }
    assert_eq!(decode(&[0x82, 126, 0x10, 0x01], Role::Client), Err(FrameError::TooLarge));
    assert_eq!(decode(&[0x81, 0], Role::Server), Err(FrameError::Protocol));
}

#[test]
fn aggregate_fragments_bounded_independently_of_each_frame() {
    let mut receiver = Receiver::new();
    let mut wire = vec![0u8; MAX_MESSAGE + 8];
    let payload = vec![b'a'; MAX_MESSAGE];
    let mask = Some([1, 2, 3, 4]);
    let encoded = encode(&mut wire, Opcode::Binary, false, &payload, Role::Client, mask).unwrap();
    assert_eq!(receiver.accept(&decoded(encoded, Role::Server)), Ok(Event::Fragment));
    let mask = Some([5, 6, 7, 8]);
    let encoded = encode(&mut wire, Opcode::Continuation, true, b"x", Role::Client, mask).unwrap();
    assert_eq!(receiver.accept(&decoded(encoded, Role::Server)), Err(FrameError::TooLarge));
}

#[test]
fn new_data_frame_during_fragmentation_and_invalid_text_fail() {
    let mut receiver = Receiver::new();
    receiver.accept(&decoded(&[0x01, 0], Role::Client)).unwrap();
    assert_eq!(receiver.accept(&decoded(&[0x82, 0], Role::Client)), Err(FrameError::Protocol));
    let mut receiver = Receiver::new();
    let frame = decoded(&[0x81, 2, 0xc0, 0x80], Role::Client);
    assert_eq!(receiver.accept(&frame), Err(FrameError::InvalidUtf8));
}

#[test]
fn close_validates_status_and_reason_forbids_further_input() {
    for code in [999u16, 1004, 1005, 1006, 1015, 2000, 5000] {
        assert_eq!(validate_close(&code.to_be_bytes()), Err(FrameError::Protocol), "{code}");
    }
    assert_eq!(validate_close(&[0]), Err(FrameError::Protocol));
    assert_eq!(validate_close(&[3, 232, 255]), Err(FrameError::InvalidUtf8));
    for code in [1000u16, 1003, 1007, 1014, 3000, 4999] {
        assert_eq!(validate_close(&code.to_be_bytes()), Ok(()), "{code}");
    }
    let mut receiver = Receiver::new();
    assert_eq!(receiver.accept(&decoded(&[0x88, 0], Role::Client)), Ok(Event::Close(b"")));
    assert!(receiver.is_closed());
    assert_eq!(receiver.accept(&decoded(&[0x89, 0], Role::Client)), Err(FrameError::Closed));
}

#[test]
fn writer_enforces_capacity_and_masking_direction() {
    let mut output = [0u8; 1];
    let text = Opcode::Text;
    assert_eq!(encode(&mut output, text, true, b"", Role::Server, None), Err(FrameError::NoSpace));
    assert_eq!(
        encode(&mut output, text, true, b"", Role::Client, None),
        Err(FrameError::Protocol)
    );
    let ping = Opcode::Ping;
    assert_eq!(
        encode(&mut output, ping, false, b"", Role::Server, None),
        Err(FrameError::Protocol)
    );
    let mut big = vec![0u8; 2 * MAX_MESSAGE];
    let long = vec![0u8; MAX_MESSAGE + 1];
    assert_eq!(encode(&mut big, text, true, &long, Role::Server, None), Err(FrameError::TooLarge));
    let close = Opcode::Close;
    assert_eq!(encode(&mut big, close, true, &[0], Role::Server, None), Err(FrameError::Protocol));
}

#[test]
fn one_bounded_reader_supports_masked_clients_and_unmasked_servers() {
    let mut bytes = vec![0u8; MAX_MESSAGE + MAX_HEADER];
    let payload = "a".repeat(512);
    for role in [Role::Server, Role::Client] {
        let sending = if role == Role::Server { Role::Client } else { Role::Server };
        let mask = (sending == Role::Client).then_some([1, 2, 3, 4]);
        let frame =
            encode(&mut bytes, Opcode::Text, true, payload.as_bytes(), sending, mask).unwrap();
        let mut reader = FrameReader::new(frame);
        let mut receiver = Receiver::new();
        let event = reader.receive(&mut receiver, role).unwrap();
        assert_eq!(event, Event::Text(&payload));
        let mut reader = FrameReader::new(frame);
        let error = reader.receive(&mut receiver, sending).unwrap_err();
        assert!(matches!(error, ReceiveError::Frame(FrameError::Protocol)));
    }
    let complete = encode(&mut bytes, Opcode::Text, true, b"Hello", Role::Server, None).unwrap();
    let complete = complete.to_vec();
    for length in 0..complete.len() {
        let mut truncated = FrameReader::new(&complete[..length]);
        let mut pending = Receiver::new();
        let error = truncated.receive(&mut pending, Role::Client).unwrap_err();
        assert!(matches!(error, ReceiveError::EndOfStream), "{length}");
    }
    let mut reader = FrameReader::new(&[0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0][..]);
    let mut receiver = Receiver::new();
    let error = reader.receive(&mut receiver, Role::Client).unwrap_err();
    assert!(matches!(error, ReceiveError::Frame(FrameError::TooLarge)));
    let mut reader = FrameReader::new(&[0x89, 126][..]);
    let error = reader.receive(&mut receiver, Role::Client).unwrap_err();
    assert!(matches!(error, ReceiveError::Frame(FrameError::Protocol)));
}

/// Yields at most `step` bytes per read and fails every other read with `WouldBlock`, like
/// a socket with a short deadline.
struct Trickle<'a> {
    bytes: &'a [u8],
    step: usize,
    stall: bool,
}

impl std::io::Read for Trickle<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.stall = !self.stall;
        if self.stall {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let count = self.step.min(out.len()).min(self.bytes.len());
        out[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn a_failed_read_keeps_the_partial_frame_and_frames_cross_compaction() {
    let mut wire = Vec::new();
    let mut buffer = vec![0u8; MAX_MESSAGE + MAX_HEADER];
    for (index, length) in [5usize, 300, 125, 126, 4000].into_iter().enumerate() {
        let payload = vec![b'0' + index as u8; length];
        let mask = Some([9, 8, 7, index as u8]);
        let frame =
            encode(&mut buffer, Opcode::Binary, true, &payload, Role::Client, mask).unwrap();
        wire.extend_from_slice(frame);
    }
    let mut reader = FrameReader::new(Trickle { bytes: &wire, step: 7, stall: false });
    let mut receiver = Receiver::new();
    let mut lengths = Vec::new();
    while lengths.len() < 5 {
        match reader.receive(&mut receiver, Role::Server) {
            Ok(Event::Binary(payload)) => lengths.push(payload.len()),
            Err(ReceiveError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(lengths, [5, 300, 125, 126, 4000]);
    assert!(reader.buffered().is_empty());
    let mut small = FrameReader::with_capacity(&wire[..], 16);
    assert!(matches!(small.receive(&mut receiver, Role::Server), Ok(Event::Binary(b"00000"))));
    let error = small.receive(&mut receiver, Role::Server).unwrap_err();
    assert!(matches!(error, ReceiveError::Frame(FrameError::NoSpace)));
}

#[test]
fn upgrade_key_validates_its_bounded_base64_and_matches_the_rfc_6455_acceptance_vector() {
    assert_eq!(&accept_key(b"dGhlIHNhbXBsZSBub25jZQ==").unwrap(), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    let twenty_five = [b'A'; 25];
    let invalid: [&[u8]; 4] = [b"", b"AAAA", b"!!!!!!!!!!!!!!!!!!!!!!==", &twenty_five];
    for encoded in invalid {
        assert_eq!(decode_key(encoded), Err(HandshakeError::InvalidRequest));
    }
    assert!(contains_token(b"keep-alive, Upgrade", b"upgrade"));
    assert!(!contains_token(b"not-upgrade", b"upgrade"));
}

#[test]
fn upgrade_requests_are_checked_field_by_field() {
    let valid = "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: WebSocket\r\n\
        Connection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    let request = parse_request(valid.as_bytes()).unwrap();
    assert_eq!(upgrade_key(&request), Ok(&b"dGhlIHNhbXBsZSBub25jZQ=="[..]));
    let broken = [
        valid.replace("GET", "POST"),
        valid.replace("HTTP/1.1", "HTTP/1.0"),
        valid.replace("Host: a\r\n", "Expect: 100-continue\r\n"),
        valid.replace("Host: a\r\n", "Content-Length: 0\r\n"),
        valid.replace("Host: a\r\n", "Transfer-Encoding: chunked\r\n"),
        valid.replace("Version: 13", "Version: 8"),
        valid.replace("Upgrade: WebSocket", "Upgrade: h2c"),
        valid.replace("keep-alive, Upgrade", "keep-alive"),
        valid.replace("Host: a\r\n", "Upgrade: websocket\r\n"),
        valid.replace("Host: a\r\n", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"),
        valid.replace("dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZQ=="),
        valid.replace("Sec-WebSocket-Version: 13\r\n", ""),
    ];
    for raw in broken {
        let request = parse_request(raw.as_bytes()).unwrap();
        assert_eq!(upgrade_key(&request), Err(HandshakeError::InvalidRequest), "{raw}");
    }
}
