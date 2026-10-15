//! Deterministic fuzzing of the frame decoder, the receiver and the frame reader.

use super::*;
use crate::test_util::{Rng, mutate};

/// What a frame decodes to, written straight from RFC 6455 section 5.2 with plain integer
/// arithmetic: `Ok(None)` while incomplete, else (fin, opcode bits, payload, mask, consumed).
type Decoded = Option<(bool, u8, Vec<u8>, Option<[u8; 4]>, usize)>;

fn reference(input: &[u8], role: Role) -> Result<Decoded, FrameError> {
    if input.len() < 2 {
        return Ok(None);
    }
    let fin = input[0] >> 7 == 1;
    let reserved = (input[0] >> 4) & 7;
    let opcode = input[0] & 15;
    let masked = input[1] >> 7 == 1;
    let marker = (input[1] & 127) as usize;
    if reserved != 0 || ![0, 1, 2, 8, 9, 10].contains(&opcode) {
        return Err(FrameError::Protocol);
    }
    if masked != (role == Role::Server) {
        return Err(FrameError::Protocol);
    }
    if opcode >= 8 && (!fin || marker > 125) {
        return Err(FrameError::Protocol);
    }
    let (length, mut at): (u128, usize) = match marker {
        126 if input.len() < 4 => return Ok(None),
        126 => (input[2] as u128 * 256 + input[3] as u128, 4),
        127 if input.len() < 10 => return Ok(None),
        127 => (input[2..10].iter().fold(0u128, |n, &b| n * 256 + b as u128), 10),
        short => (short as u128, 2),
    };
    let minimal = match marker {
        126 => length >= 126,
        127 => (65536..1 << 63).contains(&length),
        _ => true,
    };
    if !minimal {
        return Err(FrameError::Protocol);
    }
    if length > MAX_MESSAGE as u128 {
        return Err(FrameError::TooLarge);
    }
    let mut mask = None;
    if masked {
        if input.len() < at + 4 {
            return Ok(None);
        }
        mask = Some([input[at], input[at + 1], input[at + 2], input[at + 3]]);
        at += 4;
    }
    let end = at + length as usize;
    if input.len() < end {
        return Ok(None);
    }
    Ok(Some((fin, opcode, input[at..end].to_vec(), mask, end)))
}

fn random_frame(rng: &mut Rng, wire: &mut Vec<u8>) {
    const OPCODES: [Opcode; 6] = [
        Opcode::Continuation,
        Opcode::Text,
        Opcode::Binary,
        Opcode::Close,
        Opcode::Ping,
        Opcode::Pong,
    ];
    let opcode = *rng.pick(&OPCODES);
    let role = if rng.chance(2) { Role::Server } else { Role::Client };
    let mask =
        (role == Role::Client).then(|| rng.next_u64().to_le_bytes()[..4].try_into().unwrap());
    let length = *rng.pick(&[0, 1, 2, 5, 125, 126, 127, 300, 4096]);
    let mut payload: Vec<u8> = (0..length).map(|_| rng.byte() & 0x7f).collect();
    if opcode == Opcode::Close && payload.len() >= 2 {
        payload[..2].copy_from_slice(&1000u16.to_be_bytes());
    }
    let mut output = vec![0u8; MAX_HEADER + MAX_MESSAGE];
    let fin = opcode.is_control() || rng.chance(2);
    if let Ok(frame) = encode(&mut output, opcode, fin, &payload, role, mask) {
        // A frame always decodes back to what was encoded, by the receiving role.
        let receiver = if role == Role::Client { Role::Server } else { Role::Client };
        let back = decode(frame, receiver).unwrap().unwrap();
        assert_eq!(
            (back.fin, back.opcode, back.mask, back.consumed),
            (fin, opcode, mask, frame.len())
        );
        let mut plain = back.payload.to_vec();
        for (index, byte) in plain.iter_mut().enumerate() {
            *byte ^= mask.map_or(0, |key| key[index % 4]);
        }
        assert_eq!(plain, payload);
        wire.extend_from_slice(frame);
    }
}

#[test]
fn mutated_frames_agree_with_the_reference_decoder() {
    let mut rng = Rng::new(0x6455);
    let mut corpus = Vec::new();
    for _ in 0..200 {
        let mut wire = Vec::new();
        random_frame(&mut rng, &mut wire);
        corpus.push(wire);
    }
    corpus.push(vec![0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]);
    corpus.push(vec![0x81, 126, 0, 125]);
    let mut complete = 0;
    for _ in 0..150_000 {
        let mut input = rng.pick(&corpus).clone();
        for _ in 0..1 + rng.below(3) {
            let other = rng.pick(&corpus).clone();
            mutate(&mut rng, &mut input, &other);
        }
        for role in [Role::Server, Role::Client] {
            let expected = reference(&input, role);
            let actual = decode(&input, role).map(|frame| {
                frame.map(|f| (f.fin, f.opcode as u8, f.payload.to_vec(), f.mask, f.consumed))
            });
            assert_eq!(actual, expected, "{input:?}");
            if let Ok(Some(frame)) = decode(&input, role) {
                complete += 1;
                assert!(frame.consumed <= input.len() && frame.payload.len() <= MAX_MESSAGE);
                // The receiver never panics, and its events stay within its bounds.
                let mut receiver = Receiver::new();
                if let Ok(Event::Text(text)) = receiver.accept(&frame) {
                    assert!(text.len() <= MAX_MESSAGE);
                }
            }
        }
    }
    assert!(complete > 20_000, "{complete} complete frames");
}

/// Splits a random stream of frames into random reads and requires the frame reader to
/// produce the same events as decoding the whole stream at once.
#[test]
fn the_frame_reader_matches_whole_stream_decoding_under_random_splits() {
    struct Pieces<'a>(&'a [u8], Rng);
    impl std::io::Read for Pieces<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let count = (1 + self.1.below(64)).min(out.len()).min(self.0.len());
            out[..count].copy_from_slice(&self.0[..count]);
            self.0 = &self.0[count..];
            Ok(count)
        }
    }
    let mut rng = Rng::new(0x10);
    for _ in 0..500 {
        let mut wire = Vec::new();
        for _ in 0..1 + rng.below(6) {
            random_frame(&mut rng, &mut wire);
        }
        if wire.is_empty() {
            continue;
        }
        let role = if wire[1] & 0x80 != 0 { Role::Server } else { Role::Client };
        let mut whole = Vec::new();
        let mut receiver = Receiver::new();
        let mut at = 0;
        while let Ok(Some(frame)) = decode(&wire[at..], role) {
            at += frame.consumed;
            let event = receiver.accept(&frame).map(|e| format!("{e:?}"));
            let stop = event.is_err();
            whole.push(event);
            if stop {
                break;
            }
        }
        let mut reader = FrameReader::new(Pieces(&wire, Rng::new(rng.next_u64())));
        let mut receiver = Receiver::new();
        for expected in whole {
            let actual = reader.receive(&mut receiver, role).map(|e| format!("{e:?}"));
            match (actual, expected) {
                (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
                (Err(ReceiveError::Frame(actual)), Err(expected)) => assert_eq!(actual, expected),
                (actual, expected) => panic!("{actual:?} != {expected:?}"),
            }
        }
    }
}
