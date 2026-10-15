use sibuna_http::chunked::Decoder;

use super::*;
use crate::test_util::{Rng, Trickle, mutate};

fn read(
    input: &[u8],
    framing: Framing,
    capacity: usize,
    seed: u64,
) -> Result<Vec<u8>, ServeError> {
    let mut trickle = Trickle { bytes: input, rng: Rng::new(seed) };
    let mut output = vec![0u8; capacity];
    let mut transfer = [0u8; TRANSFER];
    let length = read_body(&mut trickle, framing, &mut output, &mut transfer)?;
    output.truncate(length);
    Ok(output)
}

#[test]
fn length_bodies_are_exact_and_bounded() {
    assert_eq!(read(b"hello", Framing::Length(5), 5, 1).unwrap(), b"hello");
    assert_eq!(read(b"hello world", Framing::Length(5), 64, 1).unwrap(), b"hello");
    assert_eq!(read(b"hello", Framing::Length(5), 4, 1), Err(ServeError::TooLarge));
    assert_eq!(read(b"hel", Framing::Length(5), 64, 1), Err(ServeError::EndOfStream));
    assert_eq!(read(b"anything", Framing::Empty, 0, 1).unwrap(), b"");
}

#[test]
fn chunked_bodies_decode_across_reads_and_bound_the_decoded_size() {
    let wire = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nTrailer: x\r\n\r\nNEXT";
    for seed in 1..100 {
        assert_eq!(read(wire, Framing::Chunked, 11, seed).unwrap(), b"hello world");
        assert_eq!(read(wire, Framing::Chunked, 10, seed), Err(ServeError::TooLarge));
    }
    assert_eq!(read(b"5\r\nhel", Framing::Chunked, 64, 1), Err(ServeError::EndOfStream));
    assert_eq!(
        read(b"5\nhello\r\n0\r\n\r\n", Framing::Chunked, 64, 1),
        Err(ServeError::InvalidRequest)
    );
    let mut long_line = b"1;".to_vec();
    long_line.resize(3 * MAX_LINE, b'a');
    assert_eq!(read(&long_line, Framing::Chunked, 64, 1), Err(ServeError::InvalidRequest));
}

#[test]
fn discarding_consumes_exactly_the_body() {
    let mut transfer = [0u8; TRANSFER];
    let mut input: &[u8] = b"3\r\nabc\r\n0\r\n\r\n";
    discard_body(&mut input, Framing::Chunked, &mut transfer).unwrap();
    let mut input: &[u8] = &[7u8; 20_000];
    discard_body(&mut input, Framing::Length(19_999), &mut transfer).unwrap();
    assert_eq!(input, [7]);
    let mut input: &[u8] = b"ab";
    assert_eq!(
        discard_body(&mut input, Framing::Length(3), &mut transfer),
        Err(ServeError::EndOfStream)
    );
}

/// A random, valid chunked encoding of random data, and the data.
fn encode(rng: &mut Rng) -> (Vec<u8>, Vec<u8>) {
    let mut wire = Vec::new();
    let mut data = Vec::new();
    for _ in 0..rng.below(5) {
        let size = 1 + rng.below(40);
        let chunk: Vec<u8> = (0..size).map(|_| rng.next() as u8).collect();
        let digits = if rng.chance(2) { format!("{size:x}") } else { format!("{size:04X}") };
        wire.extend_from_slice(digits.as_bytes());
        if rng.chance(3) {
            wire.extend_from_slice(b";name=value");
        }
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(&chunk);
        wire.extend_from_slice(b"\r\n");
        data.extend_from_slice(&chunk);
    }
    wire.extend_from_slice(b"0\r\n");
    if rng.chance(3) {
        wire.extend_from_slice(b"Trailer: value\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    (wire, data)
}

/// The reference: the whole input decoded in one call.
fn decode_at_once(wire: &[u8]) -> Option<Result<Vec<u8>, ()>> {
    let mut bytes = wire.to_vec();
    let mut decoder = Decoder::new();
    match decoder.decode(&mut bytes) {
        Err(_) => Some(Err(())),
        Ok(step) if decoder.is_done() => Some(Ok(bytes[..step.output].to_vec())),
        Ok(_) => None,
    }
}

#[test]
fn fuzz_chunked_bodies_agree_with_one_shot_decoding() {
    let mut rng = Rng::new(0x5eed_0002);
    for round in 0..100_000u64 {
        let (mut wire, data) = encode(&mut rng);
        let valid = rng.chance(4);
        if !valid {
            let (donor, _) = encode(&mut rng);
            mutate(&mut rng, &mut wire, &donor);
        }
        let capacity = rng.below(160);
        let result = read(&wire, Framing::Chunked, capacity, round);
        if valid {
            let expected =
                if data.len() <= capacity { Ok(data) } else { Err(ServeError::TooLarge) };
            assert_eq!(result, expected);
            continue;
        }
        match (decode_at_once(&wire), result) {
            (Some(Ok(decoded)), Ok(body)) => assert_eq!(decoded, body),
            (Some(Ok(decoded)), Err(error)) => {
                assert_eq!(error, ServeError::TooLarge);
                assert!(decoded.len() > capacity);
            }
            (Some(Err(())), Err(error)) => {
                assert!(matches!(error, ServeError::InvalidRequest | ServeError::TooLarge))
            }
            (None, Err(error)) => {
                assert!(matches!(error, ServeError::EndOfStream | ServeError::TooLarge))
            }
            (reference, result) => panic!("{wire:?}: {reference:?} but {result:?}"),
        }
    }
}
