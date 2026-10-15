//! The Zig decoder tests, ported, a reference decoder and deterministic fuzzing.

use super::*;
use crate::test_util::{Rng, mutate};

fn decode_all(raw: &[u8]) -> Result<Option<Vec<u8>>, ChunkError> {
    let mut bytes = raw.to_vec();
    let mut decoder = Decoder::new();
    let step = decoder.decode(&mut bytes)?;
    Ok(decoder.is_done().then(|| bytes[..step.output].to_vec()))
}

#[test]
fn decoder_recovers_bodies_under_the_full_rfc_grammar() {
    let cases: [(&[u8], &[u8]); 6] = [
        (b"5\r\nhello\r\n0\r\n\r\n", b"hello"),
        (b"0\r\n\r\n", b""),
        (b"A\r\n0123456789\r\n000\r\n\r\n", b"0123456789"),
        (b"3\r\n\r\n\r\r\n2;a\r\nxy\r\n0\r\n\r\n", b"\r\n\rxy"),
        (b"1 ; name = token ;q=\"a\\\"b; \\\\\"\r\nz\r\n0\r\nX-Sum: 1\r\nY:\r\n\r\n", b"z"),
        (b"000000000000000F\r\n0123456789abcde\r\n0;done\r\n\r\n", b"0123456789abcde"),
    ];
    for (raw, body) in cases {
        assert_eq!(decode_all(raw).unwrap().unwrap(), body, "{:?}", String::from_utf8_lossy(raw));
    }
}

#[test]
fn decoder_rejects_terminator_size_extension_and_trailer_ambiguities() {
    let mut long_line = b"1;".to_vec();
    long_line.extend(std::iter::repeat_n(b'a', MAX_LINE));
    long_line.extend_from_slice(b"\r\n");
    let bad: [&[u8]; 24] = [
        b"5\nhello\r\n0\r\n\r\n", // lone LF ends a size line for lenient parsers
        b"5\rX\r\nhello\r\n0\r\n\r\n", // lone CR inside the line
        b"5\r\nhello\n0\r\n\r\n", // data not followed by CRLF
        b"5\r\nhelloXY0\r\n\r\n",
        b"5 \r\nhello\r\n0\r\n\r\n", // whitespace with no extension
        b" 5\r\nhello\r\n0\r\n\r\n",
        b"+5\r\nhello\r\n0\r\n\r\n",
        b"0x5\r\nhello\r\n0\r\n\r\n",
        b"-1\r\nx\r\n0\r\n\r\n",
        b"\r\n",
        b"10000000000000000\r\n", // seventeen digits
        b"5;\r\nhello\r\n0\r\n\r\n",
        b"5;a=\r\nhello\r\n0\r\n\r\n",
        b"5;a b\r\nhello\r\n0\r\n\r\n",
        b"5;a=\"open\r\nhello\r\n0\r\n\r\n",
        b"5;a=\"x\ny\"\r\nhello\r\n0\r\n\r\n", // LF inside a quoted string
        b"5;a=\"x\ry\"\r\nhello\r\n0\r\n\r\n", // CR inside a quoted string
        b"5;a=\"x\x01\"\r\nhello\r\n0\r\n\r\n",
        b"0\r\nBad Name: x\r\n\r\n",
        b"0\r\nX : y\r\n\r\n",
        b"0\r\nno colon\r\n\r\n",
        b"0\r\nX: \x7f\r\n\r\n",
        b"0\r\n\n",
        &long_line,
    ];
    for raw in bad {
        assert_eq!(
            decode_all(raw),
            Err(ChunkError::Malformed),
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }
    let mut trailer = b"0\r\n".to_vec();
    let pad = format!("X-Pad: {}\r\n", "p".repeat(120));
    while trailer.len() <= 3 + MAX_TRAILER {
        trailer.extend_from_slice(pad.as_bytes());
    }
    trailer.extend_from_slice(b"\r\n");
    assert_eq!(decode_all(&trailer), Err(ChunkError::Malformed));
}

#[test]
fn a_line_of_exactly_max_line_bytes_is_accepted() {
    let mut line = b"1;".to_vec();
    line.extend(std::iter::repeat_n(b'a', MAX_LINE - 4));
    line.extend_from_slice(b"\r\nz\r\n0\r\n\r\n");
    assert_eq!(decode_all(&line).unwrap().unwrap(), b"z");
}

#[test]
fn incomplete_units_are_left_for_the_next_call() {
    let mut decoder = Decoder::new();
    let mut bytes = *b"5\r\nhel";
    assert_eq!(decoder.decode(&mut bytes), Ok(Step { output: 3, consumed: 6 }));
    let mut bytes = *b"lo\r";
    assert_eq!(decoder.decode(&mut bytes), Ok(Step { output: 2, consumed: 2 }));
    let mut bytes = *b"\r\n0\r\n\r\nGET";
    assert_eq!(decoder.decode(&mut bytes), Ok(Step { output: 0, consumed: 7 }));
    assert!(decoder.is_done());
    assert_eq!(decoder.decode(&mut bytes), Ok(Step { output: 0, consumed: 0 }));
}

#[test]
fn write_chunk_frames_canonically() {
    let mut out = Vec::new();
    write_chunk(&mut out, b"").unwrap();
    write_chunk(&mut out, b"hello").unwrap();
    write_chunk(&mut out, &[b'x'; 0x1ab]).unwrap();
    out.extend_from_slice(LAST_CHUNK);
    assert!(out.starts_with(b"5\r\nhello\r\n1ab\r\nxxx"));
    assert!(out.ends_with(b"xx\r\n0\r\n\r\n"));
    let mut line = [0u8; 18];
    let length = chunk_size_line(usize::MAX, &mut line);
    assert_eq!(&line[..length], b"ffffffffffffffff\r\n");
    let length = chunk_size_line(16, &mut line);
    assert_eq!(&line[..length], b"10\r\n");
}

/// Encodes `body` with random chunk sizes, extensions and trailers.
fn encode_random(rng: &mut Rng, body: &[u8], out: &mut Vec<u8>) {
    const EXTENSIONS: [&str; 5] = ["", ";a", " ; b = c", ";q=\"x\\\"y\"", ";n\t=\tv"];
    let mut at = 0;
    while at < body.len() {
        let size = (body.len() - at).min(1 + rng.below(40));
        let extension = rng.pick(&EXTENSIONS);
        let line = if rng.chance(2) {
            format!("{size:X}{extension}\r\n")
        } else {
            format!("{size:03x}{extension}\r\n")
        };
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(&body[at..at + size]);
        out.extend_from_slice(b"\r\n");
        at += size;
    }
    let end: &[u8] = if rng.chance(2) { b"0\r\n\r\n" } else { b"0;end\r\nX-Check: 7\r\n\r\n" };
    out.extend_from_slice(end);
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    failed: bool,
    done: bool,
    output: Vec<u8>,
}

/// Delivers `raw` in pieces (one piece when `whole`), carrying each call's unconsumed tail as
/// a connection reader does, and collects the decoded output. Checks on every call that the
/// decoder wrote nothing at or after the bytes it left unconsumed.
fn decode_split(rng: &mut Rng, raw: &[u8], whole: bool) -> Outcome {
    let mut work = Vec::new();
    let mut at = 0;
    let mut output = Vec::new();
    let mut decoder = Decoder::new();
    while at < raw.len() && !decoder.is_done() {
        let piece = if whole { raw.len() } else { (raw.len() - at).min(1 + rng.at_most(8)) };
        work.extend_from_slice(&raw[at..at + piece]);
        at += piece;
        let before = work.clone();
        // Output before a faulty unit is legitimately delivered earlier when split, so a
        // failure is compared by verdict alone.
        let Ok(step) = decoder.decode(&mut work) else {
            return Outcome { failed: true, done: false, output: Vec::new() };
        };
        assert!(step.output <= step.consumed && step.consumed <= work.len());
        assert_eq!(work[step.consumed..], before[step.consumed..], "wrote past the read index");
        output.extend_from_slice(&work[..step.output]);
        work.drain(..step.consumed);
    }
    Outcome { failed: false, done: decoder.is_done(), output }
}

#[test]
fn decoding_is_independent_of_how_the_stream_is_split_across_reads() {
    let mut rng = Rng::new(0x5eed_0009);
    let mutations = b"\r\n;0g \"\x01";
    for round in 0..3000 {
        // Data may hold any byte, including CR, LF and digits that look like framing.
        let body: Vec<u8> = (0..rng.at_most(160)).map(|_| b"\r\n0;a\" xZ"[rng.below(9)]).collect();
        let mut encoded = Vec::new();
        encode_random(&mut rng, &body, &mut encoded);
        if round % 2 == 1 {
            // A mutated stream may become invalid, incomplete or a different valid stream;
            // whichever it is, every split must reach the same verdict and output.
            let at = rng.below(encoded.len());
            encoded[at] = mutations[rng.below(mutations.len())];
        }
        let expected = decode_split(&mut rng, &encoded, true);
        let actual = decode_split(&mut rng, &encoded, false);
        assert_eq!(expected, actual);
        if round % 2 == 0 {
            assert!(expected.done);
            assert_eq!(expected.output, body);
        }
    }
}

mod reference;

#[test]
fn mutated_streams_agree_with_the_reference_decoder() {
    let mut rng = Rng::new(0xc4_0009);
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    for _ in 0..64 {
        let body: Vec<u8> = (0..rng.at_most(60)).map(|_| b"\r\n0;a\" xZ"[rng.below(9)]).collect();
        let mut encoded = Vec::new();
        encode_random(&mut rng, &body, &mut encoded);
        corpus.push(encoded);
    }
    let mut accepted = 0;
    for _ in 0..150_000 {
        let mut input = rng.pick(&corpus).clone();
        for _ in 0..1 + rng.below(3) {
            let other = rng.pick(&corpus).clone();
            mutate(&mut rng, &mut input, &other);
        }
        let expected = reference::decode(&input);
        let mut bytes = input.clone();
        let mut decoder = Decoder::new();
        let actual = decoder.decode(&mut bytes).map(|step| {
            assert_eq!(bytes[step.consumed..], input[step.consumed..]);
            (bytes[..step.output].to_vec(), step.consumed, decoder.is_done())
        });
        assert_eq!(actual, expected, "input {:?}", String::from_utf8_lossy(&input));
        accepted += usize::from(matches!(actual, Ok((_, _, true))));
    }
    assert!(accepted > 10_000, "{accepted} complete bodies");
}
