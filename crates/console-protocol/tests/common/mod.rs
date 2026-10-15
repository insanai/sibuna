//! Mutation helpers shared by the fuzz and differential tests.

// Each test crate uses a different part of these helpers.
#![allow(dead_code)]

/// A small xorshift generator; deterministic so failures reproduce.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

const SCALARS: [&str; 22] = [
    "0",
    "-1",
    "1.5",
    "8.0",
    "1e3",
    "1e400",
    "-0",
    "18446744073709551615",
    "18446744073709551616",
    "\"18446744073709551616\"",
    "\"9007199254740993\"",
    "\"+1_0\"",
    "\"\"",
    "null",
    "true",
    "[]",
    "{}",
    "[1,2,3]",
    "\"\\u00e9\\u0000\"",
    "\"stats\"",
    "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
    "4294967296",
];

/// Byte ranges of the scalars (numbers, strings, literals) in a JSON text.
pub fn scalar_spans(text: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let start = index;
        match text[index] {
            b'"' => {
                index += 1;
                while index < text.len() && text[index] != b'"' {
                    index += if text[index] == b'\\' { 2 } else { 1 };
                }
                index += 1;
            }
            b'-' | b'0'..=b'9' | b't' | b'f' | b'n' => {
                while index < text.len() && !b",]}: ".contains(&text[index]) {
                    index += 1;
                }
            }
            _ => {
                index += 1;
                continue;
            }
        }
        spans.push((start, index.min(text.len())));
    }
    spans
}

pub fn mutate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let seed = &seeds[rng.below(seeds.len())];
    let mut doc = seed.clone();
    for _ in 0..1 + rng.below(3) {
        match rng.below(9) {
            0 if !doc.is_empty() => {
                let at = rng.below(doc.len());
                doc[at] ^= 1 << rng.below(8);
            }
            1 => doc.truncate(rng.below(doc.len() + 1)),
            2 if !doc.is_empty() => {
                let start = rng.below(doc.len());
                let end = start + rng.below(doc.len() - start + 1).min(64);
                let copy = doc[start..end].to_vec();
                let at = rng.below(doc.len() + 1);
                doc.splice(at..at, copy);
            }
            3 => {
                let other = &seeds[rng.below(seeds.len())];
                let cut = rng.below(doc.len() + 1);
                let from = rng.below(other.len() + 1);
                doc.truncate(cut);
                doc.extend_from_slice(&other[from..]);
            }
            4..=6 => {
                let spans = scalar_spans(&doc);
                if let Some(&(start, end)) = spans.get(rng.below(spans.len())) {
                    let scalar = SCALARS[rng.below(SCALARS.len())].as_bytes().to_vec();
                    doc.splice(start..end, scalar);
                }
            }
            7 => {
                // Drop a member: remove from a key to the following comma.
                let spans = scalar_spans(&doc);
                if let Some(&(start, _)) = spans.get(rng.below(spans.len()))
                    && let Some(comma) = doc[start..].iter().position(|&b| b == b',')
                {
                    doc.drain(start..start + comma + 1);
                }
            }
            _ => {
                if let Some(brace) = doc.iter().position(|&b| b == b'{') {
                    let member = if rng.below(2) == 0 { "\"zz\":1," } else { "\"version\":1," };
                    doc.splice(brace + 1..brace + 1, member.bytes());
                }
            }
        }
    }
    doc
}

/// One token-level change: a scalar replaced or a member dropped. Most results stay valid
/// JSON, so they reach the decoders' checks rather than the parser's.
pub fn mutate_gently(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut doc = seeds[rng.below(seeds.len())].clone();
    let spans = scalar_spans(&doc);
    let Some(&(start, end)) = spans.get(rng.below(spans.len())) else { return doc };
    if rng.below(4) == 0 {
        if let Some(comma) = doc[start..].iter().position(|&b| b == b',') {
            doc.drain(start..start + comma + 1);
        }
    } else {
        doc.splice(start..end, SCALARS[rng.below(SCALARS.len())].bytes());
    }
    doc
}

/// FNV-1a over 64 bits, as Zig's `std.hash.Fnv1a_64`; it fingerprints long outputs.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}
