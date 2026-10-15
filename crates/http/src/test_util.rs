//! A deterministic pseudo-random generator and input mutations for the fuzz tests.

/// xorshift64*: small, fast and reproducible from its seed. Not for secrets.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `0..bound`; `bound` must be positive.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    /// A value in `0..=bound`.
    pub(crate) fn at_most(&mut self, bound: usize) -> usize {
        self.below(bound + 1)
    }

    pub(crate) fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    pub(crate) fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// Bytes that change the meaning of HTTP framing when inserted.
const SPECIAL: &[u8] = b"\r\n \t:\0,;=\"\x7f\x80?/";

/// Applies one random structural mutation to `input`, choosing among bit flips, insertion
/// of framing bytes, deletion, truncation, line duplication, case changes and splicing with
/// `other`.
pub(crate) fn mutate(rng: &mut Rng, input: &mut Vec<u8>, other: &[u8]) {
    let len = input.len();
    match rng.below(9) {
        0 if len > 0 => {
            let at = rng.below(len);
            input[at] ^= 1 << rng.below(8);
        }
        1 => {
            let byte = *rng.pick(SPECIAL);
            input.insert(rng.at_most(len), byte);
        }
        2 => {
            let at = rng.at_most(len);
            let piece: &[u8] = rng.pick(&[&b"\r\n"[..], b"\r\n\r\n", b"\n", b"\r"]);
            input.splice(at..at, piece.iter().copied());
        }
        3 if len > 0 => {
            input.remove(rng.below(len));
        }
        4 => input.truncate(rng.at_most(len)),
        5 => duplicate_line(rng, input),
        6 if len > 0 => {
            let start = rng.below(len);
            let end = (start + rng.at_most(16)).min(len);
            for byte in &mut input[start..end] {
                *byte = if byte.is_ascii_lowercase() {
                    byte.to_ascii_uppercase()
                } else {
                    byte.to_ascii_lowercase()
                };
            }
        }
        7 => {
            let keep = rng.at_most(len);
            let from = rng.at_most(other.len());
            input.truncate(keep);
            input.extend_from_slice(&other[from..]);
        }
        _ if len > 0 => {
            let at = rng.below(len);
            input[at] = rng.byte();
        }
        _ => input.push(rng.byte()),
    }
}

/// Copies a random CRLF-terminated line of `input` next to itself.
fn duplicate_line(rng: &mut Rng, input: &mut Vec<u8>) {
    let ends: Vec<usize> =
        input.windows(2).enumerate().filter(|(_, w)| w == b"\r\n").map(|(i, _)| i + 2).collect();
    if ends.len() < 2 {
        return;
    }
    let index = 1 + rng.below(ends.len() - 1);
    let line = input[ends[index - 1]..ends[index]].to_vec();
    input.splice(ends[index]..ends[index], line);
}

/// True when `part` lies inside `whole` (an empty `part` may sit at its end).
pub(crate) fn within(whole: &[u8], part: &[u8]) -> bool {
    let start = whole.as_ptr() as usize;
    let at = part.as_ptr() as usize;
    at >= start && at + part.len() <= start + whole.len()
}
