//! Helpers shared by the unit tests: a deterministic PRNG, input mutation and socket pairs.

use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};

/// A xorshift64* generator: deterministic, dependency-free and good enough for fuzzing.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `0..bound`; `bound` must be positive.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    pub(crate) fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Bytes that matter to HTTP framing, favoured by the mutator.
const SPECIAL: &[u8] = b"\r\n:; \t,=?/\x00\x7f\xff0123456789abcdefABCDEF";

/// Mutates `input` in place with one to four edits: bit flips, special bytes, truncation,
/// duplication of a range, deletion, or splicing in part of `donor`.
pub(crate) fn mutate(rng: &mut Rng, input: &mut Vec<u8>, donor: &[u8]) {
    for _ in 0..1 + rng.below(4) {
        let at = if input.is_empty() { 0 } else { rng.below(input.len()) };
        match rng.below(7) {
            0 if !input.is_empty() => input[at] ^= 1 << rng.below(8),
            1 if !input.is_empty() => input[at] = *rng.pick(SPECIAL),
            2 => input.truncate(at),
            3 if !input.is_empty() => {
                let end = (at + 1 + rng.below(16)).min(input.len());
                let copy = input[at..end].to_vec();
                let into = rng.below(input.len() + 1);
                input.splice(into..into, copy);
            }
            4 if !input.is_empty() => {
                let end = (at + 1 + rng.below(8)).min(input.len());
                input.drain(at..end);
            }
            5 if !donor.is_empty() => {
                let from = rng.below(donor.len());
                let end = (from + 1 + rng.below(32)).min(donor.len());
                input.splice(at..at, donor[from..end].iter().copied());
            }
            _ => input.insert(at, *rng.pick(SPECIAL)),
        }
    }
}

/// A reader that hands out its bytes in pieces of random length, as a socket might.
pub(crate) struct Trickle<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) rng: Rng,
}

impl Read for Trickle<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = (1 + self.rng.below(64)).min(out.len()).min(self.bytes.len());
        let (head, rest) = self.bytes.split_at(count);
        out[..count].copy_from_slice(head);
        self.bytes = rest;
        Ok(count)
    }
}

/// A connected pair of loopback sockets: (server side, client side).
pub(crate) fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, client)
}
