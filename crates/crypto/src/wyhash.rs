//! Wyhash, bit for bit identical to Zig 0.16's `std.hash.Wyhash`.
//!
//! Wyhash is a fast non-cryptographic hash. Sibuna stores Wyhash values in session tokens
//! (the rule hash) and uses them as table keys, so a Rust node must compute exactly the
//! values a Zig node computes. This is a port of Zig's implementation, which is "final
//! version 4" of Wang Yi's design with Zig's own streaming buffer. The one-shot [`hash`]
//! and the streaming [`Wyhash`] agree for every way of splitting the input.

/// The default secret of wyhash final version 4.
const SECRET: [u64; 4] =
    [0xa0761d6478bd642f, 0xe7037ed1a0b428db, 0x8ebc6af09c88c6e3, 0x589965cc75374cc3];

/// A streaming Wyhash hasher.
///
/// ```
/// use sibuna_crypto::wyhash::{self, Wyhash};
/// let mut hasher = Wyhash::new(0x5151_b0b0);
/// hasher.update(b"bot/");
/// hasher.update(b"gptbot");
/// assert_eq!(hasher.finish(), wyhash::hash(0x5151_b0b0, b"bot/gptbot"));
/// ```
#[derive(Clone, Debug)]
pub struct Wyhash {
    state: [u64; 3],
    total_len: u64,
    /// Unprocessed input. A full 48-byte block stays here until more input arrives, because
    /// the last block of the message is processed by the finishing steps instead. After a
    /// block has been processed, `buf[32..48]` still holds its last 16 bytes, which the
    /// finishing steps may need.
    buf: [u8; 48],
    buf_len: usize,
}

impl Wyhash {
    /// A hasher that has absorbed nothing, with the given `seed`.
    pub fn new(seed: u64) -> Self {
        Self { state: initial_state(seed), total_len: 0, buf: [0; 48], buf_len: 0 }
    }

    /// Absorbs `input`. Never fails.
    pub fn update(&mut self, input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);
        if input.len() <= 48 - self.buf_len {
            self.buf[self.buf_len..self.buf_len + input.len()].copy_from_slice(input);
            self.buf_len += input.len();
            return;
        }
        let mut i = 0;
        if self.buf_len > 0 {
            i = 48 - self.buf_len;
            self.buf[self.buf_len..].copy_from_slice(&input[..i]);
            round(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        i += absorb_blocks(&mut self.state, &input[i..]);
        let remaining = &input[i..];
        if remaining.len() < 16 && i >= 48 {
            // The finishing steps read the 16 bytes before the end; keep the ones that
            // precede `remaining` at the end of the buffer.
            let missing = 16 - remaining.len();
            self.buf[48 - missing..].copy_from_slice(&input[i - missing..i]);
        }
        self.buf[..remaining.len()].copy_from_slice(remaining);
        self.buf_len = remaining.len();
    }

    /// Returns the hash of everything absorbed so far. The hasher is unchanged.
    pub fn finish(&self) -> u64 {
        let input = &self.buf[..self.buf_len];
        let mut core = Core { state: self.state, a: 0, b: 0 };
        if self.total_len <= 16 {
            core.small_key(input);
        } else if self.buf_len < 16 {
            // Rebuild the last 16 bytes of the message from the tail of the previous block.
            let missing = 16 - self.buf_len;
            let mut scratch = [0u8; 16];
            scratch[..missing].copy_from_slice(&self.buf[48 - missing..]);
            scratch[missing..].copy_from_slice(input);
            core.fold_lanes();
            core.final1(&scratch, missing);
        } else {
            core.fold_lanes();
            core.final1(input, 0);
        }
        core.final2(self.total_len)
    }
}

impl core::hash::Hasher for Wyhash {
    fn finish(&self) -> u64 {
        Wyhash::finish(self)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// Returns the Wyhash of `input` with `seed`, equal to Zig's `std.hash.Wyhash.hash`.
pub fn hash(seed: u64, input: &[u8]) -> u64 {
    let mut core = Core { state: initial_state(seed), a: 0, b: 0 };
    if input.len() <= 16 {
        core.small_key(input);
    } else {
        let mut i = 0;
        if input.len() >= 48 {
            i = absorb_blocks(&mut core.state, input);
            core.fold_lanes();
        }
        core.final1(input, i);
    }
    core.final2(input.len() as u64)
}

/// The finishing state shared by the one-shot and the streaming paths.
struct Core {
    state: [u64; 3],
    a: u64,
    b: u64,
}

impl Core {
    /// Inputs of at most 16 bytes are read whole into `a` and `b`.
    fn small_key(&mut self, input: &[u8]) {
        let len = input.len();
        if len >= 4 {
            let end = len - 4;
            let quarter = (len >> 3) << 2;
            // 4 <= len <= 16, so `quarter <= end` and every 4-byte read lies in `input`.
            self.a = (read4(input, 0) << 32) | read4(input, quarter);
            self.b = (read4(input, end) << 32) | read4(input, end - quarter);
        } else if len > 0 {
            self.a = (u64::from(input[0]) << 16)
                | (u64::from(input[len >> 1]) << 8)
                | u64::from(input[len - 1]);
            self.b = 0;
        } else {
            self.a = 0;
            self.b = 0;
        }
    }

    fn fold_lanes(&mut self) {
        self.state[0] ^= self.state[1] ^ self.state[2];
    }

    /// Mixes the last at most 48 bytes, `input[start..]`, in 16-byte steps and loads the
    /// final 16 bytes of `input` into `a` and `b`. `input` holds at least 16 bytes; bytes
    /// before `start` are only read for that final load.
    fn final1(&mut self, input: &[u8], start: usize) {
        // Callers pass `start <= input.len()` and `input.len() >= 16`, so every read below
        // lies in `input`.
        let mut i = start;
        while i + 16 < input.len() {
            self.state[0] = mix(read8(input, i) ^ SECRET[1], read8(input, i + 8) ^ self.state[0]);
            i += 16;
        }
        self.a = read8(input, input.len() - 16);
        self.b = read8(input, input.len() - 8);
    }

    fn final2(mut self, total_len: u64) -> u64 {
        self.a ^= SECRET[1];
        self.b ^= self.state[0];
        let (a, b) = mum(self.a, self.b);
        mix(a ^ SECRET[0] ^ total_len, b ^ SECRET[1])
    }
}

fn initial_state(seed: u64) -> [u64; 3] {
    [seed ^ mix(seed ^ SECRET[0], SECRET[1]); 3]
}

/// Mixes one 48-byte block into the three lanes.
fn round(state: &mut [u64; 3], block: &[u8; 48]) {
    let (pairs, _) = block.as_chunks::<16>();
    for ((lane, pair), secret) in state.iter_mut().zip(pairs).zip(&SECRET[1..]) {
        let (a, b) = pair.split_at(8);
        *lane = mix(read8(a, 0) ^ secret, read8(b, 0) ^ *lane);
    }
}

/// Mixes every whole 48-byte block of `input` except the last one, which the finishing
/// steps need even when it is complete. Returns the number of bytes consumed.
fn absorb_blocks(state: &mut [u64; 3], input: &[u8]) -> usize {
    let count = input.len().saturating_sub(1) / 48;
    for block in input.as_chunks::<48>().0.iter().take(count) {
        round(state, block);
    }
    count * 48
}

/// The 128-bit product of `a` and `b`, as (low, high) halves.
fn mum(a: u64, b: u64) -> (u64, u64) {
    let product = u128::from(a) * u128::from(b);
    (product as u64, (product >> 64) as u64)
}

fn mix(a: u64, b: u64) -> u64 {
    let (low, high) = mum(a, b);
    low ^ high
}

/// Reads 8 little-endian bytes at `at`; callers guarantee `at + 8 <= bytes.len()`.
fn read8(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

/// Reads 4 little-endian bytes at `at`; callers guarantee `at + 4 <= bytes.len()`.
fn read4(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u64::from(u32::from_le_bytes(word))
}

#[cfg(test)]
mod tests;
