//! BLAKE3: hashing, keyed hashing and key derivation, with extendable output.
//!
//! This is a portable implementation of the BLAKE3 specification (O'Connor, Aumasson, Neves
//! and Wilcox-O'Hearn, 2020). It follows the structure of the reference implementation: a
//! chunk state that compresses 64-byte blocks of the current 1 KiB chunk, and a stack of
//! chaining values that merges completed subtrees. Sibuna hashes short inputs with BLAKE3
//! (token tags, fingerprints, the key schedule), so the SIMD paths that pay off on large
//! inputs are left out.
//!
//! Outputs are identical to Zig's `std.crypto.hash.Blake3`; a shorter output is a prefix of
//! a longer one, as the specification requires.

/// Length of the default output in bytes.
pub const OUT_LEN: usize = 32;

/// Length of a key in bytes.
pub const KEY_LEN: usize = 32;

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

/// Enough chaining values for 2^54 chunks, that is 2^64 bytes of input.
const MAX_DEPTH: usize = 54;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// The message word order of each of the seven rounds: the specification's permutation
/// applied zero to six times.
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// The quarter-round function G.
#[inline(always)]
fn g(v: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// One round: G on the four columns, then on the four diagonals.
#[inline(always)]
fn round(v: &mut [u32; 16], m: &[u32; 16], s: &[usize; 16]) {
    g(v, [0, 4, 8, 12], m[s[0]], m[s[1]]);
    g(v, [1, 5, 9, 13], m[s[2]], m[s[3]]);
    g(v, [2, 6, 10, 14], m[s[4]], m[s[5]]);
    g(v, [3, 7, 11, 15], m[s[6]], m[s[7]]);
    g(v, [0, 5, 10, 15], m[s[8]], m[s[9]]);
    g(v, [1, 6, 11, 12], m[s[10]], m[s[11]]);
    g(v, [2, 7, 8, 13], m[s[12]], m[s[13]]);
    g(v, [3, 4, 9, 14], m[s[14]], m[s[15]]);
}

/// The compression function; returns the full 16-word state.
fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut v = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    for schedule in &MSG_SCHEDULE {
        round(&mut v, block, schedule);
    }
    for i in 0..8 {
        v[i] ^= v[i + 8];
        v[i + 8] ^= cv[i];
    }
    v
}

fn first_8_words(state: [u32; 16]) -> [u32; 8] {
    let mut out = [0u32; 8];
    out.copy_from_slice(&state[..8]);
    out
}

fn words_from_le_bytes<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut words = [0u32; N];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    words
}

/// The inputs of a compression whose output is not decided yet: either a chaining value for
/// the parent, or root output bytes.
struct Output {
    input_cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    /// Fills `out` with root output bytes; output block `i` uses counter `i`.
    fn root_output_bytes(&self, out: &mut [u8]) {
        for (counter, out_block) in (0u64..).zip(out.chunks_mut(2 * OUT_LEN)) {
            let words =
                compress(&self.input_cv, &self.block, counter, self.block_len, self.flags | ROOT);
            for (bytes, word) in out_block.chunks_mut(4).zip(words) {
                bytes.copy_from_slice(&word.to_le_bytes()[..bytes.len()]);
            }
        }
    }
}

/// The state of the chunk being absorbed.
#[derive(Clone)]
struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    blocks_compressed: usize,
    flags: u32,
}

impl ChunkState {
    fn new(key: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            cv: *key,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed + self.block_len
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 { CHUNK_START } else { 0 }
    }

    /// Absorbs at most the rest of this chunk. The last block stays buffered, because it is
    /// compressed with the `CHUNK_END` flag once we know no more input follows.
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len == BLOCK_LEN {
                let words = words_from_le_bytes(&self.block);
                let flags = self.flags | self.start_flag();
                let state =
                    compress(&self.cv, &words, self.chunk_counter, BLOCK_LEN as u32, flags);
                self.cv = first_8_words(state);
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let take = (BLOCK_LEN - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_cv: self.cv,
            block: words_from_le_bytes(&self.block),
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(left: &[u32; 8], right: &[u32; 8], key: &[u32; 8], flags: u32) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(left);
    block[8..].copy_from_slice(right);
    Output {
        input_cv: *key,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flags | PARENT,
    }
}

/// An incremental BLAKE3 hasher in one of the three modes.
///
/// The state is a plain value of about 1.9 KiB (mostly the stack of subtree chaining
/// values), so a hasher can be cloned to fork a common prefix.
///
/// ```
/// use sibuna_crypto::blake3;
/// let mut hasher = blake3::Hasher::new();
/// hasher.update(b"ab").update(b"c");
/// assert_eq!(hasher.finalize(), blake3::hash(b"abc"));
/// ```
#[derive(Clone)]
pub struct Hasher {
    chunk_state: ChunkState,
    key: [u32; 8],
    cv_stack: [[u32; 8]; MAX_DEPTH],
    cv_stack_len: usize,
    flags: u32,
}

impl Hasher {
    fn with_key_words(key: [u32; 8], flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(&key, 0, flags),
            key,
            cv_stack: [[0; 8]; MAX_DEPTH],
            cv_stack_len: 0,
            flags,
        }
    }

    /// A hasher for the default hash mode.
    pub fn new() -> Self {
        Self::with_key_words(IV, 0)
    }

    /// A hasher for the keyed hash mode, a MAC and PRF keyed with `key`.
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        Self::with_key_words(words_from_le_bytes(key), KEYED_HASH)
    }

    /// A hasher for the key derivation mode. `context` should be a hardcoded, globally
    /// unique string describing the purpose of the derived key; the key material is then
    /// absorbed with [`Hasher::update`].
    pub fn new_derive_key(context: &str) -> Self {
        let mut context_hasher = Self::with_key_words(IV, DERIVE_KEY_CONTEXT);
        context_hasher.update(context.as_bytes());
        let context_key = context_hasher.finalize();
        Self::with_key_words(words_from_le_bytes(&context_key), DERIVE_KEY_MATERIAL)
    }

    /// Absorbs `data` and returns the hasher, so calls can be chained. Never fails.
    pub fn update(&mut self, mut data: &[u8]) -> &mut Self {
        while !data.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(&self.key, total_chunks, self.flags);
            }
            let take = (CHUNK_LEN - self.chunk_state.len()).min(data.len());
            self.chunk_state.update(&data[..take]);
            data = &data[take..];
        }
        self
    }

    /// Returns the 32-byte output for everything absorbed so far. The hasher is unchanged,
    /// so more input may follow.
    pub fn finalize(&self) -> [u8; OUT_LEN] {
        let mut out = [0u8; OUT_LEN];
        self.finalize_xof(&mut out);
        out
    }

    /// Fills `out` with output bytes of any length. The first 32 bytes equal
    /// [`Hasher::finalize`]. The hasher is unchanged.
    pub fn finalize_xof(&self, out: &mut [u8]) {
        let mut output = self.chunk_state.output();
        for cv in self.cv_stack[..self.cv_stack_len].iter().rev() {
            output = parent_output(cv, &output.chaining_value(), &self.key, self.flags);
        }
        output.root_output_bytes(out);
    }

    /// Merges completed subtrees: after chunk number `total_chunks`, one merge is due for
    /// every trailing zero bit of `total_chunks`.
    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            self.cv_stack_len -= 1;
            let left = &self.cv_stack[self.cv_stack_len];
            new_cv = parent_output(left, &new_cv, &self.key, self.flags).chaining_value();
            total_chunks >>= 1;
        }
        // Invariant: the stack holds one entry per set bit of the chunk count, so it cannot
        // overflow for inputs shorter than 2^64 bytes.
        self.cv_stack[self.cv_stack_len] = new_cv;
        self.cv_stack_len += 1;
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the 32-byte BLAKE3 hash of `data`.
pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
    Hasher::new().update(data).finalize()
}

/// Returns the 32-byte keyed BLAKE3 hash (MAC) of `data` under `key`.
pub fn keyed_hash(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; OUT_LEN] {
    Hasher::new_keyed(key).update(data).finalize()
}

/// Derives a 32-byte key from `key_material` for the purpose named by `context`.
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; OUT_LEN] {
    Hasher::new_derive_key(context).update(key_material).finalize()
}

#[cfg(test)]
mod tests;
