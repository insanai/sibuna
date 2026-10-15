//! Argon2 password hashing (RFC 9106, version 0x13) with a caller-provided workspace, and
//! the PHC string format of Zig's `std.crypto.pwhash.argon2.strHash` and `strVerify`.
//!
//! Argon2 fills `m` KiB of memory, organised as `p` lanes of 1 KiB [`Block`]s, in `t`
//! passes, and hashes the last blocks into the output. The memory is the caller's slice of
//! blocks: [`block_count`] says how many a parameter set needs, so a server reserves one
//! workspace once and no password check allocates.
//!
//! ```text
//!            slice 0     slice 1     slice 2     slice 3
//!          +-----------+-----------+-----------+-----------+
//!  lane 0  | segment   | segment   | segment   | segment   |
//!  lane 1  | segment   | segment   | segment   | segment   |
//!          +-----------+-----------+-----------+-----------+
//!  A segment may reference blocks of other lanes only in slices that are complete.
//! ```
//!
//! Lanes are computed one after another, slice by slice. The reference implementation may
//! run the segments of one slice in parallel threads, which changes the speed but not the
//! result; with `p = 1`, the case that matters for the console, there is nothing to run in
//! parallel anyway.
//!
//! The workspace is wiped before [`derive_key`] returns, so password-derived memory does
//! not outlive the call.

mod block;
mod phc;
#[cfg(test)]
mod tests;

use core::fmt;

pub use block::Block;
pub use phc::{Limits, PHC_MAX_LEN, PhcHash, hash_phc, verify_phc};

use crate::blake2b::{self, Blake2b};
use crate::ct;

/// The Argon2 version this module implements (1.3).
pub const VERSION: u32 = 0x13;

/// Length of the salt that Zig's `strHash` draws and the console stores, in bytes.
pub const SALT_LEN: usize = 32;

/// Length of the hash in PHC strings made by [`hash_phc`] and by Zig's `strHash`.
pub const HASH_LEN: usize = 32;

/// The shortest salt Argon2 accepts, in bytes.
pub const MIN_SALT_LEN: usize = 8;

/// The shortest output Argon2 produces, in bytes.
pub const MIN_OUTPUT_LEN: usize = 4;

/// The longest salt and hash a PHC string may carry, in bytes (Zig's `max_salt_len` and
/// `max_hash_len`).
pub const MAX_PHC_BINARY_LEN: usize = 64;

/// The largest degree of parallelism, 2^24 - 1.
pub const MAX_PARALLELISM: u32 = 0x00ff_ffff;

/// Number of slices per pass; lanes synchronise at slice boundaries.
const SYNC_POINTS: u32 = 4;

/// Length of the initial hash H0 plus the two 32-bit words appended to derive the first
/// blocks of each lane.
const H0_LEN: usize = blake2b::MAX_OUTPUT_LEN + 8;

/// The Argon2 variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Data-dependent memory access: fastest, for settings without side-channel threats.
    Argon2d = 0,
    /// Data-independent memory access, resistant to cache-timing side channels.
    Argon2i = 1,
    /// Argon2i for the first half of the first pass, Argon2d afterwards. The recommended
    /// variant for password hashing.
    Argon2id = 2,
}

impl Mode {
    /// The algorithm identifier of the PHC string format: `argon2d`, `argon2i` or
    /// `argon2id`.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Argon2d => "argon2d",
            Mode::Argon2i => "argon2i",
            Mode::Argon2id => "argon2id",
        }
    }

    /// The variant named `name` in a PHC string, if any.
    pub fn from_name(name: &[u8]) -> Option<Mode> {
        match name {
            b"argon2d" => Some(Mode::Argon2d),
            b"argon2i" => Some(Mode::Argon2i),
            b"argon2id" => Some(Mode::Argon2id),
            _ => None,
        }
    }
}

/// The cost parameters of a hash.
///
/// The default is Argon2id with `t = 2`, `m = 19456` KiB and `p = 1`: the OWASP
/// recommendation, Zig's `Params.owasp_2id`, and the console's setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// The variant.
    pub mode: Mode,
    /// Number of passes over the memory, `t`; at least 1.
    pub time_cost: u32,
    /// Memory size in KiB, `m`; at least `8 * parallelism`. It is rounded down to a
    /// multiple of `4 * parallelism` blocks.
    pub memory_kib: u32,
    /// Number of lanes, `p`; 1 to 2^24 - 1.
    pub parallelism: u32,
}

impl Default for Params {
    fn default() -> Self {
        Params { mode: Mode::Argon2id, time_cost: 2, memory_kib: 19 * 1024, parallelism: 1 }
    }
}

/// Why Argon2 hashing or verification failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A cost parameter, the salt or the output is outside what RFC 9106 allows: `t = 0`,
    /// `p = 0` or above 2^24 - 1, `m < 8p`, a salt shorter than 8 bytes, an output shorter
    /// than 4 bytes, or an input longer than 2^32 - 1 bytes.
    WeakParameters,
    /// The output is longer than 2^32 - 1 bytes.
    OutputTooLong,
    /// The workspace has fewer blocks than [`block_count`] requires.
    WorkspaceTooSmall,
    /// A PHC string is malformed, has an unknown parameter, a salt or hash longer than 64
    /// bytes, or a version other than 19.
    InvalidEncoding,
    /// A PHC string names an algorithm other than `argon2d`, `argon2i` or `argon2id`.
    UnsupportedAlgorithm,
    /// A PHC string asks for more memory, passes or lanes than the caller's [`Limits`].
    LimitExceeded,
    /// The output buffer is too small for the PHC string.
    BufferTooSmall,
    /// The password does not match the hash.
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::WeakParameters => "Argon2 parameters, salt or output length are too weak",
            Error::OutputTooLong => "Argon2 output is longer than 2^32 - 1 bytes",
            Error::WorkspaceTooSmall => "Argon2 workspace has too few blocks",
            Error::InvalidEncoding => "malformed Argon2 PHC string",
            Error::UnsupportedAlgorithm => "unsupported algorithm in PHC string",
            Error::LimitExceeded => "Argon2 PHC string exceeds the configured cost limits",
            Error::BufferTooSmall => "output buffer too small for the PHC string",
            Error::VerificationFailed => "password verification failed",
        })
    }
}

impl core::error::Error for Error {}

/// The shape of the memory for one parameter set.
#[derive(Clone, Copy, Debug)]
struct Geometry {
    mode: Mode,
    passes: u32,
    lanes: u32,
    /// Blocks per lane.
    lane_len: u32,
    /// Blocks per segment: a quarter of a lane.
    segment_len: u32,
    /// Total blocks, `m'` of RFC 9106.
    memory_blocks: u32,
}

impl Geometry {
    /// Validates the cost parameters and derives the memory layout.
    fn new(params: &Params) -> Result<Geometry, Error> {
        let lanes = params.parallelism;
        if params.time_cost < 1 || !(1..=MAX_PARALLELISM).contains(&lanes) {
            return Err(Error::WeakParameters);
        }
        if params.memory_kib / 8 < lanes {
            return Err(Error::WeakParameters);
        }
        // Both products fit in u32: lanes <= m / 8, so 4 * lanes <= m / 2.
        let quantum = SYNC_POINTS * lanes;
        let memory_blocks = (params.memory_kib / quantum * quantum).max(2 * quantum);
        let lane_len = memory_blocks / lanes;
        Ok(Geometry {
            mode: params.mode,
            passes: params.time_cost,
            lanes,
            lane_len,
            segment_len: lane_len / SYNC_POINTS,
            memory_blocks,
        })
    }
}

/// Returns the number of [`Block`]s the workspace must hold for `params`: `m` rounded down
/// to a multiple of `4p`.
///
/// Fails with [`Error::WeakParameters`] when the parameters are invalid.
pub fn block_count(params: &Params) -> Result<usize, Error> {
    Ok(Geometry::new(params)?.memory_blocks as usize)
}

/// Derives `out.len()` bytes from `password` and `salt` with Argon2, using `workspace` as
/// the memory. This is the one-call form of [`derive_key_with_secret`] without a secret
/// and without associated data.
///
/// Borrows the inputs for the call and the workspace mutably; the used part of the
/// workspace is wiped before returning. Fails with [`Error::WeakParameters`] or
/// [`Error::OutputTooLong`] for invalid inputs and with [`Error::WorkspaceTooSmall`] when
/// the workspace has fewer than [`block_count`] blocks; nothing is computed then.
pub fn derive_key(
    params: &Params,
    password: &[u8],
    salt: &[u8],
    workspace: &mut [Block],
    out: &mut [u8],
) -> Result<(), Error> {
    derive_key_with_secret(params, password, salt, &[], &[], workspace, out)
}

/// Derives `out.len()` bytes from `password`, `salt`, the optional `secret` key K and the
/// optional `associated_data` X of RFC 9106, using `workspace` as the memory.
///
/// Errors and the wiping of the workspace are as for [`derive_key`].
pub fn derive_key_with_secret(
    params: &Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    workspace: &mut [Block],
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() < MIN_OUTPUT_LEN {
        return Err(Error::WeakParameters);
    }
    if u32::try_from(out.len()).is_err() {
        return Err(Error::OutputTooLong);
    }
    if salt.len() < MIN_SALT_LEN {
        return Err(Error::WeakParameters);
    }
    let inputs = [password, salt, secret, associated_data];
    if inputs.iter().any(|input| u32::try_from(input.len()).is_err()) {
        return Err(Error::WeakParameters);
    }
    let geometry = Geometry::new(params)?;
    let memory =
        workspace.get_mut(..geometry.memory_blocks as usize).ok_or(Error::WorkspaceTooSmall)?;
    let mut h0 = initial_hash(params, out.len() as u32, inputs);
    init_lanes(memory, &mut h0, &geometry);
    ct::zeroize(&mut h0);
    for pass in 0..geometry.passes {
        for slice in 0..SYNC_POINTS {
            for lane in 0..geometry.lanes {
                fill_segment(memory, &geometry, Position { pass, lane, slice });
            }
        }
    }
    finish(memory, &geometry, out);
    memory.iter_mut().for_each(Block::wipe);
    Ok(())
}

/// H0 of RFC 9106 section 3.2, followed by eight zero bytes for the block index and lane.
fn initial_hash(params: &Params, output_len: u32, inputs: [&[u8]; 4]) -> [u8; H0_LEN] {
    let mut hasher = Blake2b::with_output_len(blake2b::MAX_OUTPUT_LEN);
    for word in [
        params.parallelism,
        output_len,
        params.memory_kib,
        params.time_cost,
        VERSION,
        params.mode as u32,
    ] {
        hasher.update(&word.to_le_bytes());
    }
    for input in inputs {
        // The caller checked that every input length fits in 32 bits.
        hasher.update(&(input.len() as u32).to_le_bytes());
        hasher.update(input);
    }
    let mut h0 = [0u8; H0_LEN];
    let (digest, _) = h0.split_at_mut(blake2b::MAX_OUTPUT_LEN);
    hasher.finalize_truncated(digest);
    h0
}

/// Computes the first two blocks of every lane: `H'(H0 || index || lane)`.
fn init_lanes(memory: &mut [Block], h0: &mut [u8; H0_LEN], geometry: &Geometry) {
    let mut bytes = [0u8; block::WORDS * 8];
    for lane in 0..geometry.lanes {
        h0[68..72].copy_from_slice(&lane.to_le_bytes());
        for index in 0..2u32 {
            h0[64..68].copy_from_slice(&index.to_le_bytes());
            hash_long(&mut bytes, &[h0.as_slice()]);
            let at = (lane * geometry.lane_len + index) as usize;
            memory[at].load(&bytes);
        }
    }
    ct::zeroize(&mut bytes);
}

/// The variable-length hash H' of RFC 9106 section 3.3 over the concatenation of `input`.
fn hash_long(out: &mut [u8], input: &[&[u8]]) {
    const HALF: usize = blake2b::MAX_OUTPUT_LEN / 2;
    let length = (out.len() as u32).to_le_bytes();
    if out.len() <= blake2b::MAX_OUTPUT_LEN {
        let mut hasher = Blake2b::with_output_len(out.len());
        hasher.update(&length);
        input.iter().for_each(|piece| hasher.update(piece));
        hasher.finalize_truncated(out);
        return;
    }
    let mut v = [0u8; blake2b::MAX_OUTPUT_LEN];
    let mut hasher = Blake2b::with_output_len(blake2b::MAX_OUTPUT_LEN);
    hasher.update(&length);
    input.iter().for_each(|piece| hasher.update(piece));
    hasher.finalize_truncated(&mut v);
    // Emit the first half of V_1, then of each V_(i+1) = H(V_i) while more than 64 bytes
    // remain.
    let (head, mut rest) = out.split_at_mut(HALF);
    head.copy_from_slice(&v[..HALF]);
    while rest.len() > blake2b::MAX_OUTPUT_LEN {
        v = blake2b::hash(&v);
        let (head, tail) = rest.split_at_mut(HALF);
        head.copy_from_slice(&v[..HALF]);
        rest = tail;
    }
    // Now 32 < rest.len() <= 64: the last V is computed with the exact remaining length.
    let mut hasher = Blake2b::with_output_len(rest.len());
    hasher.update(&v);
    hasher.finalize_truncated(rest);
    ct::zeroize(&mut v);
}

/// Where a segment lies: the pass, the lane and the slice.
#[derive(Clone, Copy, Debug)]
struct Position {
    pass: u32,
    lane: u32,
    slice: u32,
}

/// Fills one segment of one lane (RFC 9106 section 3.4).
fn fill_segment(memory: &mut [Block], geometry: &Geometry, position: Position) {
    let Position { pass, lane, slice } = position;
    let data_independent = match geometry.mode {
        Mode::Argon2i => true,
        Mode::Argon2id => pass == 0 && slice < SYNC_POINTS / 2,
        Mode::Argon2d => false,
    };
    let mut addresses = AddressGenerator::new(geometry, position);
    // The first two blocks of each lane were computed from H0. The addresses for the
    // rest of the first segment are made before its first computed block.
    let first = if pass == 0 && slice == 0 { 2 } else { 0 };
    if data_independent && first == 2 {
        addresses.refill();
    }
    let lane_start = (lane * geometry.lane_len) as usize;
    let segment_start = lane_start + (slice * geometry.segment_len) as usize;
    for index in first..geometry.segment_len {
        let current = segment_start + index as usize;
        // The block before the first one of a lane is the lane's last block.
        let prev = if current == lane_start {
            lane_start + geometry.lane_len as usize - 1
        } else {
            current - 1
        };
        let pseudo_random =
            if data_independent { addresses.value(index) } else { memory[prev].0[0] };
        let reference = reference_index(geometry, position, index, pseudo_random);
        block::compress_in_slice(memory, current, prev, reference, pass > 0);
    }
}

/// The pseudo-random values of data-independent addressing: each block of addresses is
/// G(0, G(0, input)), where the input block counts up from 1.
struct AddressGenerator {
    input: Block,
    addresses: Block,
}

impl AddressGenerator {
    fn new(geometry: &Geometry, position: Position) -> AddressGenerator {
        let mut input = Block::ZERO;
        input.0[..6].copy_from_slice(&[
            u64::from(position.pass),
            u64::from(position.lane),
            u64::from(position.slice),
            u64::from(geometry.memory_blocks),
            u64::from(geometry.passes),
            geometry.mode as u64,
        ]);
        AddressGenerator { input, addresses: Block::ZERO }
    }

    /// The value for block `index` of the segment; a new block of addresses is made
    /// every 128 blocks.
    fn value(&mut self, index: u32) -> u64 {
        let slot = index as usize % block::WORDS;
        if slot == 0 {
            self.refill();
        }
        self.addresses.0[slot]
    }

    /// Advances the counter and computes the next block of addresses.
    fn refill(&mut self) {
        self.input.0[6] += 1;
        let mut once = Block::ZERO;
        block::compress(&mut once, &Block::ZERO, &self.input, false);
        block::compress(&mut self.addresses, &Block::ZERO, &once, false);
    }
}

/// The index of the reference block for block `index` of the segment at `position`
/// (RFC 9106 section 3.4.1.2), from the pseudo-random value J1 || J2.
fn reference_index(
    geometry: &Geometry,
    position: Position,
    index: u32,
    pseudo_random: u64,
) -> usize {
    let Position { pass, lane, slice } = position;
    let segment_len = u64::from(geometry.segment_len);
    let reference_lane = if pass == 0 && slice == 0 {
        lane
    } else {
        ((pseudo_random >> 32) % u64::from(geometry.lanes)) as u32
    };
    let same_lane = reference_lane == lane;
    let index = u64::from(index);
    // The reference area: its size and, in later passes, where it starts in the lane.
    let (mut area, start) = if pass == 0 {
        let finished = u64::from(slice) * segment_len;
        (if slice == 0 || same_lane { finished + index } else { finished }, 0)
    } else {
        let finished = 3 * segment_len;
        let start = u64::from((slice + 1) % SYNC_POINTS) * segment_len;
        (if same_lane { finished + index } else { finished }, start)
    };
    // The previous block is excluded; so is the last block of another lane's finished
    // segment when this block is the first of its segment. The area is never empty here.
    if index == 0 || same_lane {
        area = area.saturating_sub(1);
    }
    let j1 = pseudo_random & 0xffff_ffff;
    let x = (j1 * j1) >> 32;
    let y = (area * x) >> 32;
    let relative = area.saturating_sub(y + 1);
    let column = (start + relative) % u64::from(geometry.lane_len);
    (u64::from(reference_lane) * u64::from(geometry.lane_len) + column) as usize
}

/// XORs the last block of every lane and hashes it with H' into `out`.
fn finish(memory: &mut [Block], geometry: &Geometry, out: &mut [u8]) {
    let lane_len = geometry.lane_len as usize;
    let mut last = memory[lane_len - 1].clone();
    for lane in 1..geometry.lanes as usize {
        last.xor_assign(&memory[lane * lane_len + lane_len - 1]);
    }
    let mut bytes = [0u8; block::WORDS * 8];
    last.store(&mut bytes);
    hash_long(out, &[bytes.as_slice()]);
    last.wipe();
    ct::zeroize(&mut bytes);
}
