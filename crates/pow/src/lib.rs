//! Client puzzles for Sibuna: Hashcash and the Cohen-Pietrzak proof of sequential work.
//!
//! Two tiers share one hash, SHA-256 from `sibuna-crypto`, which uses the x86-64 SHA
//! extensions or the ARMv8 SHA-2 instructions when the CPU has them:
//!
//! - [`hashcash`] (tier 1): find a nonce such that `SHA-256(challenge ":" decimal(nonce))`
//!   starts with a given number of zero bits. Verification is one hash.
//! - [`posw`] (tier 2): the Cohen-Pietrzak proof of sequential work (EUROCRYPT 2018). The
//!   prover labels a binary tree of depth `n` in `2^(n+1) - 1` sequential hashes; the
//!   verifier checks `t` Fiat-Shamir openings in `t * (n + 1)` hashes without allocating.
//!
//! The crate is `no_std` and never allocates. The prover works in a caller-owned
//! [`posw::Workspace`] of fixed size (about 92 KiB), so the browser solver
//! (`sibuna-pow-wasm`) compiles the very code the server verifies with, and the two cannot
//! drift apart. SID 0006 states the mathematics; SID 0010 the port.
//!
//! Both tiers produce exactly the bytes the Zig implementation produced: the tests pin
//! proofs and nonces generated with Zig 0.16.
//!
//! # Deliberate changes from Zig
//!
//! - [`posw::Params::validate`] returns a [`posw::ParamsError`] naming the field out of
//!   range; Zig returned a `bool`. [`posw::Params::is_valid`] keeps the predicate.
//! - [`posw::solve`] fails with that `ParamsError` instead of `error.InvalidParams`.
//! - Functions that Zig defined only for valid parameters are total here and never panic:
//!   [`posw::challenge_leaf`] masks with all ones for depths of 32 or more (Zig's shift
//!   would be illegal), [`posw::Params::leaf_count`] saturates, and
//!   [`hashcash::meets_hex`] rejects a hexadecimal difficulty whose bit count overflows.
//! - The verifier derives each challenged leaf from a SHA-256 state that has absorbed the
//!   statement once, instead of rehashing the statement for every challenge. The digests
//!   are the same; verification is `t` compressions cheaper.
//! - [`hashcash::solve_bits`] and the browser solver share [`hashcash::Search`], which
//!   absorbs `challenge ":"` once per batch, as the Zig browser solver did. The Zig
//!   reference solver rehashed the prefix for every nonce; the nonce found is the same.
//! - The prover keeps Zig's depth-first recursion. Its depth is at most
//!   [`posw::MAX_DEPTH`] + 1 frames, because parameters are validated before it runs.
#![no_std]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod test_util;
#[cfg(test)]
mod timings;

pub mod hashcash;
pub mod posw;
