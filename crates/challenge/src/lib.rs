//! Stateless proof-of-work challenges, session tokens and load-adaptive difficulty for
//! Sibuna (SID 0002, SID 0006 Parts C and H; the book's Parts III and IV).
//!
//! - [`keys`]: the key schedule. One 32-byte [`Seed`] derives every purpose key with keyed
//!   BLAKE3 over a domain string; [`Keys::bind_node`] binds the challenge key to a cluster
//!   node.
//! - [`token`]: the session token, a 40-byte payload carrying the holder's [`WorkLevel`],
//!   with a keyed BLAKE3 tag ([`token::mac`], 75 characters) or an Ed25519 signature
//!   ([`token::ed25519`], 139 characters); the keyed client fingerprint and the rule hash.
//! - [`Coordinator`]: issues challenge identifiers (70 characters), seals and opens
//!   requirement tickets (59 characters), verifies solutions in the order cheap checks,
//!   proof, spent set, and mints session tokens.
//! - [`spec`]: what a challenge asks for ([`ChallengeSpec`]) and what a route demands of a
//!   session ([`required_work`]).
//! - [`adaptive`]: the difficulty bump from the rate of verified solutions.
//!
//! Every format is bit for bit the Zig daemon's, so a Zig node and a Rust node that share a
//! seed verify each other's session tokens and requirement tickets, and, with the same node
//! id, each other's challenge identifiers. The tests pin vectors produced by the Zig 0.16
//! implementation and check verification in both directions (SID 0010, acceptance
//! criterion 2).
//!
//! ```
//! use sibuna_challenge::{Coordinator, Options, Seed, Solution};
//! use sibuna_pow::hashcash;
//!
//! let seed = Seed::parse(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?;
//! let coordinator = Coordinator::new(&seed, Options::default());
//! let (ip, user_agent, now) = (&b"192.0.2.1"[..], &b"Mozilla/5.0"[..], 1_700_000_000);
//!
//! let challenge = coordinator.create_challenge(ip, user_agent, now);
//! let id = challenge.id.as_bytes();
//! let nonce = hashcash::solve_bits(id, u32::from(challenge.difficulty), 1 << 32).unwrap();
//! let verified = coordinator.verify_and_mint(id, Solution::Nonce(nonce), ip, user_agent, now)?;
//!
//! let cookie = verified.token.as_str().as_bytes();
//! let session = coordinator.verify_cookie(cookie, ip, user_agent, now + 10)?;
//! assert_eq!(session.work.bits, 16);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Changes from the Zig version
//!
//! `libs/challenge/src/*.zig` and `libs/crypto/src/{keys,token}.zig` are the specification.
//! Formats, decisions, check order and error identities are unchanged. Deliberate changes:
//!
//! - The coordinator owns its spent set instead of pointing at one the daemon embeds, and
//!   every method takes `&self`: the counter, the adaptive controller and the spent set are
//!   internally synchronised, so one coordinator is shared by reference between threads.
//! - Node binding is part of construction ([`Options::node`], a `NonZeroU32`), so Zig's
//!   assertion that the id is not zero is a type, and the key cannot change once the
//!   coordinator is shared.
//! - Arithmetic that Zig would have trapped on (a time near `u64::MAX` plus a lifetime, a
//!   difficulty plus the bump past `u32::MAX`, an EWMA product, an `alpha_256` above 256)
//!   saturates. Values the daemon can produce are unaffected.
//! - [`Seed::parse`] returns a [`SeedError`] saying why, where Zig returned `null`.
//! - [`TokenError::InvalidTokenLength`] and [`TokenError::InvalidEncoding`] map to
//!   `ErrorKind::MalformedToken`, the table's entry for an undecodable cookie. Zig had no
//!   such mapping (its daemon never explained token errors, and by name they would have
//!   been "unexpected").
//! - Ed25519 key decoding happens once, in [`Coordinator::new`]; Zig decoded the public key
//!   on every verification. Accepted signatures are the same.
//! - Security fixes (2026-10-15): the adaptive controller counts verified solutions, not
//!   issued challenges, which cost a flooder nothing; issuance only advances its clock.
//!   The spent set's capacity is an option ([`Options::spent_capacity`], 1,048,576 tags by
//!   default) instead of Zig's fixed 65,536, which about 220 solutions per second filled.
//!
//! Zig machinery that Rust made unnecessary, and what replaced it:
//!
//! - `VerifiedResult`'s 139-byte buffer plus a length: [`SessionToken`], an enum of two
//!   inline texts of exact length; the encoded identifier, ticket and token arrays are
//!   [`Encoded`], whose length is its type. Nothing allocates on the request path.
//! - `catch unreachable` around Ed25519 key generation and signing: both are infallible in
//!   `sibuna-crypto`.
//! - `std.crypto.secureZero` at call sites: [`Seed`] and [`Keys`] zero themselves on drop,
//!   and their `Debug` output is redacted.
//! - The unused `Token` struct duplicating the payload's fields: both formats return
//!   [`token::Payload`].
//! - `undefined` buffers and `@intCast`: arrays built in place, and checked or saturating
//!   conversions.

pub mod adaptive;
mod coordinator;
mod encoded;
pub mod keys;
pub mod spec;
pub mod token;

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod timings;
#[cfg(test)]
mod vectors;

pub use adaptive::{Adaptive, AdaptiveConfig};
pub use coordinator::{
    CHALLENGE_ID_LEN, Challenge, ChallengeId, Coordinator, ID_PAYLOAD_LEN, ID_RAW_LEN, Options,
    RequirementTicket, SessionToken, Solution, TAG_LEN, TICKET_LEN, TokenScheme, Verified,
    VerifyError,
};
pub use encoded::Encoded;
pub use keys::{Keys, SEED_LEN, Seed, SeedError};
pub use spec::{Algorithm, ChallengeSpec, Requirement, required_work};
pub use token::{
    Payload, TokenError, WorkLevel, fingerprint_keyed, fingerprint_unkeyed, rule_hash,
};
