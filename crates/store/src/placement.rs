//! Secret placement: one keyed hash of a client per request, and a cheap derivation per table.
//!
//! The limiter and the ban table place a client by a key that nobody outside the process can
//! compute, so an attacker cannot choose addresses that share a victim's probe window. A keyed
//! hash of the client bytes in every table would cost one SipHash per table operation, and a
//! request makes up to three. Instead the caller hashes the client once with a
//! [`ClientHasher`], whose key is drawn once (when the daemon starts), and passes the
//! [`ClientHash`] to every table. Each table draws a 64-bit secret of its own when it is built
//! and derives its placement key from the hash, its secret and the scope:
//!
//! ```text
//!   client bytes --SipHash-1-3, secret 128-bit key--> h        (once per request)
//!   placement key = mix(h ^ table secret ^ scope)             (per table operation)
//! ```
//!
//! `mix` is the SplitMix64 finaliser: two multiplications and three shifts, a bijection of
//! `u64` in which every input bit affects every output bit. It is public and keyless; the
//! secrecy comes from `h`. Because `h` is a pseudorandom function of the client under a key
//! the attacker does not hold, every derived key is unpredictable too. Distinct pairs of
//! client and scope get distinct keys unless their hashes differ by exactly the difference of
//! their scopes, which happens with probability `2^-64` for a pair the attacker cannot test.
//! The per-table secret makes the placements in different tables unrelated: a set of clients
//! that collides in one table (an attacker might learn one from evictions) is scattered in
//! another, as the tests below check.
//!
//! The keyed hash stays SipHash-1-3, through the standard library's `RandomState` (keyed from
//! operating-system randomness), as before. Faster keyless or public-seed hashes (Wyhash,
//! which the Zig version used) are exactly what let an attacker compute collisions, and a
//! keyed BLAKE3 costs several times a SipHash for a 17-byte input.

use std::fmt;
use std::hash::{BuildHasher, Hasher, RandomState};

/// The keyed hash of one client's bytes, computed once per request by a [`ClientHasher`] and
/// passed to every table that places the client.
///
/// Its value is secret: it is never written anywhere and has no public accessor. A hash is
/// meaningful only with the hasher that made it; a table must be given hashes from one hasher
/// (or only bytes, through its convenience methods), or one client gets two places.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClientHash(u64);

impl fmt::Debug for ClientHash {
    /// Hides the value, which is secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientHash(..)")
    }
}

/// A keyed hash of client bytes (SipHash-1-3 under a key drawn from operating-system
/// randomness when the hasher is built). Build one per process and share it.
pub struct ClientHasher {
    keys: RandomState,
}

impl ClientHasher {
    /// Returns a hasher with a freshly drawn secret key. Never fails.
    pub fn new() -> Self {
        Self { keys: RandomState::new() }
    }

    /// Returns the keyed hash of `client`, the bytes a client is known by (an address in
    /// canonical form, say). Never fails; does not allocate.
    #[inline]
    pub fn hash(&self, client: &[u8]) -> ClientHash {
        let mut hasher = self.keys.build_hasher();
        // SipHash mixes the input length into its last block, so no prefix is needed.
        hasher.write(client);
        ClientHash(hasher.finish())
    }
}

impl Default for ClientHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ClientHasher {
    /// Hides the key, which is secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientHasher { .. }")
    }
}

/// The secret one table derives its placement keys with, drawn when the table is built.
pub(crate) struct TableSecret(u64);

impl TableSecret {
    /// Draws a fresh secret: the SipHash-1-3 of nothing under a fresh `RandomState` key, a
    /// value nobody outside the process can know.
    pub(crate) fn draw() -> Self {
        Self(RandomState::new().build_hasher().finish())
    }

    /// Returns the placement key of `client` within `scope` in this table; never zero, since
    /// zero marks an empty cell or slot.
    #[inline]
    pub(crate) fn place(&self, client: ClientHash, scope: u64) -> u64 {
        mix(client.0 ^ self.0 ^ scope).max(1)
    }
}

/// The SplitMix64 finaliser (Steele, Lea and Flood, 2014): a bijection with full avalanche.
#[inline]
fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[cfg(test)]
impl ClientHash {
    /// A hash with a chosen value, for tests that need one fixed across processes.
    pub(crate) fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// The value, for tests that print it.
    pub(crate) fn raw(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashers_and_secrets_differ_between_instances() {
        let (a, b) = (ClientHasher::new(), ClientHasher::new());
        let (s, t) = (TableSecret::draw(), TableSecret::draw());
        for n in 0..256u32 {
            let client = format!("192.0.2.{n}");
            let (ha, hb) = (a.hash(client.as_bytes()), b.hash(client.as_bytes()));
            assert_ne!(ha, hb);
            assert_eq!(ha, a.hash(client.as_bytes()), "a hasher is a function");
            assert_ne!(s.place(ha, 0), t.place(ha, 0));
            assert_ne!(s.place(ha, 0), s.place(ha, 1));
        }
        assert_eq!(format!("{a:?} {:?}", a.hash(b"x")), "ClientHasher { .. } ClientHash(..)");
    }

    /// Flipping any one input bit flips each output bit about half the time.
    #[test]
    fn the_mixer_avalanches() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut flips = [0u32; 64];
        let samples = 2000u32;
        for _ in 0..samples {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            for (bit, count) in flips.iter_mut().enumerate() {
                *count += (mix(state) ^ mix(state ^ (1 << bit))).count_ones();
            }
        }
        for (bit, &count) in flips.iter().enumerate() {
            let mean = f64::from(count) / f64::from(samples);
            assert!((28.0..36.0).contains(&mean), "input bit {bit}: {mean} output bits flip");
        }
    }
}
