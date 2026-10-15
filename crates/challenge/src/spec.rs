//! What a challenge asks for: the algorithm, the work bits, and how they map onto each
//! puzzle's own parameter.

use sibuna_pow::posw;

use crate::token::WorkLevel;

/// The proof-of-work tier of a challenge. The discriminant is the byte on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Algorithm {
    /// Tier one: Hashcash over SHA-256 with bit-level difficulty.
    #[default]
    Hashcash = 0,
    /// Tier two: the Cohen-Pietrzak proof of sequential work.
    Posw = 1,
}

impl Algorithm {
    /// Parses an algorithm name, ignoring ASCII case: `hashcash` (or its alias `sha256`)
    /// and `posw`. Returns `None` for any other text.
    pub fn parse(text: &str) -> Option<Algorithm> {
        if text.eq_ignore_ascii_case("hashcash") || text.eq_ignore_ascii_case("sha256") {
            Some(Algorithm::Hashcash)
        } else if text.eq_ignore_ascii_case("posw") {
            Some(Algorithm::Posw)
        } else {
            None
        }
    }

    /// Returns the name used in the challenge record: `"hashcash"` or `"posw"`.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Hashcash => "hashcash",
            Algorithm::Posw => "posw",
        }
    }

    /// Returns the algorithm whose wire byte is `byte`, or `None` for an unknown byte.
    pub fn from_byte(byte: u8) -> Option<Algorithm> {
        match byte {
            0 => Some(Algorithm::Hashcash),
            1 => Some(Algorithm::Posw),
            _ => None,
        }
    }

    /// Returns the wire byte of the algorithm.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns the work bits paid for `parameter`, the difficulty in the algorithm's own
    /// unit: Hashcash bits as given, PoSW depth plus [`ChallengeSpec::POSW_DEPTH_OFFSET`]
    /// (saturating at 255). This is the unit a session's work level is compared in.
    pub fn work_bits(self, parameter: u8) -> u8 {
        match self {
            Algorithm::Hashcash => parameter,
            Algorithm::Posw => parameter.saturating_add(ChallengeSpec::POSW_DEPTH_OFFSET as u8),
        }
    }
}

/// What a challenge asks for.
///
/// `difficulty` is in work bits. Hashcash needs that many leading zero bits (`2^bits`
/// expected hashes). PoSW uses a tree of depth `bits - 3`, because each of its leaves costs
/// about eight compressions, which keeps the two tiers within a factor of two of each other
/// in browser wall-clock time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChallengeSpec {
    /// The tier to issue.
    pub algorithm: Algorithm,
    /// Work bits.
    pub difficulty: u32,
    /// Number of PoSW openings; ignored for Hashcash.
    pub posw_challenges: u8,
}

impl Default for ChallengeSpec {
    fn default() -> Self {
        ChallengeSpec { algorithm: Algorithm::Hashcash, difficulty: 16, posw_challenges: 16 }
    }
}

impl ChallengeSpec {
    /// Work bits a PoSW tree of depth `n` stands for beyond `n` itself.
    pub const POSW_DEPTH_OFFSET: u32 = 3;
    /// The largest Hashcash difficulty: a digest has 256 bits, but a 64-bit nonce space
    /// cannot be expected to hold a solution beyond 64.
    pub const HASHCASH_MAX_BITS: u32 = 64;

    /// Returns the PoSW depth for this difficulty: `difficulty - 3`, clamped to
    /// [`posw::MIN_DEPTH`] and [`posw::MAX_DEPTH`].
    pub fn posw_depth(&self) -> u8 {
        let raw = self.difficulty.saturating_sub(Self::POSW_DEPTH_OFFSET);
        let clamped = raw.clamp(u32::from(posw::MIN_DEPTH), u32::from(posw::MAX_DEPTH));
        // The clamp bounds the value by MAX_DEPTH, which is a u8.
        clamped as u8
    }

    /// Returns the Hashcash bit count for this difficulty, at most 64.
    pub fn hashcash_bits(&self) -> u8 {
        // At most HASHCASH_MAX_BITS (64), so the value fits a u8.
        self.difficulty.min(Self::HASHCASH_MAX_BITS) as u8
    }

    /// Returns the difficulty in the algorithm's own unit, the value a challenge record
    /// carries: [`ChallengeSpec::hashcash_bits`] or [`ChallengeSpec::posw_depth`].
    pub fn parameter(&self) -> u8 {
        match self.algorithm {
            Algorithm::Hashcash => self.hashcash_bits(),
            Algorithm::Posw => self.posw_depth(),
        }
    }
}

/// Returns what a route demands of a session: the policy difficulty mapped through the same
/// clamping a challenge applies, without the load-adaptive bump, so a token minted for the
/// route always satisfies it and a cheaper token never does.
pub fn required_work(algorithm: Algorithm, difficulty: u32) -> WorkLevel {
    let spec = ChallengeSpec { algorithm, difficulty, ..ChallengeSpec::default() };
    WorkLevel { algorithm: algorithm.to_byte(), bits: algorithm.work_bits(spec.parameter()) }
}

/// What a challenged request demands of issuance: the challenge to issue and the identity of
/// the rule that demanded it. A requirement ticket carries it from the challenged response to
/// the challenge fetch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Requirement {
    /// The challenge to issue.
    pub spec: ChallengeSpec,
    /// The rule hash of the rule that demanded it.
    pub rule_hash: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_names_and_bytes() {
        assert_eq!(Algorithm::parse("HashCash"), Some(Algorithm::Hashcash));
        assert_eq!(Algorithm::parse("SHA256"), Some(Algorithm::Hashcash));
        assert_eq!(Algorithm::parse("PoSW"), Some(Algorithm::Posw));
        assert_eq!(Algorithm::parse("argon2"), None);
        for algorithm in [Algorithm::Hashcash, Algorithm::Posw] {
            assert_eq!(Algorithm::from_byte(algorithm.to_byte()), Some(algorithm));
            assert_eq!(Algorithm::parse(algorithm.name()), Some(algorithm));
        }
        assert_eq!(Algorithm::from_byte(2), None);
    }

    #[test]
    fn spec_mapping_clamps_like_zig() {
        let posw = |difficulty| ChallengeSpec {
            algorithm: Algorithm::Posw,
            difficulty,
            ..Default::default()
        };
        assert_eq!(posw(0).posw_depth(), 4);
        assert_eq!(posw(7).posw_depth(), 4);
        assert_eq!(posw(11).posw_depth(), 8);
        assert_eq!(posw(27).posw_depth(), 24);
        assert_eq!(posw(u32::MAX).posw_depth(), 24);
        let hashcash = |difficulty| ChallengeSpec { difficulty, ..Default::default() };
        assert_eq!(hashcash(10).hashcash_bits(), 10);
        assert_eq!(hashcash(64).hashcash_bits(), 64);
        assert_eq!(hashcash(65).parameter(), 64);
        assert_eq!(hashcash(u32::MAX).parameter(), 64);
        assert_eq!(Algorithm::Posw.work_bits(255), 255);
        assert_eq!(Algorithm::Posw.work_bits(8), 11);
    }

    #[test]
    fn required_work_matches_the_challenge_mapping() {
        assert_eq!(required_work(Algorithm::Hashcash, 10), WorkLevel { algorithm: 0, bits: 10 });
        assert_eq!(required_work(Algorithm::Hashcash, 100), WorkLevel { algorithm: 0, bits: 64 });
        assert_eq!(required_work(Algorithm::Posw, 11), WorkLevel { algorithm: 1, bits: 11 });
        // Depth clamps to 4, so a PoSW route never asks for fewer than 7 work bits.
        assert_eq!(required_work(Algorithm::Posw, 2), WorkLevel { algorithm: 1, bits: 7 });
        assert_eq!(required_work(Algorithm::Posw, 40), WorkLevel { algorithm: 1, bits: 27 });
    }
}
