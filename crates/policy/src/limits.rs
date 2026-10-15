//! Request quotas attached to terminal rules, and the identities that scope their buckets.
//!
//! A quota is immutable configuration; the mutable GCRA cells live in the node-local store.
//! The bucket scope changes when the settings change, but not when an unrelated revision of
//! the policy is published, so an operator who edits another rule does not reset quotas.

use std::fmt;

use sibuna_crypto::wyhash;

/// Seed of the bucket scope hash (`"rule-gcr"`).
const SCOPE_SEED: u64 = 0x7275_6c65_2d67_6372;
/// Seed of a managed rule's identity hash (`"managed-"`).
const MANAGED_SEED: u64 = 0x6d61_6e61_6765_642d;
/// Seed of a file rule's identity hash (`"file-rul"`), mixed with the rule's index.
const FILE_SEED: u64 = 0x6669_6c65_2d72_756c;

/// Largest accepted `rate`.
pub const MAX_RATE: u32 = 1_000_000;
/// Largest accepted `window_seconds` and `ban_seconds` (one day).
pub const MAX_SECONDS: u32 = 86_400;

/// A request quota: at most `rate` requests per `window_seconds` per client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Limits {
    /// Requests admitted per window, 1 to 1,000,000.
    pub rate: u32,
    /// Window length in seconds, 1 to 86,400.
    pub window_seconds: u32,
    /// Zero answers 429 only; a positive duration also bans the address on this node.
    pub ban_seconds: u32,
}

/// The quota settings are out of range (see `Limits::validate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRuleLimit;

impl fmt::Display for InvalidRuleLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("limits need rate 1..1000000, window_seconds 1..86400, ban_seconds <= 86400")
    }
}

impl std::error::Error for InvalidRuleLimit {}

impl Limits {
    /// Checks the ranges: `rate` 1 to 1,000,000, `window_seconds` 1 to 86,400 and
    /// `ban_seconds` at most 86,400.
    ///
    /// Fails with `InvalidRuleLimit` otherwise.
    pub fn validate(self) -> Result<(), InvalidRuleLimit> {
        let valid = (1..=MAX_RATE).contains(&self.rate)
            && (1..=MAX_SECONDS).contains(&self.window_seconds)
            && self.ban_seconds <= MAX_SECONDS;
        if valid { Ok(()) } else { Err(InvalidRuleLimit) }
    }

    /// Returns the bucket scope of these settings for the rule `identity`.
    ///
    /// Fixed-width little-endian fields avoid ambiguous concatenation; the hash is Zig's
    /// `std.hash.Wyhash` with the seed `"rule-gcr"`, so scopes agree across implementations.
    pub fn scope(self, identity: u64) -> u64 {
        let mut bytes = [0u8; 20];
        bytes[0..8].copy_from_slice(&identity.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.rate.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.window_seconds.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.ban_seconds.to_le_bytes());
        wyhash::hash(SCOPE_SEED, &bytes)
    }
}

/// Why a stored quota cell was refused by `Limits::from_json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredLimitError {
    /// Longer than 256 bytes, or settings out of range.
    InvalidRuleLimit,
    /// Not JSON of the right shape.
    Json(crate::json::JsonError),
}

impl fmt::Display for StoredLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoredLimitError::InvalidRuleLimit => InvalidRuleLimit.fmt(f),
            StoredLimitError::Json(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StoredLimitError {}

impl Limits {
    /// Reads a stored quota cell: `null` or an object with `rate`, `window_seconds` and an
    /// optional `ban_seconds`, with Zig's typed JSON rules, then validates it.
    ///
    /// Fails with `InvalidRuleLimit` above 256 bytes or out of range, or `Json`.
    pub fn from_json(text: &[u8]) -> Result<Option<Limits>, StoredLimitError> {
        if text.len() > 256 {
            return Err(StoredLimitError::InvalidRuleLimit);
        }
        let mut reader = crate::json::Reader::new(text);
        let limits =
            reader.optional(crate::loader::schema::limits).map_err(StoredLimitError::Json)?;
        reader.finish().map_err(StoredLimitError::Json)?;
        if let Some(limits) = limits {
            limits.validate().map_err(|_| StoredLimitError::InvalidRuleLimit)?;
        }
        Ok(limits)
    }
}

/// Returns the identity of a managed rule from its stable document id; never 0, so that 0
/// can mean "no identity".
pub fn managed_identity(id: &[u8]) -> u64 {
    match wyhash::hash(MANAGED_SEED, id) {
        0 => 1,
        value => value,
    }
}

/// Returns the identity of a file rule from its name and its index in the rule table.
pub fn file_identity(name: &[u8], index: usize) -> u64 {
    wyhash::hash(FILE_SEED ^ index as u64, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_limit_scopes_separate_identities_and_settings() {
        let limits = Limits { rate: 2, window_seconds: 60, ban_seconds: 0 };
        assert_eq!(limits.validate(), Ok(()));
        assert_ne!(limits.scope(managed_identity(b"a")), limits.scope(managed_identity(b"b")));
        let changed = Limits { rate: 3, ..limits };
        assert_ne!(limits.scope(7), changed.scope(7));
        assert_eq!(
            Limits { rate: 0, window_seconds: 1, ban_seconds: 0 }.validate(),
            Err(InvalidRuleLimit)
        );
        assert_eq!(
            Limits { rate: 1, window_seconds: 0, ban_seconds: 0 }.validate(),
            Err(InvalidRuleLimit)
        );
        let maximum =
            Limits { rate: MAX_RATE, window_seconds: MAX_SECONDS, ban_seconds: MAX_SECONDS };
        assert_eq!(maximum.validate(), Ok(()));
        assert!(Limits { ban_seconds: MAX_SECONDS + 1, ..maximum }.validate().is_err());
    }

    /// Expected values come from Zig 0.16 `std.hash.Wyhash` through the Zig policy library
    /// (`rule_limits.zig`), printed by a scratch program.
    #[test]
    fn identities_and_scopes_match_zig() {
        assert_eq!(managed_identity(b"checkout"), ZIG_MANAGED_CHECKOUT);
        assert_eq!(file_identity(b"Checkout", 0), ZIG_FILE_CHECKOUT_0);
        assert_eq!(file_identity(b"Checkout", 5), ZIG_FILE_CHECKOUT_5);
        let limits = Limits { rate: 2, window_seconds: 60, ban_seconds: 0 };
        assert_eq!(limits.scope(ZIG_FILE_CHECKOUT_0), ZIG_SCOPE_CHECKOUT_0);
    }

    const ZIG_MANAGED_CHECKOUT: u64 = 9_447_179_632_835_705_228;
    const ZIG_FILE_CHECKOUT_0: u64 = 13_091_537_953_574_301_833;
    const ZIG_FILE_CHECKOUT_5: u64 = 3_758_776_709_678_777_122;
    const ZIG_SCOPE_CHECKOUT_0: u64 = 975_175_031_499_903_790;
}
