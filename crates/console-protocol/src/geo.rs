//! GeoIP dataset loading: staged batches, activation and the active dataset's metadata.

use crate::text::Text;

/// The longest provider name.
pub const MAX_PROVIDER: usize = 12;
/// The longest source version.
pub const MAX_VERSION: usize = 10;
/// One or two lowercase hex digests separated by a colon: "hex" or "hex:hex".
pub const MAX_SOURCE_DIGESTS: usize = 129;
/// The largest batch: each range is two normalized 16-byte addresses plus a two-byte
/// country code.
pub const MAX_BATCH_BYTES: usize = 3400;

/// The credential of a GeoIP mutation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Authorization {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// SHA-256 of the CSRF token.
    pub csrf_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// Address presenting the credential; empty when not captured.
    pub client: Text<48>,
}

/// The active dataset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    /// The settings revision that activated it.
    pub revision: u64,
    /// SHA-256 of the canonical dataset, as hex.
    pub digest: Text<64>,
    /// The provider's name.
    pub provider: Text<MAX_PROVIDER>,
    /// The provider's release.
    pub source_version: Text<MAX_VERSION>,
    /// Digests of the source files ([`valid_source_digests`]).
    pub source_digests: Text<MAX_SOURCE_DIGESTS>,
    /// Address ranges in the dataset.
    pub ranges: u32,
    /// When it was activated, in Unix seconds.
    pub loaded_at: u64,
}

/// Starts staging a dataset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Begin {
    /// The administrator's credential.
    pub auth: Authorization,
    /// The revision the administrator saw.
    pub expected_revision: u64,
    /// SHA-256 of the canonical dataset, as hex.
    pub digest: Text<64>,
    /// The provider's name.
    pub provider: Text<MAX_PROVIDER>,
    /// The provider's release.
    pub source_version: Text<MAX_VERSION>,
    /// Digests of the source files.
    pub source_digests: Text<MAX_SOURCE_DIGESTS>,
    /// Address ranges to expect.
    pub ranges: u32,
}

/// One staged batch of encoded ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Batch {
    /// The administrator's credential.
    pub auth: Authorization,
    /// The staged dataset's digest.
    pub digest: Text<64>,
    /// The batch number.
    pub ordinal: u32,
    /// At most [`MAX_BATCH_BYTES`] bytes of encoded ranges.
    pub bytes: Vec<u8>,
}

/// Activates a fully staged dataset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Activate {
    /// The administrator's credential.
    pub auth: Authorization,
    /// The revision the administrator saw.
    pub expected_revision: u64,
    /// The staged dataset's digest.
    pub digest: Text<64>,
}

/// Reads one batch of the active dataset (for node loading).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// The dataset's digest.
    pub digest: Text<64>,
    /// The batch number.
    pub ordinal: u32,
}

/// Returns true for an empty text, one lowercase hex SHA-256 digest, or two separated by
/// a colon.
pub fn valid_source_digests(text: &str) -> bool {
    if !matches!(text.len(), 0 | 64 | MAX_SOURCE_DIGESTS) {
        return false;
    }
    text.bytes().enumerate().all(|(index, byte)| {
        if index == 64 {
            byte == b':'
        } else {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of geo.zig "source digests are one or two lowercase hex values".
    #[test]
    fn source_digests_are_one_or_two_lowercase_hex_values() {
        let hex = "a".repeat(64);
        assert!(valid_source_digests(""));
        assert!(valid_source_digests(&hex));
        assert!(valid_source_digests(&format!("{hex}:{hex}")));
        assert!(!valid_source_digests(&format!("{hex} {hex}")));
        assert!(!valid_source_digests(&"A".repeat(64)));
        assert!(!valid_source_digests(&hex[..63]));
    }
}
