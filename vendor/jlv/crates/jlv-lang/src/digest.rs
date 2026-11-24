//! Domain-separated SHA-256 digests (JDD 0004).
//!
//! A digest is `SHA256(domain || 0x00 || version || 0x00 || canonical_bytes)` with fixed
//! ASCII spellings of the domain and the decimal format version. Distinct domains keep
//! a graph, a recipe, a plan and a value with equal bytes from sharing an identity.
//! Collision resistance is an assumption about SHA-256, not a proof.

use std::fmt;

/// Plain value vectors: `jlv/value` version `1`.
pub const VALUE: Domain = Domain { name: "jlv/value", version: "1" };
/// Desired graphs.
pub const GRAPH: Domain = Domain { name: "jlv/graph", version: "1" };
/// Operation recipes.
pub const RECIPE: Domain = Domain { name: "jlv/recipe", version: "1" };
/// Saved plans.
pub const PLAN: Domain = Domain { name: "jlv/plan", version: "1" };
/// Source closures.
pub const SOURCE: Domain = Domain { name: "jlv/source", version: "1" };
/// Observation and inventory manifests; reserved by JDD 0003, as nothing digests a
/// manifest yet.
pub const OBSERVATION: Domain = Domain { name: "jlv/observation", version: "1" };
/// Artifact recipes, distinct from the digests of produced bytes; reserved by JDD 0003,
/// as nothing digests an artifact recipe yet.
pub const ARTIFACT_RECIPE: Domain = Domain { name: "jlv/artifact-recipe", version: "1" };
/// Packages (JDD 0008); version `2` leaves a plugin's executables out and counts their
/// declared digests (JDD 0017).
pub const PACKAGE: Domain = Domain { name: "jlv/package", version: "2" };

/// A digest domain: an ASCII name and a decimal format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain {
    /// The domain name, such as `jlv/plan`.
    pub name: &'static str,
    /// The format version, such as `1`.
    pub version: &'static str,
}

/// A 32-byte SHA-256 digest; its text form is 64 lower-case hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The digest of `bytes` in `domain`.
    pub fn of(domain: Domain, bytes: &[u8]) -> Digest {
        let mut hasher = gd_sha::Sha256::new();
        hasher.update(domain.name.as_bytes());
        hasher.update(&[0]);
        hasher.update(domain.version.as_bytes());
        hasher.update(&[0]);
        hasher.update(bytes);
        Digest(hasher.finish())
    }

    /// The plain SHA-256 of `bytes`, for content such as files and artifacts.
    pub fn content(bytes: &[u8]) -> Digest {
        Digest(gd_sha::sha256(bytes))
    }

    /// Reads 64 hexadecimal digits.
    pub fn parse(text: &str) -> Option<Digest> {
        let bytes = gd_sha::from_hex(text).filter(|_| text.len() == 64)?;
        bytes.try_into().ok().map(Digest)
    }

    /// The text form.
    pub fn to_hex(&self) -> String {
        gd_sha::to_hex(&self.0)
    }

    /// The first twelve hexadecimal digits, for display only.
    pub fn short(&self) -> String {
        self.to_hex()[..12].to_string()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.short())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_null_vector_matches_the_conformance_data() {
        let digest = Digest::of(VALUE, br#"["null"]"#);
        assert_eq!(
            digest.to_hex(),
            "501302680b1b76abac3c3083d4517201bc36f1c0b51abb4656429b1d327c46c3"
        );
        assert_eq!(Digest::parse(&digest.to_hex()), Some(digest));
        assert_eq!(Digest::parse("abc"), None);
    }

    #[test]
    fn domains_separate_equal_bytes() {
        assert_ne!(Digest::of(GRAPH, b"x"), Digest::of(PLAN, b"x"));
    }
}
