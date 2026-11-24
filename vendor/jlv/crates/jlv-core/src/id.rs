//! Typed version 7 UUIDs.

use std::fmt;
use std::marker::PhantomData;

use crate::random::fill_random;
use crate::time::Millis;

/// A version 7 UUID that identifies one kind of resource, named by the marker `K`.
///
/// The first 48 bits are the creation time in milliseconds, so identifiers sort by
/// creation time; the rest are random. The text form is the usual lower-case hyphenated
/// form, `01936d4e-8a2b-7c3d-9e4f-0a1b2c3d4e5f`.
pub struct Id<K> {
    bytes: [u8; 16],
    kind: PhantomData<fn() -> K>,
}

/// Why a text is not an identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdError {
    /// The rejected text, cut to 64 characters.
    pub text: String,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` is not an identifier (a lower-case hyphenated UUID)", self.text)
    }
}

impl std::error::Error for IdError {}

impl<K> Id<K> {
    /// A new identifier for the current time. Fails only when the operating system's
    /// random source cannot be read.
    pub fn generate() -> std::io::Result<Id<K>> {
        let mut random = [0u8; 10];
        fill_random(&mut random)?;
        Ok(Id::from_parts(Millis::now(), random))
    }

    /// The identifier with creation time `at` and the given random bits; for tests and
    /// for replaying recorded identifiers.
    pub fn from_parts(at: Millis, random: [u8; 10]) -> Id<K> {
        let ms = (at.0.max(0) as u64).to_be_bytes();
        let mut b = [0u8; 16];
        b[..6].copy_from_slice(&ms[2..]);
        b[6..].copy_from_slice(&random);
        b[6] = 0x70 | (b[6] & 0x0f);
        b[8] = 0x80 | (b[8] & 0x3f);
        Id { bytes: b, kind: PhantomData }
    }

    /// The creation time that a UUIDv7 holds in its first 48 bits.
    pub fn created_at(&self) -> Millis {
        let mut ms = [0u8; 8];
        ms[2..].copy_from_slice(&self.bytes[..6]);
        Millis(i64::from_be_bytes(ms))
    }

    /// The identifier with exactly these bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Id<K> {
        Id { bytes, kind: PhantomData }
    }

    /// The sixteen bytes.
    pub fn bytes(&self) -> [u8; 16] {
        self.bytes
    }

    /// Reads the hyphenated text form, in either case.
    pub fn parse(text: &str) -> Result<Id<K>, IdError> {
        let error = || IdError { text: text.chars().take(64).collect() };
        let raw = text.as_bytes();
        if raw.len() != 36 || [8, 13, 18, 23].iter().any(|&i| raw[i] != b'-') {
            return Err(error());
        }
        let hex: String = text.chars().filter(|&c| c != '-').collect();
        let decoded = gd_sha::from_hex(&hex).ok_or_else(error)?;
        let bytes: [u8; 16] = decoded.try_into().map_err(|_| error())?;
        Ok(Id::from_bytes(bytes))
    }

    /// The same bytes as an identifier of another kind, for the rare record that is
    /// identified by another resource's identifier.
    pub fn cast<L>(self) -> Id<L> {
        Id::from_bytes(self.bytes)
    }
}

impl<K> fmt::Display for Id<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = gd_sha::to_hex(&self.bytes);
        write!(f, "{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
    }
}

impl<K> fmt::Debug for Id<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

impl<K> Clone for Id<K> {
    fn clone(&self) -> Id<K> {
        *self
    }
}

impl<K> Copy for Id<K> {}

impl<K> PartialEq for Id<K> {
    fn eq(&self, other: &Id<K>) -> bool {
        self.bytes == other.bytes
    }
}

impl<K> Eq for Id<K> {}

impl<K> PartialOrd for Id<K> {
    fn partial_cmp(&self, other: &Id<K>) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for Id<K> {
    fn cmp(&self, other: &Id<K>) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<K> std::hash::Hash for Id<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A marker for tests.
    #[derive(Debug)]
    struct Org;
    type OrgId = Id<Org>;

    #[test]
    fn text_form_round_trips_and_carries_version_and_variant() {
        let id: OrgId = Id::from_parts(Millis(0x0193_6d4e_8a2b), [0xff; 10]);
        let text = id.to_string();
        assert_eq!(text, "01936d4e-8a2b-7fff-bfff-ffffffffffff");
        assert_eq!(id.created_at(), Millis(0x0193_6d4e_8a2b));
        assert_eq!(OrgId::parse(&text).unwrap(), id);
        assert_eq!(OrgId::parse(&text.to_uppercase()).unwrap(), id);
        assert!(OrgId::parse("01936d4e8a2b7fffbfffffffffffffff").is_err());
        assert!(OrgId::parse("01936d4e-8a2b-7fff-bfff-fffffffffffg").is_err());
    }

    #[test]
    fn generated_ids_sort_by_time() {
        let a: OrgId = Id::from_parts(Millis(1), [0xff; 10]);
        let b: OrgId = Id::from_parts(Millis(2), [0; 10]);
        assert!(a < b);
        let c: OrgId = Id::generate().unwrap();
        assert_ne!(c, Id::generate().unwrap());
    }
}
