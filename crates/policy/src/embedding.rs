//! Attack payload embedding for campaign clustering.
//!
//! A payload maps to a fixed 64-dimensional unit vector with the hashing trick (Weinberger
//! et al., ICML 2009) over byte trigrams (Broder's shingling, 1997): each trigram is hashed
//! to a coordinate and a sign, counts accumulate, and the vector is normalised to unit
//! length, so cosine similarity is a dot product. Two payloads of one campaign (the same
//! injection template, different targets) land close together; unrelated payloads are
//! nearly orthogonal. No model, no allocation, no training.
//!
//! The vectors are stored and compared across nodes, so every operation is bit-identical
//! to the Zig daemon: Zig's `std.hash.Wyhash` with seed `0x3a3a`, accumulation in index
//! order, and single-precision arithmetic without fused multiply-add.

use sibuna_crypto::wyhash;

/// Number of dimensions.
pub const DIM: usize = 64;

/// One embedding.
pub type Vector = [f32; DIM];

const SEED: u64 = 0x3a3a;

/// Folds bytes that vary between instances of one campaign: digits become `0`, letters
/// lower case, so the template dominates the trigram set.
fn fold(byte: u8) -> u8 {
    if byte.is_ascii_digit() { b'0' } else { byte.to_ascii_lowercase() }
}

/// Returns the unit-length embedding of `payload`; the zero vector for an empty payload.
/// Payloads shorter than three bytes hash as a whole (unfolded).
pub fn embed(payload: &[u8]) -> Vector {
    let mut vector = [0f32; DIM];
    if payload.is_empty() {
        return vector;
    }
    for window in payload.windows(3) {
        let trigram = [fold(window[0]), fold(window[1]), fold(window[2])];
        let hash = wyhash::hash(SEED, &trigram);
        let sign = if hash >> 63 == 1 { -1.0 } else { 1.0 };
        vector[(hash % DIM as u64) as usize] += sign;
    }
    if payload.len() < 3 {
        let hash = wyhash::hash(SEED, payload);
        vector[(hash % DIM as u64) as usize] += 1.0;
    }
    let mut norm = 0f32;
    for &x in &vector {
        norm += x * x;
    }
    if norm > 0.0 {
        let inverse = 1.0 / norm.sqrt();
        for x in &mut vector {
            *x *= inverse;
        }
    }
    vector
}

/// Returns the dot product of `a` and `b`, the cosine similarity of unit vectors.
pub fn cosine(a: &Vector, b: &Vector) -> f32 {
    let mut dot = 0f32;
    for (x, y) in a.iter().zip(b) {
        dot += x * y;
    }
    dot
}

/// Returns the little-endian float32 bytes of `vector`, the storage format of the vector
/// table.
pub fn to_bytes(vector: &Vector) -> [u8; DIM * 4] {
    let mut out = [0u8; DIM * 4];
    for (chunk, x) in out.as_chunks_mut::<4>().0.iter_mut().zip(vector) {
        *chunk = x.to_le_bytes();
    }
    out
}

/// Reads a vector from its little-endian float32 bytes (see `to_bytes`).
pub fn from_bytes(bytes: &[u8; DIM * 4]) -> Vector {
    let mut vector = [0f32; DIM];
    for (x, chunk) in vector.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *x = f32::from_le_bytes(*chunk);
    }
    vector
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_variants_are_close_and_unrelated_payloads_are_far() {
        let a = embed(b"id=1' UNION SELECT username,password FROM users--");
        let b = embed(b"id=42' union select name,pass from users--");
        let c = embed(b"<img src=x onerror=alert(document.cookie)>");
        let d = embed(b"../../../../etc/passwd%00");
        assert!(cosine(&a, &b) > 0.6);
        assert!(cosine(&a, &c) < 0.4);
        assert!(cosine(&a, &d) < 0.4);
        assert!(cosine(&c, &d) < 0.4);
        let norm: f32 = a.iter().map(|x| x * x).sum();
        assert!((norm - 1.0).abs() < 0.001);
        assert_eq!(to_bytes(&a).len(), DIM * 4);
        assert_eq!(from_bytes(&to_bytes(&a)), a);
        assert_eq!(embed(b"")[0], 0.0);
    }
}

/// Vectors printed by Zig 0.16 through the Zig policy library's `embedding.embed`, as the
/// bit patterns of each `f32` in order; also one `cosine` result.
#[cfg(test)]
mod zig_vectors {
    use super::*;

    const VECTORS: &str = include_str!("../tests/data/embedding_vectors.txt");

    #[test]
    fn embeddings_are_bit_identical_to_zig() {
        let mut checked = 0;
        for line in VECTORS.lines() {
            if let Some(hex) = line.strip_prefix("cosine ") {
                let a = embed(b"id=1' UNION SELECT username,password FROM users--");
                let b = embed(b"id=42' union select name,pass from users--");
                assert_eq!(cosine(&a, &b).to_bits(), u32::from_str_radix(hex, 16).unwrap());
                continue;
            }
            let rest = line.strip_prefix("embed \"").unwrap();
            let (payload, hex) = rest.rsplit_once("\" ").unwrap();
            let vector = embed(payload.as_bytes());
            for (index, x) in vector.iter().enumerate() {
                let expected = u32::from_str_radix(&hex[index * 8..index * 8 + 8], 16).unwrap();
                assert_eq!(x.to_bits(), expected, "{payload} [{index}]");
            }
            checked += 1;
        }
        assert_eq!(checked, 6);
    }
}
