//! The Cohen-Pietrzak proof of sequential work over SHA-256 (SID 0006, part B).
//!
//! The prover labels a complete binary tree of depth `n` in depth-first post-order. An
//! internal node's label hashes its two children. A leaf's label hashes the left siblings
//! of its ancestors wherever the root path turns right. Those extra edges force the work
//! to be sequential: leaf `i` cannot be labelled before every leaf to its left. The root
//! label `phi` commits to all `2^(n+1) - 1` labels. `t` leaves derived from `phi`
//! (Fiat-Shamir) are opened with their sibling paths, which the verifier checks in
//! `t * (n + 1)` hashes with no allocation.
//!
//! A node's label is `SHA-256(chi depth index_le32 parents...)`, where `chi` is the
//! statement. The proof is `phi` followed by `t` openings; an opening is the leaf label
//! followed by the siblings from depth `n` up to depth 1:
//!
//! ```text
//! proof   = phi | opening_0 | ... | opening_(t-1)            32 * (1 + t * (n + 1)) bytes
//! opening = leaf | sibling(n) | sibling(n-1) | ... | sibling(1)
//! ```

mod prover;

#[cfg(test)]
pub(crate) mod tests;

use core::fmt;

use sibuna_crypto::sha256::Sha256;

pub use prover::{Workspace, solve};

/// Length of a node label in bytes.
pub const LABEL_LEN: usize = 32;

/// A node label: a SHA-256 digest.
pub type Label = [u8; LABEL_LEN];

/// Smallest accepted tree depth.
pub const MIN_DEPTH: u8 = 4;

/// Largest accepted tree depth. It also bounds the prover's recursion.
pub const MAX_DEPTH: u8 = 24;

/// Smallest accepted number of opened leaves.
pub const MIN_CHALLENGES: u8 = 1;

/// Largest accepted number of opened leaves.
pub const MAX_CHALLENGES: u8 = 32;

/// Number of tree levels below the root whose labels the prover keeps after the first pass.
pub const STORED_DEPTH_MAX: u8 = 10;

/// Size in bytes of the largest proof, at [`MAX_DEPTH`] and [`MAX_CHALLENGES`].
pub const MAX_PROOF_SIZE: usize =
    LABEL_LEN * (1 + MAX_CHALLENGES as usize * (MAX_DEPTH as usize + 1));

/// The parameters of a proof: tree depth and number of openings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Params {
    /// Tree depth `n`. The prover performs `2^(n+1) - 1` sequential hashes.
    pub depth: u8,
    /// Number of opened leaves `t`. A prover that skipped a fraction `a` of the work
    /// escapes a fixed commitment's checks with probability about `(1 - a)^t`.
    pub challenges: u8,
}

impl Params {
    /// Checks that the depth lies in `MIN_DEPTH..=MAX_DEPTH` and the number of challenges
    /// in `MIN_CHALLENGES..=MAX_CHALLENGES`.
    ///
    /// # Errors
    ///
    /// Returns the [`ParamsError`] naming the first field out of range.
    pub const fn validate(self) -> Result<(), ParamsError> {
        if self.depth < MIN_DEPTH || self.depth > MAX_DEPTH {
            return Err(ParamsError::Depth(self.depth));
        }
        if self.challenges < MIN_CHALLENGES || self.challenges > MAX_CHALLENGES {
            return Err(ParamsError::Challenges(self.challenges));
        }
        Ok(())
    }

    /// Tells whether [`Params::validate`] accepts these parameters.
    pub const fn is_valid(self) -> bool {
        self.validate().is_ok()
    }

    /// Returns the number of leaves, `2^depth`. Saturates at `u32::MAX` for depths of 32
    /// and more, which are never valid.
    pub const fn leaf_count(self) -> u32 {
        match 1u32.checked_shl(self.depth as u32) {
            Some(count) => count,
            None => u32::MAX,
        }
    }

    /// Returns the size in bytes of one opening: the leaf and `depth` siblings.
    pub const fn opening_size(self) -> usize {
        LABEL_LEN * (self.depth as usize + 1)
    }

    /// Returns the size in bytes of a whole proof: the root label and the openings.
    pub const fn proof_size(self) -> usize {
        LABEL_LEN + self.challenges as usize * self.opening_size()
    }
}

/// Why [`Params::validate`] rejected a set of parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamsError {
    /// The depth lies outside `MIN_DEPTH..=MAX_DEPTH`.
    Depth(u8),
    /// The number of challenges lies outside `MIN_CHALLENGES..=MAX_CHALLENGES`.
    Challenges(u8),
}

impl fmt::Display for ParamsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Depth(depth) => write!(
                f,
                "proof depth {depth} is outside the accepted range {MIN_DEPTH} to {MAX_DEPTH}"
            ),
            Self::Challenges(count) => write!(
                f,
                "{count} challenges is outside the accepted range \
                 {MIN_CHALLENGES} to {MAX_CHALLENGES}"
            ),
        }
    }
}

impl core::error::Error for ParamsError {}

/// Returns a hasher that has absorbed the statement `chi`. Every node hash clones it, so
/// the statement costs no extra compression per node.
fn base_hasher(chi: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(chi);
    hasher
}

/// Returns the hasher of node `index` at `depth`, before its parents are absorbed.
#[inline]
fn node_hasher(base: &Sha256, depth: u8, index: u32) -> Sha256 {
    let mut hasher = base.clone();
    let [i0, i1, i2, i3] = index.to_le_bytes();
    hasher.update(&[depth, i0, i1, i2, i3]);
    hasher
}

/// Tells whether the root path of leaf `gamma` in a depth-`n` tree turns right at depth
/// `d`. Requires `1 <= d <= n <= MAX_DEPTH`.
#[inline]
fn turns_right(gamma: u32, n: u8, d: u8) -> bool {
    (gamma >> (n - d)) & 1 == 1
}

/// Returns the leaf that challenge `i` opens: the low `depth` bits of the little-endian
/// first word of `SHA-256(chi phi i)`. The prover cannot choose it, because it depends on
/// the commitment `phi`. Borrows its inputs only for the call; never fails. Depths of 32
/// and more keep all 32 bits.
pub fn challenge_leaf(chi: &[u8], phi: &Label, i: u8, depth: u8) -> u32 {
    challenge_leaf_from(&base_hasher(chi), phi, i, depth)
}

/// [`challenge_leaf`] from a hasher that has already absorbed `chi`.
fn challenge_leaf_from(base: &Sha256, phi: &Label, i: u8, depth: u8) -> u32 {
    let mut hasher = base.clone();
    hasher.update(phi);
    hasher.update(&[i]);
    let digest = hasher.finalize();
    let mask = match 1u32.checked_shl(depth as u32) {
        Some(count) => count - 1,
        None => u32::MAX,
    };
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) & mask
}

/// Verifies `proof` for statement `chi` under `params`.
///
/// Returns `false` for invalid parameters, a proof of the wrong length, or any opening that
/// does not lead to the committed root. Costs `t * (n + 2)` SHA-256 evaluations at most and
/// constant stack memory; never allocates and never panics.
pub fn verify(chi: &[u8], params: Params, proof: &[u8]) -> bool {
    if !params.is_valid() || proof.len() != params.proof_size() {
        return false;
    }
    let (labels, _) = proof.as_chunks::<LABEL_LEN>();
    let Some((phi, openings)) = labels.split_first() else {
        return false;
    };
    let n = params.depth;
    let base = base_hasher(chi);
    // The length check above makes this exactly `challenges` openings of `n + 1` labels.
    let openings = openings.chunks_exact(usize::from(n) + 1);
    (0..params.challenges).zip(openings).all(|(i, opening)| {
        let gamma = challenge_leaf_from(&base, phi, i, n);
        verify_opening(&base, n, phi, gamma, opening)
    })
}

/// Checks one opening of leaf `gamma`: the leaf label must hash correctly from the siblings
/// its extra edges name, and folding the siblings upward must reach `phi`. `opening` holds
/// `n + 1` labels: the leaf, then the siblings from depth `n` up to depth 1.
fn verify_opening(base: &Sha256, n: u8, phi: &Label, gamma: u32, opening: &[Label]) -> bool {
    let Some((leaf, siblings)) = opening.split_first() else {
        return false;
    };
    // `siblings` runs from depth n up to depth 1; reversed, it pairs with depths 1..=n.
    let mut hasher = node_hasher(base, n, gamma);
    for (d, sibling) in (1..=n).zip(siblings.iter().rev()) {
        if turns_right(gamma, n, d) {
            hasher.update(sibling);
        }
    }
    if hasher.finalize() != *leaf {
        return false;
    }
    let mut current = *leaf;
    for (d, sibling) in (1..=n).rev().zip(siblings) {
        let mut parent = node_hasher(base, d - 1, gamma >> (n - d + 1));
        if turns_right(gamma, n, d) {
            parent.update(sibling);
            parent.update(&current);
        } else {
            parent.update(&current);
            parent.update(sibling);
        }
        current = parent.finalize();
    }
    current == *phi
}
