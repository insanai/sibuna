//! The depth-first prover with a fixed workspace (SID 0006, Lemma 13).
//!
//! During the first pass the only labels a future leaf needs are the left siblings on the
//! current root path, one per depth: the sibling stack. The top `m` levels are copied out
//! as they are produced. To open leaf `gamma`, the prover restores the stack above depth
//! `m` from the retained levels and relabels the subtree under `gamma`'s depth-`m`
//! ancestor, capturing the leaf and the siblings on the way.

use sibuna_crypto::sha256::Sha256;

use super::{
    LABEL_LEN, Label, MAX_CHALLENGES, MAX_DEPTH, Params, ParamsError, STORED_DEPTH_MAX,
    base_hasher, challenge_leaf_from, node_hasher, turns_right,
};

/// Number of retained labels: every node of the top `STORED_DEPTH_MAX` levels fits.
const TOP_LABELS: usize = 1 << (STORED_DEPTH_MAX as usize + 1);

/// One sibling-stack entry per depth, 0 to `MAX_DEPTH`.
const STACK_LABELS: usize = MAX_DEPTH as usize + 1;

/// Labels in the largest proof.
const PROOF_LABELS: usize = 1 + MAX_CHALLENGES as usize * (MAX_DEPTH as usize + 1);

/// Fixed prover memory: 64 KiB of retained labels, the sibling stack and the proof buffer,
/// about 92 KiB in all. Declare one per solver thread or WebAssembly instance and reuse it;
/// [`solve`] overwrites it completely.
#[derive(Clone)]
pub struct Workspace {
    top: [Label; TOP_LABELS],
    stack: [Label; STACK_LABELS],
    proof: [Label; PROOF_LABELS],
}

impl Workspace {
    /// A zeroed workspace. `const`, so a `static` workspace costs no initialised data.
    pub const fn new() -> Self {
        Self {
            top: [[0; LABEL_LEN]; TOP_LABELS],
            stack: [[0; LABEL_LEN]; STACK_LABELS],
            proof: [[0; LABEL_LEN]; PROOF_LABELS],
        }
    }

    /// Borrows the whole proof buffer, [`super::MAX_PROOF_SIZE`] bytes. After a successful
    /// [`solve`] it starts with the proof; the rest is unspecified.
    pub fn proof_buffer(&self) -> &[u8] {
        self.proof.as_flattened()
    }
}

impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Produces a proof for statement `chi` in the caller's workspace and borrows it from there.
///
/// The sequential cost is `2^(n+1) - 1` hashes for the commitment plus
/// `t * (2^(n-m+1) - 1)` to open the challenges, where `m = min(n, STORED_DEPTH_MAX)`.
/// The output is byte for byte the proof of the Zig prover.
///
/// # Errors
///
/// Returns the [`ParamsError`] of [`Params::validate`] for parameters out of range.
pub fn solve<'w>(
    chi: &[u8],
    params: Params,
    workspace: &'w mut Workspace,
) -> Result<&'w [u8], ParamsError> {
    params.validate()?;
    let n = params.depth;
    let Workspace { top, stack, proof } = workspace;
    let mut prover = Prover { base: base_hasher(chi), n, m: n.min(STORED_DEPTH_MAX), top, stack };
    let phi = prover.label(0, 0, &mut Sink::Retain);
    let (head, openings) = proof.split_at_mut(1);
    head[0] = phi;
    for (i, opening) in (0..params.challenges).zip(openings.chunks_exact_mut(usize::from(n) + 1)) {
        let gamma = challenge_leaf_from(&prover.base, &phi, i, n);
        prover.open(gamma, opening);
    }
    // A valid proof size is at most MAX_PROOF_SIZE, the length of the flattened buffer.
    Ok(&proof.as_flattened()[..params.proof_size()])
}

/// Where the prover sends the labels it computes.
enum Sink<'o> {
    /// First pass: keep the labels of the top `m` levels.
    Retain,
    /// Opening pass: capture the leaf `target` and its siblings into `opening`.
    Capture { target: u32, opening: &'o mut [Label] },
}

/// The state of one proof. Parameters are valid, so `m <= n <= MAX_DEPTH`.
struct Prover<'w> {
    base: Sha256,
    n: u8,
    m: u8,
    top: &'w mut [Label; TOP_LABELS],
    stack: &'w mut [Label; STACK_LABELS],
}

/// Index of node `index` at `depth` in the retained levels, stored level by level.
fn top_index(depth: u8, index: u32) -> usize {
    (1usize << depth) - 1 + index as usize
}

impl Prover<'_> {
    /// Labels the subtree of node `index` at `depth` in post-order and returns its label.
    ///
    /// Recursion: one frame per level below `depth`, so at most `MAX_DEPTH + 1` frames,
    /// each holding one hasher and two labels (a few hundred bytes).
    fn label(&mut self, depth: u8, index: u32, sink: &mut Sink<'_>) -> Label {
        let n = self.n;
        let mut hasher = node_hasher(&self.base, depth, index);
        if depth == n {
            // The stack holds the left sibling of the ancestor at every depth 1..=n.
            for (d, left_sibling) in (1..=n).zip(&self.stack[1..]) {
                if turns_right(index, n, d) {
                    hasher.update(left_sibling);
                }
            }
        } else {
            // `index < 2^depth <= 2^23`, so the child indices cannot overflow.
            let left = self.label(depth + 1, index * 2, sink);
            self.stack[usize::from(depth) + 1] = left;
            let right = self.label(depth + 1, index * 2 + 1, sink);
            hasher.update(&left);
            hasher.update(&right);
        }
        let label = hasher.finalize();
        match sink {
            Sink::Retain if depth <= self.m => self.top[top_index(depth, index)] = label,
            Sink::Retain => {}
            Sink::Capture { target, opening } => record(n, *target, depth, index, label, opening),
        }
        label
    }

    /// Writes the opening of leaf `gamma` into `opening` (`n + 1` labels).
    fn open(&mut self, gamma: u32, opening: &mut [Label]) {
        let (n, m) = (self.n, self.m);
        for d in 1..=m {
            let sibling = (gamma >> (n - d)) ^ 1;
            let sibling_label = self.top[top_index(d, sibling)];
            opening[1 + usize::from(n - d)] = sibling_label;
            // A right turn at depth d means the leaf hashes this left sibling.
            if turns_right(gamma, n, d) {
                self.stack[usize::from(d)] = sibling_label;
            }
        }
        if m == n {
            opening[0] = self.top[top_index(n, gamma)];
            return;
        }
        let mut sink = Sink::Capture { target: gamma, opening };
        self.label(m, gamma >> (n - m), &mut sink);
    }
}

/// Stores `label` of node `index` at `depth` into `opening` when it is the target leaf or a
/// sibling on the target's root path. Requires `depth <= n`.
fn record(n: u8, target: u32, depth: u8, index: u32, label: Label, opening: &mut [Label]) {
    if depth == 0 {
        return;
    }
    if depth == n && index == target {
        opening[0] = label;
    } else if index == (target >> (n - depth)) ^ 1 {
        opening[1 + usize::from(n - depth)] = label;
    }
}
