//! Sibuna Proof of Sequential Work (Tier 2)
//!
//! Implements the Cohen–Pietrzak construction ("Simple Proofs of Sequential
//! Work", EUROCRYPT 2018) over SHA-256, whose sequentiality is proven in the
//! random oracle model and, by Blocki, Lee and Zhou (ITC 2021), against
//! quantum adversaries in the quantum random oracle model.
//!
//! The prover labels a complete binary tree of depth `n` in depth-first
//! post-order. An internal node's label hashes its two children; a leaf's
//! label hashes the labels of the *left siblings of its ancestors* wherever
//! the root path turned right. Those extra edges are what force the whole
//! computation to be sequential: leaf `i` cannot be labelled before every
//! leaf to its left has been. The root label `phi` commits to all
//! `N = 2^(n+1) - 1` labels; `t` leaves derived from `phi` by Fiat–Shamir
//! are opened with their sibling paths, which the verifier recomputes in
//! `t * (n + 1)` hashes with no allocation.
//!
//! Prover memory is `O(2^m + n)` labels: the top `m` levels are retained so
//! each opening recomputes only a `2^(n - m + 1)` node subtree.

const std = @import("std");
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const label_len = 32;
pub const Label = [label_len]u8;

pub const min_depth: u8 = 4;
pub const max_depth: u8 = 24;
pub const min_challenges: u8 = 1;
pub const max_challenges: u8 = 32;
/// Levels whose labels the prover keeps after the first pass.
pub const stored_depth_max: u8 = 10;
pub const max_proof_size = label_len * (1 + @as(usize, max_challenges) * (max_depth + 1));

pub const Params = struct {
    /// Tree depth `n`; the prover performs `2^(n+1) - 1` sequential hashes.
    depth: u8,
    /// Number of opened leaves `t`; soundness error is about `(1 - a)^t`
    /// for a prover that skipped a fraction `a` of the work.
    challenges: u8,

    pub fn validate(self: Params) bool {
        return self.depth >= min_depth and self.depth <= max_depth and
            self.challenges >= min_challenges and self.challenges <= max_challenges;
    }

    pub fn leafCount(self: Params) u32 {
        return @as(u32, 1) << @intCast(self.depth);
    }

    pub fn openingSize(self: Params) usize {
        return label_len * (@as(usize, self.depth) + 1);
    }

    pub fn proofSize(self: Params) usize {
        return label_len + @as(usize, self.challenges) * self.openingSize();
    }
};

/// `chi` is absorbed once; every node hash copies this state (SHA-256 state
/// is a value type), so the statement costs no extra compression per node.
fn baseHasher(chi: []const u8) Sha256 {
    var h = Sha256.init(.{});
    h.update(chi);
    return h;
}

fn nodeHasher(base: *const Sha256, depth: u8, index: u32) Sha256 {
    var h = base.*;
    var enc: [5]u8 = undefined;
    enc[0] = depth;
    std.mem.writeInt(u32, enc[1..5], index, .little);
    h.update(&enc);
    return h;
}

/// Bit `d` (1-based from the root) of leaf index `gamma` in a depth-`n` tree.
inline fn pathBit(gamma: u32, n: u8, d: u8) u1 {
    return @intCast((gamma >> @intCast(n - d)) & 1);
}

/// Fiat–Shamir challenge: the `i`-th opened leaf is derived from the root
/// commitment so the prover cannot choose which leaves to open.
pub fn challengeLeaf(chi: []const u8, phi: *const Label, i: u8, n: u8) u32 {
    var h = Sha256.init(.{});
    h.update(chi);
    h.update(phi);
    h.update(&[_]u8{i});
    var out: Label = undefined;
    h.final(&out);
    const mask = (@as(u32, 1) << @intCast(n)) - 1;
    return std.mem.readInt(u32, out[0..4], .little) & mask;
}

fn siblingAt(opening: []const u8, n: u8, d: u8) *const Label {
    const slot = 1 + @as(usize, n - d);
    return opening[slot * label_len ..][0..label_len];
}

fn verifyOpening(base: *const Sha256, n: u8, phi: *const Label, gamma: u32, opening: []const u8) bool {
    const leaf: *const Label = opening[0..label_len];
    var h = nodeHasher(base, n, gamma);
    var d: u8 = 1;
    while (d <= n) : (d += 1) {
        if (pathBit(gamma, n, d) == 1) h.update(siblingAt(opening, n, d));
    }
    var computed: Label = undefined;
    h.final(&computed);
    if (!std.mem.eql(u8, &computed, leaf)) return false;

    var cur = leaf.*;
    d = n;
    while (d >= 1) : (d -= 1) {
        const sib = siblingAt(opening, n, d);
        var parent = nodeHasher(base, d - 1, gamma >> @intCast(n - d + 1));
        if (pathBit(gamma, n, d) == 0) {
            parent.update(&cur);
            parent.update(sib);
        } else {
            parent.update(sib);
            parent.update(&cur);
        }
        parent.final(&cur);
    }
    return std.mem.eql(u8, &cur, phi);
}

/// Verifies a proof for statement `chi`. Runs in `t * (n + 1)` SHA-256
/// evaluations and constant stack memory regardless of `n`.
pub fn verify(chi: []const u8, params: Params, proof: []const u8) bool {
    if (!params.validate()) return false;
    if (proof.len != params.proofSize()) return false;
    const base = baseHasher(chi);
    const phi: *const Label = proof[0..label_len];
    const opening_size = params.openingSize();
    var i: u8 = 0;
    while (i < params.challenges) : (i += 1) {
        const gamma = challengeLeaf(chi, phi, i, params.depth);
        const opening = proof[label_len + @as(usize, i) * opening_size ..][0..opening_size];
        if (!verifyOpening(&base, params.depth, phi, gamma, opening)) return false;
    }
    return true;
}

/// Fixed prover memory: 64 KB of retained labels, the sibling stack, and
/// the output proof. Declare one per solver thread or WASM instance.
pub const Workspace = struct {
    top: [(@as(usize, 1) << (stored_depth_max + 1))]Label,
    stack: [max_depth + 1]Label,
    proof: [max_proof_size]u8,
};

fn topIndex(depth: u8, index: u32) usize {
    return (@as(usize, 1) << @intCast(depth)) - 1 + index;
}

const Prover = struct {
    base: Sha256,
    n: u8,
    m: u8,
    ws: *Workspace,
    target: u32 = 0,
    capture: ?[]u8 = null,

    fn labelOf(p: *Prover, depth: u8, index: u32) Label {
        var label: Label = undefined;
        var h = nodeHasher(&p.base, depth, index);
        if (depth == p.n) {
            var d: u8 = 1;
            while (d <= p.n) : (d += 1) {
                if (pathBit(index, p.n, d) == 1) h.update(&p.ws.stack[d]);
            }
        } else {
            const left = p.labelOf(depth + 1, index * 2);
            p.ws.stack[depth + 1] = left;
            const right = p.labelOf(depth + 1, index * 2 + 1);
            h.update(&left);
            h.update(&right);
        }
        h.final(&label);
        if (p.capture) |cap| {
            p.record(cap, depth, index, &label);
        } else if (depth <= p.m) {
            p.ws.top[topIndex(depth, index)] = label;
        }
        return label;
    }

    fn record(p: *Prover, cap: []u8, depth: u8, index: u32, label: *const Label) void {
        if (depth == 0) return;
        if (depth == p.n and index == p.target) {
            cap[0..label_len].* = label.*;
        } else if (index == (p.target >> @intCast(p.n - depth)) ^ 1) {
            const slot = 1 + @as(usize, p.n - depth);
            cap[slot * label_len ..][0..label_len].* = label.*;
        }
    }

    fn open(p: *Prover, gamma: u32, out: []u8) void {
        var d: u8 = 1;
        while (d <= p.m) : (d += 1) {
            const sib = (gamma >> @intCast(p.n - d)) ^ 1;
            const sib_label = p.ws.top[topIndex(d, sib)];
            out[(1 + @as(usize, p.n - d)) * label_len ..][0..label_len].* = sib_label;
            // A right turn at depth d means the leaf hashes this left sibling.
            if (pathBit(gamma, p.n, d) == 1) p.ws.stack[d] = sib_label;
        }
        if (p.m == p.n) {
            out[0..label_len].* = p.ws.top[topIndex(p.n, gamma)];
            return;
        }
        p.target = gamma;
        p.capture = out;
        _ = p.labelOf(p.m, gamma >> @intCast(p.n - p.m));
        p.capture = null;
    }
};

pub const SolveError = error{InvalidParams};

/// Produces a proof for `chi`. Sequential cost is `2^(n+1) - 1` hashes plus
/// `t * 2^(n - m + 1)` for the openings; memory is the caller's workspace.
pub fn solve(chi: []const u8, params: Params, ws: *Workspace) SolveError![]const u8 {
    if (!params.validate()) return error.InvalidParams;
    var p = Prover{
        .base = baseHasher(chi),
        .n = params.depth,
        .m = @min(params.depth, stored_depth_max),
        .ws = ws,
    };
    const phi = p.labelOf(0, 0);
    ws.proof[0..label_len].* = phi;
    const opening_size = params.openingSize();
    var i: u8 = 0;
    while (i < params.challenges) : (i += 1) {
        const gamma = challengeLeaf(chi, &phi, i, params.depth);
        const out = ws.proof[label_len + @as(usize, i) * opening_size ..][0..opening_size];
        p.open(gamma, out);
    }
    return ws.proof[0..params.proofSize()];
}

/// Reference labelling straight from the DAG definition, memoised over a
/// fully materialised table. Used only by tests to cross-check the
/// streaming prover; it shares no code with the sibling stack trick.
const Reference = struct {
    base: Sha256,
    n: u8,
    labels: []Label,
    done: []bool,

    fn label(r: *Reference, depth: u8, index: u32) Label {
        const slot = topIndex(depth, index);
        if (r.done[slot]) return r.labels[slot];
        var h = nodeHasher(&r.base, depth, index);
        if (depth == r.n) {
            var d: u8 = 1;
            while (d <= r.n) : (d += 1) {
                if (pathBit(index, r.n, d) == 1) {
                    const parent = r.label(d, (index >> @intCast(r.n - d)) ^ 1);
                    h.update(&parent);
                }
            }
        } else {
            const left = r.label(depth + 1, index * 2);
            const right = r.label(depth + 1, index * 2 + 1);
            h.update(&left);
            h.update(&right);
        }
        h.final(&r.labels[slot]);
        r.done[slot] = true;
        return r.labels[slot];
    }
};

fn referenceRoot(allocator: std.mem.Allocator, chi: []const u8, n: u8) !Label {
    const node_count = (@as(usize, 1) << @intCast(n + 1)) - 1;
    const labels = try allocator.alloc(Label, node_count);
    defer allocator.free(labels);
    const done = try allocator.alloc(bool, node_count);
    defer allocator.free(done);
    @memset(done, false);
    var r = Reference{ .base = baseHasher(chi), .n = n, .labels = labels, .done = done };
    return r.label(0, 0);
}

test "posw prover matches the reference labelling and verifies" {
    const ws = try std.testing.allocator.create(Workspace);
    defer std.testing.allocator.destroy(ws);
    const chi = "0123456789abcdef0123456789abcdef";
    inline for (.{ Params{ .depth = 6, .challenges = 4 }, Params{ .depth = 12, .challenges = 8 } }) |params| {
        const proof = try solve(chi, params, ws);
        try std.testing.expectEqual(params.proofSize(), proof.len);
        const root = try referenceRoot(std.testing.allocator, chi, params.depth);
        try std.testing.expectEqualSlices(u8, &root, proof[0..label_len]);
        try std.testing.expect(verify(chi, params, proof));
    }
}

test "posw rejects tampering, wrong statement, and wrong parameters" {
    const ws = try std.testing.allocator.create(Workspace);
    defer std.testing.allocator.destroy(ws);
    const chi = "sibuna-posw-statement";
    const params = Params{ .depth = 11, .challenges = 6 };
    const proof = try solve(chi, params, ws);
    try std.testing.expect(verify(chi, params, proof));
    try std.testing.expect(!verify("other-statement", params, proof));
    try std.testing.expect(!verify(chi, .{ .depth = 12, .challenges = 6 }, proof));
    try std.testing.expect(!verify(chi, .{ .depth = 11, .challenges = 5 }, proof));

    var copy: [max_proof_size]u8 = undefined;
    @memcpy(copy[0..proof.len], proof);
    copy[label_len + 40] ^= 0x01;
    try std.testing.expect(!verify(chi, params, copy[0..proof.len]));
    copy[label_len + 40] ^= 0x01;
    copy[3] ^= 0x80;
    try std.testing.expect(!verify(chi, params, copy[0..proof.len]));
    try std.testing.expectError(error.InvalidParams, solve(chi, .{ .depth = 2, .challenges = 1 }, ws));
}
