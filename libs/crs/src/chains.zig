//! Owned contiguous chain topology and bounded, non-recursive truth evaluation.
//! Successful indices schedule post-match actions; this module does not execute them.
const std = @import("std");
const model = @import("model.zig");
const condition = @import("condition.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = condition.Error || error{
    InvalidTopology,
    ConditionLimit,
    ChainLimit,
    InvalidRoot,
    ProgramCount,
    UnwindLimit,
};
pub const Limits = struct { conditions: usize = 4096, depth: usize = 256 };
pub const Row = struct {
    root: usize,
    end: usize,
    id: u32,
    phase: model.Phase,
    skip_to: ?usize,
};
pub const Result = struct {
    matched: bool,
    /// Borrowed caller scratch; execute in this order only on complete chain truth.
    unwind: []const usize,
    next_root: usize,
};
pub const Program = struct {
    allocator: std.mem.Allocator,
    rows: []const Row,
    maximum_depth: usize,

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    /// All scratch is reserved before the first effect. The caller must not alias
    /// unwind metadata with generation data or Frame scratch. No recursive stack grows.
    pub fn evaluate(
        self: *const Program,
        programs: []const condition.Program,
        root: usize,
        frame: condition.Frame,
        unwind: []usize,
    ) Error!Result {
        if (frame.context.failed or frame.context.store.failed) return error.TransactionFailed;
        errdefer frame.context.poison();
        const output = std.mem.sliceAsBytes(unwind);
        frame.assertDisjoint(output);
        buffers.assertDisjoint(output, std.mem.sliceAsBytes(self.rows));
        buffers.assertDisjoint(output, std.mem.sliceAsBytes(programs));
        if (programs.len != self.rows.len) return error.ProgramCount;
        if (root >= self.rows.len or self.rows[root].root != root) return error.InvalidRoot;
        const end = self.rows[root].end;
        const depth = end - root;
        if (depth > unwind.len) return error.UnwindLimit;
        try frame.budget.debit(@intCast(depth));
        for (root..end) |index| {
            if (!try programs[index].evaluate(frame)) {
                return .{ .matched = false, .unwind = &.{}, .next_root = end };
            }
        }
        for (unwind[0..depth], 0..) |*index, offset| index.* = end - offset - 1;
        return .{ .matched = true, .unwind = unwind[0..depth], .next_root = end };
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    source: []const model.Condition,
    limits: Limits,
) Error!Program {
    if (source.len > limits.conditions) return error.ConditionLimit;
    const rows = try allocator.alloc(Row, source.len);
    errdefer allocator.free(rows);
    var root: usize = 0;
    var maximum: usize = 0;
    while (root < source.len) {
        const first = source[root];
        var end = root;
        while (true) {
            if (end >= source.len) return error.InvalidTopology;
            const item = source[end];
            if (item.root != root or item.phase != first.phase or item.id != first.id) {
                return error.InvalidTopology;
            }
            const depth = end - root + 1;
            if (depth > limits.depth) return error.ChainLimit;
            end += 1;
            if (item.chain_next) |next| {
                if (next != end) return error.InvalidTopology;
            } else break;
        }
        maximum = @max(maximum, end - root);
        for (root..end) |index| rows[index] = .{
            .root = root,
            .end = end,
            .id = first.id,
            .phase = first.phase,
            .skip_to = source[index].skip_to,
        };
        root = end;
    }
    for (rows, 0..) |row, index| {
        if (row.skip_to) |target| {
            if (target <= index or target > rows.len) return error.InvalidTopology;
            if (target < rows.len and rows[target].root != target) return error.InvalidTopology;
        }
    }
    return .{ .allocator = allocator, .rows = rows, .maximum_depth = maximum };
}

test {
    _ = @import("chains_test.zig");
}
