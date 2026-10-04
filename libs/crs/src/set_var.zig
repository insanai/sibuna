//! Prepared transaction-variable operations. Rule timing belongs to the executor.
const std = @import("std");
const macros = @import("macros.zig");
const variables = @import("variables.zig");
const tx = @import("transaction_vars.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = macros.Error || tx.Error || error{ InvalidAssignment, UnsupportedNamespace };
pub const Operation = enum { assign, add, subtract, unset };
pub const Frame = struct {
    store: *tx.Store,
    view: *const variables.View,
    pieces: [][]const u8,
    key_output: []u8,
    value_output: []u8,
    budget: *work.Budget,
};
pub const Program = struct {
    operation: Operation,
    key: macros.Program,
    value: ?macros.Program,

    pub fn deinit(self: *Program) void {
        self.key.deinit();
        if (self.value) |*value| value.deinit();
        self.* = undefined;
    }

    /// Operands precede dynamic keys in the reference. Separate buffers retain both
    /// results until the one atomic store operation; the shared parts scratch is reusable.
    pub fn execute(self: *const Program, frame: Frame) Error!void {
        if (frame.store.failed) return error.TransactionFailed;
        errdefer frame.store.failed = true;
        buffers.assertDisjoint(frame.key_output, frame.value_output);
        const value = if (self.value) |*program| try program.expand(.{
            .view = frame.view,
            .pieces = frame.pieces,
            .output = frame.value_output,
            .budget = frame.budget,
        }) else "";
        const key = try self.key.expand(.{
            .view = frame.view,
            .pieces = frame.pieces,
            .output = frame.key_output,
            .budget = frame.budget,
        });
        switch (self.operation) {
            .unset => _ = try frame.store.remove(key, frame.budget),
            .assign => try frame.store.update(key, .assign, value, frame.budget),
            .add => try frame.store.update(key, .add, value, frame.budget),
            .subtract => try frame.store.update(key, .subtract, value, frame.budget),
        }
    }
};

pub fn compile(allocator: std.mem.Allocator, source: []const u8) Error!Program {
    if (source.len > 64 * 1024) return error.SourceLimit;
    const unset = std.mem.startsWith(u8, source, "!");
    const argument = if (unset) source[1..] else source;
    const separator = std.mem.indexOfScalar(u8, argument, '=');
    if (unset and separator != null) return error.InvalidAssignment;
    const target = argument[0 .. separator orelse argument.len];
    if (target.len < 4 or !std.ascii.eqlIgnoreCase(target[0..2], "tx") or
        (target[2] != '.' and target[2] != ':')) return error.UnsupportedNamespace;
    var operation: Operation = if (unset) .unset else .assign;
    var operand = if (separator) |index| argument[index + 1 ..] else "1";
    if (separator != null and operand.len > 0) {
        if (operand[0] == '+' or operand[0] == '-') {
            operation = if (operand[0] == '+') .add else .subtract;
            operand = operand[1..];
        }
    }
    var key = try macros.compile(allocator, target[3..], .{});
    errdefer key.deinit();
    const value = if (unset) null else try macros.compile(allocator, operand, .{});
    return .{ .operation = operation, .key = key, .value = value };
}

test {
    _ = @import("set_var_test.zig");
}
