//! Standard JSON tokenization with borrowed capacity. Initialize in place and do
//! not call the standard scanner's deinit: its bit storage belongs to the caller.
const std = @import("std");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = work.Error || error{
    InvalidJson,
    JsonDepthLimit,
    JsonValueLimit,
    InvalidJsonScratch,
};
pub const Scanner = struct {
    raw: std.json.Scanner,
    blocked: std.heap.FixedBufferAllocator,
    value: []u8,
    used: usize = 0,
    maximum_depth: usize,
    budget: *work.Budget,

    pub fn init(
        self: *Scanner,
        input: []const u8,
        output: []u8,
        bits: []u8,
        depth: usize,
        budget: *work.Budget,
    ) Error!void {
        if (depth == 0 or depth > 256 or bits.len < (depth + 7) / 8)
            return error.InvalidJsonScratch;
        buffers.assertExclusive(&.{ input, output, bits });
        const visits = std.math.mul(u64, input.len, 32) catch return error.WorkLimit;
        try budget.debit(std.math.add(u64, visits, 1) catch return error.WorkLimit);
        self.* = .{
            .raw = undefined,
            .blocked = .init(&.{}),
            .value = output,
            .maximum_depth = depth,
            .budget = budget,
        };
        self.raw = .initCompleteInput(self.blocked.allocator(), input);
        // BitStack.push never grows while bit_len stays below this capacity.
        // peekNextTokenType rejects excess depth before a push can allocate.
        self.raw.stack.bytes = .fromOwnedSlice(self.blocked.allocator(), bits);
    }

    /// Partial escaped strings are assembled in one fixed output region. Tokens
    /// borrow input or output only until the next call; consumers must copy first.
    pub fn next(self: *Scanner) Error!std.json.Token {
        self.used = 0;
        const kind = self.raw.peekNextTokenType() catch return error.InvalidJson;
        if ((kind == .object_begin or kind == .array_begin) and
            self.raw.stack.bit_len >= self.maximum_depth) return error.JsonDepthLimit;
        while (true) {
            try self.budget.debit(1);
            const token = self.raw.next() catch |err| switch (err) {
                error.OutOfMemory => return error.JsonDepthLimit,
                else => return error.InvalidJson,
            };
            switch (token) {
                .partial_string, .partial_number => |bytes| try self.append(bytes),
                .partial_string_escaped_1 => |bytes| try self.append(&bytes),
                .partial_string_escaped_2 => |bytes| try self.append(&bytes),
                .partial_string_escaped_3 => |bytes| try self.append(&bytes),
                .partial_string_escaped_4 => |bytes| try self.append(&bytes),
                .string => |bytes| {
                    try self.append(bytes);
                    return .{ .string = self.value[0..self.used] };
                },
                .number => |bytes| {
                    if (bytes.len > self.value.len) return error.JsonValueLimit;
                    if (self.used == 0) return token;
                    try self.append(bytes);
                    return .{ .number = self.value[0..self.used] };
                },
                .allocated_number, .allocated_string => unreachable,
                else => return token,
            }
        }
    }

    fn append(self: *Scanner, bytes: []const u8) Error!void {
        if (bytes.len > self.value.len - self.used) return error.JsonValueLimit;
        try self.budget.debit(bytes.len);
        buffers.assertDisjoint(bytes, self.value[self.used..][0..bytes.len]);
        @memcpy(self.value[self.used..][0..bytes.len], bytes);
        self.used += bytes.len;
    }
};

test {
    _ = @import("bounded_json_test.zig");
}
