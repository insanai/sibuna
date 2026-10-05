//! Bounded HTTP representation decoding. Transfer framing is already removed;
//! the retained wire entity is never modified or substituted during proxy replay.
const std = @import("std");
const codec = @import("compression");
const fields = @import("text").http_fields;
const buffers = @import("text").buffers;
pub const Error = codec.Error || error{
    UnsupportedContentCoding,
    ContentCodingLimit,
    InvalidContentCoding,
};
pub const Storage = struct {
    output: []u8,
    alternate: []u8,
    window: []u8,
    wire_limit: usize = 64 * 1024 * 1024,
};
pub const Plan = struct {
    codings: [4]codec.Coding = undefined,
    count: usize = 0,

    /// Duplicate field lines are combined in their original order. Decoding
    /// reverses that order; unsupported layers cannot become identity data.
    pub fn parse(headers: []const fields.Header, budget: anytype) Error!Plan {
        if (headers.len > 128) return error.ContentCodingLimit;
        var plan: Plan = .{};
        var empty: usize = 0;
        for (headers) |header| {
            try budget.debitLinear(header.name.len, 1, 1);
            if (!std.ascii.eqlIgnoreCase(header.name, "content-encoding")) continue;
            if (header.value.len > 4096) return error.ContentCodingLimit;
            try budget.debitLinear(header.value.len, 2, 1);
            var tokens = std.mem.splitScalar(u8, header.value, ',');
            while (tokens.next()) |token| {
                const name = std.mem.trim(u8, token, " \t");
                // RFC 9110 list recipients tolerate a bounded number of empty
                // elements. Bound them independently from actual coding layers.
                if (name.len == 0) {
                    empty += 1;
                    if (empty > 16) return error.ContentCodingLimit;
                    continue;
                }
                if (!@import("http.zig").validToken(name)) return error.InvalidContentCoding;
                if (std.ascii.eqlIgnoreCase(name, "identity")) continue;
                if (plan.count == plan.codings.len) return error.ContentCodingLimit;
                const coding = codingName(name) orelse return error.UnsupportedContentCoding;
                plan.codings[plan.count] = coding;
                plan.count += 1;
            }
        }
        return plan;
    }

    /// Both expansion buffers are reserved to the permitted decoded ceiling.
    /// Raw identity returns a borrow of wire; all layers use the same work ledger.
    pub fn decode(
        self: Plan,
        wire: []const u8,
        storage: Storage,
        budget: anytype,
    ) Error![]const u8 {
        std.debug.assert(self.count <= self.codings.len);
        if (storage.output.len != storage.alternate.len or
            storage.output.len > 64 * 1024 * 1024 or
            storage.window.len != codec.window_length or
            storage.wire_limit == 0 or storage.wire_limit > 64 * 1024 * 1024)
            return error.InvalidCompressionLimits;
        if (wire.len > storage.wire_limit) return error.CompressedInputLimit;
        if (self.count == 0 and wire.len > storage.output.len) return error.ExpansionLimit;
        buffers.assertExclusive(&.{ wire, storage.output, storage.alternate, storage.window });
        var result = wire;
        var output = storage.output;
        var alternate = storage.alternate;
        var remaining = self.count;
        while (remaining != 0) {
            remaining -= 1;
            const coding = self.codings[remaining];
            result = try codec.decode(.{
                .input = result,
                .coding = coding,
                .input_limit = 64 * 1024 * 1024,
                .member_limit = if (coding == .gzip) 64 else 1,
                .scratch = .{ .output = output, .window = storage.window },
            }, budget);
            const previous = output;
            output = alternate;
            alternate = previous;
        }
        return result;
    }
};

fn codingName(name: []const u8) ?codec.Coding {
    if (std.ascii.eqlIgnoreCase(name, "gzip") or std.ascii.eqlIgnoreCase(name, "x-gzip"))
        return .gzip;
    if (std.ascii.eqlIgnoreCase(name, "deflate")) return .zlib;
    return null;
}

test {
    _ = @import("content_coding_test.zig");
}
