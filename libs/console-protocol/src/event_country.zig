//! Persistence-time attribution, not a reconstructed request-time location.
const std = @import("std");
const Bytes = @import("root.zig").Bytes;
pub const Filter = Bytes(12);
pub const Wire = struct {
    code: ?[]const u8 = null,
    generation: ?[]const u8 = null,
    mixed: bool = false,
    recorded: bool = false,
};
pub const Mapping = struct {
    code: Bytes(2) = .{},
    generation: Bytes(64) = .{},
    mixed: bool = false,
    recorded: bool = false,

    pub fn jsonStringify(self: Mapping, json: *std.json.Stringify) !void {
        try json.write(self.wire());
    }

    /// Returned text borrows the owned mapping; callers retain it through serialization.
    pub fn wire(self: *const Mapping) Wire {
        const code: ?[]const u8 = if (self.code.len != 0) self.code.slice() else null;
        const hash = self.generation.slice();
        const digest: ?[]const u8 = if (hash.len != 0) hash else null;
        return .{
            .code = code,
            .generation = digest,
            .mixed = self.mixed,
            .recorded = self.recorded,
        };
    }

    pub fn matches(self: Mapping, filter: []const u8) bool {
        if (filter.len == 0) return true;
        if (self.mixed) return false;
        if (std.mem.eql(u8, filter, "not_recorded")) return !self.recorded;
        if (std.mem.eql(u8, filter, "unknown"))
            return self.recorded and self.code.len == 0;
        return std.mem.eql(u8, self.code.slice(), filter);
    }

    pub fn decode(input: Wire) !Mapping {
        const code = input.code;
        const generation = input.generation;
        if (code) |value| if (value.len != 2 or !validFilter(value))
            return error.InvalidCountry;
        if (generation) |value| {
            if (value.len != 64) return error.InvalidCountry;
            for (value) |byte| if (!std.ascii.isHex(byte)) return error.InvalidCountry;
        }
        return .{
            .code = try Bytes(2).init(code orelse ""),
            .generation = try Bytes(64).init(generation orelse ""),
            .mixed = input.mixed,
            .recorded = input.recorded or generation != null,
        };
    }
};

pub fn validFilter(value: []const u8) bool {
    return value.len == 0 or std.mem.eql(u8, value, "unknown") or
        std.mem.eql(u8, value, "not_recorded") or (value.len == 2 and
        value[0] >= 'A' and value[0] <= 'Z' and value[1] >= 'A' and value[1] <= 'Z');
}

test "missing mapping, unknown address and mixed source groups remain distinct" {
    const t = std.testing;
    const absent: Mapping = .{};
    const unknown = try Mapping.decode(.{ .generation = "a" ** 64 });
    const known = try Mapping.decode(.{ .code = "US", .generation = "b" ** 64 });
    try t.expect(absent.matches("not_recorded") and !absent.matches("unknown"));
    try t.expect(unknown.matches("unknown") and !unknown.matches("not_recorded"));
    try t.expect(known.matches("US") and !known.matches("DE"));
    const view = known.wire();
    try t.expectEqual(@intFromPtr(&known.code.data), @intFromPtr(view.code.?.ptr));
    try t.expectEqual(@intFromPtr(&known.generation.data), @intFromPtr(view.generation.?.ptr));
    const multiple = try Mapping.decode(.{ .recorded = true });
    try t.expect(multiple.matches("unknown") and !multiple.matches("not_recorded"));
    try t.expect(!(Mapping{ .mixed = true }).matches("not_recorded"));
    try t.expectError(error.InvalidCountry, Mapping.decode(.{ .code = "U'" }));
    try t.expectError(error.InvalidCountry, Mapping.decode(.{
        .code = "US",
        .generation = "z" ** 64,
    }));
}
