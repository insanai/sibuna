//! Local intent and effect remain separate, portable records. Names are derived
//! from fixed random identities; selectors never authorize arbitrary paths.
const std = @import("std");
pub const Id = [16]u8;
pub const Digest = [32]u8;
pub const capacity = 2048;
pub const Error = error{InvalidLocalRecord};
pub const Source = struct {
    id: Id,
    digest: Digest,
    revision: u64,

    pub fn name(self: Source) [43]u8 {
        return "generation-".* ++ std.fmt.bytesToHex(self.id, .lower);
    }

    pub fn validate(self: Source) Error!void {
        if (self.revision == 0 or self.revision > std.math.maxInt(i64) or
            std.mem.allEqual(u8, &self.id, 0)) return error.InvalidLocalRecord;
    }
};
pub const Selection = struct {
    schema: u8 = 1,
    current: Source,
    previous: ?Source,
    selected_at: u64,

    pub fn validate(self: Selection) Error!void {
        if (self.schema != 1) return error.InvalidLocalRecord;
        try self.current.validate();
        if (self.previous) |previous| {
            try previous.validate();
            if (previous.revision >= self.current.revision or
                std.mem.eql(u8, &previous.id, &self.current.id)) return error.InvalidLocalRecord;
        } else if (self.current.revision != 1) return error.InvalidLocalRecord;
    }
};
pub const State = enum { pending, applied, failed };
pub const Reason = enum { none, source, signature, incompatible, capacity, publication };
pub const Receipt = struct {
    schema: u8 = 1,
    source: Source,
    boot: Id,
    observed_at: u64,
    state: State,
    reason: Reason = .none,

    pub fn validate(self: Receipt) Error!void {
        try self.source.validate();
        if (self.schema != 1 or (self.state == .failed) != (self.reason != .none) or
            (self.state == .applied and std.mem.allEqual(u8, &self.boot, 0)))
            return error.InvalidLocalRecord;
    }
};

test "local selectors reject path-free identity reuse, invalid revisions and future schemas" {
    const t = std.testing;
    var selection: Selection = .{
        .current = .{ .id = @splat(1), .digest = @splat(2), .revision = 1 },
        .previous = null,
        .selected_at = 1,
    };
    try selection.validate();
    const name = selection.current.name();
    try t.expectEqualStrings("generation-01010101010101010101010101010101", &name);
    selection.schema = 2;
    try t.expectError(error.InvalidLocalRecord, selection.validate());
    selection.schema = 1;
    selection.current.revision = 2;
    try t.expectError(error.InvalidLocalRecord, selection.validate());
    selection.previous = .{ .id = @splat(1), .digest = @splat(3), .revision = 1 };
    try t.expectError(error.InvalidLocalRecord, selection.validate());
    selection.previous.?.id = @splat(4);
    try selection.validate();
    selection.previous.?.revision = 2;
    try t.expectError(error.InvalidLocalRecord, selection.validate());
}
