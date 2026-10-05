const std = @import("std");
const coding = @import("content_coding.zig");
const Header = @import("text").http_fields.Header;
const t = std.testing;
const payload = "bounded representation\n";
const gzip = @embedFile("testdata/coding-gzip.bin");
const zlib = @embedFile("testdata/coding-zlib.bin");
const stacked = @embedFile("testdata/coding-stacked.bin");
const Budget = struct {
    remaining: u64 = 1_000_000,

    pub fn debitLinear(self: *Budget, bytes: u64, visits: u64, overhead: u64) !void {
        const cost = std.math.mul(u64, bytes, visits) catch return error.WorkLimit;
        const total = std.math.add(u64, cost, overhead) catch return error.WorkLimit;
        if (total > self.remaining) return error.WorkLimit;
        self.remaining -= total;
    }
};
const Fixture = struct {
    output: [256]u8 = undefined,
    alternate: [256]u8 = undefined,
    window: [std.compress.flate.max_window_len]u8 = undefined,
    budget: Budget = .{},

    fn storage(self: *Fixture) coding.Storage {
        return .{ .output = &self.output, .alternate = &self.alternate, .window = &self.window };
    }
};

fn plan(name: []const u8, budget: *Budget) !coding.Plan {
    return coding.Plan.parse(&.{.{ .name = "Content-Encoding", .value = name }}, budget);
}

test "HTTP gzip, deflate and stacked codings decode in reverse order without altering wire bytes" {
    const cases = [_]struct { name: []const u8, wire: []const u8 }{
        .{ .name = "gzip", .wire = gzip },
        .{ .name = "X-GZIP", .wire = gzip },
        .{ .name = "deflate", .wire = zlib },
        .{ .name = "gzip, deflate", .wire = stacked },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        const selected = try plan(case.name, &fixture.budget);
        const decoded = try selected.decode(case.wire, fixture.storage(), &fixture.budget);
        try t.expectEqualStrings(payload, decoded);
        try t.expectEqual(@intFromPtr(&fixture.output), @intFromPtr(decoded.ptr));
    }
    var fixture: Fixture = .{};
    const selected = try coding.Plan.parse(&.{
        .{ .name = "Content-Encoding", .value = "GZIP" },
        .{ .name = "content-encoding", .value = "deflate" },
    }, &fixture.budget);
    const decoded = try selected.decode(stacked, fixture.storage(), &fixture.budget);
    try t.expectEqualStrings(payload, decoded);
    @memset(&fixture.alternate, '!');
    try t.expectEqualStrings(payload, decoded);
}

test "identity coding borrows bytes and concatenated gzip validates every member" {
    var fixture: Fixture = .{};
    const identity = try plan(", identity, ,", &fixture.budget);
    const raw = try identity.decode(payload, fixture.storage(), &fixture.budget);
    try t.expectEqual(@intFromPtr(payload.ptr), @intFromPtr(raw.ptr));
    const compressed = try plan("gzip", &fixture.budget);
    const pair = gzip ++ gzip;
    const decoded = try compressed.decode(pair, fixture.storage(), &fixture.budget);
    try t.expectEqualStrings(payload ++ payload, decoded);
    var corrupt: [pair.len]u8 = undefined;
    @memcpy(&corrupt, pair);
    corrupt[corrupt.len - 8] ^= 1;
    const result = compressed.decode(&corrupt, fixture.storage(), &fixture.budget);
    try t.expectError(error.InvalidCompressedChecksum, result);
}

test "content coding refuses unsupported, malformed and over-budget header plans" {
    const cases = [_]struct { value: []const u8, err: coding.Error }{
        .{ .value = "br", .err = error.UnsupportedContentCoding },
        .{ .value = "gzip;q=1", .err = error.InvalidContentCoding },
        .{ .value = "gzip,deflate,gzip,deflate,gzip", .err = error.ContentCodingLimit },
        .{ .value = ",,,,,,,,,,,,,,,,,", .err = error.ContentCodingLimit },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        try t.expectError(case.err, plan(case.value, &fixture.budget));
    }
    var fixture: Fixture = .{};
    const headers: [129]Header = @splat(.{ .name = "x", .value = "y" });
    try t.expectError(error.ContentCodingLimit, coding.Plan.parse(&headers, &fixture.budget));
    fixture.budget.remaining = 0;
    try t.expectError(error.WorkLimit, plan("gzip", &fixture.budget));
}

test "content expansion has independent representation and shared work bounds" {
    var fixture: Fixture = .{};
    const selected = try plan("gzip", &fixture.budget);
    var storage = fixture.storage();
    storage.wire_limit = gzip.len - 1;
    try t.expectError(error.CompressedInputLimit, selected.decode(gzip, storage, &fixture.budget));
    storage = fixture.storage();
    storage.output = fixture.output[0..4];
    storage.alternate = fixture.alternate[0..4];
    const oversized = selected.decode(gzip, storage, &fixture.budget);
    try t.expectError(error.ExpansionLimit, oversized);
    fixture.budget.remaining = 0;
    const result = selected.decode(gzip, fixture.storage(), &fixture.budget);
    try t.expectError(error.WorkLimit, result);
    storage = fixture.storage();
    storage.alternate = fixture.alternate[0..1];
    const invalid = selected.decode(gzip, storage, &fixture.budget);
    try t.expectError(error.InvalidCompressionLimits, invalid);
}
