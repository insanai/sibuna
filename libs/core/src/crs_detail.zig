//! Owned unexpanded rule templates and net score changes. No transaction bytes or
//! engine references enter this contract, which also compiles for browser clients.
const std = @import("std");
pub const Error = error{InvalidEvidence};
pub const tag_capacity = 4;
pub const bucket_count = 8;
pub const max_json = 4096;

pub fn Preview(comptime capacity: usize) type {
    return struct {
        data: [capacity]u8 = @splat(0),
        len: u16 = 0,
        bytes: u32 = 0,
        const Self = @This();

        pub fn copy(source: []const u8) Self {
            std.debug.assert(source.len <= 64 * 1024);
            var result: Self = .{ .bytes = @intCast(source.len) };
            result.len = @intCast(@min(source.len, capacity));
            @memcpy(result.data[0..result.len], source[0..result.len]);
            return result;
        }

        pub fn slice(self: *const Self) []const u8 {
            std.debug.assert(self.len <= capacity);
            return self.data[0..self.len];
        }

        pub fn validate(self: *const Self) Error!void {
            if (self.bytes > 64 * 1024 or self.len != @min(self.bytes, capacity))
                return error.InvalidEvidence;
            for (self.data[self.len..]) |byte| if (byte != 0) return error.InvalidEvidence;
        }

        pub fn jsonStringify(self: Self, json: *std.json.Stringify) !void {
            const hex = std.fmt.bytesToHex(&self.data, .lower);
            try json.write(.{ .hex = hex[0 .. self.len * 2], .bytes = self.bytes });
        }
    };
}

pub const Bucket = struct {
    writes: u32 = 0,
    delta: ?i64 = null,

    pub fn jsonStringify(self: Bucket, json: *std.json.Stringify) !void {
        var buffer: [20]u8 = undefined;
        const delta = if (self.delta) |value|
            std.fmt.bufPrint(&buffer, "{d}", .{value}) catch unreachable
        else
            null;
        try json.write(.{ .writes = self.writes, .delta = delta });
    }
};
pub const Contribution = struct {
    scope: enum { root_net } = .root_net,
    buckets: [bucket_count]Bucket = @splat(.{}),

    pub fn validate(self: *const Contribution) Error!void {
        var observed = false;
        for (self.buckets) |bucket| {
            if (bucket.writes == 0 and bucket.delta != null) return error.InvalidEvidence;
            observed = observed or bucket.writes != 0;
        }
        if (!observed) return error.InvalidEvidence;
    }
};
pub const Detail = struct {
    version: u8 = 1,
    rule_id: u32,
    phase: u8,
    message: ?Preview(96) = null,
    tags: [tag_capacity]?Preview(64) = @splat(null),
    tag_count: u8 = 0,
    omitted_tags: u32 = 0,
    score: ?Contribution = null,

    pub fn validate(self: *const Detail) Error!void {
        if (self.version != 1 or self.rule_id == 0 or self.phase < 1 or self.phase > 5 or
            self.tag_count > tag_capacity or self.omitted_tags > 65536)
            return error.InvalidEvidence;
        if (self.message) |*message| try message.validate();
        for (self.tags[0..self.tag_count]) |tag| {
            const value = tag orelse return error.InvalidEvidence;
            try value.validate();
        }
        for (self.tags[self.tag_count..]) |tag| if (tag != null) return error.InvalidEvidence;
        if (self.omitted_tags != 0 and self.tag_count != tag_capacity)
            return error.InvalidEvidence;
        if (self.score) |*score| try score.validate();
    }
};

const WirePreview = struct {
    hex: []const u8,
    bytes: u32,

    fn into(self: WirePreview, output: anytype) Error!void {
        output.* = .{ .bytes = self.bytes };
        const length: usize = @min(self.bytes, output.data.len);
        if (self.hex.len != length * 2) return error.InvalidEvidence;
        _ = std.fmt.hexToBytes(output.data[0..length], self.hex) catch
            return error.InvalidEvidence;
        output.len = @intCast(length);
        try output.validate();
    }
};
const WireBucket = struct { writes: u32, delta: ?[]const u8 };
pub const Wire = struct {
    version: u8,
    rule_id: u32,
    phase: u8,
    message: ?WirePreview,
    tags: [tag_capacity]?WirePreview,
    tag_count: u8,
    omitted_tags: u32,
    score: ?struct { scope: enum { root_net }, buckets: [bucket_count]WireBucket },

    pub fn into(self: Wire, output: *Detail) Error!void {
        output.* = .{
            .version = self.version,
            .rule_id = self.rule_id,
            .phase = self.phase,
            .tag_count = self.tag_count,
            .omitted_tags = self.omitted_tags,
        };
        if (self.message) |message| {
            var value: Preview(96) = undefined;
            try message.into(&value);
            output.message = value;
        }
        for (self.tags, &output.tags) |tag, *destination| if (tag) |value| {
            var owned: Preview(64) = undefined;
            try value.into(&owned);
            destination.* = owned;
        };
        if (self.score) |score| {
            var contribution: Contribution = .{};
            for (score.buckets, &contribution.buckets) |bucket, *destination| {
                destination.* = .{ .writes = bucket.writes };
                if (bucket.delta) |number| destination.delta = try signed(number);
            }
            output.score = contribution;
        }
        try output.validate();
    }
};

fn signed(bytes: []const u8) Error!i64 {
    if (bytes.len == 0 or bytes.len > 20) return error.InvalidEvidence;
    const start: usize = if (bytes[0] == '-') 1 else 0;
    if (start == bytes.len) return error.InvalidEvidence;
    for (bytes[start..]) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidEvidence;
    return std.fmt.parseInt(i64, bytes, 10) catch error.InvalidEvidence;
}

test {
    _ = @import("crs_detail_test.zig");
}
