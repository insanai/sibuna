//! Internal owner-to-hub feeds. These operations are not public HTTP requests. Each issuer
//! has an independent durable incident cursor; node bits are never compared across issuers.
const std = @import("std");
const p = @import("root.zig");
pub const Kind = enum { events, audit };
pub const page_rows = 8;
pub const recent_ids = 64;
pub const Request = struct {
    kind: Kind,
    node: u32 = 0,
    after: ?u64 = null,
    through: ?u64 = null,
};
pub const Event = struct {
    geography: p.events.country.Mapping = .{},
    id: u64 = 0,
    node: u32 = 0,
    time: u64 = 0,
    ip: p.Bytes(48) = .{},
    method: p.Bytes(8) = .{},
    path: p.Bytes(128) = .{},
    category: p.Bytes(32) = .{},
    display_truncated: bool = false,
    query_redacted: bool = false,

    pub fn jsonStringify(self: Event, json: *std.json.Stringify) !void {
        try json.beginObject();
        inline for (@typeInfo(Event).@"struct".fields) |field| {
            try json.objectField(field.name);
            const value = @field(self, field.name);
            if (field.type == u64) {
                try p.writeCounter(json, value);
            } else if (field.type == p.events.country.Mapping) {
                try json.write(value);
            } else if (@typeInfo(field.type) == .@"struct") {
                try json.write(value.slice());
            } else try json.write(value);
        }
        try json.endObject();
    }
};
pub const Row = union(Kind) { events: Event, audit: p.audit.Row };
pub const Page = struct {
    kind: Kind,
    node: u32,
    head: u64,
    through: u64,
    next: u64,
    missing_ids: u64 = 0,
    observed_at: u64,
    producer_dropped: ?u64 = null,
    producer_boot: p.Bytes(32) = .{},
    replica_observed_at: u64 = 0,
    replica_quorum: bool = false,
    more: bool = false,
    rows: [page_rows]Row = undefined,
    count: u8 = 0,
};

pub fn validate(input: Request) error{InvalidLimit}!void {
    if (input.node >= (1 << 23) or (input.kind == .events) != (input.node != 0))
        return error.InvalidLimit;
    for ([_]?u64{ input.after, input.through }) |value| {
        if (value) |id| {
            if (id > std.math.maxInt(i64)) return error.InvalidLimit;
            if (input.kind == .events and id >> 40 != input.node) return error.InvalidLimit;
        }
    }
    if (input.after != null and input.through != null and input.after.? > input.through.?)
        return error.InvalidLimit;
}

test "feed cursor validation prevents cross-issuer comparisons" {
    const t = std.testing;
    try validate(.{ .kind = .events, .node = 2, .after = (@as(u64, 2) << 40) + 5 });
    try t.expectError(error.InvalidLimit, validate(.{
        .kind = .events,
        .node = 1,
        .after = (@as(u64, 2) << 40) + 5,
    }));
    try t.expectError(error.InvalidLimit, validate(.{ .kind = .audit, .node = 1 }));
}
