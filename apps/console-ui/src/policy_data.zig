const std = @import("std");
const limits = @import("policy_limits.zig");
pub const Page = struct {
    committed: []const u8,
    applied: []const u8,
    total: u16,
    waf: bool,
    default_difficulty: u32,
    default_algorithm: []const u8,
    rows: []const Row,
    next: ?u8,
};
pub const Row = struct {
    limits: ?limits.Limits,
    index: u8,
    name: []const u8,
    action: []const u8,
    path: []const u8,
    user_agent: []const u8,
    truncated: bool,
    header_count: u8,
    cidr_count: u8,
    difficulty: ?u32,
    algorithm: ?[]const u8,
    weight: i32,
};
pub const Decision = struct {
    limits: ?limits.Limits,
    audited: ?u8,
    preview: bool,
    committed: ?[]const u8,
    applied: []const u8,
    action: []const u8,
    rule: []const u8,
    difficulty: u32,
    algorithm: []const u8,
    score: i32,
};

const Error = error{InvalidPolicy};

// Reuse the UI's existing bounded JSON-tree decoder. Typed value checks avoid
// instantiating a separate streaming parser for each small policy response shape.
fn field(value: std.json.Value, key: []const u8) Error!std.json.Value {
    if (value != .object) return error.InvalidPolicy;
    return value.object.get(key) orelse error.InvalidPolicy;
}

fn text(value: std.json.Value, key: []const u8) Error![]const u8 {
    const item = try field(value, key);
    if (item != .string) return error.InvalidPolicy;
    return item.string;
}

fn number(comptime T: type, value: std.json.Value, key: []const u8) Error!T {
    const item = try field(value, key);
    if (item != .integer) return error.InvalidPolicy;
    return std.math.cast(T, item.integer) orelse error.InvalidPolicy;
}

fn boolean(value: std.json.Value, key: []const u8) Error!bool {
    const item = try field(value, key);
    if (item != .bool) return error.InvalidPolicy;
    return item.bool;
}

pub fn page(value: std.json.Value, rows: *[8]Row) Error!Page {
    const items = try field(value, "rows");
    if (items != .array or items.array.items.len > rows.len) return error.InvalidPolicy;
    for (items.array.items, 0..) |item, i| rows[i] = try row(item);
    return .{
        .committed = try text(value, "committed"),
        .applied = try text(value, "applied"),
        .total = try number(u16, value, "total"),
        .waf = try boolean(value, "waf"),
        .default_difficulty = try number(u32, value, "default_difficulty"),
        .default_algorithm = try text(value, "default_algorithm"),
        .rows = rows[0..items.array.items.len],
        .next = if (try field(value, "next") == .null) null else try number(u8, value, "next"),
    };
}

fn row(value: std.json.Value) Error!Row {
    return .{
        .limits = limits.read(value) catch return error.InvalidPolicy,
        .index = try number(u8, value, "index"),
        .name = try text(value, "name"),
        .action = try text(value, "action"),
        .path = try text(value, "path"),
        .user_agent = try text(value, "user_agent"),
        .truncated = try boolean(value, "truncated"),
        .header_count = try number(u8, value, "header_count"),
        .cidr_count = try number(u8, value, "cidr_count"),
        .difficulty = if (try field(value, "difficulty") == .null)
            null
        else
            try number(u32, value, "difficulty"),
        .algorithm = if (try field(value, "algorithm") == .null)
            null
        else
            try text(value, "algorithm"),
        .weight = try number(i32, value, "weight"),
    };
}

pub fn decision(value: std.json.Value) Error!Decision {
    if (value != .object) return error.InvalidPolicy;
    const preview = if (value.object.contains("preview"))
        try boolean(value, "preview")
    else
        false;
    const audited = if (value.object.contains("audited_categories"))
        try number(u8, value, "audited_categories")
    else
        null;
    if (audited) |mask| if (mask > 15) return error.InvalidPolicy;
    return .{
        .audited = audited,
        .limits = limits.read(value) catch return error.InvalidPolicy,
        .preview = preview,
        .committed = if (preview) try text(value, "committed") else null,
        .applied = try text(value, "applied"),
        .action = try text(value, "action"),
        .rule = try text(value, "rule"),
        .difficulty = try number(u32, value, "difficulty"),
        .algorithm = try text(value, "algorithm"),
        .score = try number(i32, value, "score"),
    };
}
