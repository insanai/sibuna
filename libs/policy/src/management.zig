//! Strict management documents, separate from the compatible startup-file loader.
//! The caller owns the allocator and all returned strings. Use a bounded arena whose
//! lifetime covers candidate validation and, after publication, the engine snapshot.
const std = @import("std");
const rule = @import("rule.zig");

pub const max_document = 4096;
pub const Error = error{
    TooLarge,
    InvalidId,
    InvalidName,
    InvalidPattern,
    InvalidHeader,
    InvalidCidr,
    TooManyHeaders,
    TooManyCidrs,
    InvalidChallenge,
    InvalidWeight,
    InvalidRuleLimit,
};
pub const ParseError = Error || std.json.ParseError(std.json.Scanner);
pub const Document = struct {
    id: []const u8,
    priority: i32,
    enabled: bool,
    value: rule.PolicyRule,
    /// Original CIDRs are retained for storage; the compiled rule owns normalized matchers.
    cidrs: []const []const u8,
};
const Wire = struct {
    id: []const u8,
    name: []const u8,
    action: rule.Action,
    priority: i32 = 100,
    enabled: bool = true,
    path: ?[]const u8 = null,
    user_agent: ?[]const u8 = null,
    headers: std.json.Value = .null,
    cidrs: []const []const u8 = &.{},
    difficulty: ?u32 = null,
    algorithm: ?enum { hashcash, posw } = null,
    weight: i32 = 0,
    limits: ?@import("rule_limits.zig").Limits = null,
};

pub fn parse(allocator: std.mem.Allocator, source: []const u8) ParseError!Document {
    if (source.len > max_document) return error.TooLarge;
    // Always copy strings: source may be a mailbox value released before publication.
    // Unknown and duplicate keys remain errors instead of becoming silently ignored policy.
    const wire = try std.json.parseFromSliceLeaky(Wire, allocator, source, .{
        .allocate = .alloc_always,
    });
    try identifier(wire.id);
    if (wire.name.len == 0 or wire.name.len > 128 or !validText(wire.name))
        return error.InvalidName;
    var value: rule.PolicyRule = .{
        .name = wire.name,
        .action = wire.action,
        .path_pattern = wire.path,
        .ua_pattern = wire.user_agent,
        .difficulty = wire.difficulty,
        .algorithm = if (wire.algorithm) |algorithm| @tagName(algorithm) else null,
        .weight = wire.weight,
        .limits = wire.limits,
        .limit_identity = @import("rule_limits.zig").managedIdentity(wire.id),
    };
    for ([_]?[]const u8{ wire.path, wire.user_agent }) |optional| {
        if (optional) |pattern| {
            if (pattern.len > 512 or !validText(pattern)) return error.InvalidPattern;
        }
    }
    if (wire.difficulty) |difficulty| {
        if (wire.action != .challenge or difficulty > 64) return error.InvalidChallenge;
    }
    if (wire.algorithm != null and wire.action != .challenge) return error.InvalidChallenge;
    if (wire.weight != 0 and wire.action != .weigh) return error.InvalidWeight;
    if (wire.limits) |limits| {
        if (wire.action == .weigh) return error.InvalidRuleLimit;
        try limits.validate();
    }
    try headers(wire.headers, &value);
    if (wire.cidrs.len > rule.MAX_RULE_CIDRS) return error.TooManyCidrs;
    for (wire.cidrs, 0..) |cidr, i| {
        if (cidr.len > 48) return error.InvalidCidr;
        value.cidrs[i] = rule.CidrMatcher.parse(cidr) orelse return error.InvalidCidr;
    }
    value.cidr_count = @intCast(wire.cidrs.len);
    return .{
        .id = wire.id,
        .priority = wire.priority,
        .enabled = wire.enabled,
        .value = value,
        .cidrs = wire.cidrs,
    };
}

fn identifier(id: []const u8) Error!void {
    if (id.len == 0 or id.len > 128) return error.InvalidId;
    for (id) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_')
            return error.InvalidId;
    }
}

fn validText(value: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(value)) return false;
    for (value) |byte| if (byte < 32 or byte == 127) return false;
    return true;
}

fn headers(value: std.json.Value, output: *rule.PolicyRule) Error!void {
    if (value == .null) return;
    if (value != .object) return error.InvalidHeader;
    if (value.object.count() > rule.MAX_RULE_HEADERS) return error.TooManyHeaders;
    var iterator = value.object.iterator();
    while (iterator.next()) |entry| {
        const name = entry.key_ptr.*;
        if (name.len == 0 or name.len > 64 or entry.value_ptr.* != .string)
            return error.InvalidHeader;
        for (name) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and
                std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) == null)
                return error.InvalidHeader;
        }
        const pattern = entry.value_ptr.*.string;
        if (pattern.len > 256 or !validText(pattern)) return error.InvalidHeader;
        for (output.headers[0..output.header_count]) |previous| {
            if (std.ascii.eqlIgnoreCase(previous.name, name)) return error.InvalidHeader;
        }
        output.headers[output.header_count] = .{ .name = name, .pattern = pattern };
        output.header_count += 1;
    }
}

test "management compilation owns mailbox strings and preserves matcher semantics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var source = ("{\"id\":\"checkout\",\"name\":\"Checkout\",\"action\":\"challenge\"," ++
        "\"path\":\"/checkout/*\",\"headers\":{\"X-Api\":\"v2\"}," ++
        "\"cidrs\":[\"8.8.8.0/24\"],\"algorithm\":\"posw\",\"difficulty\":16}").*;
    const document = try parse(arena.allocator(), &source);
    @memset(&source, 'x');
    try std.testing.expectEqualStrings("checkout", document.id);
    try std.testing.expectEqualStrings("posw", document.value.algorithm.?);
    try std.testing.expect(document.value.matches("/checkout/pay", "8.8.8.8", "", &.{
        .{ .name = "x-api", .value = "v2" },
    }));
    try std.testing.expect(!document.value.matches("/checkout/pay", "8.8.4.4", "", &.{
        .{ .name = "x-api", .value = "v2" },
    }));
}

test "management input rejects ambiguous and overflowing matchers without truncation" {
    const base = "{\"id\":\"test\",\"name\":\"Test\",\"action\":\"allow\",";
    const five_headers = "\"headers\":{\"A\":\"1\",\"B\":\"2\",\"C\":\"3\"," ++
        "\"D\":\"4\",\"E\":\"5\"}}";
    const nine_cidrs = "\"cidrs\":[" ++ "\"8.8.8.0/24\"," ** 8 ++ "\"8.8.4.0/24\"]}";
    const cases = .{
        .{ five_headers, error.TooManyHeaders },
        .{ nine_cidrs, error.TooManyCidrs },
        .{ "\"headers\":{\"X-Api\":\"1\",\"x-api\":\"2\"}}", error.InvalidHeader },
        .{ "\"cidrs\":[\"not-a-network\"]}", error.InvalidCidr },
        .{ "\"difficulty\":16}", error.InvalidChallenge },
        .{ "\"weight\":5}", error.InvalidWeight },
        .{ "\"unexpected\":true}", error.UnknownField },
        .{ "\"path\":\"/a\",\"path\":\"/b\"}", error.DuplicateField },
    };
    inline for (cases) |case| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        try std.testing.expectError(case[1], parse(arena.allocator(), base ++ case[0]));
    }
}

test "management document bounds reject exhaustion and invalid identifiers" {
    var memory: [32768]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const oversized = [_]u8{' '} ** (max_document + 1);
    try std.testing.expectError(error.TooLarge, parse(arena.allocator(), &oversized));
    try std.testing.expectEqual(@as(usize, 0), arena.end_index);
    const input = "{\"id\":\"bad/id\",\"name\":\"Test\",\"action\":\"allow\"}";
    try std.testing.expectError(error.InvalidId, parse(arena.allocator(), input));
    var empty: [0]u8 = .{};
    var exhausted = std.heap.FixedBufferAllocator.init(&empty);
    try std.testing.expectError(error.OutOfMemory, parse(exhausted.allocator(), input));
}

test "terminal quota validation rejects WEIGH, partial and out-of-range settings" {
    const t = std.testing;
    const prefix = "{\"id\":\"a\",\"name\":\"A\",\"action\":\"allow\",\"limits\":";
    inline for (.{
        "{\"rate\":0,\"window_seconds\":1}",
        "{\"rate\":1000001,\"window_seconds\":1}",
        "{\"rate\":1,\"window_seconds\":0}",
        "{\"rate\":1,\"window_seconds\":86401}",
        "{\"rate\":1,\"window_seconds\":1,\"ban_seconds\":86401}",
    }) |limits| {
        var arena = std.heap.ArenaAllocator.init(t.allocator);
        defer arena.deinit();
        try t.expectError(error.InvalidRuleLimit, parse(
            arena.allocator(),
            prefix ++ limits ++ "}",
        ));
    }
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    try t.expectError(error.MissingField, parse(arena.allocator(), prefix ++ "{\"rate\":1}}"));
    try t.expectError(error.UnknownField, parse(arena.allocator(), prefix ++
        "{\"rate\":1,\"window_seconds\":1,\"typo\":0}}"));
    try t.expectError(error.InvalidRuleLimit, parse(
        arena.allocator(),
        "{\"id\":\"a\",\"name\":\"A\",\"action\":\"weigh\"," ++
            "\"limits\":{\"rate\":1,\"window_seconds\":1}}",
    ));
    const maximum = try parse(arena.allocator(), prefix ++
        "{\"rate\":1000000,\"window_seconds\":86400,\"ban_seconds\":86400}}");
    try t.expectEqual(@as(u32, 1_000_000), maximum.value.limits.?.rate);
}
