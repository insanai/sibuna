//! Category modes belong to an immutable engine snapshot, never to a console callback.
const std = @import("std");
const waf = @import("waf.zig");

pub const Mode = enum { disabled, audit, enforce };
pub const Modes = struct {
    path_traversal: Mode = .enforce,
    sqli: Mode = .enforce,
    xss: Mode = .enforce,
    rce: Mode = .enforce,

    pub fn get(self: Modes, category: waf.AttackCategory) Mode {
        return switch (category) {
            inline else => |value| @field(self, @tagName(value)),
        };
    }

    pub fn allEnforcing(self: Modes) bool {
        return self.path_traversal == .enforce and self.sqli == .enforce and
            self.xss == .enforce and self.rce == .enforce;
    }
};

pub const Findings = struct {
    denied: ?waf.Violation = null,
    /// At most one finding per audited category per request, regardless of field count.
    audited: u8 = 0,
};

pub fn bit(category: waf.AttackCategory) u8 {
    return @as(u8, 1) << @intCast(@backingInt(category));
}

pub fn auditName(category: waf.AttackCategory) []const u8 {
    return switch (category) {
        .path_traversal => "audit:path-traversal",
        .sqli => "audit:sqli",
        .xss => "audit:xss",
        .rce => "audit:rce",
    };
}

pub fn inspect(
    sigs: *const waf.Signatures,
    modes: Modes,
    request: @import("request.zig").View,
) Findings {
    var result: Findings = .{};
    for ([_][]const u8{ request.path, request.query, request.user_agent }) |text| {
        inspectField(sigs, modes, text, &result);
        if (result.denied != null) return result;
    }
    for (request.headers) |header| {
        if (waf.isStructuralHeader(header.name)) continue;
        inspectField(sigs, modes, header.value, &result);
        if (result.denied != null) return result;
    }
    var fields = @import("body_fields.zig").Fields.init(request.headers, request.body);
    while (fields.next()) |text| {
        inspectField(sigs, modes, text, &result);
        if (result.denied != null) return result;
    }
    return result;
}

fn inspectField(
    sigs: *const waf.Signatures,
    modes: Modes,
    text: []const u8,
    result: *Findings,
) void {
    // A first audit hit must not hide another category in the same field, including
    // an encoded enforcing signature. Disabled categories never run their detector.
    inline for (comptime std.enums.values(waf.AttackCategory)) |category| {
        const mode = modes.get(category);
        if (mode != .disabled and result.audited & bit(category) == 0) {
            if (waf.inspectCategory(sigs, category, text)) |violation| {
                if (mode == .audit) {
                    result.audited |= bit(category);
                } else {
                    result.denied = violation;
                    return;
                }
            }
        }
    }
}

test "audit findings do not hide enforcing categories in the same or later fields" {
    const t = std.testing;
    const sigs = try t.allocator.create(waf.Signatures);
    defer t.allocator.destroy(sigs);
    waf.buildSignatures(sigs);
    const modes: Modes = .{ .sqli = .audit, .path_traversal = .disabled };
    const mixed = inspect(sigs, modes, .{ .path = "/", .query = "union select 1; %3Cscript%3E" });
    try t.expectEqual(waf.AttackCategory.xss, mixed.denied.?.category);
    try t.expectEqual(bit(.sqli), mixed.audited);
    const later = inspect(sigs, modes, .{
        .path = "/../../etc/passwd",
        .query = "union select",
        .body = "; /bin/sh",
    });
    try t.expectEqual(waf.AttackCategory.rce, later.denied.?.category);
    try t.expectEqual(bit(.sqli), later.audited);
    const ignored = inspect(sigs, .{ .sqli = .disabled }, .{
        .path = "/",
        .query = "union select",
    });
    try t.expectEqualDeep(@as(Findings, .{}), ignored);
}

test "mixed category modes inspect multipart fields after an opaque file" {
    const t = std.testing;
    const sigs = try t.allocator.create(waf.Signatures);
    defer t.allocator.destroy(sigs);
    waf.buildSignatures(sigs);
    const body = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\n" ++
        "binary\x00file\r\n--b\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\n" ++
        "1 UNION SELECT password <script>alert(1)</script>\r\n--b--\r\n";
    const result = inspect(sigs, .{ .sqli = .audit }, .{
        .path = "/upload",
        .headers = &.{.{ .name = "Content-Type", .value = "multipart/form-data; boundary=b" }},
        .body = body,
    });
    try t.expectEqual(bit(.sqli), result.audited);
    try t.expectEqual(waf.AttackCategory.xss, result.denied.?.category);
}
