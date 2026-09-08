//! Browser contract for terminal-rule quotas; previews never consume node-local GCRA cells.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Form = @import("policy_form.zig").Form;
pub const Limits = struct { rate: u32, window_seconds: u32, ban_seconds: u32 = 0 };
const Error = error{InvalidRuleLimit};
pub const invalid_message = "POLICY007: Quotas require a terminal action, burst 1–1000000, " ++
    "window 1–86400 seconds and ban 0–86400 seconds. For WEIGH, clear all three quota fields.";

fn validate(value: Limits) Error!Limits {
    if (value.rate == 0 or value.rate > 1_000_000 or value.window_seconds == 0 or
        value.window_seconds > 86400 or value.ban_seconds > 86400) return error.InvalidRuleLimit;
    return value;
}

pub fn read(root: std.json.Value) Error!?Limits {
    if (root != .object) return error.InvalidRuleLimit;
    const item = root.object.get("limits") orelse return null;
    if (item == .null) return null;
    if (item != .object) return error.InvalidRuleLimit;
    var result: Limits = .{ .rate = 0, .window_seconds = 0 };
    var keys = item.object.iterator();
    while (keys.next()) |entry| {
        var known = false;
        inline for (@typeInfo(Limits).@"struct".fields) |field| {
            if (std.mem.eql(u8, entry.key_ptr.*, field.name)) {
                if (entry.value_ptr.* != .integer) return error.InvalidRuleLimit;
                @field(result, field.name) = std.math.cast(u32, entry.value_ptr.integer) orelse
                    return error.InvalidRuleLimit;
                known = true;
            }
        }
        if (!known) return error.InvalidRuleLimit;
    }
    return try validate(result);
}

pub fn load(form: *Form, root: std.json.Value) !void {
    const limits = (try read(root)) orelse return;
    inline for (.{
        .{ "limit_rate", "rate" },
        .{ "limit_window", "window_seconds" },
        .{ "limit_ban", "ban_seconds" },
    }) |pair| {
        const field = &@field(form, pair[0]);
        field.len = (try std.fmt.bufPrint(&field.data, "{d}", .{@field(limits, pair[1])})).len;
    }
}

pub fn document(form: *const Form) !?Limits {
    if (form.limit_rate.len == 0 and form.limit_window.len == 0 and form.limit_ban.len == 0)
        return null;
    if (std.mem.eql(u8, form.action.slice(), "weigh")) return error.InvalidRuleLimit;
    return try validate(.{
        .rate = try number(form.limit_rate.slice()),
        .window_seconds = try number(form.limit_window.slice()),
        .ban_seconds = if (form.limit_ban.len == 0) 0 else try number(form.limit_ban.slice()),
    });
}

fn number(text: []const u8) Error!u32 {
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidRuleLimit;
    return std.fmt.parseInt(u32, text, 10) catch error.InvalidRuleLimit;
}

pub fn render(writer: *std.Io.Writer, form: *const Form) std.Io.Writer.Error!void {
    try html.render(writer, @embedFile("snippets/policy-limits.html"), .{
        .rate = form.limit_rate.slice(),
        .window = form.limit_window.slice(),
        .ban = form.limit_ban.slice(),
    });
}

pub fn summary(writer: *std.Io.Writer, value: ?Limits) std.Io.Writer.Error!void {
    const limits = value orelse return;
    try writer.print("<p>Rule quota: burst {d}, paced over {d} seconds. " ++
        "Local ban on excess: {d} seconds.</p>", .{
        limits.rate, limits.window_seconds, limits.ban_seconds,
    });
}

test "rate-limit drafts round-trip and reject partial, unknown and WEIGH settings" {
    const t = std.testing;
    const source = "{\"id\":\"a\",\"name\":\"A\",\"action\":\"allow\"," ++
        "\"limits\":{\"rate\":2,\"window_seconds\":60,\"ban_seconds\":3}}";
    var form = try Form.load(source);
    const encoded = try form.document();
    const restored = try Form.load(encoded.slice());
    try t.expectEqualStrings("2", restored.limit_rate.slice());
    try t.expectEqualStrings("60", restored.limit_window.slice());
    try t.expectEqualStrings("3", restored.limit_ban.slice());
    form.action = try p.Bytes(16).init("weigh");
    try t.expectError(error.InvalidRuleLimit, form.document());
    form.action = try p.Bytes(16).init("deny");
    form.limit_rate = .{};
    try t.expectError(error.InvalidRuleLimit, form.document());
    try t.expectError(error.InvalidRuleLimit, Form.load("{\"limits\":{\"rate\":1}}"));
    try t.expectError(error.InvalidRuleLimit, Form.load(
        "{\"limits\":{\"rate\":1,\"window_seconds\":60,\"typo\":1}}",
    ));
}
