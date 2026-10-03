//! Editable strings survive validation failures; document construction has a fixed output budget.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Writer = std.Io.Writer;
const matchers = @import("policy_matchers.zig");

pub const Form = struct {
    id: p.Bytes(128) = .{},
    name: p.Bytes(128) = .{},
    path: p.Bytes(512) = .{},
    user_agent: p.Bytes(512) = .{},
    priority: p.Bytes(12) = .{},
    weight: p.Bytes(12) = .{},
    difficulty: p.Bytes(3) = .{},
    action: p.Bytes(16) = .{},
    algorithm: p.Bytes(8) = .{},
    enabled: p.Bytes(5) = .{},
    headers: p.Bytes(4096) = .{},
    cidrs: p.Bytes(512) = .{},
    limit_rate: p.Bytes(10) = .{},
    limit_window: p.Bytes(10) = .{},
    limit_ban: p.Bytes(10) = .{},

    pub fn capture(self: *Form, fields: std.json.Value) !void {
        inline for (@typeInfo(Form).@"struct".field_names) |field_name| {
            if (comptime !std.mem.eql(u8, field_name, "headers")) {
                try @field(self, field_name).set(text(fields, "rule_" ++ field_name));
            }
        }
        try matchers.capture(fields, &self.headers);
    }

    pub noinline fn load(result: *Form, source: []const u8) !void {
        var memory: [65536]u8 = undefined;
        var arena = std.heap.FixedBufferAllocator.init(&memory);
        const root = try std.json.parseFromSliceLeaky(
            std.json.Value,
            arena.allocator(),
            source,
            .{},
        );
        if (root != .object) return error.InvalidDocument;
        result.clear();
        errdefer result.clear();
        inline for (.{ "id", "name", "path", "user_agent", "action", "algorithm" }) |field| {
            try @field(result, field).set(text(root, field));
        }
        result.priority = try numeric(12, root, "priority", 100);
        result.weight = try numeric(12, root, "weight", 0);
        result.difficulty = try numeric(3, root, "difficulty", null);
        const enabled = root.object.get("enabled") orelse std.json.Value{ .bool = true };
        if (enabled != .bool) return error.InvalidDocument;
        result.enabled = try p.Bytes(5).init(if (enabled.bool) "true" else "false");
        try matchers.loadHeaders(root, &result.headers);
        try matchers.loadNetworks(root, &result.cidrs);
        try @import("policy_limits.zig").load(result, root);
    }

    pub noinline fn document(self: *const Form, output: *p.Bytes(4096)) !void {
        var memory: [65536]u8 = undefined;
        var arena = std.heap.FixedBufferAllocator.init(&memory);
        const action = fallback(self.action.slice(), "deny");
        const challenge = std.mem.eql(u8, action, "challenge");
        const weigh = std.mem.eql(u8, action, "weigh");
        output.len = 0;
        errdefer @memset(&output.data, 0);
        var writer: Writer = .fixed(&output.data);
        try std.json.Stringify.value(.{
            .id = self.id.slice(),
            .name = self.name.slice(),
            .action = action,
            .priority = try std.fmt.parseInt(i32, fallback(self.priority.slice(), "100"), 10),
            .enabled = !std.mem.eql(u8, self.enabled.slice(), "false"),
            .path = optional(self.path.slice()),
            .user_agent = optional(self.user_agent.slice()),
            .difficulty = if (challenge and self.difficulty.len != 0)
                try std.fmt.parseInt(u32, self.difficulty.slice(), 10)
            else
                null,
            .algorithm = if (challenge) optional(self.algorithm.slice()) else null,
            .weight = if (weigh)
                try std.fmt.parseInt(i32, fallback(self.weight.slice(), "0"), 10)
            else
                @as(i32, 0),
            .headers = try matchers.headers(self.headers.slice(), arena.allocator()),
            .cidrs = try matchers.networks(self.cidrs.slice()),
            .limits = try @import("policy_limits.zig").document(self),
        }, .{}, &writer);
        output.len = writer.buffered().len;
    }

    pub fn clear(self: *Form) void {
        // Form consists only of byte buffers and integer lengths, all initially zero.
        // Initialize padding too, avoiding a large constant image in Wasm.
        @memset(std.mem.asBytes(self), 0);
    }
};

pub fn render(w: *Writer, form: *const Form, existing: bool) Writer.Error!void {
    try html.render(w, "<div class=\"sb-rule-grid\"><div class=\"sb-rule-field\">" ++
        "<label for=\"rule-id\">Rule ID</label>", .{});
    if (existing) {
        try html.render(
            w,
            @embedFile("snippets/policy-id-existing.html"),
            .{ .id = form.id.slice() },
        );
    } else {
        try html.render(w, @embedFile("snippets/policy-id-new.html"), .{ .id = form.id.slice() });
    }
    try html.render(w, "</div>", .{});
    try html.render(w, @embedFile("snippets/policy-name.html"), .{
        .name = form.name.slice(),
    });
    try select(
        w,
        "action",
        "Action",
        fallback(form.action.slice(), "deny"),
        &.{ "deny", "allow", "challenge", "weigh" },
    );
    try select(
        w,
        "enabled",
        "Enabled",
        fallback(form.enabled.slice(), "true"),
        &.{ "true", "false" },
    );
    try html.render(w, @embedFile("snippets/policy-form.html"), .{
        .path = form.path.slice(),
        .user_agent = form.user_agent.slice(),
        .priority = fallback(form.priority.slice(), "100"),
    });
    try select(
        w,
        "algorithm",
        "Challenge algorithm",
        form.algorithm.slice(),
        &.{ "", "hashcash", "posw" },
    );
    try html.render(w, @embedFile("snippets/policy-extra-fields.html"), .{
        .weight = fallback(form.weight.slice(), "0"),
        .difficulty = form.difficulty.slice(),
    });
    try matchers.render(w, form.headers.slice(), form.cidrs.slice());
    try @import("policy_limits.zig").render(w, form);
    try html.render(w, "</div>", .{});
}

fn select(
    w: *Writer,
    name: []const u8,
    label: []const u8,
    selected: []const u8,
    values: []const []const u8,
) Writer.Error!void {
    try html.render(w, @embedFile("snippets/policy-select.html"), .{
        .name = name,
        .label = label,
    });
    for (values) |value| {
        try html.render(w, "<option value=\"{{ v0 }}\"{{ v1 }}>{{ v2 }}</option>", .{
            .v0 = value,
            .v1 = if (std.mem.eql(u8, value, selected)) " selected" else "",
            .v2 = if (std.mem.eql(u8, name, "enabled"))
                (if (std.mem.eql(u8, value, "true")) "Enabled" else "Disabled")
            else if (value.len == 0)
                "Inherit"
            else
                value,
        });
    }
    try html.render(w, "</select></div>", .{});
}

fn text(value: std.json.Value, name: []const u8) []const u8 {
    if (value != .object) return "";
    const item = value.object.get(name) orelse return "";
    return if (item == .string) item.string else "";
}

fn fallback(value: []const u8, default: []const u8) []const u8 {
    return if (value.len == 0) default else value;
}

fn optional(value: []const u8) ?[]const u8 {
    return if (value.len == 0) null else value;
}

fn numeric(
    comptime size: usize,
    root: std.json.Value,
    key: []const u8,
    default: ?i32,
) !p.Bytes(size) {
    const value = root.object.get(key) orelse if (default) |number|
        std.json.Value{ .integer = number }
    else
        std.json.Value.null;
    var output: p.Bytes(size) = .{};
    if (value == .null) return output;
    if (value != .integer) return error.InvalidDocument;
    output.len = (try std.fmt.bufPrint(&output.data, "{d}", .{value.integer})).len;
    return output;
}

test "editor round-trips all matchers and clears settings owned by another action" {
    const source = "{\"id\":\"checkout\",\"name\":\"Checkout\",\"action\":\"challenge\"," ++
        "\"path\":\"/checkout/*\",\"user_agent\":\"Browser*\",\"priority\":-5," ++
        "\"difficulty\":16,\"algorithm\":\"posw\",\"enabled\":false," ++
        "\"headers\":{\"X-Api\":\"v2\"},\"cidrs\":[\"8.8.8.0/24\"]}";
    var form: Form = undefined;
    try form.load(source);
    var document: p.Bytes(4096) = undefined;
    try form.document(&document);
    var restored: Form = undefined;
    try restored.load(document.slice());
    try std.testing.expectEqualStrings(form.headers.slice(), restored.headers.slice());
    try std.testing.expectEqualStrings(form.cidrs.slice(), restored.cidrs.slice());
    try std.testing.expectEqualStrings("-5", restored.priority.slice());
    try std.testing.expectEqualStrings("false", restored.enabled.slice());
    form.action = try p.Bytes(16).init("allow");
    var allowance: p.Bytes(4096) = undefined;
    try form.document(&allowance);
    var allowed: Form = undefined;
    try allowed.load(allowance.slice());
    try std.testing.expectEqual(@as(usize, 0), allowed.difficulty.len);
    try std.testing.expectEqual(@as(usize, 0), allowed.algorithm.len);
    form.headers = try p.Bytes(4096).init("invalid JSON");
    if (form.document(&document)) return error.ExpectedInvalidDocument else |_| {}
    try std.testing.expectEqualStrings("invalid JSON", form.headers.slice());
}
