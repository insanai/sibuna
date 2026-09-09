//! Operator-editable response pages. A template is validated and split into literal
//! segments and placeholder slots when it enters the engine snapshot; the request path
//! only copies segments and escapes values into a bounded writer. Validation refuses
//! script, frames, event handlers, external resources and unknown placeholders.
const std = @import("std");
pub const Kind = enum(u3) { challenge, denied, rate_limited, banned, overloaded };
pub const Placeholder = enum(u3) { status, reason, retry_after, request_id, node, challenge };
pub const max_bytes = 16 * 1024;
pub const max_segments = 32;
pub const Error = error{
    TooLarge,
    InvalidUtf8,
    ForbiddenContent,
    ForbiddenAttribute,
    ExternalReference,
    UnknownPlaceholder,
    PlaceholderInTag,
    TooManySegments,
    ChallengeSlotRequired,
    ChallengeSlotForbidden,
};
pub const Segment = union(enum) { literal: struct { start: u16, len: u16 }, slot: Placeholder };
pub const Template = struct {
    bytes: [max_bytes]u8 = undefined,
    len: u16 = 0,
    segments: [max_segments]Segment = undefined,
    count: u8 = 0,
    revision: u64 = 0,
    customized: bool = false,
    fallback: bool = false,
};
pub const Pages = struct {
    entries: [5]Template = undefined,

    pub fn get(self: *const Pages, kind: Kind) *const Template {
        return &self.entries[@intFromEnum(kind)];
    }
};
pub const Values = struct {
    status: u16,
    reason: []const u8 = "",
    retry_after: u32 = 0,
    request_id: []const u8 = "",
    node: u32 = 0,
    /// The fixed solver block for challenge pages; never escaped, never operator-supplied.
    challenge: []const u8 = "",
};
const forbidden = [_][]const u8{
    "<script",     "<iframe", "<object", "<embed",    "<base", "<link",
    "javascript:", "<form",   "data:",   "vbscript:", "url(",  "@import",
    "expression(", "<!--",
};
const url_attributes = [_][]const u8{
    "src", "href", "srcset", "action", "formaction", "xlink:href", "poster",
};

pub fn compile(kind: Kind, source: []const u8, out: *Template) Error!void {
    if (source.len > max_bytes) return error.TooLarge;
    if (!std.unicode.utf8ValidateSlice(source) or std.mem.indexOfScalar(u8, source, 0) != null)
        return error.InvalidUtf8;
    try validateMarkup(source);
    out.len = @intCast(source.len);
    @memcpy(out.bytes[0..source.len], source);
    out.count = 0;
    var challenge_slots: usize = 0;
    var cursor: usize = 0;
    var literal_start: usize = 0;
    while (std.mem.indexOfPos(u8, source, cursor, "{{")) |open| {
        const close = std.mem.indexOfPos(u8, source, open + 2, "}}") orelse
            return error.UnknownPlaceholder;
        const name = std.mem.trim(u8, source[open + 2 .. close], " \t");
        const slot = std.meta.stringToEnum(Placeholder, name) orelse
            return error.UnknownPlaceholder;
        if (insideTag(source, open)) return error.PlaceholderInTag;
        if (slot == .challenge) {
            if (kind != .challenge) return error.ChallengeSlotForbidden;
            challenge_slots += 1;
        }
        try pushLiteral(out, literal_start, open);
        try push(out, .{ .slot = slot });
        cursor = close + 2;
        literal_start = cursor;
    }
    try pushLiteral(out, literal_start, source.len);
    if (kind == .challenge and challenge_slots != 1) return error.ChallengeSlotRequired;
    out.customized = true;
    out.fallback = false;
}

fn pushLiteral(out: *Template, start: usize, end: usize) Error!void {
    if (end == start) return;
    try push(out, .{ .literal = .{ .start = @intCast(start), .len = @intCast(end - start) } });
}

fn push(out: *Template, segment: Segment) Error!void {
    if (out.count == max_segments) return error.TooManySegments;
    out.segments[out.count] = segment;
    out.count += 1;
}

fn insideTag(source: []const u8, at: usize) bool {
    const open = std.mem.lastIndexOfScalar(u8, source[0..at], '<') orelse return false;
    const close = std.mem.lastIndexOfScalar(u8, source[0..at], '>') orelse return true;
    return open > close;
}

/// One bounded pass: forbidden tokens anywhere (ASCII case-insensitive), event handler
/// attributes, and resource attributes that are not same-origin paths or fragments.
fn validateMarkup(source: []const u8) Error!void {
    for (forbidden) |token| {
        if (std.ascii.indexOfIgnoreCase(source, token) != null) return error.ForbiddenContent;
    }
    var cursor: usize = 0;
    while (std.mem.indexOfScalarPos(u8, source, cursor, '<')) |open| {
        const close = std.mem.indexOfScalarPos(u8, source, open, '>') orelse
            return error.ForbiddenContent;
        try validateTag(source[open + 1 .. close]);
        cursor = close + 1;
    }
}

fn validateTag(tag: []const u8) Error!void {
    var tokens = std.mem.tokenizeAny(u8, std.mem.trimEnd(u8, tag, "/ \t\r\n"), " \t\r\n");
    _ = tokens.next();
    while (tokens.next()) |token| {
        const equals = std.mem.indexOfScalar(u8, token, '=') orelse token.len;
        const name = token[0..equals];
        if (name.len >= 3 and std.ascii.eqlIgnoreCase(name[0..2], "on"))
            return error.ForbiddenAttribute;
        // Refresh/redirect and policy pragmas are executable in effect.
        if (std.ascii.eqlIgnoreCase(name, "http-equiv")) return error.ForbiddenAttribute;
        for (url_attributes) |attribute| {
            if (!std.ascii.eqlIgnoreCase(name, attribute)) continue;
            const value = std.mem.trim(u8, token[@min(equals + 1, token.len)..], "\"'");
            if (value.len == 0 or (value[0] != '/' and value[0] != '#') or
                std.mem.startsWith(u8, value, "//")) return error.ExternalReference;
        }
    }
}

pub fn measure(t: *const Template, values: Values) usize {
    var counter: std.Io.Writer.Discarding = .init(&.{});
    write(t, &counter.writer, values) catch unreachable;
    return counter.count;
}

/// Request-path rendering: literal copies and escaped values, no allocation.
pub fn write(t: *const Template, w: *std.Io.Writer, values: Values) std.Io.Writer.Error!void {
    for (t.segments[0..t.count]) |segment| switch (segment) {
        .literal => |span| try w.writeAll(t.bytes[span.start .. span.start + span.len]),
        .slot => |slot| switch (slot) {
            .status => try w.print("{d}", .{values.status}),
            .reason => try escape(w, values.reason),
            .retry_after => try w.print("{d}", .{values.retry_after}),
            .request_id => try escape(w, values.request_id),
            .node => try w.print("{d}", .{values.node}),
            .challenge => try w.writeAll(values.challenge),
        },
    };
}

fn escape(w: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    for (text) |byte| switch (byte) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&#39;"),
        else => try w.writeByte(byte),
    };
}

/// The library's own challenge page: the solver slot inside a minimal document. The daemon
/// replaces it with its interstitial before serving.
pub const default_challenge_minimal =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Checking your " ++
    "browser</title></head><body><h1>Checking your browser</h1>{{ challenge }}</body></html>";
pub const default_denied =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Request blocked" ++
    "</title></head><body><h1>Request blocked</h1><p>Sibuna refused this request " ++
    "({{ status }}): {{ reason }}.</p><p>Reference {{ request_id }} on node {{ node }}.</p>" ++
    "</body></html>";
pub const default_rate_limited =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Slow down</title>" ++
    "</head><body><h1>Too many requests</h1><p>Retry after {{ retry_after }} seconds.</p>" ++
    "<p>Reference {{ request_id }} on node {{ node }}.</p></body></html>";
pub const default_banned =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Access denied" ++
    "</title></head><body><h1>Access denied</h1><p>This address is temporarily banned " ++
    "({{ reason }}).</p><p>Reference {{ request_id }} on node {{ node }}.</p></body></html>";
pub const default_overloaded =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Service busy" ++
    "</title></head><body><h1>Service unavailable</h1><p>{{ reason }}. Retry after " ++
    "{{ retry_after }} seconds.</p></body></html>";

/// Installs the built-in pages. The challenge default is supplied by the daemon, which owns
/// the solver markup; other kinds use the bounded pages above.
pub fn defaults(out: *Pages, challenge_default: []const u8) void {
    const sources = [_]?[]const u8{
        challenge_default,
        default_denied,
        default_rate_limited,
        default_banned,
        default_overloaded,
    };
    for (sources, 0..) |source, index| {
        const entry = &out.entries[index];
        compile(@enumFromInt(index), source.?, entry) catch unreachable;
        entry.customized = false;
        entry.revision = 0;
    }
}

test "templates compile into bounded segments and render escaped values" {
    const t = std.testing;
    var template: Template = .{};
    try compile(.denied, "<p>Blocked: {{ reason }} ({{ status }})</p>", &template);
    try t.expectEqual(@as(u8, 5), template.count);
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const values: Values = .{ .status = 403, .reason = "<waf:sqli>" };
    try write(&template, &writer, values);
    try t.expectEqualStrings("<p>Blocked: &lt;waf:sqli&gt; (403)</p>", writer.buffered());
    try t.expectEqual(writer.buffered().len, measure(&template, values));
}

test "validation refuses script, handlers, external resources and misplaced placeholders" {
    const t = std.testing;
    var template: Template = .{};
    const cases = [_]struct { source: []const u8, err: Error }{
        .{ .source = "<ScRiPt>x</script>", .err = error.ForbiddenContent },
        .{ .source = "<a onclick=\"x\">y</a>", .err = error.ForbiddenAttribute },
        .{ .source = "<meta http-equiv=\"refresh\">", .err = error.ForbiddenAttribute },
        .{ .source = "<img src=\"https://evil/x.png\">", .err = error.ExternalReference },
        .{ .source = "<img src=\"//evil/x.png\">", .err = error.ExternalReference },
        .{ .source = "<a href=\"javascript:alert(1)\">x</a>", .err = error.ForbiddenContent },
        .{ .source = "<p style=\"background:url(x)\">", .err = error.ForbiddenContent },
        .{ .source = "<p>{{ secret }}</p>", .err = error.UnknownPlaceholder },
        .{ .source = "<p title=\"{{ status }}\">", .err = error.PlaceholderInTag },
        .{ .source = "<p>{{ challenge }}</p>", .err = error.ChallengeSlotForbidden },
        .{ .source = "<p>{{ status", .err = error.UnknownPlaceholder },
    };
    for (cases) |case| try t.expectError(case.err, compile(.denied, case.source, &template));
    const missing = compile(.challenge, "<p>no slot</p>", &template);
    try t.expectError(error.ChallengeSlotRequired, missing);
    try compile(.challenge, "<p>{{ challenge }}</p>", &template);
    try compile(.denied, "<img src=\"/logo.png\" alt=\"\"><a href=\"#top\">top</a>", &template);
    var many: [max_bytes]u8 = @splat('x');
    try t.expectError(error.TooLarge, compile(.denied, many[0..] ++ "y", &template));
    var segments: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&segments);
    for (0..20) |_| try writer.writeAll("a{{ node }}");
    try t.expectError(error.TooManySegments, compile(.denied, writer.buffered(), &template));
}

test "defaults compile for every kind and mark themselves as not customized" {
    const t = std.testing;
    const pages = try t.allocator.create(Pages);
    defer t.allocator.destroy(pages);
    defaults(pages, "<html><body>{{ challenge }}</body></html>");
    for (pages.entries) |entry| try t.expect(!entry.customized and entry.count != 0);
    try t.expect(measure(pages.get(.rate_limited), .{ .status = 429, .retry_after = 30 }) > 100);
}
