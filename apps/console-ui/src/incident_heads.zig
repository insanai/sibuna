//! Redacted heads for one incident: hex decoded, rendered under UTF-8 (lossy) or Latin-1,
//! and rebuilt as a cURL command whose values stay redacted and which states what it lacks.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const decode = @import("json_value.zig").decode;
const wire = p.incident_heads;
pub const Charset = enum { utf8, latin1 };

pub const Model = struct {
    id: u64 = 0,
    recorded: bool = false,
    loaded: bool = false,
    busy: bool = false,
    failed: bool = false,
    request: [wire.request_bytes]u8 = undefined,
    request_len: u16 = 0,
    response: [wire.response_bytes]u8 = undefined,
    response_len: u16 = 0,
    request_truncated: bool = false,
    response_truncated: bool = false,
    charset: Charset = .utf8,

    pub fn set(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const heads = try decode(struct {
            version: u8,
            id: u64,
            recorded: bool,
            request: []const u8,
            response: []const u8,
            request_truncated: bool,
            response_truncated: bool,
        }, value, allocator);
        if (heads.version != 1 or heads.id != self.id or heads.request.len % 2 != 0 or
            heads.response.len % 2 != 0 or heads.request.len > wire.request_hex or
            heads.response.len > wire.response_hex) return error.InvalidResponse;
        const request = std.fmt.hexToBytes(&self.request, heads.request) catch
            return error.InvalidResponse;
        const response = std.fmt.hexToBytes(&self.response, heads.response) catch
            return error.InvalidResponse;
        self.request_len = @intCast(request.len);
        self.response_len = @intCast(response.len);
        self.recorded = heads.recorded;
        self.request_truncated = heads.request_truncated;
        self.response_truncated = heads.response_truncated;
        self.loaded = true;
    }
};

pub fn render(state: *const State, id: u64, w: *Writer) Writer.Error!void {
    const model = &state.incident_heads;
    if (model.id != id) return html.render(w, "<p class=\"mt-3\"><button class=\"btn btn-sm\" " ++
        "data-action=\"events-heads-{{ id }}\">Show request and response heads</button></p>", .{
        .id = id,
    });
    if (model.busy) return w.writeAll("<p role=\"status\">Loading heads…</p>");
    if (model.failed) return w.writeAll("<p class=\"sb-note\">Heads unavailable. Retry.</p>");
    if (!model.loaded) return;
    if (!model.recorded) return w.writeAll("<p class=\"sb-note\">Request and response heads: " ++
        "Not recorded. Capture is off (start with --console-capture-heads) or this incident " ++
        "predates it.</p>");
    try html.render(w, "<section class=\"mt-3\" aria-label=\"Captured heads\">" ++
        "<h3>Request · Response</h3><p class=\"sb-note\">Redacted before capture: credential " ++
        "headers and every query value read [redacted]. Rendered as {{ charset }}. " ++
        "<button class=\"btn btn-xs\" data-action=\"events-heads-utf8\">UTF-8</button> " ++
        "<button class=\"btn btn-xs\" data-action=\"events-heads-latin1\">Latin-1</button></p>" ++
        "<h4>Request head{{ request_note }}</h4><pre class=\"whitespace-pre-wrap break-all\">", .{
        .charset = if (model.charset == .utf8)
            "UTF-8 (invalid bytes shown as U+FFFD)"
        else
            "Latin-1",
        .request_note = if (model.request_truncated) " (truncated at 2 KiB)" else "",
    });
    try text(w, model.request[0..model.request_len], model.charset);
    try html.render(w, "</pre><h4>Response head{{ response_note }}</h4>" ++
        "<pre class=\"whitespace-pre-wrap break-all\">", .{
        .response_note = if (model.response_truncated) " (truncated at 1 KiB)" else "",
    });
    if (model.response_len == 0) {
        try w.writeAll("Local response: no origin head; the selected status is shown above.");
    } else try text(w, model.response[0..model.response_len], model.charset);
    try w.writeAll("</pre><h4>Copy as cURL</h4><textarea readonly class=\"textarea font-mono " ++
        "w-full\" rows=\"4\">");
    try curl(w, model.request[0..model.request_len]);
    try w.writeAll("</textarea></section>");
}

/// Bytes become text without inventing content: control bytes show as U+2400 pictures,
/// UTF-8 decoding replaces invalid sequences, Latin-1 maps each byte to its code point.
pub fn text(w: *Writer, bytes: []const u8, charset: Charset) Writer.Error!void {
    var i: usize = 0;
    while (i < bytes.len) {
        const byte = bytes[i];
        if (byte == '\r') {
            i += 1;
            continue;
        }
        if (byte == '\n') {
            try w.writeByte('\n');
            i += 1;
            continue;
        }
        if (byte < 0x20 or byte == 0x7f) {
            try w.print("\u{2400}", .{});
            i += 1;
            continue;
        }
        if (byte < 0x80) {
            try @import("render.zig").escape(w, bytes[i .. i + 1]);
            i += 1;
            continue;
        }
        if (charset == .latin1) {
            var encoded: [2]u8 = undefined;
            const n = std.unicode.utf8Encode(byte, &encoded) catch unreachable;
            try w.writeAll(encoded[0..n]);
            i += 1;
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(byte) catch {
            try w.writeAll("\u{fffd}");
            i += 1;
            continue;
        };
        if (i + len > bytes.len or !std.unicode.utf8ValidateSlice(bytes[i .. i + len])) {
            try w.writeAll("\u{fffd}");
            i += 1;
            continue;
        }
        try w.writeAll(bytes[i .. i + len]);
        i += len;
    }
}

/// `curl -X METHOD 'scheme://host/target' -H 'Name: value' ...` with single quotes escaped;
/// the trailing comment states the redactions and that no body was captured.
pub fn curl(w: *Writer, head: []const u8) Writer.Error!void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const first = lines.next() orelse return;
    var words = std.mem.tokenizeScalar(u8, first, ' ');
    const method = words.next() orelse "GET";
    const target = words.next() orelse "/";
    var host: []const u8 = "host";
    var scheme: []const u8 = "http";
    var redactions: usize = 0;
    var rest = lines;
    while (rest.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " ");
        if (std.ascii.eqlIgnoreCase(name, "host")) host = value;
        if (std.ascii.eqlIgnoreCase(name, "x-forwarded-proto") and
            std.mem.eql(u8, value, "https")) scheme = "https";
        if (std.mem.indexOf(u8, value, "[redacted]") != null) redactions += 1;
    }
    if (std.mem.indexOf(u8, target, "[redacted]") != null) redactions += 1;
    try w.writeAll("curl -X ");
    try quoted(w, method);
    try w.writeAll(" ");
    try w.writeByte('\'');
    try escapeQuoted(w, scheme);
    try w.writeAll("://");
    try escapeQuoted(w, host);
    try escapeQuoted(w, target);
    try w.writeByte('\'');
    lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try w.writeAll(" \\\n  -H ");
        try quoted(w, line);
    }
    try w.print("\n# incomplete: {d} redacted values, body not captured\n", .{redactions});
}

fn quoted(w: *Writer, value: []const u8) Writer.Error!void {
    try w.writeByte('\'');
    try escapeQuoted(w, value);
    try w.writeByte('\'');
}

fn escapeQuoted(w: *Writer, value: []const u8) Writer.Error!void {
    for (value) |byte| {
        if (byte == '\'') {
            try w.writeAll("'\\''");
        } else if (byte >= 0x20 and byte != 0x7f) {
            var one = [_]u8{byte};
            try @import("render.zig").escape(w, &one);
        }
    }
}

test "heads render under both charsets and become an escaped, marked cURL command" {
    const t = std.testing;
    var buffer: [4096]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try text(&writer, "caf\xe9 <b>\r\n\x01", .latin1);
    try t.expectEqualStrings("café &lt;b&gt;\n\u{2400}", writer.buffered());
    writer = .fixed(&buffer);
    try text(&writer, "caf\xe9", .utf8);
    try t.expectEqualStrings("caf\u{fffd}", writer.buffered());
    writer = .fixed(&buffer);
    try curl(&writer, "GET /a?x=[redacted] HTTP/1.1\r\nHost: app.example\r\n" ++
        "Cookie: [redacted]\r\nX-Forwarded-Proto: https\r\nX-Q: it's\r\n");
    const out = writer.buffered();
    const opening = "curl -X 'GET' 'https://app.example/a?x=[redacted]'";
    try t.expect(std.mem.startsWith(u8, out, opening));
    try t.expect(std.mem.indexOf(u8, out, "-H 'X-Q: it'\\''s'") != null);
    const note = "# incomplete: 2 redacted values, body not captured";
    try t.expect(std.mem.indexOf(u8, out, note) != null);
}
