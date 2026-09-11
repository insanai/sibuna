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
    response_state: wire.ResponseState = .unknown,
    charset: Charset = .utf8,
    copied: enum { none, ok, failed } = .none,

    pub fn set(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const heads = try decode(struct {
            version: u8,
            id: u64,
            recorded: bool,
            request: []const u8,
            response: []const u8,
            request_truncated: bool,
            response_truncated: bool,
            response_state: wire.ResponseState,
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
        self.response_state = heads.response_state;
        self.loaded = true;
    }

    pub fn requestHead(self: *const Model) []const u8 {
        return self.request[0..self.request_len];
    }
};

pub fn render(state: *const State, id: u64, w: *Writer) Writer.Error!void {
    const model = &state.incident_heads;
    if (model.id != id) return html.render(w, "<p class=\"mt-3\"><button class=\"btn btn-sm\" " ++
        "data-action=\"events-heads-{{ id }}\">Show request and response heads</button></p>", .{
        .id = id,
    });
    if (model.busy) return w.writeAll("<p role=\"status\">Loading heads…</p>");
    if (model.failed) return html.render(w, "<p class=\"sb-note\" role=\"status\">Heads " ++
        "unavailable. <button class=\"btn btn-xs\" data-action=\"events-heads-{{ id }}\">" ++
        "Retry</button></p>", .{ .id = id });
    if (!model.loaded) return;
    if (!model.recorded) return w.writeAll("<p class=\"sb-note\">Request and response heads: " ++
        "Not recorded. Capture is off (start with --console-capture-heads) or this incident " ++
        "predates it.</p>");
    try html.render(w, "<section class=\"mt-3\" aria-label=\"Captured heads\">" ++
        "<h3>Request · Response</h3><p class=\"sb-note\">Redacted before capture: only " ++
        "listed header values are kept, credential headers and every query value read " ++
        "[redacted]. Rendered as {{ charset }}. " ++
        "<button class=\"btn btn-xs\" data-action=\"events-heads-utf8\">UTF-8</button> " ++
        "<button class=\"btn btn-xs\" data-action=\"events-heads-latin1\">Latin-1</button></p>" ++
        "<h4>Request head{{ request_note }}</h4><pre class=\"whitespace-pre-wrap break-all\">", .{
        .charset = if (model.charset == .utf8)
            "UTF-8 (invalid bytes shown as U+FFFD)"
        else
            "Latin-1",
        .request_note = if (model.request_truncated) " (truncated at 2 KiB)" else "",
    });
    try text(w, model.requestHead(), model.charset);
    try html.render(w, "</pre><h4>Response head{{ response_note }}</h4>" ++
        "<pre class=\"whitespace-pre-wrap break-all\">", .{
        .response_note = if (model.response_truncated) " (truncated at 1 KiB)" else "",
    });
    try responseText(model, w);
    try w.writeAll("</pre>");
    try curlSection(model, w);
    try w.writeAll("</section>");
}

/// Each response state says what was observed; an empty head never implies a local answer.
fn responseText(model: *const Model, w: *Writer) Writer.Error!void {
    if (model.response_len != 0)
        return text(w, model.response[0..model.response_len], model.charset);
    try w.writeAll(switch (model.response_state) {
        .captured => "Captured origin head is empty.",
        .local => "Local response: Sibuna answered the client; there is no origin head. " ++
            "The selected status is shown above.",
        .unobserved => "Forward-auth mode: the ingress relayed the origin's response; " ++
            "Sibuna did not observe it.",
        .unavailable => "Origin unavailable: the relay ended before a response head " ++
            "arrived, so the client received 502.",
        .unknown => "Not recorded: this row predates response-state capture (before " ++
            "schema version 40), so whether the response was local is unknown.",
    });
}

fn curlSection(model: *const Model, w: *Writer) Writer.Error!void {
    try w.writeAll("<h4>Copy as cURL</h4>");
    var buffer: [curl_bytes]u8 = undefined;
    var command: Writer = .fixed(&buffer);
    const generated = curl(&command, model.requestHead(), model.request_truncated) catch false;
    if (!generated) return w.writeAll("<p class=\"sb-note\">Command unavailable: the " ++
        "captured request line or Host header is incomplete, so no usable URL exists.</p>");
    try html.render(w, "<p><button class=\"btn btn-sm\" data-action=\"events-heads-copy\">" ++
        "Copy command</button> <span role=\"status\">{{ status }}</span></p>" ++
        "<textarea readonly class=\"textarea font-mono w-full\" rows=\"5\" " ++
        "aria-label=\"cURL command\">", .{ .status = switch (model.copied) {
        .none => "",
        .ok => "Copied to the clipboard.",
        .failed => "Copy failed; select the text below and copy it.",
    } });
    try @import("render.zig").escape(w, command.buffered());
    try w.writeAll("</textarea>");
}

pub const curl_bytes = 8192;

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

/// Headers cURL must not replay: framing and hop-by-hop fields, and the Host cURL derives
/// from the URL. A value that is wholly `[redacted]` is a credential placeholder and is
/// omitted rather than sent.
const skipped_headers = [_][]const u8{
    "host",                "content-length",   "transfer-encoding", "connection", "keep-alive",
    "upgrade",             "proxy-connection", "te",                "trailer",    "expect",
    "proxy-authorization",
};

fn skipped(name: []const u8) bool {
    for (skipped_headers) |entry| if (std.ascii.eqlIgnoreCase(name, entry)) return true;
    return false;
}

const Line = struct { name: []const u8, value: []const u8 };

fn headerLine(line: []const u8) ?Line {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    return .{ .name = line[0..colon], .value = std.mem.trim(u8, line[colon + 1 ..], " ") };
}

/// `curl --globoff -X 'METHOD' 'scheme://host/target' -H '...'` as plain text with
/// single quotes escaped. Returns false, writing nothing, when the request line or Host is
/// incomplete: no usable URL is ever fabricated. The trailing comment names what the
/// command lacks: redacted or omitted values, the uncaptured body and an assumed scheme.
pub fn curl(w: *Writer, head: []const u8, truncated: bool) Writer.Error!bool {
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse return false;
    var words = std.mem.tokenizeScalar(u8, head[0..line_end], ' ');
    const method = words.next() orelse return false;
    const target = words.next() orelse return false;
    if (words.next() == null or words.next() != null) return false;
    const absolute = std.mem.indexOf(u8, target, "://") != null;
    if (!absolute and (target.len == 0 or target[0] != '/')) return false;
    var host: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var redactions: usize = 0;
    var lines = std.mem.splitSequence(u8, head[line_end + 2 ..], "\r\n");
    while (lines.next()) |line| {
        const header = headerLine(line) orelse continue;
        if (std.ascii.eqlIgnoreCase(header.name, "host")) host = header.value;
        if (std.ascii.eqlIgnoreCase(header.name, "x-forwarded-proto") and
            (std.mem.eql(u8, header.value, "https") or std.mem.eql(u8, header.value, "http")))
            scheme = header.value;
        if (std.mem.indexOf(u8, header.value, "[redacted]") != null) redactions += 1;
    }
    if (std.mem.indexOf(u8, target, "[redacted]") != null) redactions += 1;
    // A truncated head may have lost the Host line; only a complete one names the URL.
    const authority = host orelse return false;
    if (truncated and lines.peek() == null and !std.mem.endsWith(u8, head, "\r\n"))
        return false;
    try w.writeAll("curl --globoff -X ");
    try quoted(w, method);
    try w.writeAll(" ");
    try w.writeByte('\'');
    if (!absolute) {
        try escapeQuoted(w, scheme orelse "http");
        try w.writeAll("://");
        try escapeQuoted(w, authority);
    }
    try escapeQuoted(w, target);
    try w.writeByte('\'');
    lines = std.mem.splitSequence(u8, head[line_end + 2 ..], "\r\n");
    while (lines.next()) |line| {
        const header = headerLine(line) orelse continue;
        if (skipped(header.name) or std.mem.eql(u8, header.value, "[redacted]")) continue;
        try w.writeAll(" \\\n  -H ");
        try quoted(w, line);
    }
    try w.print("\n# incomplete: {d} values redacted or omitted; body not captured; " ++
        "scheme {s}\n", .{
        redactions,
        if (scheme != null or absolute) "observed" else "assumed",
    });
    return true;
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
            try w.writeByte(byte);
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
    try t.expect(try curl(&writer, "GET /a?x=[redacted] HTTP/1.1\r\nHost: app.example\r\n" ++
        "Cookie: [redacted]\r\nX-Forwarded-Proto: https\r\nConnection: keep-alive\r\n" ++
        "Content-Length: 0\r\nX-Q: it's\r\nReferer: /r?k=[redacted]\r\n", false));
    const out = writer.buffered();
    const opening = "curl --globoff -X 'GET' 'https://app.example/a?x=[redacted]'";
    try t.expect(std.mem.startsWith(u8, out, opening));
    try t.expect(std.mem.indexOf(u8, out, "-H 'X-Q: it'\\''s'") != null);
    try t.expect(std.mem.indexOf(u8, out, "Cookie") == null);
    try t.expect(std.mem.indexOf(u8, out, "Connection") == null);
    try t.expect(std.mem.indexOf(u8, out, "Content-Length") == null);
    try t.expect(std.mem.indexOf(u8, out, "-H 'Referer: /r?k=[redacted]'") != null);
    const note = "# incomplete: 3 values redacted or omitted; body not captured; scheme observed";
    try t.expect(std.mem.indexOf(u8, out, note) != null);
    // No Host, an incomplete request line or a cut first line yields no command at all.
    writer = .fixed(&buffer);
    try t.expect(!try curl(&writer, "GET /a HTTP/1.1\r\nX-Q: 1\r\n", false));
    try t.expect(!try curl(&writer, "GET /a\r\nHost: h\r\n", false));
    try t.expect(!try curl(&writer, "GET /a HTTP/1.1", true));
    try t.expect(!try curl(&writer, "GET * HTTP/1.1\r\nHost: h\r\n", false));
    try t.expectEqual(@as(usize, 0), writer.buffered().len);
    try t.expect(try curl(&writer, "GET /a HTTP/1.1\r\nHost: h\r\n", false));
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "scheme assumed") != null);
}

test "response states are stated and an empty head never claims a local answer by default" {
    const t = std.testing;
    var model: Model = .{ .recorded = true, .loaded = true };
    var buffer: [1024]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try responseText(&model, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Not recorded") != null);
    model.response_state = .unobserved;
    writer = .fixed(&buffer);
    try responseText(&model, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Forward-auth") != null);
    model.response_state = .unavailable;
    writer = .fixed(&buffer);
    try responseText(&model, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "502") != null);
}
