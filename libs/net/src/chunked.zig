//! Chunked Request Bodies (RFC 9112 §7.1, SID 0009)
//!
//! Decodes the chunked transfer coding in place: decoded data is written back into the slice
//! being read, never ahead of the read position, so a body is recovered inside the connection
//! buffer that holds it. The grammar is strict where HTTP/1.1 parsers are known to disagree:
//! CRLF is the only line terminator, no other control byte may appear in a chunk line, sizes
//! are bare hexadecimal, and extensions follow the RFC grammar exactly. Extensions and trailers
//! are validated and dropped; whoever forwards the body generates its own framing.

const repeat = @import("text").repeat;
const std = @import("std");
const http = @import("http.zig");

/// Longest chunk-size or trailer line, CRLF included. A line that has not ended within this
/// many bytes is rejected, so the decoder never needs more unconsumed input than this.
pub const max_line = 4096;
/// The whole trailer section, bounded like a request head.
pub const max_trailer = 16 * 1024;
/// Sixteen hexadecimal digits fill a `u64` exactly; more cannot be counted.
const max_size_digits = 16;

pub const Error = error{MalformedChunk};

/// The decoded bytes now at the start of the slice, and the raw bytes the call used up.
pub const Step = struct { output: usize, consumed: usize };

pub const Decoder = struct {
    state: State = .size,
    /// Data bytes still owed by the current chunk.
    remaining: u64 = 0,
    trailer_bytes: u32 = 0,

    const State = enum { size, data, data_end, trailer, done };

    pub fn done(self: *const Decoder) bool {
        return self.state == .done;
    }

    /// Consumes every complete unit (a line, a run of data, the CRLF after data) at the start
    /// of `bytes` and writes the chunk data it carries to `bytes[0..output]`. The write index
    /// never passes the read index, so the copy is safe in place. An incomplete unit is left
    /// unconsumed for the next call, after more bytes have arrived behind it.
    pub fn decode(self: *Decoder, bytes: []u8) Error!Step {
        var read: usize = 0;
        var write: usize = 0;
        while (true) switch (self.state) {
            .size => {
                const line = try nextLine(bytes[read..]) orelse break;
                const size = try sizeLine(line.text);
                read += line.len;
                self.remaining = size;
                self.state = if (size == 0) .trailer else .data;
            },
            .data => {
                const count: usize = @intCast(@min(self.remaining, bytes.len - read));
                if (count == 0) break;
                if (write != read) {
                    std.mem.copyForwards(u8, bytes[write..][0..count], bytes[read..][0..count]);
                }
                read += count;
                write += count;
                self.remaining -= count;
                if (self.remaining == 0) self.state = .data_end;
            },
            .data_end => {
                const rest = bytes[read..];
                if (rest.len > 0 and rest[0] != '\r') return error.MalformedChunk;
                if (rest.len < 2) break;
                if (rest[1] != '\n') return error.MalformedChunk;
                read += 2;
                self.state = .size;
            },
            .trailer => {
                const line = try nextLine(bytes[read..]) orelse break;
                read += line.len;
                if (line.text.len == 0) {
                    self.state = .done;
                    break;
                }
                self.trailer_bytes += @intCast(line.len);
                if (self.trailer_bytes > max_trailer or !fieldLine(line.text))
                    return error.MalformedChunk;
            },
            .done => break,
        };
        return .{ .output = write, .consumed = read };
    }
};

const Line = struct { text: []const u8, len: usize };

/// The next CRLF-terminated line, or null while it is incomplete. A line ends at its first LF;
/// anything else that could end a line for some other parser (a lone CR or LF, any control
/// byte but HTAB) makes the line malformed rather than shorter.
fn nextLine(bytes: []const u8) Error!?Line {
    const window = bytes[0..@min(bytes.len, max_line)];
    const lf = std.mem.indexOfScalar(u8, window, '\n') orelse {
        if (bytes.len >= max_line) return error.MalformedChunk;
        return null;
    };
    if (lf == 0 or window[lf - 1] != '\r') return error.MalformedChunk;
    const text = window[0 .. lf - 1];
    for (text) |c| if ((c < ' ' and c != '\t') or c == 127) return error.MalformedChunk;
    return .{ .text = text, .len = lf + 1 };
}

fn sizeLine(text: []const u8) Error!u64 {
    var size: u64 = 0;
    var index: usize = 0;
    while (index < text.len) : (index += 1) {
        const digit = std.fmt.charToDigit(text[index], 16) catch break;
        if (index == max_size_digits) return error.MalformedChunk;
        size = size << 4 | digit;
    }
    if (index == 0) return error.MalformedChunk;
    try extensions(text[index..]);
    return size;
}

/// chunk-ext = *( BWS ";" BWS name [ BWS "=" BWS ( token / quoted-string ) ] )
fn extensions(text: []const u8) Error!void {
    var index: usize = 0;
    while (index < text.len) {
        index = space(text, index);
        if (index == text.len or text[index] != ';') return error.MalformedChunk;
        index = try token(text, space(text, index + 1));
        const equals = space(text, index);
        if (equals == text.len or text[equals] != '=') continue;
        const value = space(text, equals + 1);
        index = if (value < text.len and text[value] == '"')
            try quoted(text, value)
        else
            try token(text, value);
    }
}

fn space(text: []const u8, start: usize) usize {
    var index = start;
    while (index < text.len and (text[index] == ' ' or text[index] == '\t')) index += 1;
    return index;
}

/// The end of a non-empty token starting at `start`.
fn token(text: []const u8, start: usize) Error!usize {
    var index = start;
    while (index < text.len and http.tokenChar(text[index])) index += 1;
    if (index == start) return error.MalformedChunk;
    return index;
}

/// The end of a quoted string opening at `start`. Control bytes were refused with the line,
/// so every other byte is quoted text or an escaped character.
fn quoted(text: []const u8, start: usize) Error!usize {
    var index = start + 1;
    while (index < text.len) : (index += 1) {
        switch (text[index]) {
            '"' => return index + 1,
            '\\' => index += 1,
            else => {},
        }
    }
    return error.MalformedChunk;
}

fn fieldLine(text: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return false;
    return http.validToken(text[0..colon]);
}

const t = std.testing;

fn decodeAll(raw: []const u8, out: []u8) Error!?[]const u8 {
    @memcpy(out[0..raw.len], raw);
    var decoder: Decoder = .{};
    const step = try decoder.decode(out[0..raw.len]);
    if (!decoder.done()) return null;
    return out[0..step.output];
}

test "decoder recovers bodies under the full RFC grammar" {
    const cases = [_][2][]const u8{
        .{ "5\r\nhello\r\n0\r\n\r\n", "hello" },
        .{ "0\r\n\r\n", "" },
        .{ "A\r\n0123456789\r\n000\r\n\r\n", "0123456789" },
        .{ "3\r\n\r\n\r\r\n2;a\r\nxy\r\n0\r\n\r\n", "\r\n\rxy" },
        .{ "1 ; name = token ;q=\"a\\\"b; \\\\\"\r\nz\r\n0\r\nX-Sum: 1\r\nY:\r\n\r\n", "z" },
        .{ "000000000000000F\r\n0123456789abcde\r\n0;done\r\n\r\n", "0123456789abcde" },
    };
    var out: [128]u8 = undefined;
    for (cases) |case| {
        const body = (try decodeAll(case[0], &out)).?;
        try t.expectEqualStrings(case[1], body);
    }
}

test "decoder rejects terminator, size, extension and trailer ambiguities" {
    const long_line = "1;" ++ &repeat("a", max_line) ++ "\r\n";
    const bad = [_][]const u8{
        "5\nhello\r\n0\r\n\r\n", // lone LF ends a size line for lenient parsers
        "5\rX\r\nhello\r\n0\r\n\r\n", // lone CR inside the line
        "5\r\nhello\n0\r\n\r\n", // data not followed by CRLF
        "5\r\nhelloXY0\r\n\r\n",
        "5 \r\nhello\r\n0\r\n\r\n", // whitespace with no extension
        " 5\r\nhello\r\n0\r\n\r\n",
        "+5\r\nhello\r\n0\r\n\r\n",
        "0x5\r\nhello\r\n0\r\n\r\n",
        "-1\r\nx\r\n0\r\n\r\n",
        "\r\n",
        "10000000000000000\r\n", // seventeen digits
        "5;\r\nhello\r\n0\r\n\r\n",
        "5;a=\r\nhello\r\n0\r\n\r\n",
        "5;a b\r\nhello\r\n0\r\n\r\n",
        "5;a=\"open\r\nhello\r\n0\r\n\r\n",
        "5;a=\"x\ny\"\r\nhello\r\n0\r\n\r\n", // LF inside a quoted string
        "5;a=\"x\ry\"\r\nhello\r\n0\r\n\r\n", // CR inside a quoted string
        "5;a=\"x\x01\"\r\nhello\r\n0\r\n\r\n",
        "0\r\nBad Name: x\r\n\r\n",
        "0\r\nX : y\r\n\r\n",
        "0\r\nno colon\r\n\r\n",
        "0\r\nX: \x7f\r\n\r\n",
        "0\r\n\n",
        long_line,
    };
    var out: [max_line + 64]u8 = undefined;
    for (bad) |raw| try t.expectError(error.MalformedChunk, decodeAll(raw, &out));
    var trailer: [max_trailer + 512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&trailer);
    try w.writeAll("0\r\n");
    while (w.end <= "0\r\n".len + max_trailer) try w.writeAll("X-Pad: " ++
        &repeat("p", 120) ++
        "\r\n");
    try w.writeAll("\r\n");
    var big: [max_trailer + 512]u8 = undefined;
    try t.expectError(error.MalformedChunk, decodeAll(w.buffered(), &big));
}

/// Encodes `body` with random chunk sizes, extensions and trailers.
fn encodeRandom(random: std.Random, body: []const u8, w: *std.Io.Writer) !void {
    const extensions_pool = [_][]const u8{ "", ";a", " ; b = c", ";q=\"x\\\"y\"", ";n\t=\tv" };
    var at: usize = 0;
    while (at < body.len) {
        const size = @min(body.len - at, random.intRangeAtMost(usize, 1, 40));
        const ext = extensions_pool[random.uintLessThan(usize, extensions_pool.len)];
        if (random.boolean()) {
            try w.print("{X}{s}\r\n", .{ size, ext });
        } else try w.print("{x:0>3}{s}\r\n", .{ size, ext });
        try w.writeAll(body[at..][0..size]);
        try w.writeAll("\r\n");
        at += size;
    }
    try w.writeAll(if (random.boolean()) "0\r\n\r\n" else "0;end\r\nX-Check: 7\r\n\r\n");
}

const Outcome = struct { failed: bool, done: bool, len: usize };

/// Delivers `raw` in pieces (one piece when `whole`), carrying each call's unconsumed tail as a
/// connection reader does, and collects the decoded output.
fn decodeSplit(random: std.Random, raw: []const u8, out: []u8, whole: bool) Outcome {
    var work: [8192]u8 = undefined;
    var held: usize = 0;
    var at: usize = 0;
    var len: usize = 0;
    var decoder: Decoder = .{};
    while (at < raw.len and !decoder.done()) {
        const piece = if (whole) raw.len else @min(raw.len - at, random.uintAtMost(usize, 8) + 1);
        @memcpy(work[held..][0..piece], raw[at..][0..piece]);
        held += piece;
        at += piece;
        // Output before a faulty unit is legitimately delivered earlier when split, so a
        // failure is compared by verdict alone.
        const step = decoder.decode(work[0..held]) catch
            return .{ .failed = true, .done = false, .len = 0 };
        @memcpy(out[len..][0..step.output], work[0..step.output]);
        len += step.output;
        std.mem.copyForwards(u8, work[0 .. held - step.consumed], work[step.consumed..held]);
        held -= step.consumed;
    }
    return .{ .failed = false, .done = decoder.done(), .len = len };
}

test "decoding is independent of how the stream is split across reads" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0009);
    const random = prng.random();
    var body: [300]u8 = undefined;
    var raw: [8192]u8 = undefined;
    var one: [8192]u8 = undefined;
    var split: [8192]u8 = undefined;
    const mutations = "\r\n;0g \"\x01";
    for (0..3000) |round| {
        const body_len = random.uintAtMost(usize, 160);
        // Data may hold any byte, including CR, LF and digits that look like framing.
        for (body[0..body_len]) |*b| b.* = "\r\n0;a\" xZ"[random.uintLessThan(usize, 9)];
        var w: std.Io.Writer = .fixed(&raw);
        try encodeRandom(random, body[0..body_len], &w);
        const encoded = w.buffered();
        if (round % 2 == 1) {
            // A mutated stream may become invalid, incomplete or a different valid stream;
            // whichever it is, every split must reach the same verdict and output.
            const at = random.uintLessThan(usize, encoded.len);
            encoded[at] = mutations[random.uintLessThan(usize, mutations.len)];
        }
        const expected = decodeSplit(random, encoded, &one, true);
        const actual = decodeSplit(random, encoded, &split, false);
        try t.expectEqual(expected, actual);
        try t.expectEqualSlices(u8, one[0..expected.len], split[0..actual.len]);
        if (round % 2 == 0) {
            try t.expect(expected.done);
            try t.expectEqualSlices(u8, body[0..body_len], one[0..expected.len]);
        }
    }
}
