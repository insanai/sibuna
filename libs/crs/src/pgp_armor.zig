//! ASCII armor decoding into caller buffers. CRC24 is not authenticity and is
//! ignored, including a malformed footer, as RFC 9580 section 6.1 requires.
const std = @import("std");
const buffers = @import("buffers.zig");
pub const Kind = enum { key, signature };
pub const Error = error{ InvalidArmor, ArmorLimit };

pub fn decode(
    source: []const u8,
    comptime kind: Kind,
    encoded: []u8,
    output: []u8,
) Error![]const u8 {
    buffers.assertExclusive(&.{ source, encoded, output });
    if (source.len > 16 * 1024) return error.ArmorLimit;
    const label = if (kind == .key) "PGP PUBLIC KEY BLOCK" else "PGP SIGNATURE";
    const begin = "-----BEGIN " ++ label ++ "-----";
    const end = "-----END " ++ label ++ "-----";
    var lines = std.mem.splitScalar(u8, source, '\n');
    if (!std.mem.eql(u8, trim(lines.next() orelse return error.InvalidArmor), begin))
        return error.InvalidArmor;
    var headers = true;
    var footer = false;
    var checksum = false;
    var used: usize = 0;
    while (lines.next()) |raw| {
        const line = trim(raw);
        if (footer) {
            if (line.len != 0) return error.InvalidArmor;
            continue;
        }
        if (headers) {
            if (line.len == 0) {
                headers = false;
            } else if (std.mem.indexOfScalar(u8, line, ':') == null) {
                return error.InvalidArmor;
            }
            continue;
        }
        if (std.mem.eql(u8, line, end)) {
            footer = true;
            continue;
        }
        if (line.len == 0) continue;
        if (line[0] == '=' and !checksum) {
            checksum = true;
            continue;
        }
        if (checksum) return error.InvalidArmor;
        if (line.len > encoded.len - used) return error.ArmorLimit;
        @memcpy(encoded[used..][0..line.len], line);
        used += line.len;
    }
    if (!footer or used == 0) return error.InvalidArmor;
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded[0..used]) catch return error.InvalidArmor;
    if (size > output.len) return error.ArmorLimit;
    decoder.decode(output[0..size], encoded[0..used]) catch return error.InvalidArmor;
    return output[0..size];
}

fn trim(line: []const u8) []const u8 {
    return std.mem.trim(u8, line, " \t\r");
}
