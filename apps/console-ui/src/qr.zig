//! Bounded QR Model 2 provisioning: version 6, level L, byte mode, explicit mask 0.
//! A 130-byte maximum otpauth URI fits the 134-byte capacity. Native matrix fixtures
//! are checked against Project Nayuki's independent QR encoder with identical parameters.
const html = @import("html");
const std = @import("std");
pub const size = 41;
pub const max_bytes = 134;
const data_bytes = 136;
const codewords = 172;
const correction_bytes = 18;

pub const Qr = struct {
    pixels: [size * size]bool = @splat(false),
    fixed: [size * size]bool = @splat(false),

    fn function(self: *Qr, x: usize, y: usize, dark: bool) void {
        self.pixels[y * size + x] = dark;
        self.fixed[y * size + x] = true;
    }

    fn finder(self: *Qr, cx: i32, cy: i32) void {
        for (0..9) |iy| {
            for (0..9) |ix| {
                const dx = @as(i32, @intCast(ix)) - 4;
                const dy = @as(i32, @intCast(iy)) - 4;
                const x = cx + dx;
                const y = cy + dy;
                if (x < 0 or y < 0 or x >= size or y >= size) continue;
                const distance = @max(@abs(dx), @abs(dy));
                self.function(@intCast(x), @intCast(y), distance != 2 and distance != 4);
            }
        }
    }

    fn patterns(self: *Qr) void {
        for (0..size) |i| {
            self.function(6, i, i % 2 == 0);
            self.function(i, 6, i % 2 == 0);
        }
        self.finder(3, 3);
        self.finder(size - 4, 3);
        self.finder(3, size - 4);
        // Version 6 alignment centers are 6 and 34; the other three overlap finders.
        for (0..5) |y| {
            for (0..5) |x| {
                const inner = x >= 1 and x <= 3 and y >= 1 and y <= 3;
                self.function(32 + x, 32 + y, !inner or (x == 2 and y == 2));
            }
        }
        // BCH-protected format for level L and mask 0, XORed with the format mask.
        const format: u15 = 0x77c4;
        for (0..6) |i| self.function(8, i, bit(format, i));
        self.function(8, 7, bit(format, 6));
        self.function(8, 8, bit(format, 7));
        self.function(7, 8, bit(format, 8));
        for (9..15) |i| self.function(14 - i, 8, bit(format, i));
        for (0..8) |i| self.function(size - 1 - i, 8, bit(format, i));
        for (8..15) |i| self.function(8, size - 15 + i, bit(format, i));
        self.function(8, size - 8, true);
    }

    fn place(self: *Qr, bytes: [codewords]u8) void {
        var index: usize = 0;
        var right: i32 = size - 1;
        while (right >= 1) : (right -= 2) {
            if (right == 6) right = 5;
            for (0..size) |vertical| {
                const y = if ((right + 1) & 2 == 0) size - 1 - vertical else vertical;
                for (0..2) |column| {
                    const x: usize = @intCast(right - @as(i32, @intCast(column)));
                    if (self.fixed[y * size + x]) continue;
                    const value = if (index < bytes.len * 8)
                        bit(bytes[index / 8], 7 - index % 8)
                    else
                        false;
                    self.pixels[y * size + x] = value != ((x + y) % 2 == 0);
                    index += 1;
                }
            }
        }
        std.debug.assert(index == codewords * 8 + 7);
    }

    pub fn svg(self: *const Qr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try html.render(writer, "<svg class=\"sb-qr\" viewBox=\"0 0 49 49\" role=\"img\" " ++
            "aria-label=\"Authenticator enrollment QR code\" shape-rendering=\"crispEdges\">" ++
            "<rect width=\"49\" height=\"49\" fill=\"white\"/><path fill=\"black\" d=\"", .{});
        for (self.pixels, 0..) |dark, index| {
            if (dark) try writer.print("M{d} {d}h1v1h-1z", .{
                index % size + 4, index / size + 4,
            });
        }
        try html.render(writer, "\"/></svg>", .{});
    }
};

fn bit(value: anytype, index: usize) bool {
    return (value >> @as(std.math.Log2Int(@TypeOf(value)), @intCast(index))) & 1 != 0;
}

pub fn encode(input: []const u8) error{TooLarge}!Qr {
    if (input.len > max_bytes) return error.TooLarge;
    var data: [data_bytes]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &data);
    var count: usize = 0;
    append(&data, &count, 4, 4);
    append(&data, &count, @intCast(input.len), 8);
    for (input) |byte| append(&data, &count, byte, 8);
    append(&data, &count, 0, 4);
    count = (count + 7) / 8;
    var pad: u8 = 0xec;
    while (count < data.len) : (count += 1) {
        data[count] = pad;
        pad ^= 0xfd;
    }
    var words: [codewords]u8 = undefined;
    defer std.crypto.secureZero(u8, &words);
    const divisor = generator();
    for (0..2) |block| {
        const bytes = data[block * 68 ..][0..68];
        for (bytes, 0..) |byte, index| words[index * 2 + block] = byte;
        const ecc = remainder(bytes, divisor);
        for (ecc, 0..) |byte, index| words[data_bytes + index * 2 + block] = byte;
    }
    var qr: Qr = .{};
    qr.patterns();
    qr.place(words);
    return qr;
}

fn append(data: *[data_bytes]u8, count: *usize, value: u8, bits: u4) void {
    for (0..bits) |index| {
        if (bit(value, bits - 1 - index))
            data[count.* / 8] |= @as(u8, 1) << @intCast(7 - count.* % 8);
        count.* += 1;
    }
}

/// GF(256), primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d).
fn multiply(left: u8, right: u8) u8 {
    var result: u8 = 0;
    for (0..8) |i| {
        const high = result >> 7;
        result = (result << 1) ^ (high * 0x1d);
        if (bit(right, 7 - i)) result ^= left;
    }
    return result;
}

fn generator() [correction_bytes]u8 {
    var polynomial: [correction_bytes]u8 = @splat(0);
    polynomial[correction_bytes - 1] = 1;
    var root: u8 = 1;
    for (0..correction_bytes) |_| {
        for (&polynomial, 0..) |*coefficient, index| {
            coefficient.* = multiply(coefficient.*, root);
            if (index + 1 < polynomial.len) coefficient.* ^= polynomial[index + 1];
        }
        root = multiply(root, 2);
    }
    return polynomial;
}

fn remainder(input: []const u8, divisor: [correction_bytes]u8) [correction_bytes]u8 {
    var result: [correction_bytes]u8 = @splat(0);
    for (input) |byte| {
        const factor = byte ^ result[0];
        std.mem.copyForwards(u8, result[0 .. result.len - 1], result[1..]);
        result[result.len - 1] = 0;
        for (&result, divisor) |*coefficient, multiplier| {
            coefficient.* ^= multiply(multiplier, factor);
        }
    }
    return result;
}

fn expectMatrix(input: []const u8, expected: []const u8) !void {
    const qr = try encode(input);
    var bytes: [size * size]u8 = undefined;
    for (qr.pixels, &bytes) |dark, *byte| byte.* = @intFromBool(dark);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &hash, .{});
    try std.testing.expectEqualStrings(expected, &std.fmt.bytesToHex(hash, .lower));
}

test "complete QR matrices match independent version 6 L byte-mode mask-zero vectors" {
    // Nayuki QR-Code-generator v1.8.0 python/qrcodegen.py, SHA-256:
    // b089855caf16185c61421ea4927c1b213cf9468940d71fa8ab11ef83662dcc84.
    // QrSegment.make_bytes; encode_segments(..., LOW, 6, 6, 0, False).
    try expectMatrix(
        "hello",
        "fedb03e05d2f87205ef2974d1230a91c78c38927bc133b7400270283f9b10a79",
    );
    try expectMatrix(
        "otpauth://totp/Sibuna:18446744073709551615?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" ++
            "&issuer=Sibuna&algorithm=SHA1&digits=6&period=30",
        "b291480761779c290ee42743c78c72a0dc3ad5c6827cb2839ea3a543ef18ed2e",
    );
    try expectMatrix(
        &(@as([134]u8, @splat('A'))),
        "8aeff1e8995545d4486a8a1674480cc925974edaefe48f5f523224a9a5fbc323",
    );
    var binary: [134]u8 = undefined;
    for (&binary, 0..) |*byte, index| byte.* = @intCast(index);
    try expectMatrix(
        &binary,
        "c436312d2e84cc9653bfdc30666c519dc67c9a02a7c5259ee2ffc693b8147fe3",
    );
    try std.testing.expectError(error.TooLarge, encode(&(@as([135]u8, @splat(0)))));
}
