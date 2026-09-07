//! Attack Payload Embedding
//!
//! Maps an attack payload to a fixed 64-dimensional unit vector with the
//! hashing trick (Weinberger et al., ICML 2009) over byte trigrams
//! (Broder's shingling, 1997): each trigram is hashed to a coordinate and a
//! sign, counts are accumulated, and the vector is L2-normalised so cosine
//! similarity is a dot product. Two payloads from one campaign (same
//! injection template, different targets) land close together; unrelated
//! payloads are near-orthogonal. No model, no allocation, no training.

const std = @import("std");

pub const dim: usize = 64;
pub const Vector = [dim]f32;

/// Bytes that vary between instances of one campaign (digits, hex escapes'
/// case) are folded so the template dominates the trigram set.
fn fold(c: u8) u8 {
    if (std.ascii.isDigit(c)) return '0';
    return std.ascii.toLower(c);
}

pub fn embed(payload: []const u8) Vector {
    var v: Vector = [_]f32{0} ** dim;
    if (payload.len == 0) return v;
    var i: usize = 0;
    while (i + 3 <= payload.len) : (i += 1) {
        const tri = [3]u8{ fold(payload[i]), fold(payload[i + 1]), fold(payload[i + 2]) };
        const h = std.hash.Wyhash.hash(0x3a3a, &tri);
        const coord: usize = @intCast(h % dim);
        const sign: f32 = if ((h >> 63) == 1) -1.0 else 1.0;
        v[coord] += sign;
    }
    if (payload.len < 3) {
        const h = std.hash.Wyhash.hash(0x3a3a, payload);
        v[@intCast(h % dim)] += 1.0;
    }
    var norm: f32 = 0;
    for (v) |x| norm += x * x;
    if (norm > 0) {
        const inv = 1.0 / @sqrt(norm);
        for (&v) |*x| x.* *= inv;
    }
    return v;
}

pub fn cosine(a: *const Vector, b: *const Vector) f32 {
    var dot: f32 = 0;
    for (a, b) |x, y| dot += x * y;
    return dot;
}

/// Little-endian float32 bytes, the storage format sqlite-vec expects.
pub fn toBytes(v: *const Vector) [dim * 4]u8 {
    var out: [dim * 4]u8 = undefined;
    for (v, 0..) |x, i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], @bitCast(x), .little);
    }
    return out;
}

test "campaign variants are close and unrelated payloads are far" {
    const a = embed("id=1' UNION SELECT username,password FROM users--");
    const b = embed("id=42' union select name,pass from users--");
    const c = embed("<img src=x onerror=alert(document.cookie)>");
    const d = embed("../../../../etc/passwd%00");
    try std.testing.expect(cosine(&a, &b) > 0.6);
    try std.testing.expect(cosine(&a, &c) < 0.4);
    try std.testing.expect(cosine(&a, &d) < 0.4);
    try std.testing.expect(cosine(&c, &d) < 0.4);
    var norm: f32 = 0;
    for (a) |x| norm += x * x;
    try std.testing.expectApproxEqAbs(@as(f32, 1.0), norm, 0.001);
    const bytes = toBytes(&a);
    try std.testing.expectEqual(dim * 4, bytes.len);
    try std.testing.expect(embed("")[0] == 0);
}
