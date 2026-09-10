//! Engine-slot metadata is immutable while pinned. Only the storage owner prepares a spare.
const std = @import("std");
const p = @import("console").protocol.rule_hits;
const policy = @import("policy");

pub const Slot = struct {
    counters: @import("store").rule_hits.Counters(p.max_rules) = .{},
    generation: p.Generation = .{
        .node = 0,
        .boot = @splat(0),
        .number = 0,
        .revision = 0,
        .born = .{ .utc = 0, .ms = 0 },
    },

    pub fn identify(
        self: *Slot,
        engine: *const policy.Engine,
        index: usize,
        id: ?[]const u8,
        fallback_index: usize,
    ) !void {
        const name = engine.rules[index].name;
        var bytes: [160]u8 = undefined;
        const source = id orelse name;
        const readable = std.unicode.utf8ValidateSlice(source) and source.len <= 128 and
            std.mem.indexOfAny(u8, source, "\x00\r\n\t") == null;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
        const encoded = std.fmt.bytesToHex(digest, .lower);
        const key = if (id != null)
            try std.fmt.bufPrint(&bytes, "{s}:{s}", .{
                if (readable) "m" else "mh", if (readable) source else &encoded,
            })
        else
            try std.fmt.bufPrint(&bytes, "{s}:{d}:{s}", .{
                if (readable) "f" else "fh", fallback_index, if (readable) source else &encoded,
            });
        // Telemetry must not reject a policy accepted by the data plane. Preserve identity
        // for opaque SQL/file bytes, and render a safe label instead of invalid JSON text.
        self.generation.rules[index] = .{
            .key = try p.Key.init(key),
            .name = try p.Name.init(label(name)),
        };
    }
};

fn label(name: []const u8) []const u8 {
    if (!std.unicode.utf8ValidateSlice(name)) return "[invalid text]";
    var end = @min(name.len, 128);
    while (!std.unicode.utf8ValidateSlice(name[0..end])) end -= 1;
    return name[0..end];
}

test "observation metadata preserves accepted long and opaque file rule identities" {
    const t = std.testing;
    const engine = try t.allocator.create(policy.Engine);
    defer t.allocator.destroy(engine);
    engine.initInPlace(16);
    var slot: Slot = .{};
    const long = "x" ** 127 ++ "é" ** 10;
    engine.rules[0] = .{ .name = long };
    try slot.identify(engine, 0, null, 0);
    const first = slot.generation.rules[0];
    try t.expectEqualStrings("x" ** 127, first.name.slice());
    try t.expect(std.mem.startsWith(u8, first.key.slice(), "fh:0:"));
    engine.rules[0].name = long ++ "different";
    try slot.identify(engine, 0, null, 0);
    try t.expect(!std.mem.eql(u8, first.key.slice(), slot.generation.rules[0].key.slice()));
    engine.rules[0].name = "a\x00b";
    try slot.identify(engine, 0, null, 0);
    try t.expect(std.mem.startsWith(u8, slot.generation.rules[0].key.slice(), "fh:0:"));
    engine.rules[0].name = "\xff";
    try slot.identify(engine, 0, null, 0);
    try t.expectEqualStrings("[invalid text]", slot.generation.rules[0].name.slice());
}
