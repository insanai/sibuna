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
        const readable = std.unicode.utf8ValidateSlice(source) and source.len <= 128;
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
            .name = try p.Name.init(if (std.unicode.utf8ValidateSlice(name))
                name
            else
                "[invalid text]"),
        };
    }
};
