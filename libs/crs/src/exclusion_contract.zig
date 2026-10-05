//! Owned configuration descriptions, never expanded tags or request field values.
const std = @import("std");
const Bytes = @import("text").buffers.Bytes;
pub const capacity = 4096;
pub const page_capacity = 8;
pub const preview_bytes = 256;
pub const Side = enum { before, after };
pub const Scope = enum { static_target, conditional_rule, conditional_target };
pub const Selector = enum { rule_id, rule_range, tag };
pub const Selection = enum { none, all, exact, pattern, xml_elements, xml_attributes };
pub const Text = struct {
    hex: Bytes(preview_bytes * 2) = .{},
    bytes: u32 = 0,
    digest: Bytes(64) = .{},

    pub fn init(source: []const u8) Text {
        std.debug.assert(source.len <= 64 * 1024);
        const prefix = source[0..@min(source.len, preview_bytes)];
        var encoded: [preview_bytes * 2]u8 = undefined;
        const digits = "0123456789abcdef";
        for (prefix, 0..) |byte, index| {
            encoded[index * 2] = digits[byte >> 4];
            encoded[index * 2 + 1] = digits[byte & 15];
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
        return .{
            .hex = Bytes(preview_bytes * 2).init(encoded[0 .. prefix.len * 2]) catch unreachable,
            .bytes = @intCast(source.len),
            .digest = Bytes(64).init(&std.fmt.bytesToHex(&digest, .lower)) catch unreachable,
        };
    }

    pub fn validate(self: *const Text) error{InvalidExclusion}!void {
        const length = @as(usize, @min(self.bytes, preview_bytes));
        if (self.bytes > 64 * 1024 or self.hex.len != length * 2 or
            self.digest.len != 64) return error.InvalidExclusion;
        for (self.hex.slice()) |byte| if (!std.ascii.isHex(byte)) return error.InvalidExclusion;
        for (self.digest.slice()) |byte| if (!std.ascii.isHex(byte)) return error.InvalidExclusion;
    }

    pub fn jsonStringify(self: Text, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.write(.{
            .hex = self.hex.slice(),
            .bytes = self.bytes,
            .digest = self.digest.slice(),
        });
    }
};
pub const Row = struct {
    rule_id: u32,
    phase: u8,
    chain_link: u16,
    scope: Scope,
    selector: Selector,
    first: u32 = 0,
    last: u32 = 0,
    tag: ?Text = null,
    collection: ?Bytes(32) = null,
    selection: Selection = .none,
    key: ?Text = null,

    pub fn validate(self: *const Row) error{InvalidExclusion}!void {
        if (self.rule_id == 0 or self.phase < 1 or self.phase > 5 or self.chain_link >= 256)
            return error.InvalidExclusion;
        if (self.selector == .tag) {
            if (self.tag == null or self.first != 0 or self.last != 0)
                return error.InvalidExclusion;
        } else if (self.tag != null or self.first == 0 or self.last < self.first or
            (self.selector == .rule_id and self.last != self.first)) return error.InvalidExclusion;
        if ((self.scope == .conditional_rule) != (self.selection == .none) or
            (self.selection == .none) != (self.collection == null)) return error.InvalidExclusion;
        if ((self.selection == .exact or self.selection == .pattern) != (self.key != null))
            return error.InvalidExclusion;
        if (self.collection) |name| {
            if (name.len == 0 or name.len > 32) return error.InvalidExclusion;
            for (name.slice()) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_')
                return error.InvalidExclusion;
        }
        if (self.tag) |value| try value.validate();
        if (self.key) |value| try value.validate();
    }

    pub fn jsonStringify(self: Row, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.write(.{
            .rule_id = self.rule_id,
            .phase = self.phase,
            .chain_link = self.chain_link,
            .scope = self.scope,
            .selector = self.selector,
            .first = self.first,
            .last = self.last,
            .tag = self.tag,
            .collection = if (self.collection) |name| name.slice() else null,
            .selection = self.selection,
            .key = self.key,
        });
    }
};
pub const Page = struct {
    side: Side,
    total: u32,
    offset: u32,
    count: usize,
    rows: [page_capacity]?Row = @splat(null),
    next: ?u32,

    pub fn validate(self: *const Page) error{InvalidExclusion}!void {
        if (self.total > capacity or self.offset > self.total or self.count > page_capacity or
            self.count != @min(self.total - self.offset, page_capacity))
            return error.InvalidExclusion;
        const end = self.offset + @as(u32, @intCast(self.count));
        if (self.next != (if (end < self.total) end else @as(?u32, null)))
            return error.InvalidExclusion;
        for (self.rows[0..self.count]) |item| try (item orelse
            return error.InvalidExclusion).validate();
        for (self.rows[self.count..]) |item| if (item != null) return error.InvalidExclusion;
    }
};
