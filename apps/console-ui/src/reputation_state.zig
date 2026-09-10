//! Console-managed reputation prefixes and the country builder. Rows are held as the
//! server's JSON page; the last successful mutation keeps an inverse for thirty seconds.
const std = @import("std");
const p = @import("console_protocol");
pub const Kind = enum { query, edit, remove, preview, preview_page, apply };
pub const Undo = struct {
    prefix: p.Bytes(48) = .{},
    /// Restore a removed row with this action, or remove an added one.
    restore: bool = false,
    action: p.Bytes(8) = .{},
    note: p.Bytes(128) = .{},
    until: u64 = 0,
    expires_at: u64 = 0,
};
/// The page and the country summary live outside the state struct so the module's data
/// segment does not carry their zeros.
var page_bytes: [4096]u8 = undefined;
var page_len: u16 = 0;
var summary_bytes: [2048]u8 = undefined;
var summary_len: u16 = 0;

pub const Model = struct {
    committed: p.Bytes(20) = .{},
    next: p.Bytes(48) = .{},
    after: p.Bytes(48) = .{},
    summary_prefixes: u16 = 0,
    country: p.Bytes(2) = .{},
    country_action: p.Bytes(8) = .{},
    country_until: u64 = 0,
    country_review: p.Bytes(64) = .{},
    country_revision: p.Bytes(20) = .{},
    country_next: ?u16 = null,
    undo: Undo = .{},
    /// An address carried from an incident into the prefix form; never submitted by itself.
    draft_prefix: p.Bytes(48) = .{},
    draft_deny: bool = true,
    busy: bool = false,
    loaded: bool = false,
    kind: Kind = .query,
    ticket: p.Bytes(40) = .{},

    pub fn clear(self: *Model) void {
        self.* = .{};
        page_len = 0;
        summary_len = 0;
    }

    pub fn page(_: *const Model) []const u8 {
        return page_bytes[0..page_len];
    }

    pub fn summary(_: *const Model) []const u8 {
        return summary_bytes[0..summary_len];
    }

    pub fn setPage(_: *Model, value: std.json.Value) !void {
        var writer: std.Io.Writer = .fixed(&page_bytes);
        try std.json.Stringify.value(value, .{}, &writer);
        page_len = @intCast(writer.buffered().len);
    }

    pub fn setSummary(_: *Model, value: std.json.Value) !void {
        var writer: std.Io.Writer = .fixed(&summary_bytes);
        try std.json.Stringify.value(value, .{}, &writer);
        summary_len = @intCast(writer.buffered().len);
    }

    pub fn clearSummary(self: *Model) void {
        summary_len = 0;
        self.country_review = .{};
        self.country_next = null;
    }
};
