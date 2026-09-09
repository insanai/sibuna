//! Response template editor: one kind at a time, its committed revision, and the outcome
//! of the last save, reset or preview. The draft text lives in the browser form; only the
//! committed document is held here.
const std = @import("std");
const p = @import("console_protocol");
pub const Kind = enum { read, edit, preview };
/// The committed markup lives outside the state struct so the module's data segment does
/// not carry sixteen kilobytes of zeros.
var html_bytes: [p.pages.max_bytes]u8 = undefined;
var html_len: u16 = 0;
/// The operator's unsaved draft survives a refused save and a preview round trip.
var draft_bytes: [p.pages.max_bytes]u8 = undefined;
var draft_len: u16 = 0;

pub const Model = struct {
    kind: p.pages.Kind = .denied,
    revision: u64 = 0,
    customized: bool = false,
    loaded: bool = false,
    busy: bool = false,
    op: Kind = .read,
    ticket: p.Bytes(40) = .{},
    preview_path: p.Bytes(64) = .{},
    result: p.Bytes(96) = .{},
    result_ok: bool = false,

    pub fn clear(self: *Model) void {
        self.* = .{};
        html_len = 0;
        draft_len = 0;
    }

    /// The draft when one is held, otherwise the committed page.
    pub fn html(_: *const Model) []const u8 {
        return if (draft_len != 0) draft_bytes[0..draft_len] else html_bytes[0..html_len];
    }

    pub fn setDraft(_: *Model, text: []const u8) void {
        const length = @min(text.len, p.pages.max_bytes);
        @memcpy(draft_bytes[0..length], text[0..length]);
        draft_len = @intCast(length);
    }

    pub fn clearDraft(_: *Model) void {
        draft_len = 0;
    }

    pub fn decode(self: *Model, body: std.json.Value) !void {
        const string = @import("events_state.zig").string;
        const field = @import("events_state.zig").field;
        self.kind = std.meta.stringToEnum(p.pages.Kind, string(body, "kind")) orelse
            return error.InvalidResponse;
        const revision = field(body, "revision") orelse return error.InvalidResponse;
        self.revision = switch (revision) {
            .integer => |value| @intCast(@max(0, value)),
            .string => |text| std.fmt.parseInt(u64, text, 10) catch return error.InvalidResponse,
            else => return error.InvalidResponse,
        };
        const customized = field(body, "customized") orelse return error.InvalidResponse;
        self.customized = customized == .bool and customized.bool;
        const text = string(body, "html");
        if (text.len > p.pages.max_bytes) return error.InvalidResponse;
        @memcpy(html_bytes[0..text.len], text);
        html_len = @intCast(text.len);
        self.loaded = true;
    }
};
