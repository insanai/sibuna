//! Retained editor text is private operator configuration, erased on leaving the
//! page and on session reset. JSON event bytes never become retained references.
const std = @import("std");
const p = @import("console_protocol");
pub const Kind = enum { idle, status, configuration, prepare, select, discard };
pub const Model = struct {
    snapshot: ?p.crs_api.Status = null,
    editor: p.Bytes(p.crs_api.editor_bytes) = .{},
    editor_revision: u64 = 0,
    editor_loaded: bool = false,
    reviewed: ?p.crs_api.Candidate = null,
    ticket: p.Bytes(48) = .{},
    busy: Kind = .idle,
    attempted_at: u64 = 0,
    received_at: u64 = 0,
    stale: bool = true,

    pub fn clear(self: *Model) void {
        self.snapshot = null;
        self.editor_revision = 0;
        self.editor_loaded = false;
        self.reviewed = null;
        self.ticket = .{};
        self.busy = .idle;
        self.attempted_at = 0;
        self.received_at = 0;
        self.stale = true;
        std.crypto.secureZero(u8, &self.editor.data);
        self.editor.len = 0;
    }

    pub fn accept(self: *Model, value: std.json.Value, alloc: std.mem.Allocator) !void {
        var observed: p.crs_api.Status = undefined;
        try @import("json_value.zig").into(&observed, value, alloc);
        try observed.validate();
        if (self.snapshot) |previous| {
            if (previous.revision != observed.revision) self.reviewed = null;
        }
        if (self.reviewed) |reviewed| {
            var present = false;
            for (observed.candidates[0..observed.count]) |row| {
                const candidate = row.?;
                if (std.mem.eql(u8, candidate.id.slice(), reviewed.id.slice()) and
                    candidate.state == .verified) present = true;
            }
            if (!present) self.reviewed = null;
        }
        self.snapshot = observed;
        self.stale = false;
    }
};
