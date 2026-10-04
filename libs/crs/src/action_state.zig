//! Caller-reserved evidence and intervention state. This module neither logs nor
//! stores incidents: an adapter consumes completed events after redaction.
const std = @import("std");
const model = @import("model.zig");
const controls = @import("controls.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = work.Error || error{ EventLimit, TagLimit, ByteLimit, TransactionFailed };
pub const Namespace = enum { ip, global, resource };
pub const Event = struct {
    id: u32,
    phase: model.Phase,
    message: []const u8 = "",
    data: []const u8 = "",
    tags: []const []const u8 = &.{},
    severity: u3 = 0,
    save: bool = true,
    no_audit: bool = false,
    would_deny: bool = false,
};
pub const State = struct {
    control: controls.State,
    events: []Event,
    tags: [][]const u8,
    bytes: []u8,
    event_used: usize = 0,
    tag_used: usize = 0,
    byte_used: usize = 0,
    bindings: [3]?[]const u8 = @splat(null),
    status: u16 = 200,
    highest_severity: u8 = 255,
    enforce: bool,
    denied: bool = false,
    would_deny: bool = false,
    failed: bool = false,

    pub fn init(
        exclusions: []controls.Exclusion,
        events: []Event,
        tags: [][]const u8,
        bytes: []u8,
        enforce: bool,
    ) State {
        const regions = [_][]const u8{
            std.mem.sliceAsBytes(exclusions),
            std.mem.sliceAsBytes(events),
            std.mem.sliceAsBytes(tags),
            bytes,
        };
        buffers.assertExclusive(&regions);
        return .{
            .control = .{ .exclusions = exclusions },
            .events = events,
            .tags = tags,
            .bytes = bytes,
            .enforce = enforce,
        };
    }

    pub fn poison(self: *State) void {
        self.failed = true;
        self.control.failed = true;
    }

    pub fn save(self: *State, value: []const u8, budget: *work.Budget) Error![]const u8 {
        if (self.failed) return error.TransactionFailed;
        errdefer self.poison();
        if (value.len > self.bytes.len - self.byte_used) return error.ByteLimit;
        try budget.debit(value.len);
        const output = self.bytes[self.byte_used..][0..value.len];
        buffers.assertDisjoint(value, output);
        @memcpy(output, value);
        self.byte_used += value.len;
        return output;
    }

    pub fn appendTag(self: *State, value: []const u8, budget: *work.Budget) Error!void {
        if (self.failed) return error.TransactionFailed;
        errdefer self.poison();
        if (self.tag_used == self.tags.len) return error.TagLimit;
        const owned = try self.save(value, budget);
        self.tags[self.tag_used] = owned;
        self.tag_used += 1;
    }

    pub fn deny(self: *State, event: *Event) void {
        std.debug.assert(!self.failed);
        event.would_deny = true;
        self.would_deny = true;
        if (self.status == 200) self.status = 403;
        // Logging records intent after publication; it cannot retroactively deny
        // bytes already delivered. An earlier enforcing denial remains retained.
        if (self.enforce and event.phase != .logging) self.denied = true;
    }
};
