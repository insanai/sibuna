//! Storage owns the boot fence and one outstanding completion. No new effect starts while
//! its predecessor's receipt cannot be committed; retrying that id never repeats the effect.
const std = @import("std");
const p = @import("console").protocol;
pub const State = struct {
    boot: [16]u8 = @splat(0),
    started_ns: i96 = 0,
    revision: u64 = 0,
    pending: ?p.nodes.Receipt = null,
    /// Membership announcement: set after each applied rebuild; heartbeats otherwise.
    announce: bool = false,
    announce_failed: bool = false,
    last_heartbeat: u64 = 0,
    advertise: p.Bytes(p.nodes.max_url) = .{},
    storage: p.nodes.Storage = .{},
    /// Owner-thread notification sequence; the notifier thread numbers its own ring.
    event_sequence: u64 = 1 << 40,

    pub fn init(io: std.Io) State {
        var state: State = .{ .started_ns = std.Io.Clock.awake.now(io).nanoseconds };
        while (std.mem.allEqual(u8, &state.boot, 0)) io.random(&state.boot);
        return state;
    }
};
