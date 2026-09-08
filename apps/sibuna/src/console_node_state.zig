//! Storage owns the boot fence and one outstanding completion. No new effect starts while
//! its predecessor's receipt cannot be committed; retrying that id never repeats the effect.
const std = @import("std");
const p = @import("console").protocol;
pub const State = struct {
    boot: [16]u8 = @splat(0),
    started_ns: i96 = 0,
    revision: u64 = 0,
    pending: ?p.nodes.Receipt = null,

    pub fn init(io: std.Io) State {
        var state: State = .{ .started_ns = std.Io.Clock.awake.now(io).nanoseconds };
        while (std.mem.allEqual(u8, &state.boot, 0)) io.random(&state.boot);
        return state;
    }
};
