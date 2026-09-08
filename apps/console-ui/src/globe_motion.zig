const std = @import("std");
const State = @import("state.zig").State;
pub const Motion = struct {
    rotating: bool = true,
    reduced: bool = false,
    last_ms: f64 = 0,
    flow: f64 = 0,
};
pub var output: [512 * 1024]u8 = undefined;

pub fn action(state: *State, name: []const u8) bool {
    if (std.mem.eql(u8, name, "globe-motion")) {
        state.motion.rotating = !state.motion.rotating;
        state.motion.last_ms = 0;
    } else if (std.mem.eql(u8, name, "rotate-left")) {
        state.motion.rotating = false;
        state.globe.lon -= 20;
    } else if (std.mem.eql(u8, name, "rotate-right")) {
        state.motion.rotating = false;
        state.globe.lon += 20;
    } else if (std.mem.eql(u8, name, "reset-globe")) {
        state.globe = .{};
        state.motion.rotating = true;
    } else if (std.mem.eql(u8, name, "flat-map")) {
        state.globe.flat = !state.globe.flat;
    } else if (std.mem.startsWith(u8, name, "country-")) {
        state.motion.rotating = false;
        const code = std.fmt.parseInt(u16, name[8..], 10) catch return false;
        if (state.geometry) |bytes| {
            if (@import("geography.zig").center(bytes, code)) |position|
                state.globe = .{ .lon = position.lon, .lat = position.lat };
        }
    } else return false;
    if (state.globe.lon > 180) state.globe.lon -= 360;
    if (state.globe.lon < -180) state.globe.lon += 360;
    return true;
}

pub fn advance(state: *State, milliseconds: f64) bool {
    const motion = &state.motion;
    if (!state.fullAccess() or state.phase != .dashboard or state.geometry == null or
        state.hidden or state.paused or state.stale or motion.reduced or !motion.rotating or
        !std.math.isFinite(milliseconds) or milliseconds < 0)
    {
        motion.last_ms = 0;
        return false;
    }
    const elapsed = if (motion.last_ms == 0) 0 else std.math.clamp(
        milliseconds - motion.last_ms,
        0,
        100,
    );
    motion.last_ms = milliseconds;
    if (!state.globe.flat) {
        state.globe.lon = @mod(state.globe.lon + elapsed * 0.004 + 180, 360) - 180;
    }
    motion.flow = @mod(motion.flow + elapsed / 2400, 1);
    return true;
}

pub fn frame(state: *State, milliseconds: f64) usize {
    if (!advance(state, milliseconds)) return 0;
    var writer: std.Io.Writer = .fixed(&output);
    @import("globe.zig").scene(state, &writer) catch return 0;
    return writer.buffered().len;
}

test "motion requires full authentication and respects pause and reduced motion" {
    const t = std.testing;
    var state: State = .{ .phase = .dashboard, .geometry = "present" };
    try t.expect(!advance(&state, 100));
    state.csrf = try @import("console_protocol").Bytes(64).init("test");
    try t.expect(advance(&state, 100));
    try t.expect(advance(&state, 200));
    try t.expectApproxEqAbs(@as(f64, 0.4), state.globe.lon, 0.0001);
    state.motion.reduced = true;
    try t.expect(!advance(&state, 300));
    state.motion.reduced = false;
    state.paused = true;
    try t.expect(!advance(&state, 400));
    state.paused = false;
    state.globe.lon = 179.9;
    try t.expect(advance(&state, 500));
    try t.expect(advance(&state, 100000));
    try t.expect(state.globe.lon >= -180 and state.globe.lon <= 180);
    try t.expect(!advance(&state, std.math.nan(f64)));
}
