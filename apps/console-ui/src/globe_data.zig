//! Both globe modes borrow one accepted snapshot. Changing modes neither opens another
//! stream nor mixes sampled requests with locally persisted incident findings.
const p = @import("console_protocol");
const State = @import("state.zig").State;

pub const View = struct {
    countries: *const [32]p.CountryCount,
    unknown: u64,
    other: u64,
    unit: []const u8,
};

pub fn view(state: *const State) ?View {
    const stats = if (state.stats) |*snapshot| snapshot else return null;
    if (state.globe_attacks) {
        const incidents = if (stats.incident_geo) |*value| value else return null;
        if (incidents.version != 1) return null;
        return .{
            .countries = &incidents.countries,
            .unknown = incidents.unknown,
            .other = incidents.other,
            .unit = "findings",
        };
    }
    return .{
        .countries = &stats.countries,
        .unknown = stats.unknown_samples,
        .other = stats.other_country_samples,
        .unit = "samples",
    };
}

test "globe modes borrow independent observations and reject absent or future incident formats" {
    const std = @import("std");
    const t = std.testing;
    var state: State = .{};
    try t.expect(view(&state) == null);
    state.stats = std.mem.zeroes(p.StatsSnapshot);
    state.stats.?.countries[0] = .{ .code = 0x5553, .samples = 9 };
    try t.expectEqual(@as(u64, 9), view(&state).?.countries[0].samples);
    state.globe_attacks = true;
    try t.expect(view(&state) == null);
    state.stats.?.incident_geo = .{ .unknown = 3 };
    state.stats.?.incident_geo.?.countries[0] = .{ .code = 0x494e, .samples = 2 };
    try t.expectEqual(@as(u64, 2), view(&state).?.countries[0].samples);
    try t.expectEqual(@as(u64, 3), view(&state).?.unknown);
    state.stats.?.incident_geo.?.version = 2;
    try t.expect(view(&state) == null);
    state.reset();
    try t.expect(!state.globe_attacks);
}
