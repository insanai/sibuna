//! Reviewed full-page output from the native renderer. The browser patches these same
//! trees; fixtures freeze time and contain no live credentials or collected evidence.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Phase = @import("state.zig").Phase;

test "reviewed native page and authentication-state HTML" {
    const update = try std.testing.environ.containsUnempty(
        std.testing.allocator,
        "SIBUNA_UPDATE_CONSOLE_GOLDENS",
    );
    try run(std.testing.io, std.testing.allocator, update);
}

fn run(io: std.Io, alloc: std.mem.Allocator, update: bool) !void {
    var state: State = .{};
    for (std.enums.values(Phase)) |phase| {
        configure(&state, phase);
        try check(io, alloc, @tagName(phase), &state, update);
    }
    const variants = .{
        "traffic-live",
        "traffic-stale",
        "traffic-comparison",
        "kiosk-traffic",
        "kiosk-security",
        "required-password",
        "required-totp",
    };
    inline for (variants, 0..) |name, i| {
        configure(&state, .dashboard);
        state.stats = std.mem.zeroes(p.StatsSnapshot);
        state.stats.?.node = 1;
        state.stats.?.timestamp = 172800;
        state.stats.?.requests = 12345;
        state.stats.?.admitted = 12345;
        state.stats.?.outcomes_version = 1;
        state.stats.?.proxy_mode = .reverse_proxy;
        state.points[0] = .{ .second = 172800, .outcome_rates = .{ .admitted = 3 } };
        variant(&state, i);
        try check(io, alloc, name, &state, update);
    }
}

fn configure(state: *State, phase: Phase) void {
    state.reset();
    state.phase = phase;
    state.browser_time = 172800;
    state.received_at = 172799;
    switch (phase) {
        .loading, .setup, .login, .password => {},
        else => {
            state.csrf.set("fixture-only-csrf") catch unreachable;
            state.role.set("admin") catch unreachable;
        },
    }
}

fn variant(state: *State, index: usize) void {
    switch (index) {
        1 => {
            state.stale = true;
            state.received_at = 172770;
        },
        2 => {
            state.comparison = .{ .open = true, .started = true };
            for (&state.comparison.windows, 0..) |*window, i| window.* = .{
                .node = 1,
                .from = if (i == 0) 2875 else 1435,
                .until = if (i == 0) 2879 else 1439,
                .rows = 5,
                .complete_rows = 5,
                .observed_ms = 300000,
                .finished = true,
                .counts = .{ .admitted = if (i == 0) 1200 else 1000 },
            };
        },
        3, 4 => {
            state.kiosk = true;
            state.kiosk_expires = 176400;
            if (index == 4) state.phase = .security_overview;
        },
        5 => {
            state.phase = .password;
            state.must_change = true;
        },
        6 => {
            state.phase = .security;
            state.totp_required = true;
        },
        else => {},
    }
}

fn check(
    io: std.Io,
    alloc: std.mem.Allocator,
    name: []const u8,
    state: *const State,
    update: bool,
) !void {
    var buffer: [512 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try @import("render.zig").render(state, &writer);
    var path_buffer: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "apps/console-ui/golden/{s}.html", .{name});
    if (update) return std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = writer.buffered(),
    });
    const expected = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(buffer.len));
    defer alloc.free(expected);
    if (!std.mem.eql(u8, expected, writer.buffered())) {
        std.log.err(
            "console golden changed: {s}; review `zig build console-golden -- --update`",
            .{path},
        );
        return error.GoldenMismatch;
    }
}
