const std = @import("std");
const compiler = @import("compiler.zig");
const chains = @import("chains.zig");
const cursor = @import("phase_cursor.zig");
const model = @import("model.zig");
const work = @import("work.zig");

fn prepare(text: []const u8) !chains.Program {
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    try builder.addSource("test.conf", text);
    var plan = try builder.finish();
    defer plan.deinit();
    return chains.compile(std.testing.allocator, plan.conditions, .{});
}

const source =
    \\SecRule ARGS "@eq 1" "id:1,phase:2,chain,skipAfter:end"
    \\SecRule ARGS "@eq 2" "chain"
    \\SecRule ARGS "@eq 3" "t:none"
    \\SecAction "id:2,phase:1"
    \\SecAction "id:3,phase:2"
    \\SecMarker end
    \\SecAction "id:4,phase:2"
    \\SecAction "id:5,phase:5"
;

test "phase scans retain source order skip continuations and reset for the next phase" {
    var program = try prepare(source);
    defer program.deinit();
    var state = cursor.Cursor.init(&program);
    var budget: work.Budget = .{ .remaining = 100 };
    try state.begin(.request_headers);
    try std.testing.expectEqual(@as(?usize, 3), try state.next(&budget));
    try state.complete(true);
    try std.testing.expect(try state.next(&budget) == null);
    try state.begin(.request_body);
    try std.testing.expectEqual(@as(?usize, 0), try state.next(&budget));
    try state.complete(false);
    try std.testing.expectEqual(@as(?usize, 4), try state.next(&budget));
    try state.complete(true);
    try std.testing.expectEqual(@as(?usize, 5), try state.next(&budget));
    try state.complete(true);
    try std.testing.expect(try state.next(&budget) == null);
    try state.begin(.logging);
    try std.testing.expectEqual(@as(?usize, 6), try state.next(&budget));
    try state.complete(true);
    try std.testing.expect(try state.next(&budget) == null);
    try std.testing.expectEqual(@as(u3, 5), state.completed);
}

test "only a fully matched root activates forward skipAfter including a terminal marker" {
    var program = try prepare(source);
    defer program.deinit();
    var state = cursor.Cursor.init(&program);
    var budget: work.Budget = .{ .remaining = 100 };
    try state.begin(.request_body);
    try std.testing.expectEqual(@as(?usize, 0), try state.next(&budget));
    try state.complete(true);
    try std.testing.expectEqual(@as(?usize, 5), try state.next(&budget));
    try state.complete(true);
    try std.testing.expect(try state.next(&budget) == null);
    var terminal = try prepare(
        \\SecAction "id:1,phase:1,skipAfter:last"
        \\SecAction "id:2,phase:1"
        \\SecMarker last
    );
    defer terminal.deinit();
    state = cursor.Cursor.init(&terminal);
    try state.begin(.request_headers);
    try std.testing.expectEqual(@as(?usize, 0), try state.next(&budget));
    try state.complete(true);
    try std.testing.expect(try state.next(&budget) == null);
}

test "pending roots unfinished phases and backwards phases cannot resume after misuse" {
    var program = try prepare(source);
    defer program.deinit();
    for (0..5) |scenario| {
        var state = cursor.Cursor.init(&program);
        var budget: work.Budget = .{ .remaining = 100 };
        if (scenario == 0) {
            try std.testing.expectError(error.NoActivePhase, state.next(&budget));
        } else if (scenario == 1) {
            try std.testing.expectError(error.NoPendingRoot, state.complete(true));
        } else if (scenario == 2) {
            try state.begin(.request_headers);
            try std.testing.expectError(error.UnfinishedPhase, state.begin(.request_body));
        } else if (scenario == 3) {
            try state.begin(.request_headers);
            _ = try state.next(&budget);
            try std.testing.expectError(error.PendingRoot, state.next(&budget));
        } else {
            try state.begin(.response_body);
            try std.testing.expect(try state.next(&budget) == null);
            try std.testing.expectError(error.InvalidPhaseOrder, state.begin(.response_headers));
        }
        try std.testing.expect(state.failed);
        try std.testing.expectError(error.InvalidCursor, state.next(&budget));
        try std.testing.expectError(error.InvalidCursor, state.begin(.logging));
    }
}

test "exhausted scan budget remains an error instead of falsely completing a phase" {
    var program = try prepare(source);
    defer program.deinit();
    for (0..5) |allowance| {
        var state = cursor.Cursor.init(&program);
        var budget: work.Budget = .{ .remaining = allowance };
        try state.begin(.response_body);
        try std.testing.expectError(error.WorkLimit, state.next(&budget));
        try std.testing.expectEqual(@as(u3, 0), state.completed);
        try std.testing.expect(state.phase == .response_body);
        budget.remaining = 100;
        try std.testing.expectError(error.InvalidCursor, state.next(&budget));
    }
}

test "empty topology and explicit skipped phases complete without fabricated roots" {
    var program = try prepare("");
    defer program.deinit();
    var state = cursor.Cursor.init(&program);
    var budget: work.Budget = .{ .remaining = 0 };
    for ([_]model.Phase{ .request_headers, .logging }) |phase| {
        try state.begin(phase);
        try std.testing.expect(try state.next(&budget) == null);
    }
    try std.testing.expectError(error.InvalidPhaseOrder, state.begin(.logging));
}
