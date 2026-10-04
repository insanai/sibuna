const std = @import("std");
const controls = @import("controls.zig");
const work = @import("work.zig");

test "transaction exclusions retain exact tags keys inclusive IDs and collection scope" {
    var entries: [8]controls.Exclusion = undefined;
    var state: controls.State = .{ .exclusions = &entries };
    var budget: work.Budget = .{ .remaining = 10000 };
    const sources = [_][]const u8{
        "ruleRemoveById=10-12 20",
        "ruleRemoveByTag=OWASP_CRS",
        "ruleRemoveTargetByTag=attack-sqli;ARGS:password",
        "ruleRemoveTargetById=30;REQUEST_FILENAME",
    };
    var programs: [sources.len]controls.Program = undefined;
    var initialized: usize = 0;
    defer for (programs[0..initialized]) |*program| program.deinit();
    for (sources, &programs) |source, *program| {
        program.* = try controls.compile(std.testing.allocator, source);
        initialized += 1;
        try state.apply(program, &budget);
    }
    for ([_]u32{ 10, 11, 12, 20 }) |id|
        try std.testing.expect(try state.excludes(id, &.{}, null, &budget));
    for ([_]u32{ 9, 13, 19, 21 }) |id|
        try std.testing.expect(!try state.excludes(id, &.{}, null, &budget));
    try std.testing.expect(try state.excludes(100, &.{"OWASP_CRS"}, null, &budget));
    try std.testing.expect(!try state.excludes(100, &.{"owasp_crs"}, null, &budget));
    const password: controls.Target = .{ .collection = .args, .key = "password" };
    try std.testing.expect(try state.excludes(100, &.{"attack-sqli"}, password, &budget));
    try std.testing.expect(!try state.excludes(100, &.{"attack-sqli"}, null, &budget));
    try std.testing.expect(!try state.excludes(100, &.{"attack-sqli"}, .{
        .collection = .args,
        .key = "Password",
    }, &budget));
    try std.testing.expect(!try state.excludes(100, &.{"attack-sqli"}, .{
        .collection = .request_cookies,
        .key = "password",
    }, &budget));
    try std.testing.expect(try state.excludes(30, &.{}, .{
        .collection = .request_filename,
        .key = null,
    }, &budget));
    try std.testing.expect(!try state.excludes(30, &.{}, .{
        .collection = .request_uri,
        .key = null,
    }, &budget));
}

test "control application is atomic on capacity and permanently fails on exhausted work" {
    var program = try controls.compile(std.testing.allocator, "ruleRemoveById=1 2");
    defer program.deinit();
    var entries: [1]controls.Exclusion = undefined;
    var state: controls.State = .{ .exclusions = &entries };
    var budget: work.Budget = .{ .remaining = 100 };
    try std.testing.expectError(error.ExclusionLimit, state.apply(&program, &budget));
    try std.testing.expectEqual(@as(usize, 0), state.used);
    try std.testing.expectEqual(@as(u64, 100), budget.remaining);
    try std.testing.expectError(error.TransactionFailed, state.excludes(1, &.{}, null, &budget));
    var processor = try controls.compile(std.testing.allocator, "requestBodyProcessor=JSON");
    defer processor.deinit();
    state = .{ .exclusions = &entries };
    budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, state.apply(&processor, &budget));
    try std.testing.expectEqual(controls.Processor.automatic, state.processor);
    budget.remaining = 100;
    try std.testing.expectError(error.TransactionFailed, state.apply(&processor, &budget));
}

test "body and audit controls remain independently ordered" {
    var state: controls.State = .{ .exclusions = &.{} };
    var budget: work.Budget = .{ .remaining = 100 };
    for ([_][]const u8{
        "requestBodyProcessor=XML",
        "requestBodyProcessor=URLENCODED",
        "forceRequestBodyVariable=On",
        "forceRequestBodyVariable=Off",
        "auditEngine=Off",
        "auditEngine=RelevantOnly",
    }) |source| {
        var program = try controls.compile(std.testing.allocator, source);
        defer program.deinit();
        try state.apply(&program, &budget);
    }
    try std.testing.expectEqual(controls.Processor.urlencoded, state.processor);
    try std.testing.expect(!state.force_body);
    try std.testing.expectEqual(controls.Audit.relevant_only, state.audit);
    try std.testing.expect(!try state.excludes(1, &.{}, null, &budget));
}

test "invalid unsupported and ambiguous controls reject the entire program" {
    for ([_][]const u8{
        "ruleRemoveById=0",
        "ruleRemoveById=2147483648",
        "ruleRemoveById=2-1",
        "ruleRemoveById=1,2",
        "ruleRemoveById=+1",
        "ruleRemoveById=1x",
        "ruleRemoveById= ",
        "ruleRemoveTargetById=1-2;ARGS:a",
        "ruleRemoveTargetByTag=;ARGS:a",
        "ruleRemoveTargetByTag=tag;ARGS:",
        "ruleRemoveTargetByTag=tag;REQUEST_URI:key",
        "ruleRemoveTargetByTag=tag;ARGS:a;extra",
        "auditEngine=Other",
        "requestBodyProcessor=YAML",
        "forceRequestBodyVariable=Yes",
        "ruleRemoveByTag=",
        "ruleRemoveByTag=secret\x00",
        "auditEngine",
    }) |source| try std.testing.expectError(
        error.InvalidControl,
        controls.compile(std.testing.allocator, source),
    );
    try std.testing.expectError(
        error.UnsupportedControl,
        controls.compile(std.testing.allocator, "ruleEngine=Off"),
    );
}
