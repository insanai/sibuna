const std = @import("std");
const t = std.testing;
const scenarios = @import("scenario.zig");
const contract = @import("crs-protocol").tests;
const prepare = @import("rule_program_test.zig").prepare;
const limits: @import("transaction_slot.zig").Limits = .{
    .entries = 128,
    .bytes = 8192,
    .request = 1024,
    .response = 512,
    .events = 128,
    .tags = 256,
    .pieces = 32,
    .work = 1_000_000,
    .reservation = 2 * 1024 * 1024,
};

test "private enforcing tests stop before an unread malformed body" {
    var program = try prepare(
        "SecRule REQUEST_URI \"@streq /deny\" \"id:1,phase:1,deny,status:418,msg:'denied'\"",
        &.{},
    );
    defer program.deinit();
    var report: contract.Report = undefined;
    try scenarios.evaluate(.{
        .allocator = t.allocator,
        .program = &program,
        .limits = limits,
        .execution = .{ .activation = .{ .mode = .enforce } },
        .sample = .{ .request = .{
            .target = "/deny",
            .entity = .{ .body = "invalid compressed bytes" },
            .headers = &.{.{ .name = "Content-Encoding", .value = "gzip" }},
        } },
    }, &report);
    try t.expect(report.failure == null and report.denied and report.would_deny);
    try t.expectEqual(@as(?u16, 418), report.selected_status);
    try t.expectEqual(contract.Coverage.local_response, report.coverage);
    try t.expectEqual(@as(u32, 1), report.events[0].?.rule_id);
}

test "private audit tests retain full phase scores without enforcing findings" {
    var program = try prepare(
        \\SecAction "id:10,phase:1,setvar:tx.blocking_inbound_anomaly_score=0,\
        \\ setvar:tx.blocking_outbound_anomaly_score=0"
        \\SecRule ARGS:q "@streq attack" \
        \\ "id:1,phase:2,deny,msg:'request',setvar:tx.blocking_inbound_anomaly_score=+5"
        \\SecRule RESPONSE_BODY "@contains attack" \
        \\ "id:2,phase:4,deny,msg:'response',setvar:tx.blocking_outbound_anomaly_score=+4"
    , &.{});
    defer program.deinit();
    var report: contract.Report = undefined;
    try scenarios.evaluate(.{
        .allocator = t.allocator,
        .program = &program,
        .limits = limits,
        .execution = .{ .activation = .{ .mode = .audit } },
        .sample = .{
            .request = .{ .target = "/?q=attack" },
            .response = .{ .entity = .{ .body = "attack response" } },
        },
    }, &report);
    try t.expect(report.failure == null and !report.denied and report.would_deny);
    try t.expectEqual(contract.Coverage.inspected, report.coverage);
    try t.expectEqual(@as(?i32, 5), report.inbound_score);
    try t.expectEqual(@as(?i32, 4), report.outbound_score);
    try t.expectEqual(@as(usize, 2), report.event_count);
    try t.expectEqual(@as(u8, 2), report.events[0].?.phase);
    try t.expectEqual(@as(u8, 4), report.events[1].?.phase);
}

test "private headers and disabled tests cannot fabricate body inspection" {
    var program = try prepare(
        "SecRule REQUEST_BODY \"@contains attack\" \"id:1,phase:2,deny\"",
        &.{},
    );
    defer program.deinit();
    var report: contract.Report = undefined;
    var input: scenarios.Input = .{
        .allocator = t.allocator,
        .program = &program,
        .limits = limits,
        .execution = .{ .activation = .{ .mode = .enforce, .profile = .headers } },
        .sample = .{ .request = .{ .target = "/", .entity = .{ .body = "attack" } } },
    };
    try scenarios.evaluate(input, &report);
    try t.expectEqual(contract.Coverage.headers_profile, report.coverage);
    try t.expect(!report.denied and report.event_count == 0);
    input.execution.activation.mode = .off;
    input.allocator = t.failing_allocator;
    try scenarios.evaluate(input, &report);
    try t.expectEqual(contract.Coverage.disabled, report.coverage);
    try t.expectEqual(@as(u32, 0), report.work_used);
}

test "private tests share content decoding and retain binary sample ownership" {
    var program = try prepare("SecRule ARGS:q \"@streq attack\" \"id:1,phase:2,deny\"", &.{});
    defer program.deinit();
    var report: contract.Report = undefined;
    try scenarios.evaluate(.{
        .allocator = t.allocator,
        .program = &program,
        .limits = limits,
        .execution = .{ .activation = .{ .mode = .enforce } },
        .sample = .{ .request = .{
            .method = "POST",
            .target = "/upload",
            .headers = &.{
                .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
                .{ .name = "Content-Encoding", .value = "gzip" },
            },
            .entity = .{
                .body_hex = "1f8b08000000000002ff2bb44d2c29494cce06006d066e3a08000000",
            },
        } },
    }, &report);
    try t.expect(report.failure == null and report.denied);
    try t.expectEqual(contract.Coverage.local_response, report.coverage);
}

test "private malformed entities and budget failures report incomplete evaluation" {
    var program = try prepare("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=JSON\"", &.{});
    defer program.deinit();
    var report: contract.Report = undefined;
    var input: scenarios.Input = .{
        .allocator = t.allocator,
        .program = &program,
        .limits = limits,
        .execution = .{ .activation = .{ .mode = .audit } },
        .sample = .{ .request = .{ .target = "/", .entity = .{ .body = "{" } } },
    };
    try scenarios.evaluate(input, &report);
    try t.expect(report.failure != null and report.coverage == .incomplete);
    try t.expectEqual(@as(u8, 2), report.attempted_phase);
    try t.expect(report.inbound_score == null and report.outbound_score == null);
    input.limits.work = 1;
    try scenarios.evaluate(input, &report);
    try t.expectEqualStrings("WorkLimit", report.failure.?.slice());
    try t.expectEqual(contract.Coverage.incomplete, report.coverage);
}

test "private report bounds events and omits expanded secrets after slot teardown" {
    var source: std.Io.Writer.Allocating = .init(t.allocator);
    defer source.deinit();
    for (1..71) |id| try source.writer.print(
        "SecRule ARGS:token \"@contains secret\" \"id:{d},phase:1,msg:'%{{ARGS.token}}'\"\n",
        .{id},
    );
    var report: contract.Report = undefined;
    {
        var program = try prepare(source.written(), &.{});
        defer program.deinit();
        try scenarios.evaluate(.{
            .allocator = t.allocator,
            .program = &program,
            .limits = limits,
            .execution = .{ .activation = .{ .mode = .audit } },
            .sample = .{ .request = .{ .target = "/?token=secret-value" } },
        }, &report);
    }
    try t.expect(report.failure == null);
    try t.expectEqual(contract.event_capacity, report.event_count);
    try t.expectEqual(@as(usize, 6), report.omitted_events);
    const json = try std.json.Stringify.valueAlloc(t.allocator, report, .{});
    defer t.allocator.free(json);
    try t.expect(std.mem.indexOf(u8, json, "secret-value") == null);
    try t.expect(std.mem.indexOf(u8, json, "ARGS.token") == null);
}

test "private handshake and stream exclusions still enforce response-header denials" {
    var program = try prepare(
        "SecRule RESPONSE_HEADERS:X-Test \"@streq block\" " ++
            "\"id:1,phase:3,deny,msg:'header denied'\"",
        &.{},
    );
    defer program.deinit();
    const samples = [_]contract.Response{
        .{ .status = 101, .ending = .handshake }, .{ .ending = .streaming },
    };
    for (samples) |response| {
        var report: contract.Report = undefined;
        var input: scenarios.Input = .{
            .allocator = t.allocator,
            .program = &program,
            .limits = limits,
            .execution = .{ .activation = .{ .mode = .enforce } },
            .sample = .{ .request = .{ .target = "/" }, .response = response },
        };
        input.sample.response.?.headers = &.{.{ .name = "X-Test", .value = "block" }};
        try scenarios.evaluate(input, &report);
        try t.expect(report.failure == null and report.denied);
        try t.expectEqual(contract.Coverage.local_response, report.coverage);
        try t.expectEqual(@as(u8, 3), report.events[0].?.phase);
        input.execution.activation.mode = .audit;
        try scenarios.evaluate(input, &report);
        try t.expect(report.failure == null and !report.denied and report.would_deny);
        const coverage: contract.Coverage = if (response.ending == .handshake)
            .handshake_only
        else
            .streaming_excluded;
        try t.expectEqual(coverage, report.coverage);
    }
}

test "private request-only tests label absent responses without inventing an origin failure" {
    var program = try prepare("SecAction \"id:1,phase:1,nolog,pass\"", &.{});
    defer program.deinit();
    var report: contract.Report = undefined;
    try scenarios.evaluate(.{
        .allocator = t.allocator,
        .program = &program,
        .limits = limits,
        .execution = .{ .activation = .{ .mode = .enforce } },
        .sample = .{ .request = .{ .target = "/" } },
    }, &report);
    try t.expect(report.failure == null and !report.denied);
    try t.expectEqual(contract.Coverage.response_not_supplied, report.coverage);
    try t.expect(report.selected_status == null);
}

test "unlogged setup matches cannot crowd out a private terminal finding" {
    var source: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&source);
    for (1..101) |id| try writer.print(
        "SecAction \"id:{d},phase:1,nolog,pass,msg:'setup'\"\n",
        .{id},
    );
    try writer.writeAll("SecRule ARGS:q \"@streq attack\" " ++
        "\"id:1000,phase:2,nolog,deny,msg:'terminal'\"\n");
    var program = try prepare(writer.buffered(), &.{});
    defer program.deinit();
    var report: contract.Report = undefined;
    try scenarios.evaluate(.{
        .allocator = t.allocator,
        .program = &program,
        .limits = limits,
        .execution = .{ .activation = .{ .mode = .enforce } },
        .sample = .{ .request = .{ .target = "/?q=attack" } },
    }, &report);
    try report.validate();
    try t.expect(report.denied);
    try t.expectEqual(@as(usize, 100), report.unlogged_matches);
    try t.expectEqual(@as(usize, 0), report.omitted_events);
    try t.expectEqual(@as(usize, 1), report.event_count);
    try t.expectEqual(@as(u32, 1000), report.events[0].?.rule_id);
    try t.expect(!report.events[0].?.saved);
}
