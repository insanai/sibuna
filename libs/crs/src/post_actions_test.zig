const std = @import("std");
const compiler = @import("compiler.zig");
const model = @import("model.zig");
const post = @import("post_actions.zig");
const support = @import("action_test_support.zig");

fn prepare(source: []const u8) !post.Program {
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    try builder.addSource("test.conf", source);
    var plan = try builder.finish();
    defer plan.deinit();
    return post.compile(std.testing.allocator, &plan.conditions[0]);
}

fn prepareLocal(actions: []const model.Action) !post.Program {
    const source: model.Condition = .{
        .site = .{ .path = "test.conf", .line = 1 },
        .id = 1,
        .root = 0,
        .phase = .request_body,
        .selectors = "",
        .targets = &.{},
        .expression = null,
        .actions = actions,
        .inherited_actions = &.{},
    };
    return post.compile(std.testing.allocator, &source);
}

test "post actions run defaults metadata and runtime controls without repeating local writes" {
    var program = try prepare(
        \\SecDefaultAction "phase:2,pass,log,status:409,setvar:tx.order=+1"
        \\SecAction "id:1,msg:'order %{TX.order}',setvar:tx.order=9,tag:'%{TX.order}',\
        \\ severity:ERROR,initcol:ip=%{TX.order},ctl:requestBodyProcessor=JSON,\
        \\ block,nolog,auditlog,noauditlog"
    );
    defer program.deinit();
    var slot: support.Slot = .{};
    try slot.init(true);
    // The condition evaluator has already performed the local assignment.
    try slot.evaluation.store.put("order", "9", &slot.evaluation.budget);
    try post.execute(&program, slot.frame());
    try std.testing.expectEqualStrings("10", (try slot.evaluation.get("order")).?);
    const event = slot.events[0];
    try std.testing.expectEqualStrings("order 10", event.message);
    try std.testing.expectEqualStrings("10", event.tags[0]);
    try std.testing.expectEqualStrings("10", slot.state.bindings[0].?);
    try std.testing.expectEqual(@as(u3, 3), event.severity);
    try std.testing.expectEqual(@as(u8, 3), slot.state.highest_severity);
    try std.testing.expectEqual(@as(u16, 409), slot.state.status);
    try std.testing.expectEqual(
        @import("controls.zig").Processor.json,
        slot.state.control.processor,
    );
    try std.testing.expect(event.no_audit and !event.save);
    try std.testing.expect(!slot.state.denied and !event.would_deny);
    @memset(&slot.evaluation.value_output, '!');
    try std.testing.expectEqualStrings("order 10", event.message);
}

test "block resolves through the phase default and pass cannot clear earlier denial" {
    var blocking = try prepare(
        \\SecDefaultAction "phase:2,deny,status:418"
        \\SecAction "id:1,block,msg:'blocked'"
    );
    defer blocking.deinit();
    var passing = try prepare(
        \\SecAction "id:2,pass,nolog"
    );
    defer passing.deinit();
    for ([_]bool{ true, false }) |enforce| {
        var slot: support.Slot = .{};
        try slot.init(enforce);
        try post.execute(&blocking, slot.frame());
        try post.execute(&passing, slot.frame());
        try std.testing.expectEqual(enforce, slot.state.denied);
        try std.testing.expect(slot.state.would_deny and slot.events[0].would_deny);
        try std.testing.expect(!slot.events[1].would_deny);
        try std.testing.expectEqual(@as(u16, 418), slot.state.status);
    }
    var explicit = try prepare(
        \\SecDefaultAction "phase:2,pass"
        \\SecAction "id:3,deny"
    );
    defer explicit.deinit();
    var slot: support.Slot = .{};
    try slot.init(true);
    try post.execute(&explicit, slot.frame());
    try std.testing.expect(slot.state.denied);
    try std.testing.expectEqual(@as(u16, 403), slot.state.status);
}

test "only the last metadata action is expanded before ordered local runtime actions" {
    var program = try prepareLocal(&.{
        .{ .kind = .message, .value = "old" },
        .{ .kind = .message, .value = "new" },
        .{ .kind = .log_data, .value = "old" },
        .{ .kind = .log_data, .value = "new" },
        .{ .kind = .severity, .value = "DEBUG" },
        .{ .kind = .severity, .value = "CRITICAL" },
        .{ .kind = .control, .value = "ruleRemoveById=20-22" },
        .{ .kind = .audit_log, .value = null },
        .{ .kind = .no_log, .value = null },
    });
    defer program.deinit();
    var slot: support.Slot = .{};
    try slot.init(true);
    try post.execute(&program, slot.frame());
    try std.testing.expectEqualStrings("new", slot.events[0].message);
    try std.testing.expectEqualStrings("new", slot.events[0].data);
    try std.testing.expectEqual(@as(u3, 2), slot.events[0].severity);
    try std.testing.expect(!slot.events[0].save and !slot.events[0].no_audit);
    const excluded = try slot.state.control.excludes(21, &.{}, null, &slot.evaluation.budget);
    try std.testing.expect(excluded);
}

test "failed evidence cannot publish a completed event or resume with refilled capacity" {
    var program = try prepare(
        \\SecAction "id:1,msg:long,deny"
    );
    defer program.deinit();
    for (0..3) |scenario| {
        var slot: support.Slot = .{};
        try slot.init(true);
        if (scenario == 0) {
            slot.state.events = &.{};
            try std.testing.expectError(error.EventLimit, post.execute(&program, slot.frame()));
        } else if (scenario == 1) {
            slot.state.bytes = &.{};
            try std.testing.expectError(error.ByteLimit, post.execute(&program, slot.frame()));
        } else {
            slot.evaluation.budget.remaining = 0;
            try std.testing.expectError(error.WorkLimit, post.execute(&program, slot.frame()));
        }
        try std.testing.expectEqual(@as(usize, 0), slot.state.event_used);
        try std.testing.expect(slot.state.failed and slot.evaluation.context.failed);
        slot.evaluation.budget.remaining = 10000;
        try std.testing.expectError(error.TransactionFailed, post.execute(&program, slot.frame()));
    }
}

test "invalid status severity and external mutation namespaces reject preparation" {
    for ([_]model.Action{
        .{ .kind = .status, .value = "99" },
        .{ .kind = .status, .value = "600" },
        .{ .kind = .status, .value = "403suffix" },
        .{ .kind = .severity, .value = "8" },
        .{ .kind = .severity, .value = "unknown" },
        .{ .kind = .init_collection, .value = "unknown=key" },
    }) |action| {
        try std.testing.expectError(error.InvalidAction, prepareLocal(&.{action}));
    }
}

test "fully matched chains unwind once sharing leaf tags and root message metadata" {
    const condition = @import("condition.zig");
    const chains = @import("chains.zig");
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    try builder.addSource("test.conf",
        \\SecDefaultAction "phase:2,pass,setvar:tx.order=+1"
        \\SecRule TX:order "@eq 0" "id:1,chain,setvar:tx.order=9,\
        \\ tag:'root %{TX.order}',msg:'root %{TX.order}'"
        \\SecRule TX:order "@eq 9" "setvar:tx.order=11,\
        \\ tag:'leaf %{TX.order}',msg:'leaf %{TX.order}'"
    );
    var plan = try builder.finish();
    defer plan.deinit();
    var topology = try chains.compile(std.testing.allocator, plan.conditions, .{});
    defer topology.deinit();
    var candidates: [2]condition.Program = undefined;
    var programs: [2]post.Program = undefined;
    var initialized: usize = 0;
    defer for (0..initialized) |index| {
        candidates[index].deinit();
        programs[index].deinit();
    };
    for (plan.conditions, 0..) |*source, index| {
        candidates[index] = try condition.compile(std.testing.allocator, source, &.{}, .{});
        errdefer candidates[index].deinit();
        programs[index] = try post.compile(std.testing.allocator, source);
        initialized += 1;
    }
    var slot: support.Slot = .{};
    try slot.init(true);
    try slot.evaluation.store.put("order", "0", &slot.evaluation.budget);
    var indices: [2]usize = undefined;
    const result = try topology.evaluate(&candidates, 0, slot.evaluation.frame(), &indices);
    try std.testing.expect(result.matched);
    try post.executeChain(&programs, result.unwind, slot.frame());
    try std.testing.expectEqual(@as(usize, 1), slot.state.event_used);
    try std.testing.expectEqualStrings("leaf 12", slot.events[0].tags[0]);
    try std.testing.expectEqualStrings("root 13", slot.events[0].tags[1]);
    try std.testing.expectEqualStrings("root 13", slot.events[0].message);
    try std.testing.expectEqualStrings("13", (try slot.evaluation.get("order")).?);
}

test "malformed unwind is refused before any post-match effects" {
    var program = try prepare(
        \\SecAction "id:1,deny"
    );
    defer program.deinit();
    for ([_][]const usize{ &.{}, &.{1}, &.{ 0, 0 } }) |indices| {
        var slot: support.Slot = .{};
        try slot.init(true);
        try std.testing.expectError(
            error.InvalidUnwind,
            post.executeChain(&.{program}, indices, slot.frame()),
        );
        try std.testing.expectEqual(@as(usize, 0), slot.state.event_used);
        try std.testing.expect(!slot.state.denied);
        try std.testing.expect(slot.state.failed and slot.evaluation.context.failed);
    }
}
