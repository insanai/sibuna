const std = @import("std");
const prepare = @import("rule_program_test.zig").prepare;
const slots = @import("transaction_slot.zig");
const http = @import("http_acquisition.zig");
const entities = @import("entity_acquisition.zig");
const work = @import("work.zig");
const limits: slots.Limits = .{
    .entries = 96,
    .bytes = 4096,
    .request = 1024,
    .response = 512,
    .events = 16,
    .tags = 32,
    .pieces = 32,
    .work = 1_000_000,
    .reservation = 1024 * 1024,
};

fn metadata(slot: *slots.Slot, content_type: []const u8) !void {
    const headers = [_]@import("text").http_fields.Header{.{
        .name = "Content-Type",
        .value = content_type,
    }};
    try http.request(.{
        .method = "POST",
        .target = "/submit?q=query",
        .protocol = "HTTP/1.1",
        .line = "POST /submit?q=query HTTP/1.1",
        .client = "192.0.2.1",
        .id = "transaction-1",
        .headers = &headers,
    }, &slot.input, slot.formScratch(), &slot.budget);
    try slot.acquire(try slot.input.view());
}

test "phase-one processor controls select complete JSON before phase-two evaluation" {
    var program = try prepare(
        \\SecRule REQUEST_HEADERS:Content-Type "@streq application/json" \
        \\ "id:1,phase:1,ctl:requestBodyProcessor=JSON,setvar:tx.score=1"
        \\SecRule ARGS:json.q "@contains SELECT" "id:2,phase:2,setvar:tx.score=+1"
        \\SecRule ARGS_GET:q "@streq query" "id:3,phase:2,setvar:tx.score=+1"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var state = try slot.begin(.{ .entries = &.{} }, true);
    defer slot.finish();
    try metadata(&slot, "application/json");
    _ = try state.run(.request_headers);
    const descriptor = try entities.Descriptor.parse(
        "application/json",
        slot.state.control.processor,
        &slot.budget,
    );
    try std.testing.expectEqual(entities.Kind.json, descriptor.kind);
    const entity = "{\"q\":\"SELECT\"}";
    try entities.request(&slot, entity, descriptor);
    try slot.acquire(try slot.input.view());
    _ = try state.run(.request_body);
    try std.testing.expectEqualStrings("3", (try slot.store.get("score", &slot.budget)).?);
    const view = try slot.input.view();
    try std.testing.expectEqualStrings(entity, try view.lookup(.{
        .collection = .request_body,
    }, &slot.budget));
    try view.require(.args_post);
    try view.require(.xml);
}

test "empty HTTP entities have complete empty collections for every body processor" {
    var program = try prepare("SecAction \"id:1,phase:2\"", &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    for ([_]entities.Kind{ .raw, .json, .xml, .urlencoded, .multipart }) |kind| {
        var state = try slot.begin(.{ .entries = &.{} }, true);
        try metadata(&slot, "application/octet-stream");
        _ = try state.run(.request_headers);
        try entities.request(&slot, "", .{ .kind = kind, .boundary = "B" });
        try slot.acquire(try slot.input.view());
        _ = try state.run(.request_body);
        const view = try slot.input.view();
        try std.testing.expectEqualStrings("", try view.lookup(.{
            .collection = .request_body,
        }, &slot.budget));
        for (view.entries) |entry| try std.testing.expect(entry.collection != .request_body);
        try std.testing.expectEqualStrings("0", try view.lookup(.{
            .collection = .files_combined_size,
        }, &slot.budget));
        slot.finish();
    }
}

test "malformed body acquisition poisons prior views" {
    var program = try prepare("SecAction \"id:1,phase:2\"", &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var state = try slot.begin(.{ .entries = &.{} }, true);
    defer slot.finish();
    try metadata(&slot, "application/json");
    _ = try state.run(.request_headers);
    try std.testing.expectError(
        error.InvalidJson,
        entities.request(&slot, "{not json}", .{ .kind = .json }),
    );
    try std.testing.expectError(error.AcquisitionFailed, slot.input.view());
    try std.testing.expectError(error.TransactionFailed, state.run(.request_body));
}

test "raw entities retain binary bytes and query fields without invented form fields" {
    var program = try prepare("SecAction \"id:1,phase:2\"", &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var state = try slot.begin(.{ .entries = &.{} }, true);
    defer slot.finish();
    try metadata(&slot, "application/octet-stream");
    _ = try state.run(.request_headers);
    const body = "a\x00b=q&other=value";
    try entities.request(&slot, body, .{ .kind = .raw });
    try slot.acquire(try slot.input.view());
    _ = try state.run(.request_body);
    const view = try slot.input.view();
    try std.testing.expectEqualStrings(body, try view.lookup(.{
        .collection = .request_body,
    }, &slot.budget));
    try std.testing.expectEqualStrings("17", try view.lookup(.{
        .collection = .request_body_length,
    }, &slot.budget));
    try std.testing.expectEqualStrings("query", try view.lookup(.{
        .collection = .args_get,
        .key = "q",
    }, &slot.budget));
    try std.testing.expectEqualStrings("", try view.lookup(.{
        .collection = .args_post,
    }, &slot.budget));
    try std.testing.expectError(
        error.InvalidEntityPhase,
        entities.request(&slot, body, .{ .kind = .raw }),
    );
    try std.testing.expectError(error.TransactionFailed, state.run(.response_headers));
}

test "entity limits refuse oversized bodies before publishing any raw occurrence" {
    var program = try prepare("SecAction \"id:1,phase:2\"", &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    _ = try slot.begin(.{ .entries = &.{} }, true);
    defer slot.finish();
    const oversized: [1025]u8 = @splat('x');
    try std.testing.expectError(
        error.RequestEntityLimit,
        entities.request(&slot, &oversized, .{ .kind = .raw }),
    );
    try std.testing.expectEqual(@as(usize, 0), slot.input.used);
    try std.testing.expect(slot.context.failed and slot.state.failed);
}

test "entity descriptor rejects ambiguous MIME and honours explicit processor overrides" {
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    const automatic = try entities.Descriptor.parse("application/json", .automatic, &budget);
    try std.testing.expectEqual(entities.Kind.raw, automatic.kind);
    const multipart = try entities.Descriptor.parse(
        "multipart/form-data; boundary=\"B\"",
        .automatic,
        &budget,
    );
    try std.testing.expectEqualStrings("B", multipart.boundary);
    const overridden = try entities.Descriptor.parse(
        "multipart/form-data; boundary=B",
        .json,
        &budget,
    );
    try std.testing.expectEqual(entities.Kind.json, overridden.kind);
    try std.testing.expectError(error.AmbiguousBodyParameter, entities.Descriptor.parse(
        "multipart/form-data; boundary=B; boundary=C",
        .automatic,
        &budget,
    ));
    try std.testing.expectError(error.MissingMultipartBoundary, entities.Descriptor.parse(
        "multipart/form-data",
        .automatic,
        &budget,
    ));
    try std.testing.expectError(error.UnsupportedBodyCharset, entities.Descriptor.parse(
        "application/json; charset=utf-16",
        .json,
        &budget,
    ));
    try std.testing.expectError(error.InvalidMime, entities.Descriptor.parse(
        "application/invalid/extra",
        .automatic,
        &budget,
    ));
}
