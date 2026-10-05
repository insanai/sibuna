const std = @import("std");
const prepare = @import("rule_program_test.zig").prepare;
const http = @import("http_acquisition.zig");
const transactions = @import("http_transaction.zig");
const slots = @import("transaction_slot.zig");
const Result = @import("executor.zig").Result;
const limits: slots.Limits = .{
    .entries = 128,
    .bytes = 8192,
    .request = 1024,
    .response = 512,
    .events = 16,
    .tags = 32,
    .pieces = 32,
    .work = 1_000_000,
    .reservation = 1024 * 1024,
};
const request: http.Request = .{
    .method = "POST",
    .target = "/submit?q=query",
    .protocol = "HTTP/1.1",
    .line = "POST /submit?q=query HTTP/1.1",
    .client = "192.0.2.1",
    .id = "transaction-1",
    .headers = &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }},
};

test "body processor controls immediately update phase-one selectors and macros" {
    var program = try prepare(
        \\SecAction "id:1,phase:1,ctl:requestBodyProcessor=JSON"
        \\SecRule REQBODY_PROCESSOR "@streq JSON" \
        \\ "id:2,phase:1,setvar:tx.seen=1,setvar:tx.first=%{REQBODY_PROCESSOR}"
        \\SecAction "id:3,phase:1,ctl:requestBodyProcessor=XML"
        \\SecRule REQBODY_PROCESSOR "@streq XML" "id:4,phase:1,setvar:tx.last=%{REQBODY_PROCESSOR}"
        \\SecRule XML://@* "@contains attack" "id:5,phase:2,deny"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var input = request;
    input.headers = &.{.{ .name = "Content-Type", .value = "application/xml" }};
    var transaction = try transactions.Transaction.begin(&slot, .full, true, input);
    defer slot.finish();
    try std.testing.expectEqualStrings("JSON", (try slot.store.get("first", &slot.budget)).?);
    try std.testing.expectEqualStrings("1", (try slot.store.get("seen", &slot.budget)).?);
    try std.testing.expectEqualStrings("XML", (try slot.store.get("last", &slot.budget)).?);
    const view = try slot.context.view(&slot.budget);
    try std.testing.expectEqualStrings("XML", try view.lookup(.{
        .collection = .reqbody_processor,
    }, &slot.budget));
    try std.testing.expectEqual(Result.denied, try transaction.requestBody(
        "<root value=\"attack\"/>",
    ));
    try transaction.finish(.local_response);
    slot.finish();
    var again = try transactions.Transaction.begin(&slot, .headers, true, input);
    try again.finish(.headers_profile);
}

test "immutable operator tuning is installed before CRS fallback initialization" {
    var program = try prepare(
        \\SecRule &TX:blocking_paranoia_level "@eq 0" \
        \\ "id:1,phase:1,setvar:tx.blocking_paranoia_level=1"
        \\SecRule TX:blocking_paranoia_level "@eq 2" "id:2,phase:1,deny"
        \\SecAction "id:3,phase:5,setvar:tx.logged=1"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var transaction = try transactions.Transaction.beginConfigured(&slot, .{
        .activation = .{ .mode = .audit, .blocking_paranoia = 2, .detection_paranoia = 3 },
        .thresholds = .{ .inbound = 7, .outbound = 9 },
    }, request);
    try std.testing.expect(!slot.state.denied);
    try std.testing.expect(slot.state.would_deny);
    const expected = .{
        .{ "blocking_paranoia_level", "2" },
        .{ "detection_paranoia_level", "3" },
        .{ "inbound_anomaly_score_threshold", "7" },
        .{ "outbound_anomaly_score_threshold", "9" },
    };
    inline for (expected) |entry| try std.testing.expectEqualStrings(
        entry[1],
        (try slot.store.get(entry[0], &slot.budget)).?,
    );
    try transaction.finish(.local_response);
    slot.finish();
    try std.testing.expectError(error.InvalidThreshold, transactions.Transaction.beginConfigured(
        &slot,
        .{ .activation = .{ .mode = .enforce }, .thresholds = .{ .inbound = 0 } },
        request,
    ));
    try std.testing.expect(!slot.active);
    var enforce = try transactions.Transaction.beginConfigured(&slot, .{
        .activation = .{ .mode = .enforce, .blocking_paranoia = 2, .detection_paranoia = 2 },
    }, request);
    defer slot.finish();
    try std.testing.expect(slot.state.denied);
    try enforce.finish(.local_response);
    try std.testing.expectEqualStrings("5", (try slot.store.get(
        "inbound_anomaly_score_threshold",
        &slot.budget,
    )).?);
}

test "HTTP transaction executes all five phases with one budget and retained scoring" {
    var program = try prepare(
        \\SecRule REQUEST_METHOD "@streq POST" "id:1,phase:1,setvar:tx.score=1"
        \\SecRule ARGS_POST:q "@streq body" "id:2,phase:2,setvar:tx.score=+1"
        \\SecRule RESPONSE_STATUS "@streq 200" "id:3,phase:3,setvar:tx.score=+1"
        \\SecRule RESPONSE_BODY "@contains response" "id:4,phase:4,setvar:tx.score=+1"
        \\SecRule TX:score "@eq 4" "id:5,phase:5,setvar:tx.complete=1"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var transaction = try transactions.Transaction.begin(&slot, .full, true, request);
    defer slot.finish();
    const remaining = slot.budget.remaining;
    try std.testing.expectEqual(Result.complete, try transaction.requestBody("q=body"));
    try std.testing.expectEqual(Result.complete, try transaction.responseHeaders(.{
        .status = 200,
        .headers = &.{
            .{ .name = "Set-Cookie", .value = "one=1" },
            .{ .name = "Set-Cookie", .value = "two=2" },
        },
    }));
    try std.testing.expectEqual(Result.complete, try transaction.responseBody("response"));
    try transaction.finish(.inspected);
    try std.testing.expectEqualStrings("1", (try slot.store.get("complete", &slot.budget)).?);
    try std.testing.expect(slot.budget.remaining < remaining);
    var cookies: usize = 0;
    for ((try slot.input.view()).entries) |entry| {
        if (entry.collection == .response_headers and std.mem.eql(u8, entry.key, "Set-Cookie"))
            cookies += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), cookies);
}

test "request denial still runs logging and never permits origin phases" {
    var program = try prepare(
        \\SecRule ARGS_POST:q "@streq attack" "id:1,phase:2,deny,status:406"
        \\SecAction "id:2,phase:5,setvar:tx.logged=1"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var transaction = try transactions.Transaction.begin(&slot, .full, true, request);
    defer slot.finish();
    try std.testing.expectEqual(Result.denied, try transaction.requestBody("q=attack"));
    try std.testing.expectEqual(@as(u16, 406), slot.state.status);
    try transaction.finish(.local_response);
    try std.testing.expectEqualStrings("1", (try slot.store.get("logged", &slot.budget)).?);
}

test "audit would-deny continues through response evaluation" {
    var program = try prepare(
        \\SecRule ARGS_POST:q "@streq attack" "id:1,phase:2,deny"
        \\SecRule RESPONSE_BODY "@contains leak" "id:2,phase:4,deny"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var transaction = try transactions.Transaction.begin(&slot, .full, false, request);
    defer slot.finish();
    try std.testing.expectEqual(Result.complete, try transaction.requestBody("q=attack"));
    _ = try transaction.responseHeaders(.{ .status = 200, .headers = &.{} });
    try std.testing.expectEqual(Result.complete, try transaction.responseBody("leak"));
    try transaction.finish(.inspected);
    try std.testing.expect(slot.state.would_deny and !slot.state.denied);
    try std.testing.expectEqual(@as(usize, 2), slot.state.event_used);
}

test "headers and streaming completions retain explicit unavailable body coverage" {
    var program = try prepare("SecAction \"id:1,phase:5\"", &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var headers = try transactions.Transaction.begin(&slot, .headers, true, request);
    try headers.finish(.headers_profile);
    try std.testing.expectError(
        error.UnavailableCollection,
        (try slot.input.view()).require(.request_body),
    );
    slot.finish();
    var streaming = try transactions.Transaction.begin(&slot, .full, true, request);
    defer slot.finish();
    _ = try streaming.requestBody("");
    _ = try streaming.responseHeaders(.{ .status = 200, .headers = &.{} });
    try streaming.finish(.streaming_excluded);
    try std.testing.expectError(
        error.UnavailableCollection,
        (try slot.input.view()).require(.response_body),
    );
    try std.testing.expectEqual(transactions.End.streaming_excluded, streaming.end.?);
}

test "incomplete phases, repeated endings and response limits poison a transaction" {
    var program = try prepare("SecAction \"id:1,phase:5\"", &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var early = try transactions.Transaction.begin(&slot, .full, true, request);
    try std.testing.expectError(error.InvalidHttpPhase, early.finish(.inspected));
    try std.testing.expect(slot.state.failed and slot.context.failed and slot.input.failed);
    slot.finish();
    var repeated = try transactions.Transaction.begin(&slot, .headers, true, request);
    try repeated.finish(.headers_profile);
    try std.testing.expectError(error.InvalidHttpPhase, repeated.finish(.headers_profile));
    slot.finish();
    var oversized = try transactions.Transaction.begin(&slot, .full, true, request);
    defer slot.finish();
    _ = try oversized.requestBody("");
    _ = try oversized.responseHeaders(.{ .status = 200, .headers = &.{} });
    const body: [513]u8 = @splat('x');
    try std.testing.expectError(error.ResponseEntityLimit, oversized.responseBody(&body));
    try std.testing.expectError(error.TransactionFailed, oversized.finish(.streaming_excluded));
}

test "empty Content-Type differs from an absent header before entity acquisition" {
    var program = try prepare("SecAction \"id:1,phase:2\"", &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var invalid = request;
    invalid.headers = &.{.{ .name = "Content-Type", .value = "" }};
    var transaction = try transactions.Transaction.begin(&slot, .full, true, invalid);
    defer slot.finish();
    try std.testing.expectError(error.InvalidMime, transaction.requestBody("a=b"));
    try std.testing.expect(slot.context.failed and slot.input.failed and slot.state.failed);
}

test "logging records a late deny as intent without retroactively denying delivery" {
    var program = try prepare("SecAction \"id:1,phase:5,deny\"", &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    var transaction = try transactions.Transaction.begin(&slot, .full, true, request);
    defer slot.finish();
    _ = try transaction.requestBody("");
    _ = try transaction.responseHeaders(.{ .status = 200, .headers = &.{} });
    _ = try transaction.responseBody("delivered");
    try transaction.finish(.inspected);
    try std.testing.expect(slot.state.would_deny and !slot.state.denied);
    try std.testing.expectEqual(@as(usize, 1), slot.state.event_used);
}

test "response decoding scratch cannot invalidate the retained request representation" {
    var program = try prepare(
        \\SecRule REQUEST_BODY "@streq request" "id:1,phase:2,setvar:tx.request_seen=1"
        \\SecRule RESPONSE_BODY "@streq response" "id:2,phase:4,chain,deny"
        \\SecRule REQUEST_BODY "@streq request" "setvar:tx.child_seen=1"
        \\SecRule REQUEST_BODY "@streq request" "id:4,phase:5,setvar:tx.retained=1"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, limits);
    defer slot.deinit();
    const buffers = @import("buffers.zig");
    buffers.assertExclusive(&.{
        slot.request,          slot.response,       slot.request_wire,  slot.response_wire,
        slot.decode_alternate, slot.inflate_window, slot.response_head,
    });
    @memcpy(slot.request[0..7], "request");
    @memcpy(slot.request_wire[0..15], "encoded-request");
    @memcpy(slot.response[0..8], "response");
    @memcpy(slot.response_wire[0..16], "encoded-response");
    var input = request;
    input.headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }};
    var transaction = try transactions.Transaction.begin(&slot, .full, true, input);
    try std.testing.expectEqual(Result.complete, try transaction.requestBody(slot.request[0..7]));
    @memset(slot.decode_alternate, '!');
    _ = try transaction.responseHeaders(.{ .status = 200, .headers = &.{} });
    try std.testing.expectEqual(Result.denied, try transaction.responseBody(slot.response[0..8]));
    try transaction.finish(.local_response);
    try std.testing.expectEqualStrings("1", (try slot.store.get("retained", &slot.budget)).?);
    try std.testing.expectEqualStrings("encoded-request", slot.request_wire[0..15]);
    try std.testing.expectEqualStrings("encoded-response", slot.response_wire[0..16]);
    slot.finish();
}
