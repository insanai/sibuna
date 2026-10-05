const std = @import("std");
const crs = @import("crs");
const net = @import("net");
const bridge = @import("crs_entity.zig");
const t = std.testing;
const gzip = @embedFile("testdata/crs-entity.gz");
const rules =
    \\SecRule REQUEST_BODY "@contains bounded" "id:1,phase:2,setvar:tx.request_seen=1"
    \\SecRule RESPONSE_BODY "@contains bounded" "id:2,phase:4,deny"
    \\SecRule REQUEST_BODY "@contains bounded" "id:3,phase:5,setvar:tx.retained=1"
;
const input: crs.http_acquisition.Request = .{
    .method = "POST",
    .target = "/submit",
    .protocol = "HTTP/1.1",
    .line = "POST /submit HTTP/1.1",
    .client = "192.0.2.1",
    .id = "http-bridge-test",
    .headers = &.{
        .{ .name = "Content-Type", .value = "application/octet-stream" },
        .{ .name = "Content-Encoding", .value = "gzip" },
    },
};
const Fixture = struct {
    program: crs.rule_program.Program = undefined,
    slot: crs.transaction_slot.Slot = undefined,

    fn init(self: *Fixture, source: []const u8) !void {
        var compiler = crs.compiler.Compiler.init(t.allocator, .{});
        defer compiler.deinit();
        try compiler.addSource("test.conf", source);
        var plan = try compiler.finish();
        defer plan.deinit();
        self.program = try crs.rule_program.compile(t.allocator, &plan, &.{}, .{});
        errdefer self.program.deinit();
        try self.slot.init(t.allocator, &self.program, .{
            .entries = 128,
            .bytes = 8192,
            .request = 256,
            .response = 256,
            .events = 16,
            .tags = 32,
            .pieces = 32,
            .work = 1_000_000,
            .reservation = 1024 * 1024,
        });
    }

    fn deinit(self: *Fixture) void {
        if (self.slot.active) self.slot.finish();
        self.slot.deinit();
        self.program.deinit();
    }

    fn begin(self: *Fixture, enforce: bool) !crs.http_transaction.Transaction {
        @memcpy(self.slot.request_wire[0..gzip.len], gzip);
        var transaction = try crs.http_transaction.Transaction.begin(
            &self.slot,
            .full,
            enforce,
            input,
        );
        const wire = self.slot.request_wire[0..gzip.len];
        _ = try bridge.requestBody(&transaction, input.headers, wire);
        return transaction;
    }
};

fn responseBytes(out: []u8, payload: []const u8) ![]const u8 {
    const format = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n" ++
        "Content-Length: {d}\r\n\r\n";
    const head = try std.fmt.bufPrint(out, format, .{payload.len});
    @memcpy(out[head.len..][0..payload.len], payload);
    return out[0 .. head.len + payload.len];
}

fn acquire(response: *bridge.Response, raw: []const u8) !net.response_inspection.Held {
    const length = std.mem.indexOf(u8, raw, "\r\n\r\n").? + 4;
    const parsed = net.proxy.parseResponseHead(raw[0..length], false).?;
    const head: net.response_inspection.Head = .{
        .bytes = raw[0..length],
        .status = parsed.status,
        .framing = parsed.framing,
    };
    const hook = response.hooks();
    try t.expectEqual(net.response_inspection.Decision.hold, try hook.inspectHeaders(head));
    var reader = std.Io.Reader.fixed(raw);
    return hook.acquire(&reader, head, null);
}

test "CRS inspects decoded bodies while held replay retains the encoded representation" {
    for ([_]bool{ false, true }) |enforce| {
        var fixture: Fixture = undefined;
        try fixture.init(rules);
        defer fixture.deinit();
        var transaction = try fixture.begin(enforce);
        var response: bridge.Response = undefined;
        try response.init(&transaction);
        var raw_buffer: [256]u8 = undefined;
        const raw = try responseBytes(&raw_buffer, gzip);
        const held = acquire(&response, raw);
        if (enforce) {
            try t.expectError(error.InspectionDenied, held);
            try t.expect(fixture.slot.state.denied);
        } else {
            try t.expectEqualSlices(u8, gzip, (try held).body);
            try t.expect(fixture.slot.state.would_deny and !fixture.slot.state.denied);
        }
        try response.finish(.origin_unavailable);
        const retained = try fixture.slot.store.get("retained", &fixture.slot.budget);
        try t.expectEqualStrings("1", retained.?);
        try t.expectEqualSlices(u8, gzip, fixture.slot.request_wire[0..gzip.len]);
        try t.expectEqualStrings("bounded representation\n", fixture.slot.request[0..23]);
    }
}

test "failed decoding refuses enforcement but audit replay remains explicitly incomplete" {
    for ([_]bool{ false, true }) |enforce| {
        var fixture: Fixture = undefined;
        try fixture.init(rules);
        defer fixture.deinit();
        var transaction = try fixture.begin(enforce);
        var response: bridge.Response = undefined;
        try response.init(&transaction);
        var corrupt: [gzip.len]u8 = undefined;
        @memcpy(&corrupt, gzip);
        corrupt[corrupt.len - 8] ^= 1;
        var raw: [256]u8 = undefined;
        const encoded = try responseBytes(&raw, &corrupt);
        const held = acquire(&response, encoded);
        if (enforce) {
            try t.expectError(error.InspectionFailed, held);
        } else {
            try t.expectEqualSlices(u8, &corrupt, (try held).body);
        }
        try t.expectEqual(error.InvalidCompressedChecksum, response.failure.?);
        try t.expect(fixture.slot.state.failed and fixture.slot.context.failed);
        try t.expectError(error.AcquisitionFailed, fixture.slot.input.view());
        try t.expectError(error.InvalidCompressedChecksum, response.finish(.origin_unavailable));
        try t.expect(transaction.end == null and response.completion == null);
    }
}

test "audit work exhaustion streams only under the explicit incomplete-response policy" {
    for ([_]bool{ false, true }) |refuse| {
        var fixture: Fixture = undefined;
        try fixture.init(rules);
        defer fixture.deinit();
        var transaction = try fixture.begin(false);
        var response: bridge.Response = undefined;
        try response.init(&transaction);
        if (refuse) response.audit_failure = .refuse;
        fixture.slot.budget.remaining = 0;
        const hook = response.hooks();
        const head: net.response_inspection.Head = .{
            .bytes = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n",
            .status = 200,
            .framing = .{ .length = 7 },
        };
        const result = hook.inspectHeaders(head);
        if (refuse) {
            try t.expectError(error.InspectionFailed, result);
        } else {
            try t.expectEqual(net.response_inspection.Decision.stream, try result);
        }
        try t.expectEqual(error.WorkLimit, response.failure.?);
        try t.expect(fixture.slot.state.failed);
        try t.expectError(error.WorkLimit, response.finish(.origin_unavailable));
        try t.expect(transaction.end == null);
    }
}

test "streaming and WebSocket endings report absent body coverage without decoding it" {
    for ([_]bool{ false, true }) |upgrade| {
        var fixture: Fixture = undefined;
        try fixture.init(rules);
        defer fixture.deinit();
        var transaction = try fixture.begin(true);
        var response: bridge.Response = undefined;
        try response.init(&transaction);
        response.policy = .streaming_excluded;
        const raw = if (upgrade)
            "HTTP/1.1 101 Switching Protocols\r\n\r\n"
        else
            "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n";
        const head: net.response_inspection.Head = .{
            .bytes = raw,
            .status = if (upgrade) 101 else 200,
            .framing = if (upgrade) .none else .until_close,
            .upgrade = upgrade,
        };
        const hook = response.hooks();
        const decision = try hook.inspectHeaders(head);
        try t.expectEqual(net.response_inspection.Decision.stream, decision);
        try response.finish(.origin_unavailable);
        const end: crs.http_transaction.End = if (upgrade)
            .handshake_only
        else
            .streaming_excluded;
        try t.expectEqual(end, transaction.end.?);
        const view = try fixture.slot.input.view();
        const index = @backingInt(crs.variables.Collection.response_body);
        try t.expectEqual(crs.variables.Coverage.unavailable, view.coverage[index]);
    }
}

test "response-header denial precedes streaming and tunnel exclusions and still logs" {
    const source =
        \\SecRule RESPONSE_HEADERS:X-Refuse "@streq yes" "id:1,phase:3,deny"
        \\SecAction "id:2,phase:5,setvar:tx.logged=1"
    ;
    for ([_]bool{ false, true }) |upgrade| {
        var fixture: Fixture = undefined;
        try fixture.init(source);
        defer fixture.deinit();
        var transaction = try fixture.begin(true);
        var response: bridge.Response = undefined;
        try response.init(&transaction);
        response.policy = .streaming_excluded;
        const raw = if (upgrade)
            "HTTP/1.1 101 Switching Protocols\r\nX-Refuse: yes\r\n\r\n"
        else
            "HTTP/1.1 200 OK\r\nX-Refuse: yes\r\n\r\n";
        const head: net.response_inspection.Head = .{
            .bytes = raw,
            .status = if (upgrade) 101 else 200,
            .framing = if (upgrade) .none else .until_close,
            .upgrade = upgrade,
        };
        const hook = response.hooks();
        try t.expectError(error.InspectionDenied, hook.inspectHeaders(head));
        try response.finish(.origin_unavailable);
        try t.expectEqual(crs.http_transaction.End.local_response, transaction.end.?);
        const logged = try fixture.slot.store.get("logged", &fixture.slot.budget);
        try t.expectEqualStrings("1", logged.?);
    }
}

test "bodyless response metadata does not require decoding an absent representation" {
    var fixture: Fixture = undefined;
    try fixture.init(rules);
    defer fixture.deinit();
    var transaction = try fixture.begin(true);
    var response: bridge.Response = undefined;
    try response.init(&transaction);
    const raw = "HTTP/1.1 304 Not Modified\r\nContent-Encoding: br\r\n\r\n";
    const held = try acquire(&response, raw);
    try t.expectEqual(@as(usize, 0), held.body.len);
    try t.expectEqualStrings(raw, held.head);
    try response.finish(.origin_unavailable);
    try t.expectEqual(crs.http_transaction.End.inspected, transaction.end.?);
    try t.expect(!fixture.slot.state.denied);
}
