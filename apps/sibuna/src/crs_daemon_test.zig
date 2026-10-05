//! Actual sockets and daemon composition: no direct executor calls in these tests.
const std = @import("std");
const Io = std.Io;
const fixtures = @import("crs_daemon_fixture.zig");
const t = std.testing;
const io = t.io;
const gzip = @embedFile("testdata/crs-entity.gz");
const ordinary = "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
const console_enabled = @import("build_options").console;
const noop = "SecAction \"id:1,phase:1,pass\"";

fn send(stream: Io.net.Stream, bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn exchange(fixture: *fixtures.Fixture, bytes: []const u8, output: []u8) ![]const u8 {
    const stream = try fixture.connect();
    defer stream.close(io);
    try send(stream, bytes);
    var buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &buffer);
    const count = try reader.interface.readSliceShort(output);
    return output[0..count];
}

fn status(response: []const u8, code: []const u8) !void {
    try t.expect(std.mem.startsWith(u8, response, code));
}

test "phase-one denial precedes continue, body acquisition and origin delivery" {
    const fixture = try fixtures.Fixture.create(.{
        .source = "SecRule REQUEST_URI \"@contains refused\" \"id:1,phase:1,deny,status:406\"",
    });
    defer fixture.destroy();
    var output: [1024]u8 = undefined;
    const response = try exchange(fixture, "POST /refused HTTP/1.1\r\n" ++
        "Host: example.test\r\nExpect: 100-continue\r\nContent-Length: 99999\r\n\r\n", &output);
    try status(response, "HTTP/1.1 406 Not Acceptable\r\n");
    try t.expect(std.mem.indexOf(u8, response, "100 Continue") == null);
    try t.expectEqual(@as(u32, 0), fixture.received.load(.acquire));
    try t.expectEqual(@as(u64, 1), fixture.state.metrics.requests.load(.monotonic));
    try t.expectEqual(@as(u64, 1), fixture.state.crs_counts.denied.load(.monotonic));
}

test "CRS findings consume saved events exactly once without expanded request secrets" {
    const source = "SecRule REQUEST_URI \"@contains evidence\" " ++
        "\"id:942100,phase:1,deny,status:406,msg:'secret %{REQUEST_URI}',severity:2\"\n" ++
        "SecRule REQUEST_URI \"@contains evidence\" " ++
        "\"id:942101,phase:1,pass,nolog,msg:'not saved'\"\n" ++
        "SecRule REQUEST_URI \"@contains evidence\" " ++
        "\"id:942102,phase:1,pass,noauditlog,msg:'not audited'\"";
    for ([_]bool{ false, true }) |enforcing| {
        const fixture = try fixtures.Fixture.create(.{
            .source = source,
            .mode = if (enforcing) .enforce else .audit,
        });
        defer fixture.destroy();
        var output: [1024]u8 = undefined;
        const response = try exchange(fixture, "GET /evidence?token=private-value HTTP/1.1\r\n" ++
            "Host: example.test\r\nConnection: close\r\n\r\n", &output);
        try status(response, if (enforcing) "HTTP/1.1 406" else "HTTP/1.1 200");
        const finding = fixture.findings.pop().?;
        try t.expectEqual(@as(u32, 942100), finding.evidence.rule_id);
        try t.expectEqual(enforcing, finding.evidence.enforcing);
        try t.expectEqual(enforcing, finding.evidence.denied);
        try t.expect(finding.evidence.would_deny);
        try t.expectEqual(@as(usize, 0), finding.payload_bytes);
        try t.expectEqualStrings("/evidence", std.mem.sliceTo(&finding.path, 0));
        const category = if (enforcing) "waf:crs" else "audit:crs";
        try t.expectEqualStrings(category, std.mem.sliceTo(&finding.category, 0));
        try t.expect(fixture.findings.pop() == null);
        try finding.evidence.validate();
    }
}

test "CRS heads are redacted and consumed before WebSocket early release" {
    if (!console_enabled) return;
    const fixture = try fixtures.Fixture.create(.{
        .source = "SecRule REQUEST_URI \"@contains socket\" " ++
            "\"id:942100,phase:1,pass,msg:'handshake finding'\"",
        .capture = true,
    });
    defer fixture.destroy();
    const stream = try fixture.connect();
    defer stream.close(io);
    try send(stream, "GET /socket?token=private-value HTTP/1.1\r\nHost: example.test\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Authorization: Bearer private-value\r\n\r\n");
    var storage: [4096]u8 = undefined;
    var reader = stream.reader(io, &storage);
    try reader.interface.fill(12);
    // The callback finishes findings before publishing the accepted handshake.
    try t.expect(std.mem.startsWith(u8, reader.interface.buffered(), "HTTP/1.1 101"));
    const finding = fixture.findings.pop().?;
    try t.expectEqual(.handshake_only, finding.evidence.coverage);
    try t.expectEqual(.captured, finding.response_state);
    const request = std.mem.sliceTo(&finding.request, 0);
    try t.expect(std.mem.indexOf(u8, request, "private-value") == null);
    try t.expect(std.mem.indexOf(u8, request, "[redacted]") != null);
    try t.expect(std.mem.startsWith(u8, &finding.response, "HTTP/1.1 101"));
    try t.expect(fixture.findings.pop() == null);
    // A close frame permits both owned peers to end normally.
    try send(stream, &.{ 0x88, 0x82, 1, 2, 3, 4, 2, 0xea });
}

test "decoded gzip and chunked entities reach phase two before the origin" {
    const source = "SecRule REQUEST_BODY \"@contains bounded\" \"id:1,phase:2,deny,status:409\"";
    const fixture = try fixtures.Fixture.create(.{ .source = source });
    defer fixture.destroy();
    for ([_]bool{ false, true }) |chunked| {
        var request: [1024]u8 = undefined;
        var w = Io.Writer.fixed(&request);
        try w.writeAll("POST / HTTP/1.1\r\nHost: example.test\r\n" ++
            "Content-Type: application/octet-stream\r\nContent-Encoding: gzip\r\n");
        if (chunked) {
            const format = "Transfer-Encoding: chunked\r\n\r\n{x}\r\n{s}\r\n0\r\n\r\n";
            try w.print(format, .{ gzip.len, gzip });
        } else {
            try w.print("Content-Length: {d}\r\n\r\n{s}", .{ gzip.len, gzip });
        }
        var output: [1024]u8 = undefined;
        try status(try exchange(fixture, w.buffered(), &output), "HTTP/1.1 409 Conflict\r\n");
    }
    try t.expectEqual(@as(u32, 0), fixture.received.load(.acquire));
    try t.expectEqual(@as(u64, 2), fixture.state.metrics.requests.load(.monotonic));
}

test "admitted encoded uploads preserve their original representation for the origin" {
    const fixture = try fixtures.Fixture.create(.{ .source = noop });
    defer fixture.destroy();
    var request: [1024]u8 = undefined;
    var w = Io.Writer.fixed(&request);
    try w.print("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Encoding: gzip\r\n" ++
        "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ gzip.len, gzip });
    var output: [1024]u8 = undefined;
    try status(try exchange(fixture, w.buffered(), &output), "HTTP/1.1 200 OK\r\n");
    try t.expectEqual(@as(u32, 1), fixture.received.load(.acquire));
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(gzip, &expected, .{});
    try t.expectEqualSlices(u8, &expected, &fixture.body_digest);
    try t.expectEqual(@as(u64, 1), fixture.state.crs_counts.inspected.load(.monotonic));
}

test "response phases refuse before any origin head or confidential bytes are published" {
    for ([_][]const u8{
        "SecRule RESPONSE_HEADERS:Content-Type \"@streq text/plain\" " ++
            "\"id:1,phase:3,deny,status:406\"",
        "SecRule RESPONSE_BODY \"@contains confidential\" \"id:1,phase:4,deny,status:409\"",
    }, 0..) |source, index| {
        const fixture = try fixtures.Fixture.create(.{ .source = source });
        defer fixture.destroy();
        var output: [1024]u8 = undefined;
        const response = try exchange(fixture, "GET /response-deny HTTP/1.1\r\n" ++
            "Host: example.test\r\nConnection: close\r\n\r\n", &output);
        try status(response, if (index == 0) "HTTP/1.1 406 " else "HTTP/1.1 409 ");
        try t.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200") == null);
        try t.expect(std.mem.indexOf(u8, response, "confidential") == null);
        try t.expectEqual(@as(u64, 1), fixture.state.crs_counts.denied.load(.monotonic));
        if (console_enabled) {
            const totals = fixture.telemetry.totals();
            try t.expectEqual(@as(u64, 1), totals.denied);
            try t.expectEqual(@as(u64, 0), totals.admitted);
        }
        // Admission's existing allowed counter retains its established meaning.
        try t.expectEqual(@as(u64, 1), fixture.state.metrics.allowed.load(.monotonic));
        try t.expectEqual(@as(u64, 0), fixture.state.metrics.denied.load(.monotonic));
    }
}

test "audit preserves deliverable traffic and separately counts would-deny" {
    const fixture = try fixtures.Fixture.create(.{
        .source = "SecRule RESPONSE_BODY \"@contains confidential\" \"id:1,phase:4,deny\"",
        .mode = .audit,
    });
    defer fixture.destroy();
    var output: [1024]u8 = undefined;
    const response = try exchange(fixture, "GET /response-deny HTTP/1.1\r\n" ++
        "Host: example.test\r\nConnection: close\r\n\r\n", &output);
    try status(response, "HTTP/1.1 200 OK\r\n");
    try t.expect(std.mem.endsWith(u8, response, "confidential"));
    try t.expectEqual(@as(u64, 1), fixture.state.crs_counts.would_deny.load(.monotonic));
    try t.expectEqual(@as(u64, 1), fixture.state.crs_counts.inspected.load(.monotonic));
}

fn streamRequest(fixture: *fixtures.Fixture, upgrade: bool) !Io.net.Stream {
    const stream = try fixture.connect();
    errdefer stream.close(io);
    const bytes = if (upgrade)
        "GET /socket HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\n" ++
            "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    else
        "GET /stream HTTP/1.1\r\nHost: example.test\r\n\r\n";
    try send(stream, bytes);
    var bytes_in: [1024]u8 = undefined;
    var reader = stream.reader(io, &bytes_in);
    const r = &reader.interface;
    while (std.mem.indexOf(u8, r.buffered(), "\r\n\r\n") == null)
        try r.fill(r.bufferedLen() + 1);
    try status(r.buffered(), if (upgrade) "HTTP/1.1 101 " else "HTTP/1.1 200 ");
    return stream;
}

test "long-lived streams and WebSockets release the CRS slot and deadline" {
    const source =
        \\SecRule RESPONSE_HEADERS:Content-Type "@beginsWith text/event-stream" \
        \\"id:1,phase:3,pass,setvar:tx.sibuna_stream_response=1"
    ;
    for ([_]bool{ false, true }) |upgrade| {
        const fixture = try fixtures.Fixture.create(.{ .source = source, .deadline_ms = 1000 });
        defer fixture.destroy();
        const stream = try streamRequest(fixture, upgrade);
        defer stream.close(io);
        var output: [1024]u8 = undefined;
        try status(try exchange(fixture, ordinary, &output), "HTTP/1.1 200 OK\r\n");
        const counters = &fixture.state.crs_counts;
        const counter = if (upgrade) &counters.handshake else &counters.streaming;
        try t.expectEqual(@as(u64, 1), counter.load(.monotonic));
        // No inspection deadline remains on the live tunnel, even with HTTP and
        // WebSocket idle expiry deliberately disabled by this fixture.
        try Io.sleep(io, Io.Duration.fromMilliseconds(1200), .awake);
        if (upgrade) try send(stream, "still connected");
        try t.expectEqual(@as(u64, 0), fixture.state.crs_counts.incomplete.load(.monotonic));
    }
}

test "the absolute deadline bounds incomplete uploads with idle expiry disabled" {
    const fixture = try fixtures.Fixture.create(.{ .source = noop, .deadline_ms = 300 });
    defer fixture.destroy();
    var output: [1024]u8 = undefined;
    const before = Io.Clock.awake.now(io);
    const response = try exchange(fixture, "POST / HTTP/1.1\r\nHost: example.test\r\n" ++
        "Content-Length: 32768\r\n\r\npartial", &output);
    const elapsed = before.durationTo(Io.Clock.awake.now(io)).nanoseconds;
    try t.expect(elapsed < 2 * std.time.ns_per_s);
    // Interrupting both socket directions may make the refusal undeliverable.
    try t.expect(response.len == 0 or std.mem.startsWith(u8, response, "HTTP/1.1 400 "));
    try t.expectEqual(@as(u32, 0), fixture.received.load(.acquire));
    var next: [1024]u8 = undefined;
    try status(try exchange(fixture, ordinary, &next), "HTTP/1.1 200 OK\r\n");
}

test "forward-auth headers inspect the original URI without pretending to observe a body" {
    const fixture = try fixtures.Fixture.create(.{
        .source = "SecRule REQUEST_URI \"@contains blocked\" \"id:1,phase:1,deny\"",
        .profile = .headers,
        .forward_auth = true,
    });
    defer fixture.destroy();
    var output: [1024]u8 = undefined;
    const response = try exchange(fixture, "GET /auth HTTP/1.1\r\nHost: example.test\r\n" ++
        "X-Original-URI: /blocked?q=original\r\nX-Forwarded-Method: POST\r\n" ++
        "Connection: close\r\n\r\n", &output);
    try status(response, "HTTP/1.1 403 ");
    const admitted = try exchange(fixture, ordinary, &output);
    try status(admitted, "HTTP/1.1 200 ");
    try t.expectEqual(@as(u32, 0), fixture.received.load(.acquire));
    try t.expectEqual(@as(u64, 1), fixture.state.crs_counts.headers.load(.monotonic));
}

test "large retained uploads preserve pipeline framing after rebasing the next head" {
    const fixture = try fixtures.Fixture.create(.{ .source = noop });
    defer fixture.destroy();
    const bytes = try t.allocator.alloc(u8, 128 * 1024);
    defer t.allocator.free(bytes);
    var writer = Io.Writer.fixed(bytes);
    try writer.writeAll("POST / HTTP/1.1\r\nHost: example.test\r\n" ++
        "Content-Type: application/octet-stream\r\nContent-Length: 61440\r\n\r\n");
    try writer.splatByteAll('a', 61440);
    try writer.writeAll("POST / HTTP/1.1\r\nHost: example.test\r\n" ++
        "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n1;extension=");
    try writer.splatByteAll('e', 4000);
    try writer.writeAll("\r\nx\r\n0\r\n\r\n");
    var output: [2048]u8 = undefined;
    const response = try exchange(fixture, writer.buffered(), &output);
    try t.expectEqual(@as(usize, 2), std.mem.count(u8, response, "HTTP/1.1 200 OK\r\n"));
    try t.expectEqual(@as(usize, 2), std.mem.count(u8, response, "accepted"));
    try t.expectEqual(@as(u32, 2), fixture.received.load(.acquire));
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("x", &expected, .{});
    try t.expectEqualSlices(u8, &expected, &fixture.body_digest);
}

test "admission limits refuse an unread large upload before continue or origin access" {
    const fixture = try fixtures.Fixture.create(.{ .source = noop, .rate = 1 });
    defer fixture.destroy();
    var output: [1024]u8 = undefined;
    try status(try exchange(fixture, ordinary, &output), "HTTP/1.1 200 OK\r\n");
    const response = try exchange(fixture, "POST / HTTP/1.1\r\nHost: example.test\r\n" ++
        "Expect: 100-continue\r\nContent-Length: 200000\r\n\r\n", &output);
    try status(response, "HTTP/1.1 429 Too Many Requests\r\n");
    try t.expect(std.mem.indexOf(u8, response, "100 Continue") == null);
    try t.expectEqual(@as(u32, 1), fixture.received.load(.acquire));
    try t.expectEqual(@as(u64, 2), fixture.state.metrics.requests.load(.monotonic));
    try t.expectEqual(@as(u64, 1), fixture.state.metrics.rate_limited.load(.monotonic));
}

test "internal CRS coverage metrics report omissions without consuming an inspection slot" {
    const fixture = try fixtures.Fixture.create(.{ .source = noop });
    defer fixture.destroy();
    var output: [4096]u8 = undefined;
    try status(try exchange(fixture, ordinary, &output), "HTTP/1.1 200 OK\r\n");
    const metrics = try exchange(fixture, "GET /__sibuna/metrics HTTP/1.1\r\n" ++
        "Host: example.test\r\nConnection: close\r\n\r\n", &output);
    try status(metrics, "HTTP/1.1 200 OK\r\n");
    try t.expect(std.mem.indexOf(u8, metrics, "sibuna_crs_inspected_total 1\n") != null);
    try t.expect(std.mem.indexOf(u8, metrics, "sibuna_crs_streaming_total 0\n") != null);
    try t.expectEqual(@as(u64, 1), fixture.state.crs_counts.inspected.load(.monotonic));
}
