const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;

fn read(fx: *Fixture, id: u64) !p.StorageResult {
    return fx.run(.{ .incident_heads_read = .{ .session_digest = @splat(1), .id = id } });
}

test "captured heads keep their response state and legacy rows read as unknown" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/incident-heads",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    const hook = fx.state.hooks.record_incident.?;
    hook(fx.state.hooks.context, .{
        .client_ip = "8.8.8.8",
        .user_agent = "test",
        .method = "GET",
        .path = "/trap",
        .category = "honeypot",
        .payload = "",
        .now = 100,
        .request_head = "GET /trap HTTP/1.1\r\nHost: h\r\n",
        .response_state = .local,
    });
    hook(fx.state.hooks.context, .{
        .client_ip = "8.8.8.9",
        .user_agent = "test",
        .method = "GET",
        .path = "/api",
        .category = "audit:xss",
        .payload = "",
        .now = 101,
        .request_head = "GET /api HTTP/1.1\r\nHost: h\r\n",
        .response_head = "HTTP/1.1 200 OK\r\n",
        .response_truncated = true,
        .response_state = .captured,
    });
    // The batch commits on one tick and its receipt is confirmed on the next.
    try fx.owner.tick();
    try fx.owner.tick();
    try fx.owner.tick();
    // Incident ids are node-scoped: the node id in the high bits, then the sequence.
    const local = try read(fx, (1 << 40) | 1);
    defer p.releaseResult(local, fx.owner.gpa);
    try t.expect(local.incident_heads.recorded);
    try t.expectEqual(p.incident_heads.ResponseState.local, local.incident_heads.response_state);
    try t.expectEqual(@as(usize, 0), local.incident_heads.response.len);
    const captured = try read(fx, (1 << 40) | 2);
    defer p.releaseResult(captured, fx.owner.gpa);
    try t.expectEqual(
        p.incident_heads.ResponseState.captured,
        captured.incident_heads.response_state,
    );
    try t.expect(captured.incident_heads.response_truncated);
    // A row written before version 40 carries the column default and stays unknown rather
    // than being reinterpreted as a local response.
    try fx.owner.db.exec(t.allocator, "INSERT INTO security_incidents(id,node_id,client_ip," ++
        "user_agent,method,path,violation_category,offending_payload,recorded_at) " ++
        "VALUES(3,1,'8.8.8.10','t','GET','/old','honeypot','',102);" ++
        "INSERT INTO console_incident_heads(incident_id,version,request_head,response_head," ++
        "request_truncated,response_truncated) VALUES(3,1,'474554','',0,0)");
    const legacy = try read(fx, 3);
    defer p.releaseResult(legacy, fx.owner.gpa);
    try t.expect(legacy.incident_heads.recorded);
    const state = legacy.incident_heads.response_state;
    try t.expectEqual(p.incident_heads.ResponseState.unknown, state);
    const missing = try read(fx, 4);
    defer p.releaseResult(missing, fx.owner.gpa);
    try t.expect(!missing.incident_heads.recorded);
}
