//! Read and test the currently published immutable policy snapshot on its storage owner.
//! Never hold a reader pin across a tick or a publication; test inputs are owned mailboxes.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const AppState = @import("server.zig").AppState;
const store = @import("console_store.zig");
const db = @import("console_database.zig");

fn authorize(owner: *Persistent, input: p.policies.Query) !?p.Failure {
    try p.policies.validate(input);
    const identity = try store.authorize(owner, input.session_digest, input.now);
    if (identity != .authorized or identity.authorized.must_change) return .unauthorized;
    if (input.applied) |expected| {
        if (expected != owner.version) return .conflict;
    }
    return null;
}

fn committed(owner: *Persistent) !u64 {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT value FROM sibuna_meta WHERE key='policy_version' LIMIT 1",
        &.{},
    );
    defer rows.deinit();
    if (rows.rows.len != 1) return error.MissingPolicyVersion;
    return store.number(rows.rows[0][0]);
}

pub fn query(owner: *Persistent, input: p.policies.Query) !p.StorageResult {
    if (try authorize(owner, input)) |failure| return .{ .failed = failure };
    const revision = try committed(owner);
    const slot = owner.state.acquireEngine();
    defer AppState.releaseEngine(slot);
    const engine = slot.engine;
    var output: p.Bytes(p.max_message) = .{};
    var writer: std.Io.Writer = .fixed(&output.data);
    try writer.print("{{\"committed\":\"{d}\",\"applied\":\"{d}\",\"total\":{d}," ++
        "\"waf\":{},\"default_difficulty\":{d},\"default_algorithm\":\"{s}\",\"rows\":[", .{
        revision,
        owner.version,
        engine.rule_count,
        engine.waf_enabled,
        engine.default_difficulty,
        @tagName(owner.cfg.algorithm),
    });
    var index: usize = input.offset;
    while (index < engine.rule_count and index < @as(usize, input.offset) + 8) : (index += 1) {
        var scratch: [2048]u8 = undefined;
        var row: std.Io.Writer = .fixed(&scratch);
        try summary(&row, &engine.rules[index], index);
        if (writer.buffered().len + row.buffered().len + 64 > output.data.len) break;
        if (index != input.offset) try writer.writeByte(',');
        try writer.writeAll(row.buffered());
    }
    try writer.writeAll("],\"next\":");
    if (index < engine.rule_count) {
        try writer.print("{d}", .{index});
    } else try writer.writeAll("null");
    try writer.writeByte('}');
    output.len = writer.buffered().len;
    return .{ .page = output };
}

fn summary(w: *std.Io.Writer, rule: *const policy.PolicyRule, index: usize) !void {
    const path = rule.path_pattern orelse "";
    const ua = rule.ua_pattern orelse "";
    try std.json.Stringify.value(.{
        .index = index,
        .name = display(rule.name),
        .action = @tagName(rule.action),
        .path = display(path),
        .user_agent = display(ua),
        .truncated = path.len > 128 or ua.len > 128 or !std.unicode.utf8ValidateSlice(path) or
            !std.unicode.utf8ValidateSlice(ua) or !std.unicode.utf8ValidateSlice(rule.name),
        .header_count = rule.header_count,
        .cidr_count = rule.cidr_count,
        .difficulty = rule.difficulty,
        .algorithm = rule.algorithm,
        .weight = rule.weight,
    }, .{}, w);
}

fn display(value: []const u8) []const u8 {
    if (!std.unicode.utf8ValidateSlice(value)) return "[invalid text]";
    var end = @min(value.len, 128);
    while (!std.unicode.utf8ValidateSlice(value[0..end])) end -= 1;
    return value[0..end];
}

pub fn testRequest(owner: *Persistent, input: p.policies.Test) !p.StorageResult {
    try p.policies.validateTest(input);
    if (try authorize(owner, input.query)) |failure| return .{ .failed = failure };
    if (policy.radix_trie.parseIp(input.ip.slice()) == null)
        return .{ .failed = .invalid_input };
    const slot = owner.state.acquireEngine();
    defer AppState.releaseEngine(slot);
    var headers: [8]policy.Header = undefined;
    for (input.headers[0..input.header_count], 0..) |*header, i| {
        headers[i] = .{ .name = header.name.slice(), .value = header.value.slice() };
    }
    const result = slot.engine.evaluateRequest(.{
        .path = input.path.slice(),
        .query = input.query_string.slice(),
        .client_ip = input.ip.slice(),
        .user_agent = input.user_agent.slice(),
        .body = input.body.slice(),
        .headers = headers[0..input.header_count],
    });
    var output: p.Bytes(p.max_message) = .{};
    var writer: std.Io.Writer = .fixed(&output.data);
    var revision: [20]u8 = undefined;
    try std.json.Stringify.value(.{
        .applied = try std.fmt.bufPrint(&revision, "{d}", .{owner.version}),
        .action = @tagName(result.action),
        .rule = result.rule_name,
        .difficulty = result.difficulty,
        .algorithm = result.algorithm orelse @tagName(owner.cfg.algorithm),
        .score = result.score,
    }, .{}, &writer);
    output.len = writer.buffered().len;
    return .{ .page = output };
}
