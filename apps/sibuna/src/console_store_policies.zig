//! Read and test the currently published immutable policy snapshot on its storage owner.
//! Never hold a reader pin across a tick or a publication; test inputs are owned mailboxes.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const access = @import("console_read_authorize.zig");
const Persistent = @import("persistent.zig").Persistent;
const AppState = @import("server.zig").AppState;
const store = @import("console_store.zig");
const db = @import("console_database.zig");
const candidates = @import("console_policy_candidate.zig");

fn authorize(owner: *Persistent, input: p.policies.Query) !?p.Failure {
    try p.policies.validate(input);
    if (try access.check(owner, input.session_digest, input.require_totp, .policy_read)) |reason|
        return reason;
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
        "\"waf\":{},\"default_difficulty\":{d},\"default_algorithm\":\"{s}\"," ++
        "\"surface\":\"{s}\",\"rate_limit\":{d},\"rate_window_seconds\":{d}," ++
        "\"ban_seconds\":{d},", .{
        revision,
        owner.version,
        engine.rule_count,
        engine.waf_enabled,
        engine.default_difficulty,
        @tagName(owner.cfg.algorithm),
        @as([]const u8, if (owner.cfg.waf) "shield" else "gate"),
        owner.cfg.rate_limit,
        owner.cfg.rate_window_seconds,
        owner.cfg.ban_seconds,
    });
    try writer.writeAll("\"inspection\":");
    try std.json.Stringify.value(engine.inspection_modes, .{}, &writer);
    try writer.writeAll(",\"rows\":[");
    var index: usize = input.offset;
    while (index < engine.rule_count and index < @as(usize, input.offset) + 8) : (index += 1) {
        var scratch: [p.max_message]u8 = undefined;
        var row: std.Io.Writer = .fixed(&scratch);
        const identity = &slot.hits.generation.rules[index];
        try summary(&row, .{
            .rule = &engine.rules[index],
            .index = index,
            .key = identity.key.slice(),
            .today = try @import("console_rule_hit_today.zig").read(owner, identity.key),
        });
        if (writer.buffered().len + row.buffered().len + 64 > output.data.len) {
            if (index == input.offset) return error.ResultTooLarge;
            break;
        }
        if (index != input.offset) try writer.writeByte(',');
        try writer.writeAll(row.buffered());
    }
    try writer.writeAll("],\"next\":");
    if (index < engine.rule_count) {
        try writer.print("{d}", .{index});
    } else try writer.writeAll("null");
    try writer.writeByte('}');
    output.len = writer.buffered().len;
    if (try access.check(owner, input.session_digest, input.require_totp, .policy_read)) |reason|
        return .{ .failed = reason };
    return .{ .page = output };
}

const Summary = struct {
    rule: *const policy.PolicyRule,
    index: usize,
    key: []const u8,
    today: p.rule_hit_history.Today,
};

fn summary(w: *std.Io.Writer, view: Summary) !void {
    const rule = view.rule;
    const path = rule.path_pattern orelse "";
    const ua = rule.ua_pattern orelse "";
    try std.json.Stringify.value(.{
        .index = view.index,
        .history_key = view.key,
        .today = view.today,
        .name = display(rule.name),
        .action = @tagName(rule.action),
        .path = display(path),
        .user_agent = display(ua),
        .truncated = path.len > 128 or ua.len > 128 or rule.name.len > 128 or
            !std.unicode.utf8ValidateSlice(path) or
            !std.unicode.utf8ValidateSlice(ua) or !std.unicode.utf8ValidateSlice(rule.name),
        .header_count = rule.header_count,
        .cidr_count = rule.cidr_count,
        .difficulty = rule.difficulty,
        .algorithm = if (rule.algorithm) |a| a.name() else null,
        .weight = rule.weight,
        .limits = rule.limits,
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
    if (input.draft != null) return testDraft(owner, input);
    const slot = owner.state.acquireEngine();
    defer AppState.releaseEngine(slot);
    const result = try evaluate(owner, input, slot.engine);
    if (try authorize(owner, input.query)) |failure| return .{ .failed = failure };
    return result;
}

fn testDraft(owner: *Persistent, input: p.policies.Test) !p.StorageResult {
    var candidate = candidates.build(
        owner,
        input.committed.?,
        input.draft.?.slice(),
        owner.nowSeconds(),
    ) catch |err| return .{ .failed = draftFailure(err) };
    defer candidate.deinit();
    const result = try evaluate(owner, input, candidate.engine);
    // Recheck after bounded reads and compilation, including remote reads.
    if (try authorize(owner, input.query)) |failure| return .{ .failed = failure };
    return result;
}

pub fn draftFailure(err: anyerror) p.Failure {
    if (err == error.Conflict) return .conflict;
    if (err == error.OutOfMemory) return .unavailable;
    if (err == error.InvalidStoredPolicy or err == error.WriteFailed) return .invalid_input;
    inline for (@typeInfo(policy.candidate.Error).error_set.?) |field| {
        if (err == @field(anyerror, field.name)) return .invalid_input;
    }
    return .unavailable;
}

fn evaluate(
    owner: *Persistent,
    input: p.policies.Test,
    engine: *const policy.Engine,
) !p.StorageResult {
    var headers: [8]policy.Header = undefined;
    for (input.headers[0..input.header_count], 0..) |*header, i| {
        headers[i] = .{ .name = header.name.slice(), .value = header.value.slice() };
    }
    const result = engine.evaluateRequest(.{
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
    var committed_revision: [20]u8 = undefined;
    try std.json.Stringify.value(.{
        .applied = try std.fmt.bufPrint(&revision, "{d}", .{owner.version}),
        .preview = input.draft != null,
        .committed = if (input.committed) |value|
            try std.fmt.bufPrint(&committed_revision, "{d}", .{value})
        else
            null,
        .action = @tagName(result.action),
        .rule = result.rule_name,
        .difficulty = result.difficulty,
        .algorithm = if (result.algorithm) |a| a.name() else @tagName(owner.cfg.algorithm),
        .score = result.score,
        .audited_categories = result.audited,
        .limits = result.limits,
    }, .{}, &writer);
    output.len = writer.buffered().len;
    return .{ .page = output };
}
