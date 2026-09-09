//! Replays retained incidents against the live engine or a draft candidate. Only inputs the
//! evidence envelope proves complete (no query, no body, nothing truncated) count as
//! conclusive; the request path's rate, ban and session state is never reproduced.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const w = p.workflows;
const Persistent = @import("persistent.zig").Persistent;
const AppState = @import("server.zig").AppState;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");
const access = @import("console_read_authorize.zig");

pub fn replay(owner: *Persistent, input: w.Replay, now: u64) !p.StorageResult {
    try p.validate(.{ .policy_replay = input });
    const auth = input.auth;
    if (try access.check(owner, auth.session_digest, auth.require_totp, .policy_read)) |f|
        return .{ .failed = f };
    if (input.draft) |draft| {
        var candidate = candidates.build(owner, input.committed.?, draft.slice(), now) catch |err|
            return .{ .failed = @import("console_store_policies.zig").draftFailure(err) };
        defer candidate.deinit();
        return .{ .replay_summary = try scan(owner, input, candidate.engine, now) };
    }
    const slot = owner.state.acquireEngine();
    defer AppState.releaseEngine(slot);
    return .{ .replay_summary = try scan(owner, input, slot.engine, now) };
}

fn scan(
    owner: *Persistent,
    input: w.Replay,
    engine: *const policy.Engine,
    now: u64,
) !w.ReplaySummary {
    var summary: w.ReplaySummary = .{
        .applied = owner.version,
        .committed = try candidates.revision(owner),
        .preview = input.draft != null,
    };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,client_ip,path,user_agent,e.version,e.query_bytes,e.body_bytes,e.truncated " ++
            "FROM security_incidents LEFT JOIN console_incident_evidence e ON e.incident_id=id " ++
            "WHERE recorded_at>=? ORDER BY recorded_at DESC,id DESC LIMIT ?",
        &.{ util.integer(now -| @as(u64, input.hours) * 3600), util.integer(w.replay_scan) },
    );
    defer rows.deinit();
    for (rows.rows) |cells| {
        const ip = cells[1] orelse continue;
        if (policy.radix_trie.parseIp(ip) == null) continue;
        const path: []const u8 = cells[2] orelse "";
        const decision = engine.evaluateRequest(.{
            .path = path,
            .client_ip = ip,
            .user_agent = cells[3] orelse "",
        });
        // The engine's rule name can point at evaluation scratch; keep a copy at once.
        var name_buffer: [64]u8 = undefined;
        const name_len = @min(decision.rule_name.len, name_buffer.len);
        @memcpy(name_buffer[0..name_len], decision.rule_name[0..name_len]);
        const rule_name = name_buffer[0..name_len];
        const conclusive = cells[4] != null and (try util.number(cells[4])) == 1 and
            (try util.number(cells[5])) == 0 and (try util.number(cells[6])) == 0 and
            (try util.number(cells[7])) & 0b1111 == 0;
        const matched = if (input.rule.len == 0)
            decision.action != .allow
        else
            std.mem.eql(u8, rule_name, input.rule.slice());
        summary.total += 1;
        if (matched) summary.matched += 1;
        if (!conclusive) summary.inconclusive += 1;
        if (summary.count < w.replay_rows) {
            summary.rows[summary.count] = .{
                .id = try util.number(cells[0]),
                .ip = try p.Bytes(w.max_prefix).init(ip[0..@min(ip.len, w.max_prefix)]),
                .path = try p.Bytes(128).init(path[0..@min(path.len, 128)]),
                .action = try p.Bytes(16).init(@tagName(decision.action)),
                .rule = try p.Bytes(64).init(rule_name),
                .conclusive = conclusive,
                .matched = matched,
            };
            summary.count += 1;
        }
    }
    return summary;
}

fn bounded(text: []const u8, limit: usize) []const u8 {
    return text[0..@min(text.len, limit)];
}
