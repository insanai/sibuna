//! Console-managed reputation prefixes: bounded pages, one revision-checked edit or
//! removal at a time, and a private-candidate preflight so a prefix that would exhaust the
//! trie is refused before anything is staged.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const w = p.workflows;
const zx = @import("zaxonlite");
const Persistent = @import("persistent.zig").Persistent;
const AppState = @import("server.zig").AppState;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");
const auth = @import("console_policy_authorization.zig");
const access = @import("console_read_authorize.zig");

pub fn query(owner: *Persistent, input: w.ReputationQuery, now: u64) !p.StorageResult {
    _ = now;
    const digest = input.auth.session_digest;
    if (try access.check(owner, digest, input.auth.require_totp, .policy_read)) |f|
        return .{ .failed = f };
    var page: w.ReputationPage = .{ .committed = try candidates.revision(owner) };
    const slot = owner.state.acquireEngine();
    page.nodes = slot.engine.ip_trie.node_count;
    AppState.releaseEngine(slot);
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT ip_or_cidr,reputation_score,banned_until,trigger_rule,source,note,hits," ++
            "last_seen FROM ip_reputation WHERE ip_or_cidr>? ORDER BY ip_or_cidr LIMIT 9",
        &.{util.text(input.after.slice())},
    );
    defer rows.deinit();
    for (rows.rows) |cells| {
        if (page.count == w.page_rows) {
            page.next = page.rows[page.count - 1].prefix;
            break;
        }
        page.rows[page.count] = .{
            .prefix = try p.Bytes(w.max_prefix).init(cells[0] orelse ""),
            .score = try std.fmt.parseInt(i32, cells[1] orelse "0", 10),
            .banned_until = if (cells[2] != null) try util.number(cells[2]) else null,
            .trigger = try p.Bytes(64).init(bounded(cells[3] orelse "", 64)),
            .source = try p.Bytes(w.max_source).init(bounded(cells[4] orelse "", w.max_source)),
            .note = try p.Bytes(w.max_note).init(bounded(cells[5] orelse "", w.max_note)),
            .hits = try util.number(cells[6]),
            .last_seen = try util.number(cells[7]),
        };
        page.count += 1;
    }
    return .{ .reputation_page = page };
}

fn bounded(text: []const u8, limit: usize) []const u8 {
    return text[0..@min(text.len, limit)];
}

pub fn edit(owner: *Persistent, input: w.ReputationEdit, now: u64) !p.StorageResult {
    try p.validate(.{ .reputation_edit = input });
    if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
    if (policy.radix_trie.parseCidr(input.prefix.slice()) == null)
        return .{ .failed = .invalid_input };
    if (input.until) |until| if (until <= now) return .{ .failed = .invalid_input };
    // Preflight in a private candidate: capacity is refused before staging.
    var candidate = candidates.current(owner, input.expected_revision, now) catch |err|
        return .{ .failed = @import("console_store_policies.zig").draftFailure(err) };
    defer candidate.deinit();
    const action: policy.Action = if (input.action == .deny) .deny else .allow;
    candidate.engine.ip_trie.insertCidr(input.prefix.slice(), action) catch |err| return .{
        .failed = if (err == error.TrieFull) .capacity else .invalid_input,
    };
    const credentials = auth.Credentials.fromAuth(input.auth, now);
    const changes = try stage(owner, credentials, .{
        util.integer(now),
        util.integer(input.expected_revision),
        util.text(input.prefix.slice()),
        .{ .integer = if (input.action == .deny) -100 else 100 },
        if (input.until) |until| util.integer(until) else .null_value,
        util.text(input.note.slice()),
        util.text("console"),
        util.integer(0),
    }, input.expected_revision);
    if (changes == 0) {
        if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
        return .{ .failed = .conflict };
    }
    return .{ .revision = .{
        .committed = input.expected_revision + 1,
        .applied = owner.version,
    } };
}

pub fn remove(owner: *Persistent, input: w.ReputationRemove, now: u64) !p.StorageResult {
    try p.validate(.{ .reputation_remove = input });
    if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT 1 FROM ip_reputation WHERE ip_or_cidr=? LIMIT 1",
        &.{util.text(input.prefix.slice())},
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return .{ .failed = .invalid_input };
    const credentials = auth.Credentials.fromAuth(input.auth, now);
    const changes = try stage(owner, credentials, .{
        util.integer(now),
        util.integer(input.expected_revision),
        util.text(input.prefix.slice()),
        util.integer(0),
        .null_value,
        util.text(""),
        util.text("console"),
        util.integer(1),
    }, input.expected_revision);
    if (changes == 0) {
        if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
        return .{ .failed = .conflict };
    }
    return .{ .revision = .{
        .committed = input.expected_revision + 1,
        .applied = owner.version,
    } };
}

fn stage(
    owner: *Persistent,
    credentials: auth.Credentials,
    values: [8]zx.Value,
    expected: u64,
) !i64 {
    return db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_reputation_stage SELECT 1,u.id," ++ auth.role ++
            ",?,?,?,?,?,?,?,? " ++
            "FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE " ++ auth.predicate ++ "AND " ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')=?",
        &(values ++ credentials.values() ++ [_]zx.Value{util.integer(expected)}),
    );
}
