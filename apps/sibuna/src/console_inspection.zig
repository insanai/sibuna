//! Settings and their audit/history publish together. Runtime application is a later tick.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");

pub fn edit(owner: *Persistent, input: p.policies.Edit) !p.StorageResult {
    try p.validate(.{ .inspection_edit = input });
    if (try authorize(owner, input)) |failure| return .{ .failed = failure };
    var memory: [16384]u8 = undefined;
    var allocator = std.heap.FixedBufferAllocator.init(&memory);
    // Management replaces the complete matrix; omitted categories must not silently
    // return to enforcement. The compatible file loader still accepts partial defaults.
    const fields = std.json.parseFromSliceLeaky(
        struct {
            path_traversal: policy.inspection.Mode,
            sqli: policy.inspection.Mode,
            xss: policy.inspection.Mode,
            rce: policy.inspection.Mode,
        },
        allocator.allocator(),
        input.document.slice(),
        .{},
    ) catch return .{ .failed = .invalid_input };
    const modes: policy.inspection.Modes = .{
        .path_traversal = fields.path_traversal,
        .sqli = fields.sqli,
        .xss = fields.xss,
        .rce = fields.rce,
    };
    var candidate = candidates.current(owner, input.expected_revision, input.now) catch |err|
        return .{ .failed = @import("console_store_policies.zig").draftFailure(err) };
    defer candidate.deinit();
    var previous: [256]u8 = undefined;
    const before = try encode(&previous, candidate.engine.inspection_modes);
    candidate.engine.inspection_modes = modes;
    var document: [256]u8 = undefined;
    const after = try encode(&document, modes);
    const changes = try commit(owner, input, modes, before, after);
    if (changes == 0) {
        if (try authorize(owner, input)) |failure| return .{ .failed = failure };
        return .{ .failed = .conflict };
    }
    return .{ .revision = .{
        .committed = input.expected_revision + 1,
        .applied = owner.version,
    } };
}

fn authorize(owner: *Persistent, input: p.policies.Edit) !?p.Failure {
    const identity = try util.authorize(owner, input.session_digest, input.now);
    if (identity != .authorized or identity.authorized.must_change) return .unauthorized;
    if (!identity.authorized.role.allows(.manage_policy)) return .forbidden;
    if (!std.crypto.timing_safe.eql([32]u8, input.csrf_digest, identity.authorized.csrf_digest))
        return .forbidden;
    return null;
}

fn encode(buffer: []u8, modes: policy.inspection.Modes) ![]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    try std.json.Stringify.value(modes, .{}, &writer);
    return writer.buffered();
}

fn commit(
    owner: *Persistent,
    input: p.policies.Edit,
    modes: policy.inspection.Modes,
    before: []const u8,
    after: []const u8,
) !i64 {
    const digest = std.fmt.bytesToHex(input.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.csrf_digest, .lower);
    return db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_inspection_stage SELECT 1,u.id,?,?,?,?,?,?,?,? " ++
            "FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE s.digest=? AND s.csrf_digest=? AND MIN(s.expires,s.idle_expires)>? " ++
            "AND u.disabled=0 AND u.must_change=0 AND u.role IN ('operator','admin') " ++
            "AND u.revision=s.revision AND " ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')=?",
        &.{
            util.integer(input.now),
            util.integer(input.expected_revision),
            util.text(after),
            util.text(before),
            util.text(@tagName(modes.path_traversal)),
            util.text(@tagName(modes.sqli)),
            util.text(@tagName(modes.xss)),
            util.text(@tagName(modes.rce)),
            util.text(&digest),
            util.text(&csrf),
            util.integer(input.now),
            util.integer(input.expected_revision),
        },
    );
}
