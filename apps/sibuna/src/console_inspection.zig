//! Settings and their audit/history publish together. Runtime application is a later tick.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");
const auth = @import("console_policy_authorization.zig");

pub fn edit(owner: *Persistent, input: p.policies.Edit) !p.StorageResult {
    try p.validate(.{ .inspection_edit = input });
    if (try auth.check(owner, input)) |failure| return .{ .failed = failure };
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
    var candidate = candidates.current(
        owner,
        input.expected_revision,
        owner.nowSeconds(),
    ) catch |err|
        return .{ .failed = @import("console_store_policies.zig").draftFailure(err) };
    defer candidate.deinit();
    var previous: [256]u8 = undefined;
    const before = try encode(&previous, candidate.engine.inspection_modes);
    candidate.engine.inspection_modes = modes;
    var document: [256]u8 = undefined;
    const after = try encode(&document, modes);
    const changes = try commit(owner, input, modes, before, after);
    if (changes == 0) {
        if (try auth.check(owner, input)) |failure| return .{ .failed = failure };
        return .{ .failed = .conflict };
    }
    return .{ .revision = .{
        .committed = input.expected_revision + 1,
        .applied = owner.version,
    } };
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
    const credentials = auth.Credentials.init(input, owner.nowSeconds());
    return db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_inspection_stage SELECT 1,u.id,?,?,?,?,?,?,?,?," ++
            auth.role ++ " " ++
            "FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE " ++ auth.predicate ++ "AND " ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')=?",
        &([_]@import("zaxonlite").Value{
            util.integer(credentials.now),
            util.integer(input.expected_revision),
            util.text(after),
            util.text(before),
            util.text(@tagName(modes.path_traversal)),
            util.text(@tagName(modes.sqli)),
            util.text(@tagName(modes.xss)),
            util.text(@tagName(modes.rce)),
        } ++ credentials.values() ++ [_]@import("zaxonlite").Value{
            util.integer(input.expected_revision),
        }),
    );
}
