//! Atomic set import: documents arrive in chunks, each parsed into canonical columns, and
//! one commit replaces every managed rule after the whole set validated as a candidate.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const w = p.workflows;
const zx = @import("zaxonlite");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");
const auth = @import("console_policy_authorization.zig");
const failure = @import("console_store_policies.zig").draftFailure;

pub fn chunk(owner: *Persistent, input: w.ImportChunk, now: u64) !p.StorageResult {
    try p.validate(.{ .import_chunk = input });
    var memory: [65536]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const document = policy.management.parse(arena.allocator(), input.document.slice()) catch
        return .{ .failed = .invalid_input };
    var header_buffer: [4096]u8 = undefined;
    const headers = try @import("console_policy_write.zig").headerJson(
        &header_buffer,
        document.value,
    );
    var cidr_buffer: [512]u8 = undefined;
    var cidrs: std.Io.Writer = .fixed(&cidr_buffer);
    try std.json.Stringify.value(document.cidrs, .{}, &cidrs);
    var limit_buffer: [256]u8 = undefined;
    var limits: std.Io.Writer = .fixed(&limit_buffer);
    try std.json.Stringify.value(document.value.limits, .{}, &limits);
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT OR REPLACE INTO console_policy_import_stage(digest,ordinal,recorded_at," ++
            "document,policy_id,name,priority,enabled,path_pattern,ua_pattern,action," ++
            "difficulty,algorithm,weight,header_matchers,cidr_matchers,limit_config) " ++
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        &.{
            util.text(&digest),
            util.integer(input.ordinal),
            util.integer(now),
            util.text(input.document.slice()),
            util.text(document.id),
            util.text(document.value.name),
            .{ .integer = document.priority },
            util.integer(@intFromBool(document.enabled)),
            optional(document.value.path_pattern),
            optional(document.value.ua_pattern),
            util.text(@tagName(document.value.action)),
            if (document.value.difficulty) |value| util.integer(value) else .null_value,
            optional(if (document.value.algorithm) |a| a.name() else null),
            .{ .integer = document.value.weight },
            util.text(headers),
            util.text(cidrs.buffered()),
            util.text(limits.buffered()),
        },
    );
    return .command_recorded;
}

fn optional(value: ?[]const u8) zx.Value {
    return if (value) |text| util.text(text) else .null_value;
}

pub fn commit(owner: *Persistent, input: w.ImportCommit, now: u64) !p.StorageResult {
    try p.validate(.{ .import_commit = input });
    if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    const memory = try owner.gpa.alloc(u8, 640 * 1024);
    defer owner.gpa.free(memory);
    var arena = std.heap.FixedBufferAllocator.init(memory);
    var sources: [policy.engine.MAX_RULES][]const u8 = undefined;
    var count: usize = 0;
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT document FROM console_policy_import_stage WHERE digest=? " ++
            "ORDER BY ordinal LIMIT 129",
        &.{util.text(&digest)},
    );
    defer rows.deinit();
    if (rows.rows.len != input.count) return .{ .failed = .invalid_input };
    for (rows.rows) |cells| {
        const document = cells[0] orelse return error.InvalidStoredPolicy;
        sources[count] = try arena.allocator().dupe(u8, document);
        count += 1;
    }
    var candidate = candidates.fromSources(
        owner,
        input.expected_revision,
        sources[0..count],
        now,
    ) catch |err| return .{ .failed = failure(err) };
    candidate.deinit();
    const credentials = auth.Credentials.fromAuth(input.auth, now);
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_policy_import_commit SELECT 1,u.id," ++ auth.role ++ ",?,?,?,?,? " ++
            "FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE " ++ auth.predicate ++ "AND " ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')=?",
        &([_]zx.Value{
            util.integer(now),
            util.integer(input.expected_revision),
            util.text(&digest),
            util.integer(input.count),
            credentials.address(),
        } ++ credentials.values() ++ [_]zx.Value{util.integer(input.expected_revision)}),
    );
    if (changes == 0) {
        if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
        return .{ .failed = .conflict };
    }
    return .{ .revision = .{
        .committed = input.expected_revision + 1,
        .applied = owner.version,
    } };
}
