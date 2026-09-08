//! Candidate validation precedes one conditional statement committing policy, history and audit.
//! The following storage tick publishes an engine; a committed edit is not an applied revision.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const zx = @import("zaxonlite");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");
const failure = @import("console_store_policies.zig").draftFailure;

pub fn edit(owner: *Persistent, input: p.policies.Edit) !p.StorageResult {
    try p.validate(.{ .policy_edit = input });
    const identity = try util.authorize(owner, input.session_digest, input.now);
    if (identity != .authorized or identity.authorized.must_change)
        return .{ .failed = .unauthorized };
    if (!identity.authorized.role.allows(.manage_policy)) return .{ .failed = .forbidden };
    if (!std.crypto.timing_safe.eql([32]u8, input.csrf_digest, identity.authorized.csrf_digest))
        return .{ .failed = .forbidden };
    var candidate = candidates.build(
        owner,
        input.expected_revision,
        input.document.slice(),
        input.now,
    ) catch |err| return .{ .failed = failure(err) };
    defer candidate.deinit();
    var memory: [65536]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const document = try policy.management.parse(arena.allocator(), input.document.slice());
    const previous = candidates.readDocument(
        owner,
        document.id,
    ) catch |err| switch (failure(err)) {
        .invalid_input => null,
        else => return err,
    };
    const changes = try commit(owner, input, document, previous);
    if (changes == 0) {
        const current = try util.authorize(owner, input.session_digest, input.now);
        if (current != .authorized or current.authorized.must_change)
            return .{ .failed = .unauthorized };
        if (!current.authorized.role.allows(.manage_policy)) return .{ .failed = .forbidden };
        return .{ .failed = .conflict };
    }
    return .{ .revision = .{
        .committed = input.expected_revision + 1,
        .applied = owner.version,
    } };
}

fn commit(
    owner: *Persistent,
    input: p.policies.Edit,
    document: policy.management.Document,
    previous: ?p.Bytes(4096),
) !i64 {
    const digest = std.fmt.bytesToHex(input.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.csrf_digest, .lower);
    var header_buffer: [4096]u8 = undefined;
    const headers = try headerJson(&header_buffer, document.value);
    var cidr_buffer: [512]u8 = undefined;
    var cidrs: std.Io.Writer = .fixed(&cidr_buffer);
    try std.json.Stringify.value(document.cidrs, .{}, &cidrs);
    return db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_policy_stage SELECT 1,u.id,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? " ++
            "FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE s.digest=? AND s.csrf_digest=? AND MIN(s.expires,s.idle_expires)>? " ++
            "AND u.disabled=0 AND u.must_change=0 AND u.role IN ('operator','admin') " ++
            "AND u.revision=s.revision AND " ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')=?",
        &.{
            util.integer(input.now),
            util.integer(input.expected_revision),
            util.text(input.document.slice()),
            if (previous) |*value| util.text(value.slice()) else .null_value,
            util.text(document.id),
            util.text(document.value.name),
            .{ .integer = document.priority },
            util.integer(@intFromBool(document.enabled)),
            optionalText(document.value.path_pattern),
            optionalText(document.value.ua_pattern),
            util.text(@tagName(document.value.action)),
            if (document.value.difficulty) |value| util.integer(value) else .null_value,
            optionalText(document.value.algorithm),
            .{ .integer = document.value.weight },
            util.text(headers),
            util.text(cidrs.buffered()),
            util.text(&digest),
            util.text(&csrf),
            util.integer(input.now),
            util.integer(input.expected_revision),
        },
    );
}

fn optionalText(value: ?[]const u8) zx.Value {
    return if (value) |text| util.text(text) else .null_value;
}

fn headerJson(buffer: []u8, value: policy.PolicyRule) ![]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.writeByte('{');
    for (value.headers[0..value.header_count], 0..) |header, i| {
        if (i != 0) try writer.writeByte(',');
        try std.json.Stringify.value(header.name, .{}, &writer);
        try writer.writeByte(':');
        try std.json.Stringify.value(header.pattern, .{}, &writer);
    }
    try writer.writeByte('}');
    return writer.buffered();
}
