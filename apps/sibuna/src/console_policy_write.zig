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
const auth = @import("console_policy_authorization.zig");

pub fn edit(owner: *Persistent, input: p.policies.Edit) !p.StorageResult {
    try p.validate(.{ .policy_edit = input });
    if (try auth.check(owner, input)) |reason| return .{ .failed = reason };
    var candidate = candidates.build(
        owner,
        input.expected_revision,
        input.document.slice(),
        owner.nowSeconds(),
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
        if (try auth.check(owner, input)) |reason| return .{ .failed = reason };
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
    const credentials = auth.Credentials.init(input, owner.nowSeconds());
    var header_buffer: [4096]u8 = undefined;
    const headers = try headerJson(&header_buffer, document.value);
    var cidr_buffer: [512]u8 = undefined;
    var cidrs: std.Io.Writer = .fixed(&cidr_buffer);
    try std.json.Stringify.value(document.cidrs, .{}, &cidrs);
    var limit_buffer: [256]u8 = undefined;
    var limits: std.Io.Writer = .fixed(&limit_buffer);
    try std.json.Stringify.value(document.value.limits, .{}, &limits);
    return db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_policy_stage SELECT 1,u.id,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? " ++
            "FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE " ++ auth.predicate ++ "AND " ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')=?",
        &([_]zx.Value{
            util.integer(credentials.now),
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
            util.text(limits.buffered()),
        } ++ credentials.values() ++ [_]zx.Value{util.integer(input.expected_revision)}),
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
