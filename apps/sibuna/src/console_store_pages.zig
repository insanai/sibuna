//! Page templates execute on the storage owner. An edit is compiled with the same
//! validator the engine uses before it is staged; a reset deletes the stored row so the
//! built-in page returns at the next rebuild. Audit rows carry digests and sizes only.
const std = @import("std");
const p = @import("console").protocol;
const policy = @import("policy");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const settings = @import("console_store_settings.zig");
const authorization = @import("console_policy_authorization.zig");
const defaults = @import("console_pages_load.zig");

pub fn read(owner: *Persistent, input: p.pages.Read, now: u64) !p.StorageResult {
    if (try settings.admin(owner, input.auth, now) == null) return .{ .failed = .forbidden };
    return .{ .page_document = try document(owner, input.kind) };
}

/// The caller owns the returned document's HTML block.
pub fn document(owner: *Persistent, kind: p.pages.Kind) !p.pages.Document {
    const html = try owner.gpa.create(p.pages.Html);
    errdefer owner.gpa.destroy(html);
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT html,sha256,revision FROM console_pages WHERE kind=? LIMIT 1",
        &.{util.text(@tagName(kind))},
    );
    defer rows.deinit();
    if (rows.rows.len == 1) {
        const cells = rows.rows[0];
        try html.set(cells[0] orelse "");
        return .{
            .kind = kind,
            .revision = try util.number(cells[2]),
            .customized = true,
            .sha256 = try p.Bytes(64).init(cells[1] orelse ""),
            .html = html,
        };
    }
    const source = defaults.source(kind);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    try html.set(source);
    return .{
        .kind = kind,
        .revision = 0,
        .customized = false,
        .sha256 = try p.Bytes(64).init(&std.fmt.bytesToHex(digest, .lower)),
        .html = html,
    };
}

pub fn edit(owner: *Persistent, input: p.pages.Edit, now: u64) !p.StorageResult {
    p.pages.validateEdit(input) catch return .{ .failed = .invalid_input };
    const actor = try settings.admin(owner, input.auth, now) orelse
        return .{ .failed = .forbidden };
    const kind: policy.page_template.Kind = @enumFromInt(@intFromEnum(input.kind));
    const html: []const u8 = if (input.html) |block| block.slice() else "";
    if (!input.reset) {
        const scratch = try owner.gpa.create(policy.page_template.Template);
        defer owner.gpa.destroy(scratch);
        policy.page_template.compile(kind, html, scratch) catch
            return .{ .failed = .invalid_input };
    }
    const current = try document(owner, input.kind);
    defer owner.gpa.destroy(current.html);
    if (current.revision != input.expected_revision) return .{ .failed = .conflict };
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(html, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const changed = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_page_stage(id,actor,actor_role,recorded_at,kind," ++
            "expected_revision,reset,html,sha256,bytes,previous_sha256,previous_bytes," ++
            "client_ip) VALUES(1,?,'admin',?,?,?,?,?,?,?,?,?,?)",
        &.{
            util.integer(actor),
            util.integer(now),
            util.text(@tagName(input.kind)),
            util.integer(input.expected_revision),
            util.integer(@intFromBool(input.reset)),
            if (input.reset) nul() else util.text(html),
            if (input.reset) nul() else util.text(&hex),
            util.integer(html.len),
            if (current.customized) util.text(current.sha256.slice()) else nul(),
            if (current.customized) util.integer(current.html.len) else nul(),
            util.address(&input.auth.client),
        },
    );
    if (changed == 0) return .{ .failed = .conflict };
    _ = authorization;
    return .command_recorded;
}

fn nul() @import("zaxonlite").Value {
    return .null_value;
}
