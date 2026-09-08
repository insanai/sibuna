//! The storage/control owner serializes intent, local effect and completion. SQL commit
//! is not atomic with runtime state: a single retained completion prevents unsafe retries.
const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const access = @import("console_node_access.zig");
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const reads = @import("console_node_read.zig");

pub fn execute(owner: *Persistent, input: p.nodes.Command) !p.StorageResult {
    try p.nodes.validate(input);
    if (try access.check(owner, input.auth, true)) |reason| return .{ .failed = reason };
    if (input.node != owner.node_id) return .{ .failed = .invalid_input };
    if (try reads.load(owner, input.id)) |previous| {
        if (!matches(previous, input)) return .{ .failed = .conflict };
        return .{ .node_receipt = previous };
    }
    if (!std.mem.eql(u8, &input.boot, &owner.console_node.boot) or
        input.expected_revision != owner.console_node.revision) return .{ .failed = .conflict };
    if (owner.console_node.pending != null) return .{ .failed = .unavailable };
    const now = owner.nowSeconds();
    if (input.expires <= now or input.expires - now > p.nodes.command_seconds)
        return .{ .failed = .invalid_input };
    try prune(owner, now);
    if (!try intent(owner, input, now)) return .{ .failed = .unavailable };
    var receipt: p.nodes.Receipt = .{
        .id = try p.Bytes(32).init(&std.fmt.bytesToHex(input.id, .lower)),
        .boot = try p.Bytes(32).init(&std.fmt.bytesToHex(input.boot, .lower)),
        .node = input.node,
        .kind = input.kind,
        .state = .rejected,
        .expected_revision = input.expected_revision,
        .requested_at = now,
        .completed_at = owner.nowSeconds(),
    };
    // A remote intent commit can span expiry or revocation. No effect uses that old grant.
    if ((try access.check(owner, input.auth, true)) == null and
        owner.nowSeconds() < input.expires)
    {
        switch (input.kind) {
            .drain => owner.state.draining.store(true, .release),
            .@"resume" => owner.state.draining.store(false, .release),
            .clear_local_bans => {
                receipt.cleared_entries = owner.state.bans.clear(owner.nowSeconds());
            },
        }
        owner.console_node.revision += 1;
        receipt.applied_revision = owner.console_node.revision;
        receipt.state = .applied;
    }
    receipt.completed_at = owner.nowSeconds();
    owner.console_node.pending = receipt;
    flush(owner) catch return .{ .node_receipt = receipt };
    receipt.completion_persisted = true;
    return .{ .node_receipt = receipt };
}

fn matches(receipt: p.nodes.Receipt, input: p.nodes.Command) bool {
    const boot = std.fmt.bytesToHex(input.boot, .lower);
    return receipt.node == input.node and receipt.kind == input.kind and
        receipt.expected_revision == input.expected_revision and
        std.mem.eql(u8, receipt.boot.slice(), &boot);
}

fn intent(owner: *Persistent, input: p.nodes.Command, now: u64) !bool {
    const id = std.fmt.bytesToHex(input.id, .lower);
    const boot = std.fmt.bytesToHex(input.boot, .lower);
    const digest = std.fmt.bytesToHex(input.auth.session_digest, .lower);
    const csrf = std.fmt.bytesToHex(input.auth.csrf_digest, .lower);
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_commands(id,node,boot,kind,expected_revision,requested_at," ++
            "actor,actor_role) SELECT ?,?,?,?,?,?,u.id,u.role FROM console_sessions s " ++
            "JOIN console_users u ON u.id=s.user_id WHERE s.digest=? AND s.csrf_digest=? " ++
            "AND s.token_id IS NULL AND MIN(s.expires,s.idle_expires)>? " ++
            "AND u.revision=s.revision AND u.disabled=0 AND u.must_change=0 " ++
            "AND u.role IN ('operator','admin') AND (?=0 OR u.role!='admin' OR " ++
            "EXISTS(SELECT 1 FROM console_totp t WHERE t.user_id=u.id AND t.enabled=1)) " ++
            "AND (SELECT COUNT(*) FROM console_commands WHERE node=?)<4096",
        &.{
            util.text(&id),
            util.integer(input.node),
            util.text(&boot),
            util.text(@tagName(input.kind)),
            util.integer(input.expected_revision),
            util.integer(now),
            util.text(&digest),
            util.text(&csrf),
            util.integer(now),
            util.integer(@intFromBool(input.auth.require_totp)),
            util.integer(input.node),
        },
    );
    // Zaxonlite reports total changes, including the atomic audit trigger.
    return changes > 0;
}

/// Called once per owner tick. A failed transaction retains the exact result for retry;
/// a clear command is never re-executed to reconstruct its missing completion.
pub fn flush(owner: *Persistent) !void {
    const receipt = owner.console_node.pending orelse return;
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "UPDATE console_commands SET state=?,completed_at=?,applied_revision=?," ++
            "cleared_entries=? WHERE id=? AND boot=? AND (state='intent' OR " ++
            "(state=? AND completed_at=? AND applied_revision IS ? AND cleared_entries IS ?))",
        &.{
            util.text(@tagName(receipt.state)),
            util.integer(receipt.completed_at.?),
            if (receipt.applied_revision) |value| util.integer(value) else .null_value,
            if (receipt.cleared_entries) |value| util.integer(value) else .null_value,
            util.text(receipt.id.slice()),
            util.text(receipt.boot.slice()),
            util.text(@tagName(receipt.state)),
            util.integer(receipt.completed_at.?),
            if (receipt.applied_revision) |value| util.integer(value) else .null_value,
            if (receipt.cleared_entries) |value| util.integer(value) else .null_value,
        },
    );
    if (changes <= 0) return error.CompletionConflict;
    owner.console_node.pending = null;
}

fn prune(owner: *Persistent, now: u64) !void {
    const boot = std.fmt.bytesToHex(owner.console_node.boot, .lower);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "DELETE FROM console_commands WHERE id IN (SELECT id FROM console_commands " ++
            "WHERE node=? AND requested_at<? AND (boot!=? OR state!='intent') " ++
            "ORDER BY requested_at,id LIMIT 16)",
        &.{
            util.integer(owner.node_id),
            util.integer(now -| (p.nodes.receipt_days * 86400)),
            util.text(&boot),
        },
    );
}
