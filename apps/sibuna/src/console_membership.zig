//! Each node announces itself into the replicated membership table from the storage owner
//! tick: at start, every minute, and after each successfully applied rebuild. A row states
//! facts about its writer only; consoles never probe an address read from this table.
const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const version = @import("server.zig").version;
const heartbeat_seconds = 60;
const retry_seconds = 30;
const coalesce_seconds = 2;

pub fn tick(owner: *Persistent) void {
    // Announcements start with the console's first storage request, which runs migrations,
    // and stop as soon as shutdown begins so the owner thread never blocks on a late write.
    if (!owner.console_initialized or owner.stopping.load(.acquire)) return;
    const state = &owner.console_node;
    const now = owner.nowSeconds();
    const since = now -| state.last_heartbeat;
    const spacing: u64 = if (state.announce_failed) retry_seconds else coalesce_seconds;
    if (since < spacing) return;
    if (!state.announce and since < heartbeat_seconds) return;
    upsert(owner, now) catch |err| {
        if (!state.announce_failed) std.log.warn("console membership not recorded: {t}", .{err});
        state.announce_failed = true;
        state.last_heartbeat = now;
        return;
    };
    state.announce_failed = false;
    state.announce = false;
    state.last_heartbeat = now;
}

fn address(listen: ?[]const u8) []const u8 {
    const value = listen orelse return "local";
    return if (value.len <= p.nodes.max_address) value else "local";
}

fn upsert(owner: *Persistent, now: u64) !void {
    const state = &owner.console_node;
    const boot = std.fmt.bytesToHex(state.boot, .lower);
    _ = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_nodes(node,address,console_url,version,boot,first_seen," ++
            "last_seen,applied_revision,control_revision,applied_slot,decided_slot,draining) " ++
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node) DO UPDATE SET " ++
            "address=excluded.address,console_url=excluded.console_url," ++
            "version=excluded.version,boot=excluded.boot,last_seen=excluded.last_seen," ++
            "applied_revision=excluded.applied_revision," ++
            "control_revision=excluded.control_revision,applied_slot=excluded.applied_slot," ++
            "decided_slot=excluded.decided_slot,draining=excluded.draining",
        &.{
            util.integer(owner.node_id),
            util.text(address(owner.cfg.cluster_listen)),
            util.text(state.advertise.slice()),
            util.text(version),
            util.text(&boot),
            util.integer(now),
            util.integer(now),
            util.integer(owner.version),
            util.integer(state.revision),
            util.integer(state.storage.applied),
            util.integer(state.storage.decided),
            util.integer(@intFromBool(owner.state.draining.load(.acquire))),
        },
    );
}
