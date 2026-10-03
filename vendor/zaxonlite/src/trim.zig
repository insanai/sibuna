//! Conservative log trimming: policy and the durable TRIM record
//! (ZDS 0011).
//!
//! The cluster trim `G` is a chosen Paxos entry, computed under the v1
//! policy as the minimum durable-state frontier of every current data
//! replica: nothing is proposed for deletion until every replica that
//! materializes SQLite could recover from its own applied anchor without
//! the trimmed prefix. Witnesses vote but never report a durable-state
//! frontier and never count toward the minimum.
//!
//! Choosing `G` authorizes nothing locally by itself. Physical deletion
//! is governed by the local delete floor
//!
//!     T_i = min(G, A_i, retention_cutoff, min lease base)
//!
//! so a node whose own anchor regressed after disk repair, a configured
//! retention horizon, and any active transfer lease each independently
//! cap what may be unlinked. The `TRIM` file makes the adopted anchor and
//! the active leases durable before any segment is removed; after a
//! restart it is the local authority for both.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

const command = @import("command.zig");
const durability = @import("durability.zig");
const failpoint = @import("failpoint.zig");
const paxos = @import("paxos");

const magic: u32 = 0x5254585a; // "ZXTR" in file byte order.
const version: u16 = 2;

pub const file_name = "TRIM";

/// Test-only control for paths whose required error diagnostics would make
/// Zig's test runner fail an otherwise expected invariant test.
pub const test_options = if (builtin.is_test) struct {
    pub var suppress_adoption_log = false;
} else struct {};

/// Concurrent transfer leases are bounded; one repair or replacement at a
/// time is the product shape, with headroom.
pub const max_leases = 4;

pub const Lease = struct {
    lease_id: u64,
    receiver_id: u32,
    base_slot: u64,
    expiry_ticks_left: u32,
};

/// The durable local trim state: the adopted cluster anchor plus every
/// active lease capping deletion.
pub const State = struct {
    /// Global Paxos slot of the chosen trim command.
    decision_slot: u64 = 0,
    through_slot: u64 = 0,
    history_hash: [32]u8 = @as([32]u8, @splat(0)),
    configuration_id: u64 = 0,
    lease_count: u8 = 0,
    leases: [max_leases]Lease = undefined,

    pub fn leasesSlice(self: *const State) []const Lease {
        return self.leases[0..self.lease_count];
    }
};

/// One replica's reported progress, as carried by state reports.
pub const Frontier = struct {
    node_id: paxos.NodeId,
    configuration_id: u64,
    durable_state_slot: u64,
    history_hash: [32]u8,
    executed_slot: u64,
    persisted_slot: u64,
    local_delete_floor: u64,
};

pub const Candidate = struct {
    through_slot: u64,
    history_hash: [32]u8,
};

pub const PolicyError = error{
    /// Two replicas reported the same durable slot under different
    /// history anchors: divergence, never something to trim over.
    HistoryMismatch,
};

/// The conservative v1 candidate: the minimum durable-state frontier over
/// `data_replicas`, with its history anchor. Returns null unless every
/// data replica has a fresh report for `configuration_id`; a permanently
/// missing replica freezes trimming until it recovers or is replaced
/// (ZDS 0008), which is the deliberate first-release behavior.
pub fn candidate(
    frontiers: []const ?Frontier,
    data_replicas: []const paxos.NodeId,
    configuration_id: u64,
) PolicyError!?Candidate {
    var minimum: ?Candidate = null;
    for (data_replicas) |id| {
        const frontier = findFrontier(frontiers, id, configuration_id) orelse return null;
        if (minimum == null or frontier.durable_state_slot < minimum.?.through_slot) {
            minimum = .{
                .through_slot = frontier.durable_state_slot,
                .history_hash = frontier.history_hash,
            };
        }
    }
    const chosen = minimum orelse return null;
    // Every replica at exactly the minimum must agree on the anchor.
    for (data_replicas) |id| {
        const frontier = findFrontier(frontiers, id, configuration_id).?;
        if (frontier.durable_state_slot == chosen.through_slot and
            !std.mem.eql(u8, &frontier.history_hash, &chosen.history_hash))
        {
            return error.HistoryMismatch;
        }
    }
    if (chosen.through_slot == 0) return null;
    return chosen;
}

fn findFrontier(
    frontiers: []const ?Frontier,
    id: paxos.NodeId,
    configuration_id: u64,
) ?Frontier {
    for (frontiers) |slot| {
        const frontier = slot orelse continue;
        if (frontier.node_id == id and frontier.configuration_id == configuration_id) {
            return frontier;
        }
    }
    return null;
}

/// The local delete floor: never past the chosen trim, the local durable
/// state, the configured retention cutoff, or any active lease base.
pub fn deleteFloor(
    chosen_trim: u64,
    durable_state_slot: u64,
    retention_cutoff: u64,
    leases: []const Lease,
) u64 {
    var floor = @min(chosen_trim, durable_state_slot);
    floor = @min(floor, retention_cutoff);
    for (leases) |lease| {
        floor = @min(floor, lease.base_slot);
    }
    return floor;
}

/// Classifies a chosen trim against the already durable anchor. Exact replay
/// is idempotent. Older decisions and later decisions that authorize no more
/// deletion are safe to ignore: retaining more history cannot violate a
/// GlobalTrim invariant, and recovery's page-image replay treats maintenance
/// commands the same way. A decision-slot twin or a different history at the
/// same trim frontier is durable-history divergence and remains fatal.
pub const Adoption = enum {
    adopt,
    ignore_replay,
    ignore_stale,
    ignore_duplicate,
    diverged,
};

pub fn classify(
    state: *const State,
    decision_slot: u64,
    record: command.TrimRecord,
) Adoption {
    if (decision_slot == state.decision_slot) {
        const same = record.through_slot == state.through_slot and
            record.configuration_id == state.configuration_id and
            std.mem.eql(u8, &record.history_hash, &state.history_hash);
        return if (same) .ignore_replay else .diverged;
    }
    if (decision_slot < state.decision_slot) return .ignore_stale;
    if (record.through_slot < state.through_slot) return .ignore_stale;
    if (record.through_slot == state.through_slot) {
        const same_history = record.configuration_id == state.configuration_id and
            std.mem.eql(u8, &record.history_hash, &state.history_hash);
        return if (same_history) .ignore_duplicate else .diverged;
    }
    return .adopt;
}

/// Applies the classified trim outcome to a node host. Keeping the transition
/// beside `classify` makes the safe-ignore and fatal-divergence cases share one
/// policy boundary; `node.zig` supplies the durable stores and Paxos adapter.
pub fn adoptChosen(node: anytype, decision_slot: u64, record: command.TrimRecord) !void {
    const adoption = classify(&node.trim_state, decision_slot, record);
    switch (adoption) {
        .ignore_replay => return,
        .ignore_stale, .ignore_duplicate => {
            logAdoption(node.trim_state, adoption, decision_slot, record);
            node.trim_ignored_count +|= 1;
            return;
        },
        .diverged => {
            logAdoption(node.trim_state, adoption, decision_slot, record);
            node.fatal_storage_error = true;
            return error.TrimRegression;
        },
        .adopt => {},
    }
    node.trim_state.decision_slot = decision_slot;
    node.trim_state.through_slot = record.through_slot;
    node.trim_state.history_hash = record.history_hash;
    node.trim_state.configuration_id = record.configuration_id;
    failpoint.hit("before_trim_file");
    store(node.io, node.journal.dir, node.trim_state) catch |err| {
        node.fatal_storage_error = true;
        return err;
    };
    failpoint.hit("after_trim_file");
    node.log.installChosenTrim(.{
        .trim_id = decision_slot,
        .chosen_trim_slot = record.through_slot,
        .history_hash = record.history_hash,
    }, node.effects) catch |err| {
        node.fatal_storage_error = true;
        return err;
    };
    node.journal.noteTrimAnchor(
        decision_slot,
        record.through_slot,
        record.history_hash,
    );
}

fn logAdoption(
    state: State,
    adoption: Adoption,
    decision_slot: u64,
    record: command.TrimRecord,
) void {
    if (builtin.is_test and test_options.suppress_adoption_log) return;
    std.log.err(
        "trim {s}: decision={d} adopted=({d},{d}," ++
            "{x:0>2}{x:0>2}{x:0>2}{x:0>2}) record=({d}," ++
            "{x:0>2}{x:0>2}{x:0>2}{x:0>2})",
        .{
            @tagName(adoption),     decision_slot,
            state.decision_slot,    state.through_slot,
            state.history_hash[0],  state.history_hash[1],
            state.history_hash[2],  state.history_hash[3],
            record.through_slot,    record.history_hash[0],
            record.history_hash[1], record.history_hash[2],
            record.history_hash[3],
        },
    );
}

/// Persists a newly chosen transfer lease. Capacity overflow is a
/// deterministic no-op; the sender's pinned image remains the safety owner.
pub fn trackLease(node: anytype, lease: command.TransferLease) !void {
    for (node.trim_state.leasesSlice()) |held| {
        if (held.lease_id == lease.lease_id) return;
    }
    if (node.trim_state.lease_count >= max_leases) return;
    node.trim_state.leases[node.trim_state.lease_count] = .{
        .lease_id = lease.lease_id,
        .receiver_id = lease.receiver_id,
        .base_slot = lease.base_slot,
        .expiry_ticks_left = lease.expires_after_leader_ticks,
    };
    node.trim_state.lease_count += 1;
    store(node.io, node.journal.dir, node.trim_state) catch |err| {
        node.fatal_storage_error = true;
        return err;
    };
}

/// Removes and persists a chosen transfer lease, or does nothing when replay
/// has already removed it.
pub fn releaseLease(node: anytype, lease_id: u64) !void {
    var index: u8 = 0;
    while (index < node.trim_state.lease_count) : (index += 1) {
        if (node.trim_state.leases[index].lease_id == lease_id) break;
    } else return;
    node.trim_state.lease_count -= 1;
    node.trim_state.leases[index] = node.trim_state.leases[node.trim_state.lease_count];
    store(node.io, node.journal.dir, node.trim_state) catch |err| {
        node.fatal_storage_error = true;
        return err;
    };
}

const record_size = 4 + 2 + 2 + 8 + 8 + 32 + 8 + 1 +
    max_leases * lease_size + 32;
const lease_size = 8 + 4 + 8 + 4;

/// Durably writes the trim state by atomic replace.
pub fn store(io: Io, dir: Io.Dir, state: State) !void {
    var bytes = @as([record_size]u8, @splat(0));
    var offset: usize = 0;
    writeInt(u32, &bytes, &offset, magic);
    writeInt(u16, &bytes, &offset, version);
    writeInt(u16, &bytes, &offset, 0);
    writeInt(u64, &bytes, &offset, state.decision_slot);
    writeInt(u64, &bytes, &offset, state.through_slot);
    writeBytes(&bytes, &offset, &state.history_hash);
    writeInt(u64, &bytes, &offset, state.configuration_id);
    bytes[offset] = state.lease_count;
    offset += 1;
    for (state.leasesSlice()) |lease| {
        writeInt(u64, &bytes, &offset, lease.lease_id);
        writeInt(u32, &bytes, &offset, lease.receiver_id);
        writeInt(u64, &bytes, &offset, lease.base_slot);
        writeInt(u32, &bytes, &offset, lease.expiry_ticks_left);
    }
    offset = record_size - 32;
    var checksum: [32]u8 = undefined;
    Sha256.hash(bytes[0..offset], &checksum, .{});
    writeBytes(&bytes, &offset, &checksum);

    var atomic = try dir.createFileAtomic(io, file_name, .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writePositionalAll(io, &bytes, 0);
    try durability.syncFile(io, atomic.file);
    try atomic.replace(io);
    try durability.syncPathnameTransition(io, dir, file_name);
}

pub const LoadError = error{ CorruptTrimRecord, UnsupportedTrimVersion };

/// Reads the durable trim state; a missing file is a fresh database. A
/// malformed record fails closed rather than permitting deletion.
pub fn load(io: Io, dir: Io.Dir) !?State {
    const file = dir.openFile(io, file_name, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    var bytes: [record_size]u8 = undefined;
    const read = file.readPositionalAll(io, &bytes, 0) catch
        return error.CorruptTrimRecord;
    if (read != record_size) return error.CorruptTrimRecord;

    var expected: [32]u8 = undefined;
    Sha256.hash(bytes[0 .. record_size - 32], &expected, .{});
    if (!std.mem.eql(u8, &expected, bytes[record_size - 32 ..])) {
        return error.CorruptTrimRecord;
    }

    var offset: usize = 0;
    if (readInt(u32, &bytes, &offset) != magic) return error.CorruptTrimRecord;
    if (readInt(u16, &bytes, &offset) != version) return error.UnsupportedTrimVersion;
    if (readInt(u16, &bytes, &offset) != 0) return error.CorruptTrimRecord;
    var state = State{
        .decision_slot = readInt(u64, &bytes, &offset),
        .through_slot = readInt(u64, &bytes, &offset),
    };
    readBytes(&bytes, &offset, &state.history_hash);
    state.configuration_id = readInt(u64, &bytes, &offset);
    state.lease_count = bytes[offset];
    offset += 1;
    if (state.lease_count > max_leases) return error.CorruptTrimRecord;
    for (state.leases[0..state.lease_count]) |*lease| {
        lease.lease_id = readInt(u64, &bytes, &offset);
        lease.receiver_id = readInt(u32, &bytes, &offset);
        lease.base_slot = readInt(u64, &bytes, &offset);
        lease.expiry_ticks_left = readInt(u32, &bytes, &offset);
    }
    return state;
}

fn writeInt(comptime T: type, out: *[record_size]u8, offset: *usize, value: T) void {
    std.mem.writeInt(T, out[offset.*..][0..@sizeOf(T)], value, .little);
    offset.* += @sizeOf(T);
}

fn writeBytes(out: *[record_size]u8, offset: *usize, value: []const u8) void {
    @memcpy(out[offset.*..][0..value.len], value);
    offset.* += value.len;
}

fn readInt(comptime T: type, bytes: *const [record_size]u8, offset: *usize) T {
    const value = std.mem.readInt(T, bytes[offset.*..][0..@sizeOf(T)], .little);
    offset.* += @sizeOf(T);
    return value;
}

fn readBytes(bytes: *const [record_size]u8, offset: *usize, out: []u8) void {
    @memcpy(out, bytes[offset.*..][0..out.len]);
    offset.* += out.len;
}

const testing = std.testing;

fn testFrontier(id: paxos.NodeId, applied: u64, hash_byte: u8) Frontier {
    return .{
        .node_id = id,
        .configuration_id = 1,
        .durable_state_slot = applied,
        .history_hash = @as([32]u8, @splat(hash_byte)),
        .executed_slot = applied + 5,
        .persisted_slot = applied + 10,
        .local_delete_floor = 0,
    };
}

test "the candidate is the minimum data-replica frontier and needs every report" {
    const data = [_]paxos.NodeId{ 1, 2 };
    var frontiers = [_]?Frontier{ testFrontier(1, 300, 1), null, testFrontier(3, 50, 9) };

    // Replica 2 has not reported: no candidate, trimming stays frozen.
    try testing.expectEqual(@as(?Candidate, null), try candidate(&frontiers, &data, 1));

    frontiers[1] = testFrontier(2, 200, 2);
    const chosen = (try candidate(&frontiers, &data, 1)).?;
    try testing.expectEqual(@as(u64, 200), chosen.through_slot);
    try testing.expectEqual(@as(u8, 2), chosen.history_hash[0]);

    // A stale-configuration report does not count.
    frontiers[1].?.configuration_id = 99;
    try testing.expectEqual(@as(?Candidate, null), try candidate(&frontiers, &data, 1));

    // Two replicas at the minimum slot with different anchors is
    // divergence, not a trim opportunity.
    frontiers[1] = testFrontier(2, 200, 2);
    frontiers[0] = testFrontier(1, 200, 1);
    try testing.expectError(error.HistoryMismatch, candidate(&frontiers, &data, 1));
}

test "the delete floor honors trim, local state, retention, and leases" {
    const no_leases = [_]Lease{};
    try testing.expectEqual(
        @as(u64, 150),
        deleteFloor(200, 150, 1000, &no_leases),
    );
    try testing.expectEqual(
        @as(u64, 120),
        deleteFloor(200, 150, 120, &no_leases),
    );
    const leases = [_]Lease{.{
        .lease_id = 1,
        .receiver_id = 4,
        .base_slot = 90,
        .expiry_ticks_left = 100,
    }};
    try testing.expectEqual(
        @as(u64, 90),
        deleteFloor(200, 150, 1000, &leases),
    );
}

test "trim adoption distinguishes replay stale duplicate and divergence" {
    const state = State{
        .decision_slot = 20,
        .through_slot = 100,
        .history_hash = @as([32]u8, @splat(1)),
        .configuration_id = 1,
    };
    const same = command.TrimRecord{
        .through_slot = 100,
        .history_hash = @as([32]u8, @splat(1)),
        .configuration_id = 1,
        .policy = 0,
    };
    try testing.expectEqual(Adoption.ignore_replay, classify(&state, 20, same));

    var conflicting = same;
    conflicting.history_hash = @as([32]u8, @splat(9));
    try testing.expectEqual(Adoption.diverged, classify(&state, 20, conflicting));

    var newer = same;
    newer.through_slot = 150;
    try testing.expectEqual(Adoption.adopt, classify(&state, 30, newer));

    var regressing = newer;
    regressing.through_slot = 50;
    try testing.expectEqual(Adoption.ignore_stale, classify(&state, 30, regressing));

    var nonadvancing = newer;
    nonadvancing.through_slot = state.through_slot;
    try testing.expectEqual(Adoption.ignore_duplicate, classify(&state, 30, nonadvancing));

    nonadvancing.history_hash = @as([32]u8, @splat(9));
    try testing.expectEqual(Adoption.diverged, classify(&state, 30, nonadvancing));

    nonadvancing = same;
    nonadvancing.configuration_id = 2;
    try testing.expectEqual(Adoption.diverged, classify(&state, 30, nonadvancing));

    var older = same;
    older.through_slot = 40;
    try testing.expectEqual(Adoption.ignore_stale, classify(&state, 10, older));
}

test "the durable trim record round trips and fails closed on corruption" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try testing.expectEqual(@as(?State, null), try load(io, tmp.dir));

    var state = State{
        .decision_slot = 5,
        .through_slot = 700,
        .history_hash = @as([32]u8, @splat(3)),
        .configuration_id = 2,
        .lease_count = 1,
    };
    state.leases[0] = .{
        .lease_id = 9,
        .receiver_id = 4,
        .base_slot = 650,
        .expiry_ticks_left = 42,
    };
    try store(io, tmp.dir, state);
    const loaded = (try load(io, tmp.dir)).?;
    try testing.expectEqual(@as(u64, 5), loaded.decision_slot);
    try testing.expectEqual(@as(u64, 700), loaded.through_slot);
    try testing.expectEqual(@as(u8, 1), loaded.lease_count);
    try testing.expectEqual(@as(u64, 650), loaded.leases[0].base_slot);

    {
        const file = try tmp.dir.openFile(io, file_name, .{ .mode = .read_write });
        defer file.close(io);
        var byte: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &byte, 10);
        byte[0] +%= 1;
        try file.writePositionalAll(io, &byte, 10);
    }
    try testing.expectError(error.CorruptTrimRecord, load(io, tmp.dir));
}

test "TRIM version 1 is explicitly unsupported" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try store(io, tmp.dir, .{});
    const file = try tmp.dir.openFile(io, file_name, .{ .mode = .read_write });
    defer file.close(io);
    var bytes: [record_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &bytes, 0);
    std.mem.writeInt(u16, bytes[4..6], 1, .little);
    Sha256.hash(bytes[0 .. record_size - 32], bytes[record_size - 32 ..][0..32], .{});
    try file.writePositionalAll(io, &bytes, 0);
    try testing.expectError(error.UnsupportedTrimVersion, load(io, tmp.dir));
}
