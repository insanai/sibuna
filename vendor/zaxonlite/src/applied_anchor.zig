//! The durable SQLite applied-state anchor (ZDS 0011).
//!
//! Two alternating fixed-size records, `APPLIED.0` and `APPLIED.1`, name
//! the greatest contiguous chosen slot whose page images are synchronized
//! into `current.db`, together with the history anchor and file geometry
//! at that slot. Recovery selects the valid record with the greatest
//! generation and replays the journal suffix from there, so startup cost
//! follows the anchor cadence instead of the whole log.
//!
//! A record is never trusted on faith: magic, version, database identity,
//! and checksum must all validate, and a corrupt or missing record only
//! ever falls back to the older generation or to conservative replay. The
//! two host-extension fields, `last_data_slot` and `last_chain`, restore
//! the transaction batch-chain cursor at the anchor; once history below
//! the anchor is trimmed they cannot be recomputed from the log, and the
//! anchor's `history_hash` commits to them without being invertible.
//!
//! Each publish atomically replaces the inactive file and synchronizes
//! it, so at most one record is ever mid-write and a crash between the
//! database barrier and the anchor barrier is harmless: replaying an
//! already-applied suffix rewrites identical page images (ZDS 0011,
//! applied-anchor crash safety).

const std = @import("std");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

const durability = @import("durability.zig");
const failpoint = @import("failpoint.zig");

const magic: u32 = 0x5041585a; // "ZXAP" in file byte order.
const version: u16 = 1;

/// Total encoded record size; both files are exactly this long.
pub const record_size = 4 + 2 + 2 + 8 + 16 + 8 + 8 + 32 + 4 + 8 + 8 + 16 + 32 + 32;

const file_names = [2][]const u8{ "APPLIED.0", "APPLIED.1" };

pub const Anchor = struct {
    generation: u64,
    database_id: u128,
    global_slot: u64,
    /// The configuration in effect at the anchor slot; replay resumes
    /// history leaves under it.
    configuration_id: u64,
    history_hash: [32]u8,
    sqlite_page_size: u32,
    sqlite_page_count: u64,
    last_data_slot: u64,
    /// Batch identity at `last_data_slot`; zero when no batch precedes.
    last_batch_id: u128,
    last_chain: [32]u8,
};

/// Selects the valid anchor with the greatest generation, or null when
/// neither file holds one for this database.
pub fn select(io: Io, dir: Io.Dir, database_id: u128) ?Anchor {
    var best: ?Anchor = null;
    for (file_names) |name| {
        const anchor = readOne(io, dir, name, database_id) orelse continue;
        if (best == null or best.?.generation < anchor.generation) {
            best = anchor;
        }
    }
    return best;
}

/// Durably publishes `anchor` into the inactive generation file. The
/// caller must already have made the database pages it claims durable.
pub fn publish(io: Io, dir: Io.Dir, anchor: Anchor) !void {
    var bytes: [record_size]u8 = undefined;
    encode(anchor, &bytes);
    const name = file_names[@intCast(anchor.generation & 1)];
    failpoint.hit("before_applied_write");
    var atomic = try dir.createFileAtomic(io, name, .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writePositionalAll(io, &bytes, 0);
    try durability.syncFile(io, atomic.file);
    try atomic.replace(io);
    try durability.syncPathnameTransition(io, dir, name);
    failpoint.hit("after_applied_barrier");
}

fn encode(anchor: Anchor, out: *[record_size]u8) void {
    var offset: usize = 0;
    writeInt(u32, out, &offset, magic);
    writeInt(u16, out, &offset, version);
    writeInt(u16, out, &offset, 0);
    writeInt(u64, out, &offset, anchor.generation);
    writeInt(u128, out, &offset, anchor.database_id);
    writeInt(u64, out, &offset, anchor.global_slot);
    writeInt(u64, out, &offset, anchor.configuration_id);
    writeBytes(out, &offset, &anchor.history_hash);
    writeInt(u32, out, &offset, anchor.sqlite_page_size);
    writeInt(u64, out, &offset, anchor.sqlite_page_count);
    writeInt(u64, out, &offset, anchor.last_data_slot);
    writeInt(u128, out, &offset, anchor.last_batch_id);
    writeBytes(out, &offset, &anchor.last_chain);
    var checksum: [32]u8 = undefined;
    Sha256.hash(out[0..offset], &checksum, .{});
    writeBytes(out, &offset, &checksum);
    std.debug.assert(offset == record_size);
}

fn readOne(io: Io, dir: Io.Dir, name: []const u8, database_id: u128) ?Anchor {
    const file = dir.openFile(io, name, .{}) catch return null;
    defer file.close(io);
    var bytes: [record_size]u8 = undefined;
    const read = file.readPositionalAll(io, &bytes, 0) catch return null;
    if (read != record_size) return null;

    var expected: [32]u8 = undefined;
    Sha256.hash(bytes[0 .. record_size - 32], &expected, .{});
    if (!std.mem.eql(u8, &expected, bytes[record_size - 32 ..])) return null;

    var offset: usize = 0;
    if (readInt(u32, &bytes, &offset) != magic) return null;
    if (readInt(u16, &bytes, &offset) != version) return null;
    if (readInt(u16, &bytes, &offset) != 0) return null;
    const generation = readInt(u64, &bytes, &offset);
    if (readInt(u128, &bytes, &offset) != database_id) return null;
    var anchor = Anchor{
        .generation = generation,
        .database_id = database_id,
        .global_slot = readInt(u64, &bytes, &offset),
        .configuration_id = readInt(u64, &bytes, &offset),
        .history_hash = undefined,
        .sqlite_page_size = undefined,
        .sqlite_page_count = undefined,
        .last_data_slot = undefined,
        .last_batch_id = undefined,
        .last_chain = undefined,
    };
    readBytes(&bytes, &offset, &anchor.history_hash);
    anchor.sqlite_page_size = readInt(u32, &bytes, &offset);
    anchor.sqlite_page_count = readInt(u64, &bytes, &offset);
    anchor.last_data_slot = readInt(u64, &bytes, &offset);
    anchor.last_batch_id = readInt(u128, &bytes, &offset);
    readBytes(&bytes, &offset, &anchor.last_chain);
    return anchor;
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

fn sampleAnchor(generation: u64, slot: u64) Anchor {
    return .{
        .generation = generation,
        .database_id = 77,
        .global_slot = slot,
        .configuration_id = 1,
        .history_hash = @as([32]u8, @splat(1)),
        .sqlite_page_size = 4096,
        .sqlite_page_count = 12,
        .last_data_slot = slot - 1,
        .last_batch_id = 7,
        .last_chain = @as([32]u8, @splat(2)),
    };
}

test "publish alternates generations and select returns the newest" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try testing.expectEqual(@as(?Anchor, null), select(io, tmp.dir, 77));

    try publish(io, tmp.dir, sampleAnchor(1, 100));
    try publish(io, tmp.dir, sampleAnchor(2, 200));
    const newest = select(io, tmp.dir, 77).?;
    try testing.expectEqual(@as(u64, 2), newest.generation);
    try testing.expectEqual(@as(u64, 200), newest.global_slot);

    // The two generations live in different files, so the older one is
    // still intact as the fallback.
    try tmp.dir.access(io, "APPLIED.0", .{});
    try tmp.dir.access(io, "APPLIED.1", .{});
}

test "a corrupt or torn newest record falls back to the older generation" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try publish(io, tmp.dir, sampleAnchor(1, 100));
    try publish(io, tmp.dir, sampleAnchor(2, 200));

    // Generation 2 lives in APPLIED.0; flip one byte of its checksum.
    {
        const file = try tmp.dir.openFile(io, "APPLIED.0", .{ .mode = .read_write });
        defer file.close(io);
        var byte: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &byte, record_size - 1);
        byte[0] +%= 1;
        try file.writePositionalAll(io, &byte, record_size - 1);
    }
    const fallback = select(io, tmp.dir, 77).?;
    try testing.expectEqual(@as(u64, 1), fallback.generation);
    try testing.expectEqual(@as(u64, 100), fallback.global_slot);

    // Truncate the fallback too: nothing valid remains.
    {
        const file = try tmp.dir.openFile(io, "APPLIED.1", .{ .mode = .read_write });
        defer file.close(io);
        try file.setLength(io, record_size - 10);
    }
    try testing.expectEqual(@as(?Anchor, null), select(io, tmp.dir, 77));
}

test "an anchor for another database is never trusted" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try publish(io, tmp.dir, sampleAnchor(1, 100));
    try testing.expectEqual(@as(?Anchor, null), select(io, tmp.dir, 78));
}
