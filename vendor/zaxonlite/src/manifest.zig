//! The journal v3 manifest: the authoritative list of retained segments
//! (ZDS 0011).
//!
//! Segment file names are hints; only the manifest names the current
//! generation. Rotation seals the active segment, publishes a new
//! generation by atomic replace, synchronizes the directory, and only
//! then opens the next active file, so a crash exposes either the old
//! complete generation or the new one, and recovery never infers an
//! interior segment from directory listings. Files present but not named
//! by the selected manifest are rotation or trim garbage and are safe to
//! unlink after the manifest is durable.
//!
//! The manifest carries two cluster-critical rollups alongside the
//! segment table: `max_promised`, the highest promise ballot ever
//! recorded (promise records are slot-less, so trimming their segments
//! would otherwise forget them and let a restarted acceptor double-vote),
//! and the durable trim anchor `(decision_slot, trimmed_through, history_hash)`
//! that answers Phase 1 for the deleted prefix.

const std = @import("std");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

const durability = @import("durability.zig");
const paxos = @import("paxos");

const magic: u32 = 0x334d585a; // "ZXM3" in file byte order.
const previous_magic: u32 = 0x324d585a; // "ZXM2", intentionally unsupported.
const version: u16 = 3;

pub const file_name = "MANIFEST";

/// Upper bound on retained segments; caps the manifest near 3 MiB and is
/// far above any sane retention budget at ~10 MiB per segment.
pub const max_segments = 65536;

pub const SegmentEntry = struct {
    first_slot: u64,
    last_slot: u64,
    digest: [32]u8,
};

pub const Manifest = struct {
    generation: u64,
    database_id: u128,
    max_promised: paxos.Ballot,
    chosen_through: u64,
    trim_decision_slot: u64,
    trimmed_through: u64,
    trim_history_hash: [32]u8,
    active_first_slot: u64,
    segments: []const SegmentEntry,
};

pub const Error = error{
    CorruptManifest,
    UnsupportedManifestVersion,
    TooManySegments,
};

const fixed_size = 4 + 2 + 2 + 8 + 16 + 16 + 8 + 8 + 8 + 32 + 8 + 4;
const entry_size = 8 + 8 + 32;
const checksum_size = 32;

/// Serializes and atomically publishes `manifest`, replacing the current
/// generation. The caller owns ordering: every segment the manifest names
/// must already be sealed and synchronized.
pub fn publish(io: Io, gpa: std.mem.Allocator, dir: Io.Dir, manifest: Manifest) !void {
    if (manifest.segments.len > max_segments) return error.TooManySegments;
    const total = fixed_size + manifest.segments.len * entry_size + checksum_size;
    const bytes = try gpa.alloc(u8, total);
    defer gpa.free(bytes);

    var offset: usize = 0;
    writeInt(u32, bytes, &offset, magic);
    writeInt(u16, bytes, &offset, version);
    writeInt(u16, bytes, &offset, 0);
    writeInt(u64, bytes, &offset, manifest.generation);
    writeInt(u128, bytes, &offset, manifest.database_id);
    writeInt(u64, bytes, &offset, manifest.max_promised.round);
    writeInt(u32, bytes, &offset, manifest.max_promised.priority);
    writeInt(u32, bytes, &offset, manifest.max_promised.node);
    writeInt(u64, bytes, &offset, manifest.chosen_through);
    writeInt(u64, bytes, &offset, manifest.trim_decision_slot);
    writeInt(u64, bytes, &offset, manifest.trimmed_through);
    writeBytes(bytes, &offset, &manifest.trim_history_hash);
    writeInt(u64, bytes, &offset, manifest.active_first_slot);
    writeInt(u32, bytes, &offset, @intCast(manifest.segments.len));
    for (manifest.segments) |entry| {
        writeInt(u64, bytes, &offset, entry.first_slot);
        writeInt(u64, bytes, &offset, entry.last_slot);
        writeBytes(bytes, &offset, &entry.digest);
    }
    var checksum: [32]u8 = undefined;
    Sha256.hash(bytes[0..offset], &checksum, .{});
    writeBytes(bytes, &offset, &checksum);
    std.debug.assert(offset == total);

    var atomic = try dir.createFileAtomic(io, file_name, .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writePositionalAll(io, bytes, 0);
    try durability.syncFile(io, atomic.file);
    try atomic.replace(io);
    try durability.syncPathnameTransition(io, dir, file_name);
}

/// The manifest plus its caller-owned segment table storage.
pub const Loaded = struct {
    manifest: Manifest,
    storage: []SegmentEntry,

    pub fn deinit(self: *Loaded, gpa: std.mem.Allocator) void {
        gpa.free(self.storage);
        self.* = undefined;
    }
};

/// Reads and validates the current generation for this database. A
/// missing file returns null; anything malformed fails closed.
pub fn load(
    io: Io,
    gpa: std.mem.Allocator,
    dir: Io.Dir,
    database_id: u128,
) !?Loaded {
    const file = dir.openFile(io, file_name, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    const length = try file.length(io);
    if (length < fixed_size + checksum_size) return error.CorruptManifest;
    if (length > fixed_size + max_segments * entry_size + checksum_size) {
        return error.CorruptManifest;
    }
    const bytes = try gpa.alloc(u8, @intCast(length));
    defer gpa.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len) {
        return error.CorruptManifest;
    }

    var expected: [32]u8 = undefined;
    Sha256.hash(bytes[0 .. bytes.len - checksum_size], &expected, .{});
    if (!std.mem.eql(u8, &expected, bytes[bytes.len - checksum_size ..])) {
        return error.CorruptManifest;
    }

    var offset: usize = 0;
    const found_magic = readInt(u32, bytes, &offset);
    if (found_magic == previous_magic) return error.UnsupportedManifestVersion;
    if (found_magic != magic) return error.CorruptManifest;
    if (readInt(u16, bytes, &offset) != version) return error.UnsupportedManifestVersion;
    if (readInt(u16, bytes, &offset) != 0) return error.CorruptManifest;
    const generation = readInt(u64, bytes, &offset);
    if (readInt(u128, bytes, &offset) != database_id) return error.CorruptManifest;
    var manifest = Manifest{
        .generation = generation,
        .database_id = database_id,
        .max_promised = .{
            .round = readInt(u64, bytes, &offset),
            .priority = readInt(u32, bytes, &offset),
            .node = readInt(u32, bytes, &offset),
        },
        .chosen_through = readInt(u64, bytes, &offset),
        .trim_decision_slot = readInt(u64, bytes, &offset),
        .trimmed_through = readInt(u64, bytes, &offset),
        .trim_history_hash = undefined,
        .active_first_slot = undefined,
        .segments = &.{},
    };
    readBytes(bytes, &offset, &manifest.trim_history_hash);
    manifest.active_first_slot = readInt(u64, bytes, &offset);
    const segment_count = readInt(u32, bytes, &offset);
    if (segment_count > max_segments) return error.CorruptManifest;
    if (bytes.len != fixed_size + segment_count * entry_size + checksum_size) {
        return error.CorruptManifest;
    }

    const storage = try gpa.alloc(SegmentEntry, segment_count);
    errdefer gpa.free(storage);
    try readSegmentTable(&manifest, storage, bytes, &offset);
    manifest.segments = storage;
    return .{ .manifest = manifest, .storage = storage };
}

fn readSegmentTable(
    manifest: *const Manifest,
    storage: []SegmentEntry,
    bytes: []const u8,
    offset: *usize,
) !void {
    var previous_last: u64 = 0;
    for (storage, 0..) |*entry, index| {
        entry.first_slot = readInt(u64, bytes, offset);
        entry.last_slot = readInt(u64, bytes, offset);
        readBytes(bytes, offset, &entry.digest);
        // Retained segments are contiguous ascending ranges. The oldest
        // may straddle the trim anchor: physical reclamation removes only
        // whole segments, so its first slot sits at or below the anchor
        // plus one, never above it (that would be a hole in retained
        // history).
        const contiguous = if (index == 0)
            entry.first_slot <= manifest.trimmed_through + 1
        else
            entry.first_slot == previous_last + 1;
        if (!contiguous or entry.last_slot < entry.first_slot) {
            return error.CorruptManifest;
        }
        previous_last = entry.last_slot;
    }
    // The active segment continues the sealed chain; with everything
    // sealed reclaimed, it must still cover the slot after the anchor.
    if (storage.len > 0) {
        if (manifest.active_first_slot != previous_last + 1) {
            return error.CorruptManifest;
        }
    } else if (manifest.active_first_slot > manifest.trimmed_through + 1) {
        return error.CorruptManifest;
    }
}

fn writeInt(comptime T: type, out: []u8, offset: *usize, value: T) void {
    std.mem.writeInt(T, out[offset.*..][0..@sizeOf(T)], value, .little);
    offset.* += @sizeOf(T);
}

fn writeBytes(out: []u8, offset: *usize, value: []const u8) void {
    @memcpy(out[offset.*..][0..value.len], value);
    offset.* += value.len;
}

fn readInt(comptime T: type, bytes: []const u8, offset: *usize) T {
    const value = std.mem.readInt(T, bytes[offset.*..][0..@sizeOf(T)], .little);
    offset.* += @sizeOf(T);
    return value;
}

fn readBytes(bytes: []const u8, offset: *usize, out: []u8) void {
    @memcpy(out, bytes[offset.*..][0..out.len]);
    offset.* += out.len;
}

const testing = std.testing;

fn sampleManifest(segments: []const SegmentEntry) Manifest {
    return .{
        .generation = 3,
        .database_id = 55,
        .max_promised = .{ .round = 9, .priority = 0, .node = 2 },
        .chosen_through = 210,
        .trim_decision_slot = 2,
        .trimmed_through = 100,
        .trim_history_hash = @as([32]u8, @splat(7)),
        .active_first_slot = 201,
        .segments = segments,
    };
}

test "the manifest round trips and validates its segment chain" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try testing.expectEqual(@as(?Loaded, null), try load(io, testing.allocator, tmp.dir, 55));

    const segments = [_]SegmentEntry{
        .{ .first_slot = 101, .last_slot = 150, .digest = @as([32]u8, @splat(1)) },
        .{ .first_slot = 151, .last_slot = 200, .digest = @as([32]u8, @splat(2)) },
    };
    try publish(io, testing.allocator, tmp.dir, sampleManifest(&segments));

    var loaded = (try load(io, testing.allocator, tmp.dir, 55)).?;
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 3), loaded.manifest.generation);
    try testing.expectEqual(@as(u64, 9), loaded.manifest.max_promised.round);
    try testing.expectEqual(@as(u64, 100), loaded.manifest.trimmed_through);
    try testing.expectEqual(@as(usize, 2), loaded.manifest.segments.len);
    try testing.expectEqual(@as(u64, 151), loaded.manifest.segments[1].first_slot);

    // A different database never trusts this manifest.
    try testing.expectError(
        error.CorruptManifest,
        load(io, testing.allocator, tmp.dir, 56),
    );
}

test "a gap in the retained ranges fails closed" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const gapped = [_]SegmentEntry{
        .{ .first_slot = 101, .last_slot = 150, .digest = @as([32]u8, @splat(1)) },
        .{ .first_slot = 152, .last_slot = 200, .digest = @as([32]u8, @splat(2)) },
    };
    try publish(io, testing.allocator, tmp.dir, sampleManifest(&gapped));
    try testing.expectError(
        error.CorruptManifest,
        load(io, testing.allocator, tmp.dir, 55),
    );
}

test "a flipped byte fails the checksum closed" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try publish(io, testing.allocator, tmp.dir, sampleManifest(&.{}));
    {
        const file = try tmp.dir.openFile(io, file_name, .{ .mode = .read_write });
        defer file.close(io);
        var byte: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &byte, 8);
        byte[0] +%= 1;
        try file.writePositionalAll(io, &byte, 8);
    }
    try testing.expectError(
        error.CorruptManifest,
        load(io, testing.allocator, tmp.dir, 55),
    );
}

test "journal v2 manifest is explicitly unsupported" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try publish(io, testing.allocator, tmp.dir, sampleManifest(&.{}));
    const file = try tmp.dir.openFile(io, file_name, .{ .mode = .read_write });
    defer file.close(io);
    var bytes: [fixed_size + checksum_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &bytes, 0);
    std.mem.writeInt(u32, bytes[0..4], previous_magic, .little);
    Sha256.hash(
        bytes[0 .. bytes.len - checksum_size],
        bytes[bytes.len - checksum_size ..][0..32],
        .{},
    );
    try file.writePositionalAll(io, &bytes, 0);
    try testing.expectError(
        error.UnsupportedManifestVersion,
        load(io, testing.allocator, tmp.dir, 55),
    );
}
