//! Immutable consensus journal segments (journal v3, ZDS 0011).
//!
//! A segment is a contiguous run of journal records for absolute global
//! slots: a fixed header naming the database and the first slot, framed
//! checksummed records in write order, and a sealed trailer with the last
//! slot, the record count, a sparse slot index, and a digest over the
//! whole file. Sealed segments never change; deletion of a chosen prefix
//! unlinks whole files.
//!
//! Two trailer fields are load-bearing beyond bookkeeping. `max_promised`
//! rolls up the highest promise ballot recorded in the segment: promise
//! records carry no slot, so once trimming deletes the segments that held
//! them, only this rollup (carried forward by the manifest) keeps a
//! restarted acceptor from promising backwards and double-voting.
//! `chosen_through` snapshots the writer's contiguous chosen prefix at
//! seal time, which bounds what replay must reconstruct.
//!
//! Segments are capped by record count, not bytes, so the writer's seal
//! state stays a small fixed allocation. Payload reachability is computed
//! by streaming retained segments rather than from a per-trailer digest
//! manifest; a digest set for a byte-capped segment would need megabytes
//! of seal-time memory, and garbage collection is rare while retention is
//! bounded (deviation from the ZDS 0011 sketch, recorded there when the
//! format contract is amended). Replay memory is one record buffer plus
//! the sparse index: never proportional to segment bytes.

const std = @import("std");
const Io = std.Io;
const Crc32 = std.hash.crc.@"CRC-32/ISO-HDLC";
const Sha256 = std.crypto.hash.sha2.Sha256;

const durability = @import("durability.zig");
const paxos = @import("paxos");
const types = @import("types.zig");

pub const header_magic: u32 = 0x3353585a; // "ZXS3" in file byte order.
pub const trailer_magic: u32 = 0x3354585a; // "ZXT3" in file byte order.
const record_magic: u32 = 0x3352585a; // "ZXR3" in file byte order.
const previous_header_magic: u32 = 0x3253585a; // "ZXS2", unsupported.
pub const format_version: u8 = 3;

/// Records per sealed segment. With record bodies bounded by
/// `types.max_write_size` this caps a segment near 10 MiB while keeping
/// the sparse index and seal state in fixed storage.
pub const capacity_records = 16384;

/// Rotation threshold, `capacity_records` in production. Test harnesses
/// lower it (never raise it — the sparse index and seal state are sized
/// for the constant) so segment-scale scenarios like beyond-retention
/// state transfer rotate and reclaim without millions of writes.
pub var rotation_records: usize = capacity_records;

/// One sparse index entry per this many records.
pub const sparse_stride = 64;

pub const max_sparse_entries = capacity_records / sparse_stride;

pub const header_size = 4 + 1 + 3 + 16 + 8 + 32;

pub const record_header_size = 4 + 1 + 1 + 2 + 8 + 8 + 4 + 4;

pub const max_record_size = record_header_size + types.max_write_size;

const trailer_fixed_size = 4 + 8 + 8 + 16 + 8 + 4;
const trailer_tail_size = 32 + 4;

pub const Header = struct {
    database_id: u128,
    first_global_slot: u64,
    previous_segment_digest: [32]u8,
};

pub const Trailer = struct {
    last_global_slot: u64,
    record_count: u64,
    max_promised: paxos.Ballot,
    chosen_through: u64,
    sparse_count: u32,
    sparse: [max_sparse_entries]SparseEntry,
    segment_digest: [32]u8,
};

pub const SparseEntry = struct {
    slot: u64,
    offset: u64,
};

/// One decoded record: the global journal sequence, the record kind, the
/// slot it addresses (zero for slot-less kinds such as promises), and the
/// payload bytes, valid until the next reader call.
pub const Record = struct {
    sequence: u64,
    kind: u8,
    slot: u64,
    payload: []const u8,
};

pub const ReadError = error{
    CorruptSegment,
    UnsupportedSegmentVersion,
};

/// Appends records into one segment file and seals it immutably. The
/// running digest covers every byte written, so the sealed digest commits
/// to the header, all records, and the trailer prefix.
pub const Writer = struct {
    io: Io,
    file: Io.File,
    hasher: Sha256,
    end_offset: u64,
    first_slot: u64,
    last_slot: u64,
    record_count: u64,
    max_promised: paxos.Ballot,
    sparse_count: u32,
    sparse: [max_sparse_entries]SparseEntry,
    sealed: bool,

    pub fn create(
        io: Io,
        dir: Io.Dir,
        name: []const u8,
        header: Header,
    ) !Writer {
        const file = try dir.createFile(io, name, .{ .exclusive = true, .read = true });
        errdefer file.close(io);

        var bytes: [header_size]u8 = undefined;
        var offset: usize = 0;
        writeInt(u32, &bytes, &offset, header_magic);
        bytes[offset] = format_version;
        offset += 1;
        @memset(bytes[offset .. offset + 3], 0);
        offset += 3;
        writeInt(u128, &bytes, &offset, header.database_id);
        writeInt(u64, &bytes, &offset, header.first_global_slot);
        @memcpy(bytes[offset..][0..32], &header.previous_segment_digest);
        offset += 32;
        std.debug.assert(offset == header_size);
        try file.writePositionalAll(io, &bytes, 0);

        var writer = Writer{
            .io = io,
            .file = file,
            .hasher = Sha256.init(.{}),
            .end_offset = header_size,
            .first_slot = header.first_global_slot,
            .last_slot = 0,
            .record_count = 0,
            .max_promised = paxos.Ballot.zero,
            .sparse_count = 0,
            .sparse = undefined,
            .sealed = false,
        };
        writer.hasher.update(&bytes);
        return writer;
    }

    pub fn close(self: *Writer) void {
        self.file.close(self.io);
    }

    /// Reopens an unsealed active segment for appending after a restart.
    /// The valid record prefix is rescanned to rebuild the digest, counts,
    /// and sparse index; a torn tail is truncated away. The caller decodes
    /// records separately; this pass only restores writer state.
    pub fn adopt(io: Io, dir: Io.Dir, name: []const u8) !Writer {
        var reader = try Reader.open(io, dir, name);
        var end: u64 = header_size;
        var count: u64 = 0;
        var last: u64 = 0;
        var sparse_count: u32 = 0;
        var sparse: [max_sparse_entries]SparseEntry = undefined;
        while (true) {
            const start_offset = reader.offset;
            const record = reader.next() catch {
                // A record cut off by the end of the file is a torn tail
                // from a crash and is truncated away; corruption strictly
                // inside the durable prefix stops the node instead.
                if (!recordTouchesEof(&reader, start_offset)) {
                    reader.close();
                    return error.CorruptSegment;
                }
                break;
            } orelse break;
            if (count % sparse_stride == 0 and record.slot != 0) {
                sparse[sparse_count] = .{
                    .slot = record.slot,
                    .offset = start_offset,
                };
                sparse_count += 1;
            }
            end = reader.offset;
            count += 1;
            if (record.slot > last) last = record.slot;
        }
        reader.close();

        const file = try dir.openFile(io, name, .{ .mode = .read_write });
        errdefer file.close(io);
        try file.setLength(io, end);
        var hasher = Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var position: u64 = 0;
        while (position < end) {
            const want: usize = @intCast(@min(buffer.len, end - position));
            const read = try file.readPositionalAll(io, buffer[0..want], position);
            if (read != want) return error.CorruptSegment;
            hasher.update(buffer[0..want]);
            position += want;
        }
        const header = try readHeader(io, file);
        return .{
            .io = io,
            .file = file,
            .hasher = hasher,
            .end_offset = end,
            .first_slot = header.first_global_slot,
            .last_slot = last,
            .record_count = count,
            .max_promised = paxos.Ballot.zero,
            .sparse_count = sparse_count,
            .sparse = sparse,
            .sealed = false,
        };
    }

    /// Whether the segment reached its record capacity and must rotate.
    pub fn full(self: *const Writer) bool {
        return self.record_count >= rotation_records;
    }

    /// Appends one record. `slot` is zero for slot-less kinds; a promise
    /// ballot must be reported through `observePromise` by the caller so
    /// the rollup survives trimming.
    pub fn append(
        self: *Writer,
        sequence: u64,
        kind: u8,
        slot: u64,
        payload: []const u8,
    ) !void {
        std.debug.assert(!self.sealed);
        std.debug.assert(!self.full());
        std.debug.assert(payload.len <= types.max_write_size);

        var buffer: [max_record_size]u8 = undefined;
        var offset: usize = 0;
        writeInt(u32, buffer[0..max_record_size], &offset, record_magic);
        buffer[offset] = format_version;
        offset += 1;
        buffer[offset] = kind;
        offset += 1;
        writeInt(u16, buffer[0..max_record_size], &offset, 0);
        writeInt(u64, buffer[0..max_record_size], &offset, sequence);
        writeInt(u64, buffer[0..max_record_size], &offset, slot);
        writeInt(u32, buffer[0..max_record_size], &offset, @intCast(payload.len));
        const crc_offset = offset;
        writeInt(u32, buffer[0..max_record_size], &offset, 0);
        std.debug.assert(offset == record_header_size);
        @memcpy(buffer[offset..][0..payload.len], payload);
        const crc = recordCrc(buffer[0..crc_offset], payload);
        std.mem.writeInt(u32, buffer[crc_offset..][0..4], crc, .little);

        const total = record_header_size + payload.len;
        if (self.record_count % sparse_stride == 0 and slot != 0) {
            self.sparse[self.sparse_count] = .{ .slot = slot, .offset = self.end_offset };
            self.sparse_count += 1;
        }
        try self.file.writePositionalAll(self.io, buffer[0..total], self.end_offset);
        self.hasher.update(buffer[0..total]);
        self.end_offset += total;
        self.record_count += 1;
        if (slot > self.last_slot) self.last_slot = slot;
    }

    /// Folds a promise ballot into the trailer rollup.
    pub fn observePromise(self: *Writer, ballot: paxos.Ballot) void {
        if (self.max_promised.lessThan(ballot)) self.max_promised = ballot;
    }

    /// Writes and synchronizes the trailer; the segment is immutable after
    /// this returns. Returns the sealed segment digest.
    pub fn seal(self: *Writer, chosen_through: u64) ![32]u8 {
        std.debug.assert(!self.sealed);
        var bytes: [trailer_size_max]u8 = undefined;
        var offset: usize = 0;
        writeInt(u32, &bytes, &offset, trailer_magic);
        writeInt(u64, &bytes, &offset, self.last_slot);
        writeInt(u64, &bytes, &offset, self.record_count);
        writeInt(u64, &bytes, &offset, self.max_promised.round);
        writeInt(u32, &bytes, &offset, self.max_promised.priority);
        writeInt(u32, &bytes, &offset, self.max_promised.node);
        writeInt(u64, &bytes, &offset, chosen_through);
        writeInt(u32, &bytes, &offset, self.sparse_count);
        for (self.sparse[0..self.sparse_count]) |entry| {
            writeInt(u64, &bytes, &offset, entry.slot);
            writeInt(u64, &bytes, &offset, entry.offset);
        }
        self.hasher.update(bytes[0..offset]);
        var digest: [32]u8 = undefined;
        self.hasher.final(&digest);
        @memcpy(bytes[offset..][0..32], &digest);
        offset += 32;
        const trailer_len: u32 = @intCast(offset + 4);
        writeInt(u32, &bytes, &offset, trailer_len);

        try self.file.writePositionalAll(self.io, bytes[0..offset], self.end_offset);
        try durability.syncFile(self.io, self.file);
        self.end_offset += offset;
        self.sealed = true;
        return digest;
    }

    pub const trailer_size_max = trailer_fixed_size +
        max_sparse_entries * 16 + trailer_tail_size;
};

/// Streams one segment with a single record buffer. `openSealed` also
/// verifies the trailer digest over the whole file, so a sealed segment
/// either replays exactly or fails closed.
pub const Reader = struct {
    io: Io,
    file: Io.File,
    header: Header,
    trailer: ?Trailer,
    offset: u64,
    records_end: u64,
    buffer: [max_record_size]u8,

    pub fn open(io: Io, dir: Io.Dir, name: []const u8) !Reader {
        const file = try dir.openFile(io, name, .{});
        errdefer file.close(io);
        const header = try readHeader(io, file);
        const length = try file.length(io);
        return .{
            .io = io,
            .file = file,
            .header = header,
            .trailer = null,
            .offset = header_size,
            .records_end = length,
            .buffer = undefined,
        };
    }

    /// Opens a sealed segment, parses its trailer, and verifies the
    /// digest covering every byte before it.
    pub fn openSealed(io: Io, dir: Io.Dir, name: []const u8) !Reader {
        var reader = try open(io, dir, name);
        errdefer reader.close();
        const trailer = try readTrailer(io, reader.file);
        try verifyDigest(io, reader.file, trailer.digest_end, trailer.trailer.segment_digest);
        reader.trailer = trailer.trailer;
        reader.records_end = trailer.records_end;
        return reader;
    }

    pub fn close(self: *Reader) void {
        self.file.close(self.io);
    }

    /// Positions the reader at the sparse entry at or before `slot`.
    pub fn seekToSlot(self: *Reader, slot: u64) void {
        const trailer = self.trailer orelse return;
        var target: u64 = header_size;
        for (trailer.sparse[0..trailer.sparse_count]) |entry| {
            if (entry.slot > slot) break;
            target = entry.offset;
        }
        self.offset = target;
    }

    /// Returns the next record, or null at the end of the records region.
    /// The payload slice is valid until the next call.
    pub fn next(self: *Reader) ReadError!?Record {
        if (self.offset >= self.records_end) return null;
        const remaining = self.records_end - self.offset;
        if (remaining < record_header_size) return error.CorruptSegment;

        const header_bytes = self.buffer[0..record_header_size];
        const read = self.file.readPositionalAll(self.io, header_bytes, self.offset) catch
            return error.CorruptSegment;
        if (read != record_header_size) return error.CorruptSegment;

        var offset: usize = 0;
        if (readInt(u32, header_bytes, &offset) != record_magic) {
            return error.CorruptSegment;
        }
        if (header_bytes[offset] != format_version) return error.UnsupportedSegmentVersion;
        offset += 1;
        const kind = header_bytes[offset];
        offset += 1;
        if (readInt(u16, header_bytes, &offset) != 0) return error.CorruptSegment;
        const sequence = readInt(u64, header_bytes, &offset);
        const slot = readInt(u64, header_bytes, &offset);
        const payload_len = readInt(u32, header_bytes, &offset);
        const stored_crc = readInt(u32, header_bytes, &offset);
        if (payload_len > types.max_write_size) return error.CorruptSegment;
        if (remaining < record_header_size + payload_len) return error.CorruptSegment;

        const payload = self.buffer[record_header_size..][0..payload_len];
        const payload_read = self.file.readPositionalAll(
            self.io,
            payload,
            self.offset + record_header_size,
        ) catch return error.CorruptSegment;
        if (payload_read != payload_len) return error.CorruptSegment;
        if (recordCrc(header_bytes[0 .. record_header_size - 4], payload) != stored_crc) {
            return error.CorruptSegment;
        }

        self.offset += record_header_size + payload_len;
        return .{ .sequence = sequence, .kind = kind, .slot = slot, .payload = payload };
    }
};

/// Whether the record starting at `offset` could extend past the end of
/// the file, which marks a torn tail rather than interior corruption.
fn recordTouchesEof(reader: *const Reader, offset: u64) bool {
    const remaining = reader.records_end - offset;
    if (remaining < record_header_size) return true;
    var header_bytes: [record_header_size]u8 = undefined;
    const read = reader.file.readPositionalAll(
        reader.io,
        &header_bytes,
        offset,
    ) catch return true;
    if (read != record_header_size) return true;
    const payload_len = std.mem.readInt(
        u32,
        header_bytes[record_header_size - 8 ..][0..4],
        .little,
    );
    return remaining < record_header_size + payload_len;
}

const ParsedTrailer = struct {
    trailer: Trailer,
    records_end: u64,
    digest_end: u64,
};

/// Reads and validates one segment header without adopting the file, so
/// the journal can check ancestry before trusting an active segment.
pub fn peekHeader(io: Io, dir: Io.Dir, name: []const u8) !Header {
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);
    return readHeader(io, file);
}

fn readHeader(io: Io, file: Io.File) !Header {
    var bytes: [header_size]u8 = undefined;
    const read = file.readPositionalAll(io, &bytes, 0) catch return error.CorruptSegment;
    if (read != header_size) return error.CorruptSegment;
    var offset: usize = 0;
    const found_magic = readInt(u32, &bytes, &offset);
    if (found_magic == previous_header_magic) return error.UnsupportedSegmentVersion;
    if (found_magic != header_magic) return error.CorruptSegment;
    if (bytes[offset] != format_version) return error.UnsupportedSegmentVersion;
    offset += 4;
    var header = Header{
        .database_id = readInt(u128, &bytes, &offset),
        .first_global_slot = readInt(u64, &bytes, &offset),
        .previous_segment_digest = undefined,
    };
    @memcpy(&header.previous_segment_digest, bytes[offset..][0..32]);
    return header;
}

fn readTrailer(io: Io, file: Io.File) !ParsedTrailer {
    const length = try file.length(io);
    if (length < header_size + trailer_fixed_size + trailer_tail_size) {
        return error.CorruptSegment;
    }
    var len_bytes: [4]u8 = undefined;
    if (try file.readPositionalAll(io, &len_bytes, length - 4) != 4) {
        return error.CorruptSegment;
    }
    const trailer_len = std.mem.readInt(u32, &len_bytes, .little);
    if (trailer_len < trailer_fixed_size + trailer_tail_size or
        trailer_len > Writer.trailer_size_max or
        length < header_size + trailer_len)
    {
        return error.CorruptSegment;
    }

    var bytes: [Writer.trailer_size_max]u8 = undefined;
    const start = length - trailer_len;
    if (try file.readPositionalAll(io, bytes[0..trailer_len], start) != trailer_len) {
        return error.CorruptSegment;
    }
    var offset: usize = 0;
    if (readInt(u32, &bytes, &offset) != trailer_magic) return error.CorruptSegment;
    var trailer = Trailer{
        .last_global_slot = readInt(u64, &bytes, &offset),
        .record_count = readInt(u64, &bytes, &offset),
        .max_promised = .{
            .round = readInt(u64, &bytes, &offset),
            .priority = readInt(u32, &bytes, &offset),
            .node = readInt(u32, &bytes, &offset),
        },
        .chosen_through = readInt(u64, &bytes, &offset),
        .sparse_count = readInt(u32, &bytes, &offset),
        .sparse = undefined,
        .segment_digest = undefined,
    };
    if (trailer.sparse_count > max_sparse_entries) return error.CorruptSegment;
    if (trailer_len != trailer_fixed_size + trailer.sparse_count * 16 + trailer_tail_size) {
        return error.CorruptSegment;
    }
    for (trailer.sparse[0..trailer.sparse_count]) |*entry| {
        entry.slot = readInt(u64, &bytes, &offset);
        entry.offset = readInt(u64, &bytes, &offset);
    }
    @memcpy(&trailer.segment_digest, bytes[offset..][0..32]);
    return .{
        .trailer = trailer,
        .records_end = start,
        .digest_end = start + @as(u64, offset),
    };
}

fn verifyDigest(io: Io, file: Io.File, digest_end: u64, expected: [32]u8) !void {
    var hasher = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var position: u64 = 0;
    while (position < digest_end) {
        const want: usize = @intCast(@min(buffer.len, digest_end - position));
        const read = file.readPositionalAll(io, buffer[0..want], position) catch
            return error.CorruptSegment;
        if (read != want) return error.CorruptSegment;
        hasher.update(buffer[0..want]);
        position += want;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    if (!std.mem.eql(u8, &digest, &expected)) return error.CorruptSegment;
}

fn recordCrc(header: []const u8, payload: []const u8) u32 {
    var crc = Crc32.init();
    crc.update(header);
    crc.update(payload);
    return crc.final();
}

fn writeInt(comptime T: type, out: []u8, offset: *usize, value: T) void {
    std.mem.writeInt(T, out[offset.*..][0..@sizeOf(T)], value, .little);
    offset.* += @sizeOf(T);
}

fn readInt(comptime T: type, bytes: []const u8, offset: *usize) T {
    const value = std.mem.readInt(T, bytes[offset.*..][0..@sizeOf(T)], .little);
    offset.* += @sizeOf(T);
    return value;
}

const testing = std.testing;

fn appendSample(writer: *Writer, sequence: u64, slot: u64) !void {
    var payload: [24]u8 = undefined;
    std.mem.writeInt(u64, payload[0..8], slot, .little);
    std.mem.writeInt(u64, payload[8..16], sequence, .little);
    std.mem.writeInt(u64, payload[16..24], 0xabcd, .little);
    try writer.append(sequence, 1, slot, &payload);
}

test "a sealed segment replays exactly and verifies its digest" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var writer = try Writer.create(io, tmp.dir, "seg", .{
        .database_id = 9,
        .first_global_slot = 100,
        .previous_segment_digest = @as([32]u8, @splat(0)),
    });
    var sequence: u64 = 1;
    var slot: u64 = 100;
    while (slot < 100 + 2 * sparse_stride) : (slot += 1) {
        try appendSample(&writer, sequence, slot);
        sequence += 1;
    }
    writer.observePromise(.{ .round = 5, .priority = 0, .node = 2 });
    const digest = try writer.seal(90);
    writer.close();

    var reader = try Reader.openSealed(io, tmp.dir, "seg");
    defer reader.close();
    const trailer = reader.trailer.?;
    try testing.expectEqual(@as(u64, 100 + 2 * sparse_stride - 1), trailer.last_global_slot);
    try testing.expectEqual(@as(u64, 2 * sparse_stride), trailer.record_count);
    try testing.expectEqual(@as(u64, 5), trailer.max_promised.round);
    try testing.expectEqual(@as(u64, 90), trailer.chosen_through);
    try testing.expectEqual(@as(u32, 2), trailer.sparse_count);
    try testing.expectEqualSlices(u8, &digest, &trailer.segment_digest);

    var expected_slot: u64 = 100;
    var expected_sequence: u64 = 1;
    while (try reader.next()) |record| {
        try testing.expectEqual(expected_sequence, record.sequence);
        try testing.expectEqual(expected_slot, record.slot);
        try testing.expectEqual(@as(u8, 1), record.kind);
        expected_slot += 1;
        expected_sequence += 1;
    }
    try testing.expectEqual(@as(u64, 100 + 2 * sparse_stride), expected_slot);

    // The sparse index skips ahead of the first stride.
    reader.seekToSlot(100 + sparse_stride + 3);
    const sought = (try reader.next()).?;
    try testing.expectEqual(@as(u64, 100 + sparse_stride), sought.slot);
}

test "a flipped byte fails the sealed digest closed" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var writer = try Writer.create(io, tmp.dir, "seg", .{
        .database_id = 9,
        .first_global_slot = 1,
        .previous_segment_digest = @as([32]u8, @splat(0)),
    });
    try appendSample(&writer, 1, 1);
    _ = try writer.seal(1);
    writer.close();

    {
        const file = try tmp.dir.openFile(io, "seg", .{ .mode = .read_write });
        defer file.close(io);
        var byte: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &byte, header_size + 8);
        byte[0] +%= 1;
        try file.writePositionalAll(io, &byte, header_size + 8);
    }
    try testing.expectError(error.CorruptSegment, Reader.openSealed(io, tmp.dir, "seg"));
}

test "an unsealed segment streams records until the end of file" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var writer = try Writer.create(io, tmp.dir, "active", .{
        .database_id = 9,
        .first_global_slot = 1,
        .previous_segment_digest = @as([32]u8, @splat(0)),
    });
    try appendSample(&writer, 1, 1);
    try appendSample(&writer, 2, 2);
    writer.close();

    var reader = try Reader.open(io, tmp.dir, "active");
    defer reader.close();
    try testing.expectEqual(@as(u64, 1), (try reader.next()).?.slot);
    try testing.expectEqual(@as(u64, 2), (try reader.next()).?.slot);
    try testing.expectEqual(@as(?Record, null), try reader.next());
}

test "journal v2 segment is explicitly unsupported" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try Writer.create(io, tmp.dir, "old", .{
        .database_id = 9,
        .first_global_slot = 1,
        .previous_segment_digest = @as([32]u8, @splat(0)),
    });
    writer.close();
    const file = try tmp.dir.openFile(io, "old", .{ .mode = .read_write });
    defer file.close(io);
    var old_magic: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_magic, previous_header_magic, .little);
    try file.writePositionalAll(io, &old_magic, 0);
    try testing.expectError(error.UnsupportedSegmentVersion, peekHeader(io, tmp.dir, "old"));
}
