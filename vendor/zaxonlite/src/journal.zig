//! The authoritative consensus journal: manifest-governed, segmented,
//! and trimmable (journal v3, ZDS 0011).
//!
//! One `consensus/` directory holds the database's whole retained journal
//! for its lifetime: immutable sealed segments, one active segment, and
//! the `MANIFEST` naming exactly which segments are current. Segment
//! files are named by their first global slot at creation and are never
//! renamed; a file's sealed trailer, not its name, says what it is, so
//! every rotation crash window resolves by inspection: a sealed segment
//! the manifest still calls active is adopted, a missing active file is
//! recreated, and any file the manifest does not name is garbage from a
//! crashed rotation or trim and is deleted.
//!
//! Replay is streaming: one bounded record buffer per segment pass, never
//! memory proportional to journal size. Trimming unlinks only complete
//! sealed segments after the successor manifest generation is durable,
//! and the manifest's `max_promised` rollup keeps a restarted acceptor
//! from promising backwards even when every promise-bearing segment has
//! been deleted.
//!
//! The v1 one-file-per-configuration journal (`paxos-*.log`, "ZXJ1") is
//! not read; a database holding one fails closed as unsupported.

const std = @import("std");
const Io = std.Io;

const durability = @import("durability.zig");
const manifest_mod = @import("manifest.zig");
const paxos = @import("paxos");
const segment = @import("segment.zig");
const types = @import("types.zig");

pub const directory_name = "consensus";

pub const OpenError = error{
    CorruptJournal,
    UnsupportedJournalVersion,
    SequenceGap,
};

/// Summary of one open/replay pass.
pub const ReplayInfo = struct {
    record_count: u64 = 0,
    next_sequence: u64 = 1,
    truncated_bytes: u64 = 0,
};

fn segmentName(buffer: *[20]u8, first_slot: u64) []const u8 {
    return std.fmt.bufPrint(buffer, "{x:0>16}.zxj", .{first_slot}) catch unreachable;
}

pub const Journal = struct {
    io: Io,
    gpa: std.mem.Allocator,
    dir: Io.Dir,
    database_id: u128,
    generation: u64,
    segments: std.ArrayList(manifest_mod.SegmentEntry),
    active: segment.Writer,
    active_first_slot: u64,
    next_sequence: u64,
    /// The greatest slot durably present (P_i).
    persisted: u64,
    /// The node's contiguous chosen prefix, noted for seal metadata.
    chosen_hint: u64,
    /// Rollup across deleted history plus the retained run.
    max_promised: paxos.Ballot,
    trim_decision_slot: u64,
    trimmed_through: u64,
    trim_history_hash: [32]u8,
    /// Total bytes of sealed retained segments, maintained from file
    /// lengths at open and adjusted by rotation and trimming.
    sealed_bytes: u64 = 0,

    /// Creates a fresh journal for a new database: manifest generation
    /// one and an empty active segment starting at global slot one.
    pub fn create(
        io: Io,
        gpa: std.mem.Allocator,
        parent: Io.Dir,
        database_id: u128,
    ) !Journal {
        var dir = try parent.createDirPathOpen(io, directory_name, .{});
        errdefer dir.close(io);
        try durability.syncChildDirectory(io, parent, directory_name);

        var self = Journal{
            .io = io,
            .gpa = gpa,
            .dir = dir,
            .database_id = database_id,
            .generation = 1,
            .segments = .empty,
            .active = undefined,
            .active_first_slot = 1,
            .next_sequence = 1,
            .persisted = 0,
            .chosen_hint = 0,
            .max_promised = paxos.Ballot.zero,
            .trim_decision_slot = 0,
            .trimmed_through = 0,
            .trim_history_hash = @as([32]u8, @splat(0)),
        };
        try self.publishManifest();
        var name_buffer: [20]u8 = undefined;
        self.active = try segment.Writer.create(
            io,
            dir,
            segmentName(&name_buffer, 1),
            .{
                .database_id = database_id,
                .first_global_slot = 1,
                .previous_segment_digest = @as([32]u8, @splat(0)),
            },
        );
        try durability.syncDirectory(dir);
        return self;
    }

    /// Opens the journal, repairs any crashed rotation, replays every
    /// retained record into `durable`, and resumes the active segment.
    pub fn open(
        io: Io,
        gpa: std.mem.Allocator,
        parent: Io.Dir,
        database_id: u128,
        durable: *types.Log.DurableState,
        info: *ReplayInfo,
    ) !Journal {
        var dir = try parent.openDir(io, directory_name, .{ .iterate = true });
        errdefer dir.close(io);
        var loaded = (try manifest_mod.load(io, gpa, dir, database_id)) orelse
            return error.CorruptJournal;
        defer loaded.deinit(gpa);
        const m = &loaded.manifest;

        var self = Journal{
            .io = io,
            .gpa = gpa,
            .dir = dir,
            .database_id = database_id,
            .generation = m.generation,
            .segments = .empty,
            .active = undefined,
            .active_first_slot = m.active_first_slot,
            .next_sequence = 1,
            .persisted = 0,
            .chosen_hint = m.chosen_through,
            .max_promised = m.max_promised,
            .trim_decision_slot = m.trim_decision_slot,
            .trimmed_through = m.trimmed_through,
            .trim_history_hash = m.trim_history_hash,
        };
        errdefer self.segments.deinit(gpa);
        try self.segments.appendSlice(gpa, m.segments);

        try self.sweepOrphans();
        try self.adoptActive();
        info.* = .{};
        try self.replay(durable, info);
        // Deleted history may have held the highest promise; the rollup
        // restores it so the acceptor can never promise backwards.
        if (durable.promised.lessThan(self.max_promised)) {
            try durable.apply(.{ .promise = self.max_promised });
        }
        // Trimmed history was durably persisted before it was deleted;
        // progress never regresses below the certified trim frontier.
        self.persisted = @max(self.persisted, self.trimmed_through);
        return self;
    }

    pub fn close(self: *Journal) void {
        self.active.close();
        self.segments.deinit(self.gpa);
        self.dir.close(self.io);
    }

    /// Appends encoded writes to the active segment, rotating at segment
    /// capacity. Durability requires a following `sync`.
    pub fn appendWrites(self: *Journal, writes: []const types.Write) !void {
        for (writes) |write| {
            if (self.active.full()) try self.rotate();
            var buffer: [types.max_write_size]u8 = undefined;
            var cursor = types.Cursor{ .buffer = &buffer };
            types.encodeWrite(write, &cursor);
            const slot: u64 = switch (write) {
                .promise => 0,
                .accept => |accept| accept.slot,
                .commit => |commit| commit.slot,
                .trim_anchor => 0,
            };
            switch (write) {
                .promise => |ballot| self.observePromise(ballot),
                .accept => |accept| self.observePromise(accept.ballot),
                else => {},
            }
            try self.active.append(
                self.next_sequence,
                @backingInt(write),
                slot,
                buffer[0..cursor.offset],
            );
            self.next_sequence += 1;
            if (slot > self.persisted) self.persisted = slot;
        }
    }

    /// Synchronizes the active segment; the caller's durability barrier.
    pub fn sync(self: *Journal) !void {
        try durability.syncFile(self.io, self.active.file);
    }

    /// Notes the node's contiguous chosen prefix for seal metadata.
    pub fn noteChosen(self: *Journal, through: u64) void {
        if (through > self.chosen_hint) self.chosen_hint = through;
    }

    /// Records the adopted trim anchor carried by future manifests.
    pub fn noteTrimAnchor(
        self: *Journal,
        decision_slot: u64,
        through: u64,
        history_hash: [32]u8,
    ) void {
        if (decision_slot <= self.trim_decision_slot) return;
        self.trim_decision_slot = decision_slot;
        self.trimmed_through = through;
        self.trim_history_hash = history_hash;
    }

    /// Unlinks every sealed segment wholly at or below `floor`, after a
    /// successor manifest generation is durable. Only complete segments
    /// go; the caller has already made its TRIM state durable. Returns
    /// whether any segment was removed.
    pub fn trimThrough(self: *Journal, floor: u64) !bool {
        var keep: usize = 0;
        while (keep < self.segments.items.len and
            self.segments.items[keep].last_slot <= floor)
        {
            keep += 1;
        }
        if (keep == 0) return false;

        const removed = try self.gpa.dupe(
            manifest_mod.SegmentEntry,
            self.segments.items[0..keep],
        );
        defer self.gpa.free(removed);
        std.mem.copyForwards(
            manifest_mod.SegmentEntry,
            self.segments.items,
            self.segments.items[keep..],
        );
        self.segments.shrinkRetainingCapacity(self.segments.items.len - keep);
        try self.publishManifest();
        // A crash from here leaves orphans; the next open sweeps them.
        for (removed) |entry| {
            var name_buffer: [20]u8 = undefined;
            const name = segmentName(&name_buffer, entry.first_slot);
            if (self.dir.openFile(self.io, name, .{})) |file| {
                const length = file.length(self.io) catch 0;
                file.close(self.io);
                self.sealed_bytes -|= length;
            } else |_| {}
            self.dir.deleteFile(self.io, name) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
        }
        try durability.syncDirectory(self.dir);
        return true;
    }

    /// Streams retained commits in `[first, first + count - 1]` to `sink`,
    /// serving catch-up below the core's memory floor.
    pub fn serveRange(
        self: *Journal,
        first: u64,
        count: u32,
        context: anytype,
        comptime sink: fn (@TypeOf(context), u64, types.Entry) anyerror!void,
    ) !void {
        const limit = first +| (count - 1);
        var it = try self.iterate(first);
        defer it.close();
        while (try it.next()) |write| {
            switch (write) {
                .commit => |commit| {
                    if (commit.slot < first or commit.slot > limit) continue;
                    try sink(context, commit.slot, commit.value);
                },
                else => {},
            }
        }
    }

    /// The greatest slot durably present in this journal.
    pub fn persistedThrough(self: *const Journal) u64 {
        return self.persisted;
    }

    /// The first slot of the oldest retained segment.
    pub fn retainedFirstSlot(self: *const Journal) u64 {
        if (self.segments.items.len > 0) {
            return self.segments.items[0].first_slot;
        }
        return self.active_first_slot;
    }

    pub const Stats = struct {
        segment_count: usize,
        journal_bytes: u64,
    };

    pub fn stats(self: *const Journal) Stats {
        return .{
            .segment_count = self.segments.items.len + 1,
            .journal_bytes = self.sealed_bytes + self.active.end_offset,
        };
    }

    /// A streaming pass over retained records from `from_slot` upward
    /// (promise and trim records interleave in sequence order).
    pub fn iterate(self: *Journal, from_slot: u64) !Iterator {
        var start: usize = 0;
        for (self.segments.items, 0..) |entry, index| {
            if (entry.last_slot >= from_slot) {
                start = index;
                break;
            }
            start = index + 1;
        }
        return .{
            .journal = self,
            .segment_index = start,
            .reader = null,
            .active_offset = segment.header_size,
        };
    }

    pub const Iterator = struct {
        journal: *Journal,
        segment_index: usize,
        reader: ?segment.Reader,
        active_offset: u64,
        buffer: [segment.max_record_size]u8 = undefined,

        pub fn close(self: *Iterator) void {
            if (self.reader) |*reader| reader.close();
            self.reader = null;
        }

        /// Returns the next retained record's decoded write.
        pub fn next(self: *Iterator) !?types.Write {
            while (true) {
                if (self.reader == null) {
                    if (self.segment_index >= self.journal.segments.items.len) {
                        return self.nextActive();
                    }
                    const entry = self.journal.segments.items[self.segment_index];
                    var name_buffer: [20]u8 = undefined;
                    const name = segmentName(&name_buffer, entry.first_slot);
                    // Manifest entries are sealed: validate their digest and
                    // stop at the records boundary, before the trailer.
                    self.reader = segment.Reader.openSealed(
                        self.journal.io,
                        self.journal.dir,
                        name,
                    ) catch return error.CorruptJournal;
                }
                const record = self.reader.?.next() catch
                    return error.CorruptJournal;
                if (record) |found| {
                    return types.decodeWrite(found.payload) catch
                        error.CorruptJournal;
                }
                self.reader.?.close();
                self.reader = null;
                self.segment_index += 1;
            }
        }

        fn nextActive(self: *Iterator) !?types.Write {
            const active = &self.journal.active;
            if (self.active_offset >= active.end_offset) return null;
            var reader = segment.Reader{
                .io = self.journal.io,
                .file = active.file,
                .header = undefined,
                .trailer = null,
                .offset = self.active_offset,
                .records_end = active.end_offset,
                .buffer = undefined,
            };
            const record = (reader.next() catch return error.CorruptJournal) orelse
                return null;
            self.active_offset = reader.offset;
            return types.decodeWrite(record.payload) catch error.CorruptJournal;
        }
    };

    fn observePromise(self: *Journal, ballot: paxos.Ballot) void {
        self.active.observePromise(ballot);
        if (self.max_promised.lessThan(ballot)) self.max_promised = ballot;
    }

    fn rotate(self: *Journal) !void {
        const digest = try self.active.seal(self.chosen_hint);
        const sealed_first = self.active.first_slot;
        const sealed_last = @max(self.active.last_slot, sealed_first);
        self.sealed_bytes += self.active.end_offset;
        self.active.close();
        try self.segments.append(self.gpa, .{
            .first_slot = sealed_first,
            .last_slot = sealed_last,
            .digest = digest,
        });
        self.active_first_slot = sealed_last + 1;
        try self.publishManifest();
        var name_buffer: [20]u8 = undefined;
        self.active = try segment.Writer.create(
            self.io,
            self.dir,
            segmentName(&name_buffer, self.active_first_slot),
            .{
                .database_id = self.database_id,
                .first_global_slot = self.active_first_slot,
                .previous_segment_digest = digest,
            },
        );
        try durability.syncDirectory(self.dir);
    }

    fn publishManifest(self: *Journal) !void {
        self.generation += 1;
        try manifest_mod.publish(self.io, self.gpa, self.dir, .{
            .generation = self.generation,
            .database_id = self.database_id,
            .max_promised = self.max_promised,
            .chosen_through = self.chosen_hint,
            .trim_decision_slot = self.trim_decision_slot,
            .trimmed_through = self.trimmed_through,
            .trim_history_hash = self.trim_history_hash,
            .active_first_slot = self.active_first_slot,
            .segments = self.segments.items,
        });
    }

    /// Deletes every `.zxj` file the manifest does not account for: the
    /// leavings of a crashed rotation or trim.
    fn sweepOrphans(self: *Journal) !void {
        var it = self.dir.iterate();
        var swept = false;
        while (self.dirNext(&it)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".zxj")) continue;
            const stem = entry.name[0 .. entry.name.len - 4];
            const first = std.fmt.parseInt(u64, stem, 16) catch {
                return error.CorruptJournal;
            };
            if (first == self.active_first_slot) continue;
            var known = false;
            for (self.segments.items) |kept| {
                if (kept.first_slot == first) {
                    known = true;
                    break;
                }
            }
            if (known) continue;
            var name_buffer: [20]u8 = undefined;
            const name = segmentName(&name_buffer, first);
            self.dir.deleteFile(self.io, name) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
            swept = true;
        }
        if (swept) try durability.syncDirectory(self.dir);
    }

    fn dirNext(self: *Journal, it: *Io.Dir.Iterator) ?Io.Dir.Entry {
        return it.next(self.io) catch null;
    }

    /// Resumes the active segment across every rotation crash window: a
    /// sealed file still named active is adopted into the manifest, a
    /// missing file is recreated, and an unsealed file resumes appending
    /// after torn-tail repair.
    fn adoptActive(self: *Journal) !void {
        var name_buffer: [20]u8 = undefined;
        const name = segmentName(&name_buffer, self.active_first_slot);
        const previous_digest = if (self.segments.items.len > 0)
            self.segments.items[self.segments.items.len - 1].digest
        else
            @as([32]u8, @splat(0));

        if (segment.Reader.openSealed(self.io, self.dir, name)) |sealed_value| {
            var sealed = sealed_value;
            // Crash between seal and manifest publication.
            const trailer = sealed.trailer.?;
            sealed.close();
            try self.segments.append(self.gpa, .{
                .first_slot = self.active_first_slot,
                .last_slot = @max(trailer.last_global_slot, self.active_first_slot),
                .digest = trailer.segment_digest,
            });
            self.active_first_slot =
                @max(trailer.last_global_slot, self.active_first_slot) + 1;
            try self.publishManifest();
            const next_name = segmentName(&name_buffer, self.active_first_slot);
            self.active = try segment.Writer.create(self.io, self.dir, next_name, .{
                .database_id = self.database_id,
                .first_global_slot = self.active_first_slot,
                .previous_segment_digest = trailer.segment_digest,
            });
            try durability.syncDirectory(self.dir);
            return;
        } else |err| switch (err) {
            error.FileNotFound => {
                // Crash between manifest publication and creation.
                self.active = try segment.Writer.create(self.io, self.dir, name, .{
                    .database_id = self.database_id,
                    .first_global_slot = self.active_first_slot,
                    .previous_segment_digest = previous_digest,
                });
                try durability.syncDirectory(self.dir);
                return;
            },
            else => {},
        }
        // The resumed active segment must be this database's and chain
        // onto the last sealed segment; a swapped-in stray would
        // otherwise be appended to silently.
        const header = segment.peekHeader(self.io, self.dir, name) catch
            return error.CorruptJournal;
        if (header.database_id != self.database_id or
            header.first_global_slot != self.active_first_slot or
            (self.segments.items.len > 0 and
                !std.mem.eql(
                    u8,
                    &header.previous_segment_digest,
                    &previous_digest,
                )))
        {
            return error.CorruptJournal;
        }
        self.active = try segment.Writer.adopt(self.io, self.dir, name);
    }

    /// Streams every retained record into the durable state in order,
    /// validating segment identity, digests, and sequence continuity.
    fn replay(self: *Journal, durable: *types.Log.DurableState, info: *ReplayInfo) !void {
        var expected: ?u64 = null;
        // The oldest retained segment's ancestor was legitimately deleted
        // by trimming, so only links between adjacent retained segments
        // are checkable.
        var previous_digest: ?[32]u8 = null;
        for (self.segments.items) |entry| {
            var name_buffer: [20]u8 = undefined;
            const name = segmentName(&name_buffer, entry.first_slot);
            var reader = segment.Reader.openSealed(self.io, self.dir, name) catch
                return error.CorruptJournal;
            defer reader.close();
            if (reader.header.database_id != self.database_id or
                !std.mem.eql(u8, &reader.trailer.?.segment_digest, &entry.digest))
            {
                return error.CorruptJournal;
            }
            // A self-consistent but foreign segment (stale copy, forged
            // manifest row) must not replay: its header must name the
            // manifest's slot range and chain onto its predecessor.
            if (reader.header.first_global_slot != entry.first_slot) {
                return error.CorruptJournal;
            }
            if (previous_digest) |digest| {
                if (!std.mem.eql(
                    u8,
                    &reader.header.previous_segment_digest,
                    &digest,
                )) {
                    return error.CorruptJournal;
                }
            }
            previous_digest = entry.digest;
            const trailer = reader.trailer.?;
            if (@max(trailer.last_global_slot, entry.first_slot) != entry.last_slot) {
                return error.CorruptJournal;
            }
            if (durable.promised.lessThan(trailer.max_promised)) {
                try durable.apply(.{ .promise = trailer.max_promised });
            }
            self.sealed_bytes += reader.file.length(self.io) catch 0;
            try self.replaySegment(&reader, durable, info, &expected);
        }
        try self.replayActive(durable, info, &expected);
        info.next_sequence = self.next_sequence;
    }

    fn replaySegment(
        self: *Journal,
        reader: *segment.Reader,
        durable: *types.Log.DurableState,
        info: *ReplayInfo,
        expected: *?u64,
    ) !void {
        while (reader.next() catch return error.CorruptJournal) |record| {
            try self.replayRecord(record, durable, info, expected);
        }
    }

    fn replayActive(
        self: *Journal,
        durable: *types.Log.DurableState,
        info: *ReplayInfo,
        expected: *?u64,
    ) !void {
        // The active segment was already torn-tail repaired by adopt;
        // decode failures here are corruption.
        var reader = segment.Reader{
            .io = self.io,
            .file = self.active.file,
            .header = undefined,
            .trailer = null,
            .offset = segment.header_size,
            .records_end = self.active.end_offset,
            .buffer = undefined,
        };
        while (reader.next() catch return error.CorruptJournal) |record| {
            try self.replayRecord(record, durable, info, expected);
        }
    }

    fn replayRecord(
        self: *Journal,
        record: segment.Record,
        durable: *types.Log.DurableState,
        info: *ReplayInfo,
        expected: *?u64,
    ) !void {
        if (expected.*) |want| {
            if (record.sequence != want) return error.SequenceGap;
        }
        expected.* = record.sequence + 1;
        self.next_sequence = record.sequence + 1;
        const write = types.decodeWrite(record.payload) catch
            return error.CorruptJournal;
        durable.replayFold(write) catch return error.CorruptJournal;
        switch (write) {
            .promise => |ballot| {
                if (self.max_promised.lessThan(ballot)) self.max_promised = ballot;
            },
            .accept => |accept| {
                if (self.max_promised.lessThan(accept.ballot)) {
                    self.max_promised = accept.ballot;
                }
                if (accept.slot > self.persisted) self.persisted = accept.slot;
            },
            .commit => |commit| {
                if (commit.slot > self.persisted) self.persisted = commit.slot;
            },
            .trim_anchor => {},
        }
        info.record_count += 1;
    }
};

const testing = std.testing;

fn testWrite(slot: u64) types.Write {
    return .{ .commit = .{
        .slot = slot,
        .value = .{ .command = .noop },
    } };
}

test "the journal replays across rotation and restart" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.create(io, testing.allocator, tmp.dir, 42);
    var slot: u64 = 1;
    while (slot <= 5) : (slot += 1) {
        journal.noteChosen(slot -| 1);
        try journal.appendWrites(&.{testWrite(slot)});
    }
    try journal.sync();
    journal.close();

    var durable = types.Log.DurableState{};
    var info: ReplayInfo = undefined;
    var reopened = try Journal.open(io, testing.allocator, tmp.dir, 42, &durable, &info);
    defer reopened.close();
    try testing.expectEqual(@as(u64, 5), info.record_count);
    try testing.expectEqual(@as(u64, 6), info.next_sequence);
    try testing.expectEqual(@as(u64, 5), reopened.persistedThrough());
    try testing.expect(durable.committedAt(3) != null);
}

test "a torn active tail is repaired and appending resumes" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.create(io, testing.allocator, tmp.dir, 42);
    try journal.appendWrites(&.{ testWrite(1), testWrite(2) });
    try journal.sync();
    const good_end = journal.active.end_offset;
    try journal.appendWrites(&.{testWrite(3)});
    try journal.sync();
    const torn_end = journal.active.end_offset - 3;
    journal.close();

    {
        var dir = try tmp.dir.openDir(io, directory_name, .{});
        defer dir.close(io);
        const file = try dir.openFile(io, "0000000000000001.zxj", .{
            .mode = .read_write,
        });
        defer file.close(io);
        try file.setLength(io, torn_end);
    }

    var durable = types.Log.DurableState{};
    var info: ReplayInfo = undefined;
    var reopened = try Journal.open(io, testing.allocator, tmp.dir, 42, &durable, &info);
    try testing.expectEqual(@as(u64, 2), info.record_count);
    try testing.expect(durable.committedAt(2) != null);
    try testing.expectEqual(@as(?types.Entry, null), durable.committedAt(3));
    try testing.expectEqual(good_end, reopened.active.end_offset);

    try reopened.appendWrites(&.{testWrite(3)});
    try reopened.sync();
    reopened.close();

    var durable_two = types.Log.DurableState{};
    var again = try Journal.open(io, testing.allocator, tmp.dir, 42, &durable_two, &info);
    defer again.close();
    try testing.expect(durable_two.committedAt(3) != null);
}

test "trimming unlinks sealed prefixes and keeps the promise rollup" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.create(io, testing.allocator, tmp.dir, 42);
    const high = paxos.Ballot{ .round = 9, .priority = 0, .node = 2 };
    try journal.appendWrites(&.{.{ .promise = high }});
    var slot: u64 = 1;
    while (slot <= segment.capacity_records + 10) : (slot += 1) {
        journal.noteChosen(slot -| 1);
        try journal.appendWrites(&.{testWrite(slot)});
    }
    try journal.sync();
    try testing.expectEqual(@as(usize, 1), journal.segments.items.len);

    journal.noteTrimAnchor(1, segment.capacity_records - 1, @as([32]u8, @splat(5)));
    try testing.expect(try journal.trimThrough(segment.capacity_records - 1));
    try testing.expectEqual(@as(usize, 0), journal.segments.items.len);
    journal.close();

    // The deleted segment held the highest promise; replay still knows it.
    var durable = types.Log.DurableState{};
    var info: ReplayInfo = undefined;
    var reopened = try Journal.open(io, testing.allocator, tmp.dir, 42, &durable, &info);
    defer reopened.close();
    try testing.expect(!durable.promised.lessThan(high));
    try testing.expectEqual(
        @as(u64, segment.capacity_records),
        reopened.retainedFirstSlot(),
    );
}

test "a trim anchor inside a retained segment survives reopening" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Two sealed segments plus an active one; the anchor lands strictly
    // inside the second segment, so reclamation removes only the first
    // and the retained chain starts below the anchor. Cluster nodes hit
    // this shape whenever their delete floor lags the chosen trim.
    var journal = try Journal.create(io, testing.allocator, tmp.dir, 42);
    var slot: u64 = 1;
    while (slot <= 2 * segment.capacity_records + 10) : (slot += 1) {
        journal.noteChosen(slot -| 1);
        try journal.appendWrites(&.{testWrite(slot)});
    }
    try journal.sync();
    try testing.expectEqual(@as(usize, 2), journal.segments.items.len);
    const anchor = journal.segments.items[1].first_slot + 100;
    try testing.expect(anchor < journal.segments.items[1].last_slot);

    journal.noteTrimAnchor(1, anchor, @as([32]u8, @splat(7)));
    try testing.expect(try journal.trimThrough(anchor));
    try testing.expectEqual(@as(usize, 1), journal.segments.items.len);
    try testing.expect(journal.segments.items[0].first_slot <= anchor);
    const retained_first = journal.segments.items[0].first_slot;
    journal.close();

    // Reopening must accept the straddling manifest and keep both the
    // anchor and the retained chain.
    var durable = types.Log.DurableState{};
    var info: ReplayInfo = undefined;
    var reopened = try Journal.open(io, testing.allocator, tmp.dir, 42, &durable, &info);
    defer reopened.close();
    try testing.expectEqual(anchor, reopened.trimmed_through);
    try testing.expectEqual(retained_first, reopened.retainedFirstSlot());
    try testing.expect(durable.committedAt(2 * segment.capacity_records + 10) != null);
}

test "retained iteration crosses sealed trailers and reaches the active segment" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var journal = try Journal.create(io, testing.allocator, tmp.dir, 42);
    defer journal.close();
    try journal.appendWrites(&.{ testWrite(1), testWrite(2) });
    try journal.rotate();
    try journal.appendWrites(&.{ testWrite(3), testWrite(4) });
    try journal.rotate();
    try journal.appendWrites(&.{testWrite(5)});
    try journal.sync();

    try expectRetainedSlots(&journal, 1, 5);
    try expectRetainedSlots(&journal, 3, 5);
    const Sink = struct {
        next: u64 = 2,
        fn accept(self: *@This(), slot: u64, value: types.Entry) !void {
            try testing.expectEqual(self.next, slot);
            try testing.expectEqualDeep(testWrite(slot).commit.value, value);
            self.next += 1;
        }
    };
    var sink = Sink{};
    try journal.serveRange(2, 3, &sink, Sink.accept);
    try testing.expectEqual(@as(u64, 5), sink.next);

    journal.noteTrimAnchor(1, 2, @as([32]u8, @splat(7)));
    try testing.expect(try journal.trimThrough(2));
    try expectRetainedSlots(&journal, 3, 5);
}

fn expectRetainedSlots(journal: *Journal, first: u64, last: u64) !void {
    var it = try journal.iterate(first);
    defer it.close();
    var expected = first;
    while (try it.next()) |write| {
        try testing.expectEqualDeep(testWrite(expected), write);
        expected += 1;
    }
    try testing.expectEqual(last + 1, expected);
}

test "retained iteration rejects a damaged sealed digest before yielding records" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var journal = try Journal.create(io, testing.allocator, tmp.dir, 42);
    defer journal.close();
    try journal.appendWrites(&.{ testWrite(1), testWrite(2) });
    try journal.rotate();
    const file = try journal.dir.openFile(io, "0000000000000001.zxj", .{ .mode = .read_write });
    defer file.close(io);
    // The digest is immediately before the four-byte trailer length. Record
    // CRCs remain valid, so only sealed-segment validation catches this damage.
    const offset = try file.length(io) - 5;
    var byte: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try file.readPositionalAll(io, &byte, offset));
    byte[0] ^= 1;
    try file.writePositionalAll(io, &byte, offset);
    var it = try journal.iterate(1);
    defer it.close();
    try testing.expectError(error.CorruptJournal, it.next());
}
