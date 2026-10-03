//! WAL frame capture and deterministic page-level apply.
//!
//! Capture technique (Phase 0 ADR): the node runs one writer connection in
//! WAL mode with automatic checkpoints disabled. `sqlite3_wal_hook` reports
//! the committed frame count after every commit; the frames between the
//! previous and new count are read directly from the `-wal` file. Rolled
//! back transactions never advance the hook count, so their frames are never
//! captured. Checkpoints happen only at state-anchor boundaries, after
//! which capture restarts at frame zero.
//!
//! Apply technique: a committed payload is applied offline by writing each
//! frame's page image at `(page_number - 1) * page_size` and truncating the
//! database file to the commit frame's page count. Given the same base image
//! and the same frame bytes this transition is deterministic; it is how a
//! materialized SQLite image is rebuilt from the durable anchor plus the
//! retained journal suffix.

const std = @import("std");
const Io = std.Io;
const durability = @import("durability.zig");

pub const wal_header_size = 32;
pub const frame_header_size = 24;

pub const payload_magic: u32 = 0x4c50585a; // "ZXPL"
pub const payload_version: u8 = 1;
pub const payload_header_size = 4 + 1 + 3 + 4 + 16 + 4 + 4;
pub const transaction_record_size = 8 + 8 + 4 + 4 + 8;
pub const frame_record_size = 4 + 4;

pub const FrameInfo = struct {
    page_number: u32,
    /// Database size in pages after this frame when it is a commit frame,
    /// zero otherwise.
    commit_size: u32,
};

pub const FrameSet = struct {
    infos: []FrameInfo,
    pages: []u8,
    page_size: u32,

    pub fn deinit(self: *FrameSet, gpa: std.mem.Allocator) void {
        gpa.free(self.infos);
        gpa.free(self.pages);
        self.* = undefined;
    }

    pub fn pageAt(self: *const FrameSet, index: usize) []const u8 {
        return self.pages[index * self.page_size ..][0..self.page_size];
    }
};

/// One transaction boundary inside a payload, in captured commit order.
pub const Transaction = struct {
    session_id: u64,
    sequence: u64,
    first_frame: u32,
    frame_count: u32,
    change_count: i64,
};

pub const CaptureError = error{
    TornWal,
    NonCommitTail,
} || anyerror;

/// Reads committed frames `[from_frame, to_frame)` from a WAL file. Frame
/// indices are zero-based; `to_frame` normally comes from the wal hook.
pub fn readCommittedFrames(
    io: Io,
    gpa: std.mem.Allocator,
    dir: Io.Dir,
    wal_name: []const u8,
    page_size: u32,
    from_frame: u32,
    to_frame: u32,
) CaptureError!FrameSet {
    std.debug.assert(from_frame <= to_frame);
    const count = to_frame - from_frame;
    const infos = try gpa.alloc(FrameInfo, count);
    errdefer gpa.free(infos);
    const pages = try gpa.alloc(u8, @as(usize, count) * page_size);
    errdefer gpa.free(pages);

    if (count == 0) {
        return .{ .infos = infos, .pages = pages, .page_size = page_size };
    }

    const file = try dir.openFile(io, wal_name, .{});
    defer file.close(io);

    const frame_size: u64 = frame_header_size + @as(u64, page_size);
    var header: [frame_header_size]u8 = undefined;
    for (0..count) |index| {
        const frame_index = from_frame + index;
        const offset = wal_header_size + @as(u64, frame_index) * frame_size;
        const header_read = try file.readPositionalAll(io, &header, offset);
        if (header_read != header.len) return error.TornWal;
        infos[index] = .{
            .page_number = std.mem.readInt(u32, header[0..4], .big),
            .commit_size = std.mem.readInt(u32, header[4..8], .big),
        };
        const page = pages[index * page_size ..][0..page_size];
        const page_read = try file.readPositionalAll(io, page, offset + frame_header_size);
        if (page_read != page.len) return error.TornWal;
    }
    if (infos[count - 1].commit_size == 0) return error.NonCommitTail;
    return .{ .infos = infos, .pages = pages, .page_size = page_size };
}

/// Serializes one transaction batch and its frames into an immutable payload.
pub fn encodePayload(
    gpa: std.mem.Allocator,
    database_id: u128,
    transactions: []const Transaction,
    frames: *const FrameSet,
) ![]u8 {
    const total = payload_header_size +
        transactions.len * transaction_record_size +
        frames.infos.len * frame_record_size +
        frames.pages.len;
    const bytes = try gpa.alloc(u8, total);
    errdefer gpa.free(bytes);

    var offset: usize = 0;
    writeInt(u32, bytes, &offset, payload_magic);
    bytes[offset] = payload_version;
    offset += 1;
    @memset(bytes[offset..][0..3], 0);
    offset += 3;
    writeInt(u32, bytes, &offset, frames.page_size);
    writeInt(u128, bytes, &offset, database_id);
    writeInt(u32, bytes, &offset, @intCast(transactions.len));
    writeInt(u32, bytes, &offset, @intCast(frames.infos.len));

    for (transactions) |transaction| {
        writeInt(u64, bytes, &offset, transaction.session_id);
        writeInt(u64, bytes, &offset, transaction.sequence);
        writeInt(u32, bytes, &offset, transaction.first_frame);
        writeInt(u32, bytes, &offset, transaction.frame_count);
        writeInt(i64, bytes, &offset, transaction.change_count);
    }
    for (frames.infos) |info| {
        writeInt(u32, bytes, &offset, info.page_number);
        writeInt(u32, bytes, &offset, info.commit_size);
    }
    @memcpy(bytes[offset..][0..frames.pages.len], frames.pages);
    offset += frames.pages.len;
    std.debug.assert(offset == total);
    return bytes;
}

pub const PayloadError = error{
    InvalidPayloadMagic,
    UnsupportedPayloadVersion,
    TruncatedPayload,
    InvalidPayloadShape,
};

/// A validated, zero-copy view over immutable payload bytes.
pub const PayloadView = struct {
    bytes: []const u8,
    page_size: u32,
    database_id: u128,
    transaction_count: u32,
    frame_count: u32,

    pub fn parse(bytes: []const u8) PayloadError!PayloadView {
        if (bytes.len < payload_header_size) return error.TruncatedPayload;
        var offset: usize = 0;
        const magic = readInt(u32, bytes, &offset);
        if (magic != payload_magic) return error.InvalidPayloadMagic;
        const version = bytes[offset];
        offset += 4;
        if (version != payload_version) return error.UnsupportedPayloadVersion;
        const page_size = readInt(u32, bytes, &offset);
        if (page_size < 512 or page_size > 65536) return error.InvalidPayloadShape;
        if (!std.math.isPowerOfTwo(page_size)) return error.InvalidPayloadShape;
        const database_id = readInt(u128, bytes, &offset);
        const transaction_count = readInt(u32, bytes, &offset);
        const frame_count = readInt(u32, bytes, &offset);

        const expected = payload_header_size +
            @as(u64, transaction_count) * transaction_record_size +
            @as(u64, frame_count) * frame_record_size +
            @as(u64, frame_count) * page_size;
        if (bytes.len != expected) return error.TruncatedPayload;
        if (transaction_count == 0 or frame_count == 0) {
            return error.InvalidPayloadShape;
        }

        const view = PayloadView{
            .bytes = bytes,
            .page_size = page_size,
            .database_id = database_id,
            .transaction_count = transaction_count,
            .frame_count = frame_count,
        };
        // Transactions must tile the frame range in order, and every
        // transaction must end on a commit frame.
        var next_frame: u32 = 0;
        for (0..transaction_count) |index| {
            const transaction = view.transactionAt(@intCast(index));
            if (transaction.first_frame != next_frame) return error.InvalidPayloadShape;
            if (transaction.frame_count == 0) return error.InvalidPayloadShape;
            next_frame += transaction.frame_count;
            if (next_frame > frame_count) return error.InvalidPayloadShape;
            const last = view.frameInfoAt(next_frame - 1);
            if (last.commit_size == 0) return error.InvalidPayloadShape;
        }
        if (next_frame != frame_count) return error.InvalidPayloadShape;
        for (0..frame_count) |index| {
            if (view.frameInfoAt(@intCast(index)).page_number == 0) {
                return error.InvalidPayloadShape;
            }
        }
        return view;
    }

    pub fn transactionAt(self: *const PayloadView, index: u32) Transaction {
        std.debug.assert(index < self.transaction_count);
        var offset = payload_header_size +
            @as(usize, index) * transaction_record_size;
        return .{
            .session_id = readInt(u64, self.bytes, &offset),
            .sequence = readInt(u64, self.bytes, &offset),
            .first_frame = readInt(u32, self.bytes, &offset),
            .frame_count = readInt(u32, self.bytes, &offset),
            .change_count = readInt(i64, self.bytes, &offset),
        };
    }

    pub fn frameInfoAt(self: *const PayloadView, index: u32) FrameInfo {
        std.debug.assert(index < self.frame_count);
        var offset = payload_header_size +
            @as(usize, self.transaction_count) * transaction_record_size +
            @as(usize, index) * frame_record_size;
        return .{
            .page_number = readInt(u32, self.bytes, &offset),
            .commit_size = readInt(u32, self.bytes, &offset),
        };
    }

    pub fn framePage(self: *const PayloadView, index: u32) []const u8 {
        std.debug.assert(index < self.frame_count);
        const base = payload_header_size +
            @as(usize, self.transaction_count) * transaction_record_size +
            @as(usize, self.frame_count) * frame_record_size;
        return self.bytes[base + @as(usize, index) * self.page_size ..][0..self.page_size];
    }
};

/// Applies every frame of a committed payload to a database file image.
/// The file must not be open in any SQLite connection.
pub fn applyPayload(io: Io, file: Io.File, view: *const PayloadView) !void {
    var final_size: u32 = 0;
    for (0..view.frame_count) |index| {
        const info = view.frameInfoAt(@intCast(index));
        const page = view.framePage(@intCast(index));
        const offset = @as(u64, info.page_number - 1) * view.page_size;
        try file.writePositionalAll(io, page, offset);
        if (info.commit_size != 0) final_size = info.commit_size;
    }
    std.debug.assert(final_size != 0);
    try file.setLength(io, @as(u64, final_size) * view.page_size);
}

fn writeInt(comptime T: type, bytes: []u8, offset: *usize, value: T) void {
    std.mem.writeInt(T, bytes[offset.*..][0..@sizeOf(T)], value, .little);
    offset.* += @sizeOf(T);
}

fn readInt(comptime T: type, bytes: []const u8, offset: *usize) T {
    const value = std.mem.readInt(T, bytes[offset.*..][0..@sizeOf(T)], .little);
    offset.* += @sizeOf(T);
    return value;
}

const testing = std.testing;
const sqlite = @import("sqlite.zig");

const SpikeDb = struct {
    db: sqlite.Db,
    committed_frames: u32 = 0,
    captured_frames: u32 = 0,
    db_path: [:0]const u8,
    wal_name: []const u8,

    fn open(gpa: std.mem.Allocator, dir: Io.Dir, name: []const u8) !*SpikeDb {
        var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
        const dir_len = try dir.realPath(testing.io, &path_buffer);
        const db_path = try gpa.printSentinel(
            "{s}/{s}",
            .{ path_buffer[0..dir_len], name },
            0,
        );
        errdefer gpa.free(db_path);
        const wal_name = try std.fmt.allocPrint(gpa, "{s}-wal", .{name});
        errdefer gpa.free(wal_name);

        const self = try gpa.create(SpikeDb);
        errdefer gpa.destroy(self);
        self.* = .{
            .db = try sqlite.Db.open(db_path),
            .db_path = db_path,
            .wal_name = wal_name,
        };
        try self.db.exec("pragma page_size = 4096");
        try self.db.exec("pragma journal_mode = wal");
        try self.db.exec("pragma wal_autocheckpoint = 0");
        try self.db.exec("pragma synchronous = normal");
        self.db.trackCommittedFrames(&self.committed_frames);
        return self;
    }

    fn close(self: *SpikeDb, gpa: std.mem.Allocator) void {
        self.db.close();
        gpa.free(self.db_path);
        gpa.free(self.wal_name);
        gpa.destroy(self);
    }

    /// Runs one write transaction and returns its encoded payload.
    fn commitAndCapture(
        self: *SpikeDb,
        gpa: std.mem.Allocator,
        dir: Io.Dir,
        sql: [:0]const u8,
    ) ![]u8 {
        try self.db.exec(sql);
        try testing.expect(self.committed_frames > self.captured_frames);
        var frames = try readCommittedFrames(
            testing.io,
            gpa,
            dir,
            self.wal_name,
            4096,
            self.captured_frames,
            self.committed_frames,
        );
        defer frames.deinit(gpa);
        self.captured_frames = self.committed_frames;

        const transactions = [_]Transaction{.{
            .session_id = 0,
            .sequence = 0,
            .first_frame = 0,
            .frame_count = @intCast(frames.infos.len),
            .change_count = self.db.changes(),
        }};
        return encodePayload(gpa, 1, &transactions, &frames);
    }
};

fn rebuildFromPayloads(dir: Io.Dir, name: []const u8, payloads: []const []u8) !void {
    const io = testing.io;
    const file = try dir.createFile(io, name, .{ .read = true });
    defer file.close(io);
    for (payloads) |payload| {
        const view = try PayloadView.parse(payload);
        try applyPayload(io, file, &view);
    }
    try durability.syncFile(io, file);
}

fn expectSameFileBytes(dir: Io.Dir, left: []const u8, right: []const u8) !void {
    const io = testing.io;
    const gpa = testing.allocator;
    const left_file = try dir.openFile(io, left, .{});
    defer left_file.close(io);
    const right_file = try dir.openFile(io, right, .{});
    defer right_file.close(io);

    const left_len = try left_file.length(io);
    const right_len = try right_file.length(io);
    try testing.expectEqual(left_len, right_len);

    const left_bytes = try gpa.alloc(u8, @intCast(left_len));
    defer gpa.free(left_bytes);
    const right_bytes = try gpa.alloc(u8, @intCast(right_len));
    defer gpa.free(right_bytes);
    _ = try left_file.readPositionalAll(io, left_bytes, 0);
    _ = try right_file.readPositionalAll(io, right_bytes, 0);
    try testing.expectEqualSlices(u8, left_bytes, right_bytes);
}

test "captured frames rebuild a byte-identical database" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const spike = try SpikeDb.open(gpa, tmp.dir, "source.db");
    defer spike.close(gpa);

    var payloads: std.ArrayList([]u8) = .empty;
    defer {
        for (payloads.items) |payload| gpa.free(payload);
        payloads.deinit(gpa);
    }

    const commits = [_][:0]const u8{
        // DDL, triggers, and an index.
        \\create table items(id integer primary key, v text, n integer);
        \\create table audit(item_id integer, note text);
        \\create trigger items_audit after insert on items begin
        \\  insert into audit values (new.id, 'added ' || new.v);
        \\end;
        \\create index items_n on items(n);
        ,
        // Plain DML through the trigger.
        "insert into items(v, n) values ('tea', 1), ('coffee', 2), ('water', 3)",
        // Nondeterministic SQL is safe: frames capture its outcome.
        "insert into items(v, n) values (hex(randomblob(16)), abs(random() % 100))",
        // A large blob spanning many pages.
        "insert into items(v, n) values (hex(randomblob(20000)), 9)",
        // Savepoint partially rolled back inside one committed transaction.
        \\begin;
        \\insert into items(v, n) values ('kept', 10);
        \\savepoint sp;
        \\insert into items(v, n) values ('discarded', 11);
        \\rollback to sp;
        \\release sp;
        \\commit;
        ,
        // Update and delete touching the index.
        "update items set n = n + 100 where n < 50",
        "delete from items where v = 'water'",
        // Schema change after data exists.
        "alter table items add column extra text default 'x'",
    };
    for (commits) |sql| {
        const payload = try spike.commitAndCapture(gpa, tmp.dir, sql);
        try payloads.append(gpa, payload);
    }

    // A rolled-back transaction must not advance the committed frame count.
    const before_rollback = spike.committed_frames;
    try spike.db.exec("begin; insert into items(v, n) values ('never', 0); rollback;");
    try testing.expectEqual(before_rollback, spike.committed_frames);

    // A transaction after the rollback overwrites the abandoned frames.
    const payload = try spike.commitAndCapture(
        gpa,
        tmp.dir,
        "insert into items(v, n) values ('after-rollback', 12)",
    );
    try payloads.append(gpa, payload);

    try rebuildFromPayloads(tmp.dir, "rebuilt.db", payloads.items);

    // Checkpointing the source database materializes all WAL content into
    // the main file; the rebuilt image must match it byte for byte.
    try spike.db.checkpointTruncate();
    try expectSameFileBytes(tmp.dir, "source.db", "rebuilt.db");

    // The rebuilt image must be a healthy database with identical content.
    var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const rebuilt_path = try gpa.printSentinel(
        "{s}/rebuilt.db",
        .{path_buffer[0..dir_len]},
        0,
    );
    defer gpa.free(rebuilt_path);
    var rebuilt = try sqlite.Db.open(rebuilt_path);
    defer rebuilt.close();
    try testing.expect(try rebuilt.integrityCheckOk());

    var stmt = try rebuilt.prepare(
        "select count(*), coalesce(sum(n), 0) from items",
    );
    defer stmt.finalize();
    try testing.expect(try stmt.step());
    var source_stmt = try spike.db.prepare(
        "select count(*), coalesce(sum(n), 0) from items",
    );
    defer source_stmt.finalize();
    try testing.expect(try source_stmt.step());
    try testing.expectEqual(source_stmt.columnInt64(0), stmt.columnInt64(0));
    try testing.expectEqual(source_stmt.columnInt64(1), stmt.columnInt64(1));

    var audit_stmt = try rebuilt.prepare("select count(*) from audit");
    defer audit_stmt.finalize();
    try testing.expect(try audit_stmt.step());
    try testing.expect(audit_stmt.columnInt64(0) >= 4);
}

test "fts5 and vec0 shadow state rebuilds byte-identically" {
    // The load-bearing determinism proof for ZDS 0009: FTS5 segment pages
    // and vec0 shadow-table pages captured from the leader's WAL must
    // materialize the same bytes on a replica, including index
    // maintenance. Nondeterminism here forbids the search feature.
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const spike = try SpikeDb.open(gpa, tmp.dir, "search-source.db");
    defer spike.close(gpa);

    var payloads: std.ArrayList([]u8) = .empty;
    defer {
        for (payloads.items) |payload| gpa.free(payload);
        payloads.deinit(gpa);
    }

    const commits = [_][:0]const u8{
        // Base rows, an external-content FTS5 index, and one vec0 table
        // holding both vector representations (ZDS 0009 layout).
        \\create table media(id integer primary key, title text, uri text);
        \\create virtual table media_fts using fts5(
        \\  title, content='media', content_rowid='id');
        \\create virtual table media_vec using vec0(
        \\  item_id integer primary key,
        \\  embedding float[8],
        \\  embedding_coarse bit[8]);
        ,
        // One atomic multimodal insert: base + tokens + float + bit.
        \\begin;
        \\insert into media(id, title, uri) values
        \\  (1, 'paxos replicates sqlite', 'zx://one'),
        \\  (2, 'vectors rank media', 'zx://two'),
        \\  (3, 'hamming coarse scan', 'zx://three');
        \\insert into media_fts(rowid, title) select id, title from media;
        \\insert into media_vec(item_id, embedding, embedding_coarse) values
        \\  (1, vec_f32('[1,0,0,0,0,0,0,0]'),
        \\      vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))),
        \\  (2, vec_f32('[0,1,0,0,0,0,0,0]'),
        \\      vec_quantize_binary(vec_f32('[-1,1,-1,-1,-1,-1,-1,-1]'))),
        \\  (3, vec_f32('[1,1,0,0,0,0,0,0]'),
        \\      vec_quantize_binary(vec_f32('[1,1,-1,-1,-1,-1,-1,-1]')));
        \\commit;
        ,
        // Update and delete flow through all three representations.
        \\begin;
        \\insert into media_fts(media_fts, rowid, title)
        \\  values ('delete', 1, 'paxos replicates sqlite');
        \\update media set title = 'paxos replicates pages' where id = 1;
        \\insert into media_fts(rowid, title) values (1, 'paxos replicates pages');
        \\insert into media_fts(media_fts, rowid, title)
        \\  values ('delete', 2, 'vectors rank media');
        \\delete from media where id = 2;
        \\delete from media_vec where item_id = 2;
        \\update media_vec set embedding = vec_f32('[0.5,0.5,0,0,0,0,0,0]')
        \\  where item_id = 3;
        \\commit;
        ,
        // Bounded FTS5 maintenance exactly as ZDS 0009 prescribes.
        \\begin;
        \\insert into media_fts(media_fts, rank) values ('usermerge', 4);
        \\insert into media_fts(media_fts, rank) values ('merge', 10);
        \\commit;
        ,
        // Index compaction inside one replicated commit.
        "insert into media_fts(media_fts) values ('optimize')",
    };
    for (commits) |sql| {
        const payload = try spike.commitAndCapture(gpa, tmp.dir, sql);
        try payloads.append(gpa, payload);
    }

    try rebuildFromPayloads(tmp.dir, "search-rebuilt.db", payloads.items);
    try spike.db.checkpointTruncate();
    try expectSameFileBytes(tmp.dir, "search-source.db", "search-rebuilt.db");

    // The rebuilt image answers the hybrid coarse + exact-rerank query
    // identically to the source.
    var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const rebuilt_path = try gpa.printSentinel(
        "{s}/search-rebuilt.db",
        .{path_buffer[0..dir_len]},
        0,
    );
    defer gpa.free(rebuilt_path);
    var rebuilt = try sqlite.Db.open(rebuilt_path);
    defer rebuilt.close();
    try testing.expect(try rebuilt.integrityCheckOk());

    const hybrid_sql =
        \\with coarse as (
        \\  select item_id, embedding from media_vec
        \\  where embedding_coarse match
        \\    vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))
        \\  and k = 2)
        \\select item_id,
        \\  zaxon_vec_distance_cosine(embedding, vec_f32('[1,0,0,0,0,0,0,0]'))
        \\from coarse order by 2, item_id
    ;
    var source_query = try spike.db.prepare(hybrid_sql);
    defer source_query.finalize();
    var rebuilt_query = try rebuilt.prepare(hybrid_sql);
    defer rebuilt_query.finalize();
    while (try source_query.step()) {
        try testing.expect(try rebuilt_query.step());
        try testing.expectEqual(
            source_query.columnInt64(0),
            rebuilt_query.columnInt64(0),
        );
        try testing.expectEqual(
            source_query.columnDouble(1),
            rebuilt_query.columnDouble(1),
        );
    }
    try testing.expect(!try rebuilt_query.step());

    var fts_query = try rebuilt.prepare(
        "select rowid from media_fts where media_fts match 'paxos'",
    );
    defer fts_query.finalize();
    try testing.expect(try fts_query.step());
    try testing.expectEqual(@as(i64, 1), fts_query.columnInt64(0));
    try testing.expect(!try fts_query.step());
}

test "a byte-budgeted vector batch stays under the payload target" {
    // ZDS 0009 operational rule: bulk vector writes are byte-budgeted at
    // a 16 MiB captured-payload target. A 1500-row batch of
    // 1536-dimensional float32 plus coarse bit vectors must fit.
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const spike = try SpikeDb.open(gpa, tmp.dir, "batch.db");
    defer spike.close(gpa);

    const schema_payload = try spike.commitAndCapture(
        gpa,
        tmp.dir,
        "create virtual table media_vec using vec0(" ++
            "item_id integer primary key, " ++
            "embedding float[1536], " ++
            "embedding_coarse bit[1536])",
    );
    defer gpa.free(schema_payload);

    const batch_payload = try spike.commitAndCapture(
        gpa,
        tmp.dir,
        \\begin;
        \\with recursive n(i) as
        \\  (select 1 union all select i + 1 from n where i < 1500)
        \\insert into media_vec(item_id, embedding, embedding_coarse)
        \\  select i, randomblob(6144), vec_bit(randomblob(192)) from n;
        \\commit;
        ,
    );
    defer gpa.free(batch_payload);

    // The payload really carries the vector bytes...
    try testing.expect(batch_payload.len > 1500 * 6144);
    // ...and stays inside the 16 MiB captured-payload target.
    try testing.expect(batch_payload.len <= 16 * 1024 * 1024);
}

test "payload parser rejects malformed shapes" {
    const gpa = testing.allocator;
    var infos = [_]FrameInfo{
        .{ .page_number = 1, .commit_size = 0 },
        .{ .page_number = 2, .commit_size = 2 },
    };
    const pages = try gpa.alloc(u8, 2 * 4096);
    defer gpa.free(pages);
    @memset(pages, 0xaa);
    const frames = FrameSet{ .infos = &infos, .pages = pages, .page_size = 4096 };
    const transactions = [_]Transaction{.{
        .session_id = 1,
        .sequence = 1,
        .first_frame = 0,
        .frame_count = 2,
        .change_count = 1,
    }};
    const good = try encodePayload(gpa, 7, &transactions, &frames);
    defer gpa.free(good);
    _ = try PayloadView.parse(good);

    try testing.expectError(error.TruncatedPayload, PayloadView.parse(good[0 .. good.len - 1]));

    const bad_magic = try gpa.dupe(u8, good);
    defer gpa.free(bad_magic);
    bad_magic[0] ^= 0xff;
    try testing.expectError(error.InvalidPayloadMagic, PayloadView.parse(bad_magic));

    // A transaction whose last frame is not a commit frame is invalid.
    var no_commit_infos = [_]FrameInfo{
        .{ .page_number = 1, .commit_size = 1 },
        .{ .page_number = 2, .commit_size = 0 },
    };
    const no_commit_frames = FrameSet{
        .infos = &no_commit_infos,
        .pages = pages,
        .page_size = 4096,
    };
    const bad_shape = try encodePayload(gpa, 7, &transactions, &no_commit_frames);
    defer gpa.free(bad_shape);
    try testing.expectError(error.InvalidPayloadShape, PayloadView.parse(bad_shape));
}
