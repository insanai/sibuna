//! The content-addressed, immutable transaction payload store.
//!
//! A payload is named by the SHA-256 of its bytes and installed with
//! write-temp, sync, atomic-rename. Bytes stored under a hash are never
//! mutated. A descriptor may enter the Paxos core only after its payload
//! is installed here; deletion requires a durable reachability proof
//! owned by the host, never age alone.
//!
//! Durability contract: `put`/`putNamed` flush the object and its
//! directory entries to the drive but deliberately stop before the
//! drive-cache barrier. The host's next journal sync — which precedes
//! every vote, recovered-value message, and client acknowledgement — is
//! the single barrier that makes installed payloads power-loss durable
//! (see `durability.zig`). Anchor publication likewise barriers before
//! the alternate APPLIED record is adopted (the old CURRENT pointer name
//! survives only as a legacy-artifact tripwire). So every counted vote
//! and every acknowledged
//! write still implies durable payload bytes at its consumer, at one
//! full flush per commit point instead of three.

const std = @import("std");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const named_atomic = @import("named_atomic.zig");
const durability = @import("durability.zig");

pub const Hash = [32]u8;

pub const LoadError = error{
    PayloadMissing,
    PayloadCorrupt,
} || anyerror;

pub const PayloadStore = struct {
    io: Io,
    dir: Io.Dir,
    /// Bytes of retained payload objects, counted once at open and
    /// maintained across installs and removals; feeds the storage
    /// budget alongside journal bytes (ZDS 0011).
    retained_bytes: u64 = 0,

    pub fn init(io: Io, parent: Io.Dir) !PayloadStore {
        // Iterate so the long-lived handle is a real descriptor: it is
        // fsynced on the write path, and Linux non-iterating opens are
        // `O_PATH`, which `fsync` rejects.
        const dir = try parent.createDirPathOpen(io, "payloads", .{
            .open_options = .{ .iterate = true },
        });
        errdefer dir.close(io);
        try durability.syncDirectory(parent);
        try durability.syncDirectory(dir);
        var self = PayloadStore{ .io = io, .dir = dir };
        self.retained_bytes = try self.measureRetainedBytes();
        return self;
    }

    /// Sums every retained object once at open. Fails closed: capacity
    /// enforcement built on an undercount would be a lie, so an
    /// unreadable shard or object is an open error, not a zero.
    fn measureRetainedBytes(self: *PayloadStore) !u64 {
        var total: u64 = 0;
        var shards = self.dir.iterate();
        while (try shards.next(self.io)) |shard| {
            if (shard.kind != .directory or shard.name.len != 2) continue;
            var shard_name: [2]u8 = shard.name[0..2].*;
            var shard_dir = try self.dir.openDir(
                self.io,
                &shard_name,
                .{ .iterate = true },
            );
            defer shard_dir.close(self.io);
            // Node.open holds the exclusive directory LOCK before init; no
            // live writer can own a stage while crash leftovers are removed.
            var removed_stage = false;
            var objects = shard_dir.iterate();
            while (try objects.next(self.io)) |object| {
                if (object.kind != .file) continue;
                if (named_atomic.isTemporaryName(object.name)) {
                    try shard_dir.deleteFile(self.io, object.name);
                    removed_stage = true;
                    continue;
                }
                var object_name: [62]u8 = undefined;
                if (object.name.len != 62) continue;
                object_name = object.name[0..62].*;
                const stat = try shard_dir.statFile(
                    self.io,
                    &object_name,
                    .{},
                );
                total +|= stat.size;
            }
            if (removed_stage) try durability.syncDirectory(shard_dir);
        }
        return total;
    }

    pub fn deinit(self: *PayloadStore) void {
        self.dir.close(self.io);
        self.* = undefined;
    }

    pub fn hashOf(bytes: []const u8) Hash {
        var digest: Hash = undefined;
        Sha256.hash(bytes, &digest, .{});
        return digest;
    }

    /// Stores `bytes` under their content hash and returns the hash;
    /// power-loss durability follows at the caller's next storage
    /// barrier (see the module comment). Idempotent: an
    /// already-installed payload is left untouched.
    pub fn put(self: *PayloadStore, bytes: []const u8) !Hash {
        const digest = hashOf(bytes);
        try self.putNamed(digest, bytes);
        return digest;
    }

    /// Stores bytes whose hash the caller already knows (e.g. verified
    /// transfer). Asserts the digest matches in safe builds.
    pub fn putNamed(self: *PayloadStore, digest: Hash, bytes: []const u8) !void {
        if (!std.mem.eql(u8, &hashOf(bytes), &digest)) {
            return error.PayloadHashMismatch;
        }
        if (self.verify(digest)) |_| {
            return;
        } else |err| switch (err) {
            error.PayloadMissing => {},
            error.PayloadCorrupt => self.remove(digest) catch |remove_err| switch (remove_err) {
                error.FileNotFound => {},
                else => return remove_err,
            },
            else => return err,
        }

        var path_buffer: [65]u8 = undefined;
        const path = pathOf(&path_buffer, digest);
        // Only a newly created two-hex shard changes the payload root. The
        // previous implementation fsynced that unchanged root for every
        // object, adding one syscall per voter per write. The shard itself
        // still receives a positional directory sync after the link.
        const shard_status = try self.dir.createDirPathStatus(
            self.io,
            path[0..2],
            @fromBackingInt(@intCast(0o700)),
        );
        if (shard_status == .created) {
            try durability.syncDirectoryBeforeBarrier(self.dir);
        }
        // A named stage uses no-replace rename rather than O_TMPFILE linkat.
        // Some filesystems stall that link long enough to starve protocol ticks.
        // Byte, directory and journal barriers retain their existing order.
        var atomic = try named_atomic.NamedAtomic.init(self.io, self.dir, path[0..2]);
        defer atomic.deinit(self.io);
        try atomic.file.writePositionalAll(self.io, bytes, 0);
        try durability.syncFileBeforeBarrier(self.io, atomic.file);
        atomic.finish(self.io, path[3..]) catch |err| switch (err) {
            // Another writer installed identical content first; it also
            // counted the bytes.
            error.PathAlreadyExists => {
                try durability.syncChildDirectoryBeforeBarrier(
                    self.io,
                    self.dir,
                    path[0..2],
                );
                return;
            },
            else => return err,
        };
        self.retained_bytes +|= bytes.len;
        try durability.syncChildDirectoryBeforeBarrier(self.io, self.dir, path[0..2]);
    }

    pub fn contains(self: *PayloadStore, digest: Hash) bool {
        self.verify(digest) catch return false;
        return true;
    }

    /// Verifies an installed object without allocating its contents. This is
    /// the predicate used by the Paxos host before a descriptor may enter the
    /// core; mere pathname existence is not sufficient.
    pub fn verify(self: *PayloadStore, digest: Hash) !void {
        var path_buffer: [65]u8 = undefined;
        const path = pathOf(&path_buffer, digest);
        const file = self.dir.openFile(self.io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.PayloadMissing,
            else => return err,
        };
        defer file.close(self.io);

        var hasher = Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (true) {
            const read = try file.readPositionalAll(self.io, &buffer, offset);
            if (read == 0) break;
            hasher.update(buffer[0..read]);
            offset += read;
            if (read < buffer.len) break;
        }
        var actual: Hash = undefined;
        hasher.final(&actual);
        if (!std.mem.eql(u8, &actual, &digest)) return error.PayloadCorrupt;
    }

    /// Loads and digest-verifies one payload. Caller owns the returned bytes.
    pub fn load(self: *PayloadStore, gpa: std.mem.Allocator, digest: Hash) ![]u8 {
        var path_buffer: [65]u8 = undefined;
        const path = pathOf(&path_buffer, digest);
        const file = self.dir.openFile(self.io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.PayloadMissing,
            else => return err,
        };
        defer file.close(self.io);

        const len = try file.length(self.io);
        const bytes = try gpa.alloc(u8, @intCast(len));
        errdefer gpa.free(bytes);
        const read_len = try file.readPositionalAll(self.io, bytes, 0);
        if (read_len != bytes.len) return error.PayloadCorrupt;
        if (!std.mem.eql(u8, &hashOf(bytes), &digest)) return error.PayloadCorrupt;
        return bytes;
    }

    /// Deletes every stored object absent from `reachable`. The caller
    /// owns the reachability proof (a streamed scan of every retained
    /// journal record); a crash mid-sweep leaks objects but never removes
    /// a reachable one.
    pub fn sweepUnreachable(
        self: *PayloadStore,
        reachable: *const std.AutoHashMap(Hash, void),
    ) !void {
        var shards = self.dir.iterate();
        while (shards.next(self.io) catch null) |shard| {
            if (shard.kind != .directory or shard.name.len != 2) continue;
            var shard_name: [2]u8 = shard.name[0..2].*;
            var shard_dir = self.dir.openDir(
                self.io,
                &shard_name,
                .{ .iterate = true },
            ) catch continue;
            defer shard_dir.close(self.io);
            var objects = shard_dir.iterate();
            while (objects.next(self.io) catch null) |object| {
                if (object.kind != .file or object.name.len != 62) continue;
                var hex: [64]u8 = undefined;
                @memcpy(hex[0..2], &shard_name);
                @memcpy(hex[2..], object.name[0..62]);
                var digest: Hash = undefined;
                _ = std.fmt.hexToBytes(&digest, &hex) catch continue;
                if (reachable.contains(digest)) continue;
                var object_name: [62]u8 = object.name[0..62].*;
                const stat = shard_dir.statFile(self.io, &object_name, .{}) catch null;
                shard_dir.deleteFile(self.io, &object_name) catch continue;
                if (stat) |s| self.retained_bytes -|= s.size;
            }
        }
    }

    /// Removes one payload object. The caller owns the reachability proof.
    pub fn remove(self: *PayloadStore, digest: Hash) !void {
        var path_buffer: [65]u8 = undefined;
        const path = pathOf(&path_buffer, digest);
        const stat = self.dir.statFile(self.io, path, .{}) catch null;
        try self.dir.deleteFile(self.io, path);
        if (stat) |s| self.retained_bytes -|= s.size;
    }

    fn pathOf(buffer: *[65]u8, digest: Hash) []const u8 {
        const hex = std.fmt.bytesToHex(digest, .lower);
        buffer[0] = hex[0];
        buffer[1] = hex[1];
        buffer[2] = '/';
        @memcpy(buffer[3..], hex[2..]);
        return buffer;
    }
};

const testing = std.testing;

test "payload store round trips and is idempotent" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try PayloadStore.init(io, tmp.dir);
    defer store.deinit();

    const payload = "frame bytes for one committed transaction batch";
    const digest = try store.put(payload);
    try testing.expect(store.contains(digest));
    const again = try store.put(payload);
    try testing.expectEqualSlices(u8, &digest, &again);

    const loaded = try store.load(testing.allocator, digest);
    defer testing.allocator.free(loaded);
    try testing.expectEqualStrings(payload, loaded);
}

test "payload store detects corruption and missing objects" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try PayloadStore.init(io, tmp.dir);
    defer store.deinit();

    const digest = try store.put("original bytes");

    var path_buffer: [65]u8 = undefined;
    const path = PayloadStore.pathOf(&path_buffer, digest);
    const file = try store.dir.openFile(io, path, .{ .mode = .read_write });
    try file.writePositionalAll(io, "X", 0);
    file.close(io);

    try testing.expectError(
        error.PayloadCorrupt,
        store.load(testing.allocator, digest),
    );
    try testing.expectError(error.PayloadCorrupt, store.verify(digest));
    try testing.expect(!store.contains(digest));

    // A verified transfer repairs an object whose existing pathname contains
    // corrupt bytes, rather than treating pathname existence as durability.
    try store.putNamed(digest, "original bytes");
    try store.verify(digest);
    try testing.expectError(
        error.PayloadHashMismatch,
        store.putNamed(digest, "different bytes"),
    );

    const absent = PayloadStore.hashOf("never stored");
    try testing.expect(!store.contains(absent));
    try testing.expectError(
        error.PayloadMissing,
        store.load(testing.allocator, absent),
    );
}

test "retained bytes track installs, duplicates, removal, and reopening" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    var store = try PayloadStore.init(io, tmp.dir);
    const first = try store.put("twelve bytes");
    try std.testing.expectEqual(@as(u64, 12), store.retained_bytes);
    // An idempotent re-install of identical content counts once.
    _ = try store.put("twelve bytes");
    try std.testing.expectEqual(@as(u64, 12), store.retained_bytes);
    _ = try store.put("four");
    try std.testing.expectEqual(@as(u64, 16), store.retained_bytes);

    try store.remove(first);
    try std.testing.expectEqual(@as(u64, 4), store.retained_bytes);
    store.deinit();

    // A reopen recounts what the directory actually holds.
    var reopened = try PayloadStore.init(io, tmp.dir);
    defer reopened.deinit();
    try std.testing.expectEqual(@as(u64, 4), reopened.retained_bytes);
}

test "reopen discards only abandoned named stages and preserves payloads" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const payload = "chosen payload survives abandoned staging";
    const stages = [_][]const u8{
        ".stage-0123456789abcdef0123456789abcdef",
        ".stage-ffffffffffffffffffffffffffffffff",
    };
    const foreign = [_][]const u8{
        ".stage-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ".stage-0123",
        "operator-note",
    };
    const stage_directory = ".stage-22222222222222222222222222222222";
    var digest: Hash = undefined;
    var path_buffer: [65]u8 = undefined;
    {
        var store = try PayloadStore.init(io, tmp.dir);
        defer store.deinit();
        digest = try store.put(payload);
        const path = PayloadStore.pathOf(&path_buffer, digest);
        var shard = try store.dir.openDir(io, path[0..2], .{ .iterate = true });
        defer shard.close(io);
        // Simulate process death before installation; none of these bytes are chosen.
        for (stages) |name| try shard.writeFile(io, .{
            .sub_path = name,
            .data = "unfinished upload",
        });
        for (foreign) |name| try shard.writeFile(io, .{
            .sub_path = name,
            .data = "keep these bytes",
        });
        try shard.createDirPath(io, stage_directory);
    }

    var reopened = try PayloadStore.init(io, tmp.dir);
    defer reopened.deinit();
    try testing.expectEqual(@as(u64, payload.len), reopened.retained_bytes);
    const loaded = try reopened.load(testing.allocator, digest);
    defer testing.allocator.free(loaded);
    try testing.expectEqualStrings(payload, loaded);
    const path = PayloadStore.pathOf(&path_buffer, digest);
    var shard = try reopened.dir.openDir(io, path[0..2], .{ .iterate = true });
    defer shard.close(io);
    for (stages) |name| try testing.expectError(error.FileNotFound, shard.access(io, name, .{}));
    for (foreign) |name| {
        const bytes = try shard.readFileAlloc(io, name, testing.allocator, .limited(64));
        defer testing.allocator.free(bytes);
        try testing.expectEqualStrings("keep these bytes", bytes);
    }
    var preserved = try shard.openDir(io, stage_directory, .{});
    preserved.close(io);
}

test "named payload repair counts one object across repeated installs and reopen" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const payload = "replicated immutable transaction";
    var digest: Hash = undefined;
    {
        var store = try PayloadStore.init(io, tmp.dir);
        defer store.deinit();
        digest = try store.put(payload);
        var path_buffer: [65]u8 = undefined;
        const path = PayloadStore.pathOf(&path_buffer, digest);
        const file = try store.dir.openFile(io, path, .{ .mode = .read_write });
        try file.writePositionalAll(io, "X", 0);
        file.close(io);
        try testing.expectError(error.PayloadCorrupt, store.verify(digest));

        try store.putNamed(digest, payload);
        try store.verify(digest);
        try testing.expectEqual(@as(u64, payload.len), store.retained_bytes);
        try store.putNamed(digest, payload);
        try testing.expectEqual(@as(u64, payload.len), store.retained_bytes);
    }
    var reopened = try PayloadStore.init(io, tmp.dir);
    defer reopened.deinit();
    try testing.expectEqual(@as(u64, payload.len), reopened.retained_bytes);
    const loaded = try reopened.load(testing.allocator, digest);
    defer testing.allocator.free(loaded);
    try testing.expectEqualStrings(payload, loaded);
}
