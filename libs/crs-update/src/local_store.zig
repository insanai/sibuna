//! Filesystem-authorized selection for engine deployments. Immutable directories
//! carry verified sources; atomic selection is intent and a receipt is an effect.
const std = @import("std");
const crs = @import("crs");
const records = @import("local_records.zig");
const files = @import("local_files.zig");
const artifact = @import("artifact.zig");
const candidates = @import("candidate_directory.zig");
const ownership = @import("prepared.zig");
const locking = @import("local_lock.zig");
const Io = std.Io;
pub const Error = files.Error || artifact.Error || candidates.Error || locking.Error ||
    crs.generation.Error ||
    crs.http_policy.Error || Io.Dir.DeleteTreeError || Io.Dir.Iterator.Error ||
    Io.Dir.StatFileError || Io.File.StatError || error{
    LocalStoreBusy,
    LocalStoreConflict,
    LocalStoreCapacity,
    InvalidLocalSource,
    InvalidLocalClock,
};
pub const Source = records.Source;
pub const Selection = records.Selection;
pub const Receipt = records.Receipt;
pub const State = records.State;
pub const Reason = records.Reason;
pub const Id = records.Id;
pub const maximum_generations = 4;
const selector = "selection.bin";
const receipt = "applied.bin";
pub const Store = struct {
    allocator: std.mem.Allocator,
    io: Io,
    /// Borrowed, opened with iterate=true. The operator owns this directory.
    directory: Io.Dir,

    pub fn lock(self: Store, mode: Io.File.Lock) Error!Locked {
        const config: locking.Config = .{
            .io = self.io,
            .directory = self.directory,
            .name = ".writer.lock",
            .mode = mode,
        };
        return .{ .store = self, .guard = try config.open() };
    }

    /// One daemon owns this store's boot-fenced receipt for its entire lifetime.
    /// This guard is independent of the short-lived selection writer lock.
    pub fn claimDaemon(self: Store) Error!Io.File {
        const config: locking.Config = .{
            .io = self.io,
            .directory = self.directory,
            .name = ".daemon.lock",
            .mode = .exclusive,
        };
        return config.open();
    }

    /// Verification and pool reservation finish before installation. A failure
    /// leaves an unselected private directory; the next writer reclaims it.
    pub fn select(
        self: Store,
        expected: u64,
        manifest: crs.artifact_manifest.Manifest,
        prepared: *ownership.Prepared,
    ) Error!Selection {
        var locked = try self.lock(.exclusive);
        defer locked.deinit();
        const previous = try locked.selection();
        try checkRevision(previous, expected);
        if (manifest.revision != expected + 1 or manifest.previous_revision != expected)
            return error.LocalStoreConflict;
        try manifest.bind(prepared.package orelse return error.PreparedPackageTransferred);
        const options = try manifest.options(.request_response);
        try crs.http_policy.validate(&prepared.package.?.program, options.activation);
        try locked.reclaim(previous);
        var id: Id = undefined;
        self.io.random(&id);
        if (std.mem.allEqual(u8, &id, 0)) return error.InvalidLocalSource;
        var encoded: [crs.artifact_manifest.capacity]u8 = undefined;
        const bytes = try manifest.encode(&encoded);
        var source: Source = .{ .id = id, .digest = undefined, .revision = manifest.revision };
        std.crypto.hash.sha2.Sha256.hash(bytes, &source.digest, .{});
        const timestamp = try self.now();
        try candidates.write(.{
            .io = self.io,
            .parent = self.directory,
            .name = &source.name(),
            .now = timestamp,
        }, manifest, prepared);
        try locked.syncSource(source);
        const generation = try crs.generation.Generation.create(
            self.allocator,
            prepared.package.?,
            options,
        );
        _ = prepared.takePackage();
        defer generation.deinit();
        return locked.install(previous, expected, source, timestamp);
    }

    pub fn now(self: Store) Error!u64 {
        const seconds = @divFloor(Io.Clock.real.now(self.io).nanoseconds, std.time.ns_per_s);
        if (seconds < 0 or seconds > std.math.maxInt(u64)) return error.InvalidLocalClock;
        return @intCast(seconds);
    }
};
pub const Locked = struct {
    store: Store,
    guard: Io.File,

    pub fn deinit(self: *Locked) void {
        self.guard.close(self.store.io);
        self.* = undefined;
    }

    pub fn selection(self: *const Locked) Error!?Selection {
        const store = self.store;
        const result = files.read(Selection, store.allocator, store.io, store.directory, selector);
        return result catch |err| switch (err) {
            error.FileNotFound => null,
            else => err,
        };
    }

    pub fn observation(self: *const Locked) Error!?Receipt {
        const store = self.store;
        return files.read(Receipt, store.allocator, store.io, store.directory, receipt) catch |err|
            switch (err) {
                error.FileNotFound => null,
                else => err,
            };
    }

    pub fn record(self: *const Locked, value: Receipt) Error!void {
        const selected = try self.selection() orelse return error.LocalStoreConflict;
        if (!std.meta.eql(selected.current, value.source)) return error.LocalStoreConflict;
        try files.write(self.store.io, self.store.directory, receipt, value);
    }

    pub fn load(self: *const Locked, source: Source) Error!artifact.Candidate {
        const expected = try self.manifest(source);
        const store = self.store;
        const directory = try store.directory.openDir(store.io, &source.name(), .{
            .follow_symlinks = false,
            .iterate = true,
        });
        defer directory.close(store.io);
        var loaded = try artifact.load(.{
            .allocator = store.allocator,
            .io = store.io,
            .directory = directory,
            .now = try store.now(),
            .observation = .request_response,
        });
        errdefer loaded.deinit();
        if (!std.meta.eql(loaded.manifest, expected)) return error.InvalidLocalSource;
        return loaded;
    }

    /// Configuration is locally authorized metadata, never proof of archive
    /// authenticity. Executable loading still authenticates every source byte.
    pub fn manifest(self: *const Locked, source: Source) Error!crs.artifact_manifest.Manifest {
        const store = self.store;
        const directory = try store.directory.openDir(store.io, &source.name(), .{
            .follow_symlinks = false,
            .iterate = true,
        });
        defer directory.close(store.io);
        const reader: @import("artifact_files.zig").Reader = .{
            .allocator = store.allocator,
            .io = store.io,
            .directory = directory,
        };
        const bytes = try reader.read("manifest.bin", .{
            .maximum = crs.artifact_manifest.capacity,
        });
        defer store.allocator.free(bytes.buffer);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes.value, &digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, digest, source.digest))
            return error.InvalidLocalSource;
        const parsed = try crs.artifact_manifest.decode(bytes.value);
        if (parsed.revision != source.revision) return error.InvalidLocalSource;
        return parsed;
    }

    pub fn configuration(self: *const Locked, source: Source) Error!ownership.Bytes {
        const metadata = try self.manifest(source);
        const store = self.store;
        const directory = try store.directory.openDir(store.io, &source.name(), .{
            .follow_symlinks = false,
        });
        defer directory.close(store.io);
        const reader: @import("artifact_files.zig").Reader = .{
            .allocator = store.allocator,
            .io = store.io,
            .directory = directory,
        };
        const bytes = try reader.read("operator.conf", .{ .exact = metadata.configuration_bytes });
        errdefer {
            std.crypto.secureZero(u8, bytes.buffer);
            store.allocator.free(bytes.buffer);
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes.value, &digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, digest, metadata.operator_digest))
            return error.InvalidLocalSource;
        return bytes;
    }

    fn syncSource(self: *const Locked, source: Source) Error!void {
        const store = self.store;
        const directory = try store.directory.openDir(store.io, &source.name(), .{
            .follow_symlinks = false,
            .iterate = true,
        });
        defer directory.close(store.io);
        inline for (.{ "archive.tar.gz", "signature.asc", "operator.conf", "manifest.bin" }) |name|
            try files.syncName(store.io, directory, name);
        var path: [64]u8 = undefined;
        const marker = std.fmt.bufPrint(&path, "{s}/manifest.bin", .{source.name()}) catch
            unreachable;
        try files.syncName(store.io, store.directory, marker);
    }

    fn install(
        self: *const Locked,
        previous: ?Selection,
        expected: u64,
        source: Source,
        now: u64,
    ) Error!Selection {
        try checkRevision(try self.selection(), expected);
        const selected: Selection = .{
            .current = source,
            .previous = if (previous) |value| value.current else null,
            .selected_at = now,
        };
        try files.write(self.store.io, self.store.directory, selector, selected);
        // Installation may succeed even if this later receipt write fails. The
        // caller must query intent; reporting failure never means rollback.
        try self.record(.{
            .source = source,
            .boot = @splat(0),
            .observed_at = now,
            .state = .pending,
        });
        return selected;
    }

    fn reclaim(self: *const Locked, selected: ?Selection) Error!void {
        var garbage: [maximum_generations][43]u8 = undefined;
        var count: usize = 0;
        var visited: usize = 0;
        var iterator = self.store.directory.iterate();
        while (try iterator.next(self.store.io)) |entry| {
            visited += 1;
            if (visited > 256) return error.LocalStoreCapacity;
            if (!generatedName(entry.name)) continue;
            if (entry.kind != .directory) return error.ArtifactFileKind;
            if (count == garbage.len) return error.LocalStoreCapacity;
            @memcpy(&garbage[count], entry.name);
            count += 1;
        }
        for (garbage[0..count]) |name| {
            if (selected) |value| {
                if (std.mem.eql(u8, &name, &value.current.name())) continue;
                if (value.previous) |previous|
                    if (std.mem.eql(u8, &name, &previous.name())) continue;
            }
            try self.store.directory.deleteTree(self.store.io, &name);
        }
    }
};

fn checkRevision(selected: ?Selection, expected: u64) Error!void {
    const revision = if (selected) |value| value.current.revision else 0;
    if (expected >= std.math.maxInt(i64) or revision != expected) return error.LocalStoreConflict;
}

fn generatedName(name: []const u8) bool {
    if (name.len != 43 or !std.mem.startsWith(u8, name, "generation-")) return false;
    for (name[11..]) |byte|
        if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return false;
    return true;
}

test {
    _ = records;
    _ = @import("local_store_test.zig");
}

test "local selector commit remains visible when its completion record cannot be written" {
    const t = std.testing;
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const store: Store = .{
        .allocator = t.allocator,
        .io = t.io,
        .directory = temporary.dir,
    };
    try temporary.dir.createDir(t.io, receipt, .default_dir);
    var locked = try store.lock(.exclusive);
    defer locked.deinit();
    const source: Source = .{ .id = @splat(1), .digest = @splat(2), .revision = 1 };
    // Namespace replacement cannot replace a directory. Installation happened
    // first, so a lost completion must not be interpreted as a failed intent.
    if (locked.install(null, 0, source, 3)) |_| {
        return error.TestUnexpectedSuccess;
    } else |err| switch (err) {
        error.IsDir, error.NotDir, error.PathAlreadyExists, error.AccessDenied => {},
        else => return err,
    }
    try t.expectEqualDeep(source, (try locked.selection()).?.current);
    try t.expectError(error.LocalStoreConflict, locked.install(null, 0, source, 3));
}

test "local collection retains both selected sources and leaves unrelated operator files" {
    const t = std.testing;
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const store: Store = .{
        .allocator = t.allocator,
        .io = t.io,
        .directory = temporary.dir,
    };
    const current: Source = .{ .id = @splat(1), .digest = @splat(2), .revision = 2 };
    const previous: Source = .{ .id = @splat(3), .digest = @splat(4), .revision = 1 };
    const orphan: Source = .{ .id = @splat(5), .digest = @splat(6), .revision = 3 };
    const selected: Selection = .{ .current = current, .previous = previous, .selected_at = 1 };
    for ([_]Source{ current, previous, orphan }) |source|
        try temporary.dir.createDir(t.io, &source.name(), .default_dir);
    try temporary.dir.writeFile(t.io, .{ .sub_path = "operator-notes", .data = "keep" });
    var locked = try store.lock(.exclusive);
    defer locked.deinit();
    try locked.reclaim(selected);
    _ = try temporary.dir.statFile(t.io, &current.name(), .{});
    _ = try temporary.dir.statFile(t.io, &previous.name(), .{});
    _ = try temporary.dir.statFile(t.io, "operator-notes", .{});
    try t.expectError(error.FileNotFound, temporary.dir.statFile(t.io, &orphan.name(), .{}));
}
