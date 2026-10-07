//! Same-directory no-replace staging avoids long ZFS O_TMPFILE link operations.
//! The caller flushes bytes before finish and the containing directory after it.
const std = @import("std");
const Io = std.Io;
const prefix = ".stage-";
const name_len = prefix.len + 32;
const attempts = 16;

const InitError = Io.Dir.OpenError || Io.File.OpenError || error{TemporaryNameCollision};

pub const NamedAtomic = struct {
    dir: Io.Dir,
    file: Io.File,
    name: [name_len]u8,
    file_open: bool = true,
    installed: bool = false,

    pub fn init(io: Io, parent: Io.Dir, shard: []const u8) InitError!NamedAtomic {
        var names = RandomNames{ .io = io };
        return initWithNames(io, parent, shard, &names);
    }

    fn initWithNames(
        io: Io,
        parent: Io.Dir,
        shard: []const u8,
        names: anytype,
    ) InitError!NamedAtomic {
        const dir = try parent.openDir(io, shard, .{ .iterate = true });
        errdefer dir.close(io);
        for (0..attempts) |_| {
            const name = names.next();
            const file = dir.createFile(io, &name, .{
                .exclusive = true,
                .permissions = @fromBackingInt(@intCast(0o600)),
            }) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return err,
            };
            return .{ .dir = dir, .file = file, .name = name };
        }
        return error.TemporaryNameCollision;
    }

    pub fn finish(
        self: *NamedAtomic,
        io: Io,
        destination: []const u8,
    ) Io.Dir.RenamePreserveError!void {
        std.debug.assert(!self.installed);
        if (self.file_open) {
            self.file.close(io);
            self.file_open = false;
        }
        try self.dir.renamePreserve(&self.name, self.dir, destination, io);
        self.installed = true;
    }

    pub fn deinit(self: *NamedAtomic, io: Io) void {
        if (self.file_open) self.file.close(io);
        if (!self.installed) self.dir.deleteFile(io, &self.name) catch {};
        self.dir.close(io);
        self.* = undefined;
    }
};

pub fn isTemporaryName(name: []const u8) bool {
    if (name.len != name_len or !std.mem.startsWith(u8, name, prefix)) return false;
    for (name[prefix.len..]) |byte| {
        if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

const RandomNames = struct {
    io: Io,

    fn next(self: *RandomNames) [name_len]u8 {
        var random: [16]u8 = undefined;
        self.io.random(&random);
        var name: [name_len]u8 = undefined;
        @memcpy(name[0..prefix.len], prefix);
        @memcpy(name[prefix.len..], &std.fmt.bytesToHex(random, .lower));
        return name;
    }
};

test "staging closes and removes its own unpublished temporary file" {
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(t.io, "aa", .default_dir);
    var staged = try NamedAtomic.init(t.io, tmp.dir, "aa");
    const name = staged.name;
    try staged.file.writePositionalAll(t.io, "not published", 0);
    staged.deinit(t.io);
    var shard = try tmp.dir.openDir(t.io, "aa", .{});
    defer shard.close(t.io);
    try t.expectError(error.FileNotFound, shard.openFile(t.io, &name, .{}));
}

test "staging refuses replacement and preserves the existing destination" {
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(t.io, "aa", .default_dir);
    var first = try NamedAtomic.init(t.io, tmp.dir, "aa");
    defer first.deinit(t.io);
    try first.file.writePositionalAll(t.io, "first", 0);
    try first.file.sync(t.io);
    try first.finish(t.io, "object");
    var second = try NamedAtomic.init(t.io, tmp.dir, "aa");
    defer second.deinit(t.io);
    try second.file.writePositionalAll(t.io, "second", 0);
    try second.file.sync(t.io);
    try t.expectError(error.PathAlreadyExists, second.finish(t.io, "object"));
    var file = try first.dir.openFile(t.io, "object", .{});
    defer file.close(t.io);
    var bytes: [16]u8 = undefined;
    const count = try file.readPositionalAll(t.io, &bytes, 0);
    try t.expectEqualStrings("first", bytes[0..count]);
}

test "temporary name collisions stop at the fixed attempt bound" {
    const t = std.testing;
    const Collisions = struct {
        count: usize = 0,

        fn next(self: *@This()) [name_len]u8 {
            self.count += 1;
            return (prefix ++ "00000000000000000000000000000000").*;
        }
    };
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(t.io, "aa", .default_dir);
    var names = Collisions{};
    var first = try NamedAtomic.initWithNames(t.io, tmp.dir, "aa", &names);
    defer first.deinit(t.io);
    names.count = 0;
    try t.expectError(
        error.TemporaryNameCollision,
        NamedAtomic.initWithNames(t.io, tmp.dir, "aa", &names),
    );
    try t.expectEqual(attempts, names.count);
    try first.file.writePositionalAll(t.io, "still owned", 0);
}
