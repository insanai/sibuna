//! Stable lock inodes are never renamed or removed. Nonblocking acquisition
//! fails safely on contention; closing a handle releases crash-stale ownership.
const std = @import("std");
const Io = std.Io;
pub const Error = Io.File.OpenError || Io.File.StatError || error{
    LocalStoreBusy,
    ArtifactFileKind,
};
pub const Config = struct {
    io: Io,
    directory: Io.Dir,
    name: []const u8,
    mode: Io.File.Lock,

    pub fn open(self: Config) Error!Io.File {
        std.debug.assert(self.mode == .shared or self.mode == .exclusive);
        std.debug.assert(std.mem.eql(u8, self.name, ".writer.lock") or
            std.mem.eql(u8, self.name, ".daemon.lock"));
        const file = self.directory.openFile(self.io, self.name, .{
            .mode = .read_write,
            .follow_symlinks = false,
            .allow_directory = false,
            .lock = self.mode,
            .lock_nonblocking = true,
        }) catch |err| switch (err) {
            error.WouldBlock => return error.LocalStoreBusy,
            error.FileNotFound => return self.create(),
            else => return err,
        };
        errdefer file.close(self.io);
        if ((try file.stat(self.io)).kind != .file) return error.ArtifactFileKind;
        return file;
    }

    fn create(self: Config) Error!Io.File {
        return self.directory.createFile(self.io, self.name, .{
            .read = true,
            .exclusive = true,
            .lock = self.mode,
            .lock_nonblocking = true,
            .permissions = if (@import("builtin").os.tag == .windows)
                .default_file
            else
                @fromBackingInt(0o600),
        }) catch |err| switch (err) {
            error.WouldBlock => error.LocalStoreBusy,
            error.PathAlreadyExists => self.open(),
            else => err,
        };
    }
};
