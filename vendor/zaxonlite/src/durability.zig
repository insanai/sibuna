//! Small durability helpers shared by the storage components.
//!
//! Syncing file contents does not necessarily persist the directory entry
//! created by link/rename. Callers sync the relevant parent after every
//! authoritative pathname transition.
//!
//! Windows has no directory sync, and needs none. NTFS is write-ahead
//! logged: `$LogFile` is one sequential metadata journal per volume, so
//! flushing it through a given record persists every record before it, and
//! flushing any file forces the log through that file's last update.
//! Microsoft documents the file rather than the directory as the durable
//! unit -- "the file metadata may still be cached (for example, when
//! creating an empty file). To ensure that the metadata is flushed to disk,
//! use the FlushFileBuffers function". So a pathname transition is
//! persisted by flushing the file it produced, which means the barrier
//! follows the rename on Windows where it precedes it on POSIX. That is
//! what `syncPathnameTransition` exists to hide. The ordering property of
//! the log is standard write-ahead-log behavior rather than a documented
//! contract, and it holds only on a journaling filesystem: FAT has no
//! metadata log at all. `probePathnameSemantics` rejects volumes that
//! cannot support the model before any storage is written.
//!
//! Sync policy: on macOS, `fsync(2)` flushes data to the drive but not
//! the drive's volatile cache to stable media, so acknowledged writes can
//! vanish on power loss. For a consensus journal that is a safety issue,
//! not merely data loss: a voter that forgets an acknowledged promise can
//! vote again and break quorum intersection. The `full` mode therefore
//! issues `fcntl(F_FULLFSYNC)` on Darwin (falling back to `fsync` on
//! filesystems that refuse it), and is the default for real binaries.
//! The `os` mode keeps the platform `fsync`; process-crash recovery is
//! identical under both, only power-loss durability differs. On other
//! supported platforms the modes are equivalent.
//!
//! Group fsync: `F_FULLFSYNC` flushes the drive's entire cache, so one
//! barrier per commit point suffices for every block already handed to
//! the drive. The `...BeforeBarrier` variants therefore issue only the
//! platform `fsync` — moving the bytes from the page cache into the
//! drive — and rely on the caller's next `syncFile`/`syncDirectory`
//! barrier on the same volume to make them power-loss durable. The
//! write path uses this to pay exactly one full flush per replicated
//! write (the journal sync inside `consumeEffects`), which precedes
//! every vote, acknowledgement, and outgoing envelope.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub const SyncMode = enum { os, full };

/// Process-wide policy, set once during startup before any storage I/O
/// or thread creation. Test builds default to `os`: the crash campaigns
/// simulate process death, which loses nothing under either mode, and a
/// laptop-development loop should not pay the full-flush latency.
var sync_mode: SyncMode = if (builtin.is_test)
    .os
else if (builtin.os.tag.isDarwin())
    .full
else
    .os;

pub fn setSyncMode(mode: SyncMode) void {
    sync_mode = mode;
}

pub fn syncMode() SyncMode {
    return sync_mode;
}

/// Makes `file`'s written contents durable under the configured policy.
pub fn syncFile(io: Io, file: Io.File) !void {
    if (comptime builtin.os.tag.isDarwin()) {
        if (sync_mode == .full and fullFsync(file.handle)) return;
    }
    try file.sync(io);
}

/// Persists `dir`'s entries. On POSIX this is the barrier itself. On
/// Windows no directory handle can flush the volume log, so this is a no-op
/// and the caller must be able to name the later file-level barrier on the
/// same volume that commits the entry. Callers that need the entry durable
/// immediately use `syncPathnameTransition` instead.
pub fn syncDirectory(dir: Io.Dir) !void {
    if (comptime builtin.os.tag == .windows) return;
    if (comptime builtin.os.tag.isDarwin()) {
        if (sync_mode == .full and fullFsync(dir.handle)) return;
    }
    try directoryFsync(dir);
}

/// Persists the entry for `name`, which a create, rename, or replace has
/// just put in `dir`. POSIX syncs the parent. Windows flushes the file
/// itself, because NTFS carries the namespace change in the volume log, so
/// this must be called after the transition rather than before it.
pub fn syncPathnameTransition(io: Io, dir: Io.Dir, name: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return syncDirectory(dir);
    // A flush needs write or append access; a read-only handle is refused.
    const file = try dir.openFile(io, name, .{ .mode = .read_write });
    defer file.close(io);
    try syncFile(io, file);
}

pub fn syncChildDirectory(io: Io, parent: Io.Dir, path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return;
    // Iterating opens carry a real descriptor on every platform, so the
    // fsync below is one syscall instead of the `O_PATH` reopen fallback.
    var child = try parent.openDir(io, path, .{ .iterate = true });
    defer child.close(io);
    try syncDirectory(child);
}

/// Rejects a volume that cannot carry the durability model, before any
/// storage is written. Replacing a file that is still open is precisely
/// what the legacy Windows rename path cannot do, so one attempt separates
/// the supported floor -- Windows 10 1809 or Server 2019 and newer, on
/// NTFS -- from older releases, FAT volumes, and network filesystems that
/// degrade quietly. Zig chooses the POSIX or the legacy rename per call and
/// does not report which, so this tests the behavior rather than the
/// version. POSIX platforms pass it, which also catches an exotic mount.
pub fn probePathnameSemantics(io: Io, dir: Io.Dir) !void {
    const held_name = ".zx-probe-held";
    const spare_name = ".zx-probe-spare";
    dir.deleteFile(io, held_name) catch {};
    dir.deleteFile(io, spare_name) catch {};

    const held = try dir.createFile(io, held_name, .{});
    defer {
        held.close(io);
        dir.deleteFile(io, held_name) catch {};
    }
    const spare = try dir.createFile(io, spare_name, .{});
    spare.close(io);
    errdefer dir.deleteFile(io, spare_name) catch {};

    // The held handle stays open across the rename on purpose.
    dir.rename(spare_name, dir, held_name, io) catch
        return error.UnsupportedDurabilityPlatform;
}

/// Flushes `file` to the drive without forcing the drive's cache to
/// stable media. The bytes become power-loss durable at the caller's
/// next barrier (`syncFile`/`syncDirectory`) on the same volume, which
/// must happen before anything acknowledges or announces them.
pub fn syncFileBeforeBarrier(io: Io, file: Io.File) !void {
    try file.sync(io);
}

/// Directory-entry counterpart of `syncFileBeforeBarrier`. Windows keeps
/// the entry in the volume log until the caller's next barrier, which is
/// exactly this function's contract, so there is nothing to issue there.
pub fn syncDirectoryBeforeBarrier(dir: Io.Dir) !void {
    if (comptime builtin.os.tag == .windows) return;
    try directoryFsync(dir);
}

pub fn syncChildDirectoryBeforeBarrier(
    io: Io,
    parent: Io.Dir,
    path: []const u8,
) !void {
    if (comptime builtin.os.tag == .windows) return;
    // See syncChildDirectory: a real descriptor keeps this one syscall.
    var child = try parent.openDir(io, path, .{ .iterate = true });
    defer child.close(io);
    try syncDirectoryBeforeBarrier(child);
}

/// `fsync(2)` for a directory handle. `Io.Dir` opens non-iterating
/// directory handles with `O_PATH` where the platform has it (Linux),
/// and the kernel rejects `fsync` on such descriptors with `EBADF`;
/// reopening `"."` through the handle yields a syncable descriptor
/// (`openat` accepts an `O_PATH` base). The fallback triggers only on
/// `EBADF`: retrying a failed sync on a fresh descriptor after `EIO`
/// could report success for writes the kernel already dropped.
fn directoryFsync(dir: Io.Dir) error{DirectorySyncFailed}!void {
    switch (fsyncErrno(dir.handle)) {
        .SUCCESS => return,
        .BADF => {},
        else => return error.DirectorySyncFailed,
    }
    if (comptime !@hasField(std.posix.O, "PATH")) return error.DirectorySyncFailed;
    const fd = std.posix.openat(dir.handle, ".", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0) catch return error.DirectorySyncFailed;
    defer _ = std.c.close(fd);
    if (fsyncErrno(fd) != .SUCCESS) return error.DirectorySyncFailed;
}

fn fsyncErrno(handle: std.posix.fd_t) std.posix.E {
    while (true) {
        const rc = std.c.fsync(handle);
        if (rc == 0) return .SUCCESS;
        const err = std.posix.errno(rc);
        if (err == .INTR) continue;
        return err;
    }
}

/// True when the full flush succeeded; false directs the caller to fall
/// back to plain `fsync` (some filesystems refuse `F_FULLFSYNC`).
fn fullFsync(handle: std.posix.fd_t) bool {
    if (comptime !builtin.os.tag.isDarwin()) return false;
    while (true) {
        const rc = std.c.fcntl(handle, std.c.F.FULLFSYNC, @as(c_int, 0));
        if (rc != -1) return true;
        if (std.posix.errno(rc) == .INTR) continue;
        return false;
    }
}

test "sync mode is settable and file sync succeeds in every mode" {
    const previous = syncMode();
    defer setSyncMode(previous);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var file = try tmp.dir.createFile(io, "synced", .{});
    defer file.close(io);
    try file.writeStreamingAll(io, "payload");

    for ([_]SyncMode{ .os, .full }) |mode| {
        setSyncMode(mode);
        try std.testing.expectEqual(mode, syncMode());
        try syncFile(io, file);
        try syncDirectory(tmp.dir);
    }
}
