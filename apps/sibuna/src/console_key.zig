//! The console seed-encryption key is provisioned separately; never derive it from
//! the data-plane or cluster secret, generate it implicitly, or store it in the database.
const std = @import("std");

pub fn read(io: std.Io, path: []const u8) ![32]u8 {
    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    if (@hasDecl(std.Io.File.Permissions, "toMode")) {
        if (stat.permissions.toMode() & 0o077 != 0) return error.ConsoleKeyPermissions;
    }
    var buffer: [67]u8 = undefined;
    var scratch: [128]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    defer std.crypto.secureZero(u8, &scratch);
    var reader = file.reader(io, &scratch);
    const length = try reader.interface.readSliceShort(&buffer);
    const encoded = std.mem.trimEnd(u8, buffer[0..length], "\r\n");
    if (length == buffer.len or encoded.len != 64) return error.InvalidConsoleKey;
    var key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, encoded) catch return error.InvalidConsoleKey;
    return key;
}
