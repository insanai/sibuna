//! Offline acceptance check for a downloaded DB-IP gzip. Never opens application storage.
const std = @import("std");
const gzip = @import("console").geoip_gzip;

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const path = args.next() orelse return error.MissingPath;
    if (args.next() != null) return error.TooManyArguments;
    const file = try std.Io.Dir.cwd().openFile(init.io, path, .{});
    defer file.close(init.io);
    const buffer = try init.gpa.alloc(u8, gzip.max_compressed_bytes);
    defer init.gpa.free(buffer);
    var scratch: [8192]u8 = undefined;
    var reader = file.reader(init.io, &scratch);
    const count = try reader.interface.readSliceShort(buffer);
    if (count == buffer.len) return error.TooLarge;
    var stopping = std.atomic.Value(bool).init(false);
    var dataset = try gzip.decode(init.gpa, init.io, buffer[0..count], &stopping);
    defer dataset.deinit();
    std.debug.print("console-geoip-check: {d} known ranges; SHA-256 {s}\n", .{
        dataset.ranges.len, std.fmt.bytesToHex(dataset.digest, .lower),
    });
}
