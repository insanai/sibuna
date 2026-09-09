//! Offline country-data tool. Validates provider downloads or an SBGEOIP1 snapshot and
//! optionally writes a snapshot. Never opens application storage or the network.
//!
//!   geoip-snapshot --provider user-country --version 2026-09-09 ipv4.csv ipv6.csv
//!   geoip-snapshot --provider dbip --version 2026-09 dbip-country-lite-2026-09.csv.gz
//!   geoip-snapshot --snapshot snapshot.bin
//!   ... --snapshot-out snapshot.bin   (write after validation)
//!   ... --lookup 8.8.8.8              (repeatable, at most 64; prints the country)
const std = @import("std");
const geoip = @import("geoip");
const max_input = 32 * 1024 * 1024;
const Options = struct {
    provider: ?geoip.Provider = null,
    version: []const u8 = "",
    snapshot: ?[]const u8 = null,
    out: ?[]const u8 = null,
    files: [geoip.provider.max_files][]const u8 = undefined,
    count: u8 = 0,
    lookups: [64][]const u8 = undefined,
    lookup_count: u8 = 0,
};

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const options = try parse(&args);
    var db = if (options.snapshot) |path|
        try loadSnapshot(init, path)
    else
        try loadSources(init, options);
    defer db.deinit();
    report(&db);
    for (options.lookups[0..options.lookup_count]) |text| {
        const found = db.lookupText(text);
        std.debug.print("geoip-snapshot: {s} {s}\n", .{ text, if (found) |c| &c else "ZZ" });
    }
    if (options.out) |path| try writeSnapshot(init, path, &db);
}

fn parse(args: *std.process.Args.Iterator) !Options {
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--provider")) {
            const name = args.next() orelse return error.MissingProvider;
            options.provider = geoip.Provider.parse(name) orelse return error.UnknownProvider;
        } else if (std.mem.eql(u8, arg, "--version")) {
            options.version = args.next() orelse return error.MissingVersion;
        } else if (std.mem.eql(u8, arg, "--snapshot")) {
            options.snapshot = args.next() orelse return error.MissingPath;
        } else if (std.mem.eql(u8, arg, "--snapshot-out")) {
            options.out = args.next() orelse return error.MissingPath;
        } else if (std.mem.eql(u8, arg, "--lookup")) {
            if (options.lookup_count == options.lookups.len) return error.TooManyArguments;
            options.lookups[options.lookup_count] = args.next() orelse return error.MissingAddress;
            options.lookup_count += 1;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            return error.UnknownOption;
        } else {
            if (options.count == options.files.len) return error.TooManyArguments;
            options.files[options.count] = arg;
            options.count += 1;
        }
    }
    if (options.snapshot != null) {
        if (options.count != 0 or options.provider != null) return error.ConflictingOptions;
        return options;
    }
    const provider = options.provider orelse return error.MissingProvider;
    if (options.count != provider.fileCount()) return error.WrongFileCount;
    if (!provider.versionValid(options.version)) return error.InvalidVersion;
    return options;
}

const Read = struct { buffer: []u8, data: []const u8 };

fn readFile(init: std.process.Init, path: []const u8, limit: usize) !Read {
    const file = try std.Io.Dir.cwd().openFile(init.io, path, .{});
    defer file.close(init.io);
    const buffer = try init.gpa.alloc(u8, limit + 1);
    errdefer init.gpa.free(buffer);
    var scratch: [16384]u8 = undefined;
    var reader = file.reader(init.io, &scratch);
    const count = try reader.interface.readSliceShort(buffer);
    if (count > limit) return error.TooLarge;
    return .{ .buffer = buffer, .data = buffer[0..count] };
}

fn loadSnapshot(init: std.process.Init, path: []const u8) !geoip.Database {
    const read = try readFile(init, path, geoip.snapshot.max_bytes);
    defer init.gpa.free(read.buffer);
    return geoip.snapshot.decode(init.gpa, read.data);
}

fn loadSources(init: std.process.Init, options: Options) !geoip.Database {
    const provider = options.provider.?;
    if (provider.compression() == .gzip) {
        const read = try readFile(init, options.files[0], geoip.gzip.max_compressed_bytes);
        defer init.gpa.free(read.buffer);
        var stopping = std.atomic.Value(bool).init(false);
        return geoip.gzip.decode(
            init.gpa,
            init.io,
            provider,
            options.version,
            read.data,
            &stopping,
        );
    }
    var loader = try geoip.Loader.init(init.gpa);
    errdefer loader.abandon();
    for (options.files[0..options.count]) |path| {
        const read = try readFile(init, path, max_input);
        defer init.gpa.free(read.buffer);
        reportUnknownCodes(path, read.data);
        try loader.feed(read.data);
        try loader.endFile();
    }
    return loader.finish(provider, options.version);
}

/// Lists distinct third-column codes the library rejects, so an import failure names
/// the code instead of only the error. Bounded to sixteen distinct values.
fn reportUnknownCodes(path: []const u8, bytes: []const u8) void {
    var seen: [16][2]u8 = undefined;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        var columns = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\r"), ',');
        _ = columns.next();
        _ = columns.next();
        const code = columns.next() orelse continue;
        if (geoip.countryValid(code) or code.len != 2) continue;
        var known = false;
        for (seen[0..count]) |value| known = known or std.mem.eql(u8, &value, code);
        if (known) continue;
        if (count == seen.len) break;
        seen[count] = code[0..2].*;
        count += 1;
    }
    for (seen[0..count]) |code|
        std.debug.print("geoip-snapshot: {s}: code outside the ISO list: {s}\n", .{ path, &code });
}

fn report(db: *const geoip.Database) void {
    std.debug.print("geoip-snapshot: {s} {s}: {d} known ranges; SHA-256 {s}\n", .{
        db.provider.name(),
        db.version.slice(),
        db.ranges.len,
        std.fmt.bytesToHex(db.digest, .lower),
    });
    for (db.file_digests[0..db.files], 0..) |digest, index| {
        std.debug.print("geoip-snapshot: file {d} SHA-256 {s}\n", .{
            index,
            std.fmt.bytesToHex(digest, .lower),
        });
    }
}

fn writeSnapshot(init: std.process.Init, path: []const u8, db: *const geoip.Database) !void {
    const file = try std.Io.Dir.cwd().createFile(init.io, path, .{});
    defer file.close(init.io);
    var scratch: [65536]u8 = undefined;
    var writer = file.writer(init.io, &scratch);
    try geoip.snapshot.encode(&writer.interface, db);
    try writer.interface.flush();
    std.debug.print("geoip-snapshot: wrote {s}\n", .{path});
}
