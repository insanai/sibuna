//! A database is one immutable, sorted generation with its provenance. The loader accepts
//! source bytes in bounded chunks, hashes them for the generation digest, and validates
//! every row before the caller may publish the result.
const std = @import("std");
const address = @import("address.zig");
const ranges = @import("range.zig");
const providers = @import("provider.zig");
pub const Range = ranges.Range;
pub const Provider = providers.Provider;
pub const max_ranges = 1024 * 1024;
pub const max_csv_bytes = 128 * 1024 * 1024;
pub const max_files = providers.max_files;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Version = struct {
    bytes: [providers.max_version]u8 = @splat(0),
    len: u8 = 0,

    pub fn init(text: []const u8) error{InvalidVersion}!Version {
        if (text.len == 0 or text.len > providers.max_version) return error.InvalidVersion;
        var version: Version = .{ .len = @intCast(text.len) };
        @memcpy(version.bytes[0..text.len], text);
        return version;
    }

    pub fn slice(self: *const Version) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Database = struct {
    allocator: std.mem.Allocator,
    ranges: []const Range,
    allocation: []Range,
    digest: [32]u8,
    provider: Provider,
    version: Version,
    file_digests: [max_files][32]u8 = @splat(@splat(0)),
    files: u8 = 0,

    pub fn lookup(self: *const Database, ip: [16]u8) ?[2]u8 {
        return ranges.lookup(self.ranges, ip);
    }

    pub fn lookupText(self: *const Database, text: []const u8) ?[2]u8 {
        const ip = address.parse(text) catch return null;
        return self.lookup(ip);
    }

    pub fn deinit(self: *Database) void {
        self.allocator.free(self.allocation);
        self.* = undefined;
    }
};

pub const Loader = struct {
    allocator: std.mem.Allocator,
    builder: ranges.Builder,
    line: [ranges.max_line]u8 = undefined,
    length: usize = 0,
    bytes: usize = 0,
    all: Sha256 = Sha256.init(.{}),
    file: Sha256 = Sha256.init(.{}),
    file_digests: [max_files][32]u8 = @splat(@splat(0)),
    files: u8 = 0,

    pub const Error = ranges.Error || std.mem.Allocator.Error;

    /// Reserves the maximum range capacity up front; finish() shrinks it to fit.
    pub fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!Loader {
        const storage = try allocator.alloc(Range, max_ranges);
        return .{ .allocator = allocator, .builder = .{ .storage = storage } };
    }

    pub fn feed(self: *Loader, bytes: []const u8) Error!void {
        if (bytes.len > max_csv_bytes - self.bytes) return error.Capacity;
        self.bytes += bytes.len;
        self.all.update(bytes);
        self.file.update(bytes);
        for (bytes) |byte| {
            if (byte == '\n') {
                try self.builder.append(self.line[0..self.length]);
                self.length = 0;
                continue;
            }
            if (self.length == self.line.len) return error.InvalidRow;
            self.line[self.length] = byte;
            self.length += 1;
        }
    }

    /// Ends one source file: flushes an unterminated final row and records its digest.
    pub fn endFile(self: *Loader) Error!void {
        if (self.files == max_files) return error.Capacity;
        if (self.length != 0) try self.builder.append(self.line[0..self.length]);
        self.length = 0;
        self.file.final(&self.file_digests[self.files]);
        self.file = Sha256.init(.{});
        self.files += 1;
    }

    /// Transfers the validated ranges into a database; the loader is consumed.
    pub fn finish(self: *Loader, provider: Provider, version: []const u8) !Database {
        if (self.files == 0 or self.files != provider.fileCount()) return error.InvalidRow;
        const sorted = try self.builder.finish();
        const storage = self.allocator.realloc(self.builder.storage, sorted.len) catch
            self.builder.storage;
        var digest: [32]u8 = undefined;
        self.all.final(&digest);
        const database: Database = .{
            .allocator = self.allocator,
            .ranges = storage[0..sorted.len],
            .allocation = storage,
            .digest = digest,
            .provider = provider,
            .version = try Version.init(version),
            .file_digests = self.file_digests,
            .files = self.files,
        };
        self.* = undefined;
        return database;
    }

    pub fn abandon(self: *Loader) void {
        self.allocator.free(self.builder.storage);
        self.* = undefined;
    }
};

/// One in-memory CSV as a complete generation (pasted imports and tests).
pub fn fromCsv(
    allocator: std.mem.Allocator,
    provider: Provider,
    version: []const u8,
    csv: []const u8,
) !Database {
    if (csv.len == 0 or csv.len > max_csv_bytes) return error.Capacity;
    var loader = try Loader.init(allocator);
    errdefer loader.abandon();
    try loader.feed(csv);
    var file: u8 = 0;
    while (file < provider.fileCount()) : (file += 1) try loader.endFile();
    return loader.finish(provider, version);
}

test "loader hashes all fed bytes and splits rows across chunk boundaries" {
    const t = std.testing;
    var loader = try Loader.init(t.allocator);
    errdefer loader.abandon();
    try loader.feed("1.0.0.0,1.0.0.");
    try loader.feed("255,AU\n8.8.8.0,8.8.8.255,US");
    try loader.endFile();
    try loader.feed("2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n");
    try loader.endFile();
    var database = try loader.finish(.user_country, "2026-09-09");
    defer database.deinit();
    try t.expectEqual(@as(usize, 3), database.ranges.len);
    try t.expectEqualStrings("AU", &database.lookupText("1.0.0.1").?);
    try t.expectEqualStrings("US", &database.lookupText("2001:4860::8888").?);
    try t.expect(database.lookupText("9.9.9.9") == null);
    try t.expect(database.lookupText("nonsense") == null);
    try t.expectEqual(@as(u8, 2), database.files);
    var expected: [32]u8 = undefined;
    Sha256.hash(
        "1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US" ++
            "2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n",
        &expected,
        .{},
    );
    try t.expectEqualSlices(u8, &expected, &database.digest);
    try t.expectEqualStrings("2026-09-09", database.version.slice());
}

test "loader rejects an invalid row without publishing and frees on abandon" {
    const t = std.testing;
    var loader = try Loader.init(t.allocator);
    try t.expectError(error.InvalidCountry, loader.feed("8.8.8.0,8.8.8.255,AA\n"));
    loader.abandon();
    try t.expectError(error.InvalidRow, fromCsv(t.allocator, .dbip, "2026-09", "\n"));
    var one = try fromCsv(t.allocator, .dbip, "2026-09", "8.8.8.0,8.8.8.255,US");
    defer one.deinit();
    try t.expectEqual(@as(u8, 1), one.files);
    try t.expectEqualSlices(u8, &one.digest, &one.file_digests[0]);
}
