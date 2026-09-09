//! One joined import task owns its inputs and staged allocation. Durable publication precedes
//! in-memory activation; no claim of atomicity spans the database and local runtime effect.
const std = @import("std");
const App = @import("app.zig").App;
const p = @import("console_protocol");
const geoip = @import("geoip");
const download = @import("geoip_download.zig");
pub const Input = struct {
    auth: p.geo.Authorization,
    expected_revision: u64,
    provider: p.Bytes(p.geo.max_provider),
    source_version: p.Bytes(p.geo.max_version),
    checksum: p.Bytes(64) = .{},
    csv: p.Bytes(8192) = .{},
};
pub const Status = enum(u8) { idle, downloading, validating, storing, applied, failed };
pub const Job = struct {
    app: *App = undefined,
    mutex: std.Io.Mutex = .init,
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = .init(false),
    status: std.atomic.Value(Status) = .init(.idle),
    progress: std.atomic.Value(u32) = .init(0),
    input: Input = undefined,
    metadata: p.geo.Metadata = .{},
    /// True while an embedded build snapshot serves lookups in place of a durable generation.
    embedded: bool = false,

    /// Startup restores only the durable active pointer; incomplete staging is invisible.
    pub fn restore(self: *Job) !void {
        const result = try self.app.background(.geo_metadata);
        if (result != .geo_metadata) return error.StorageUnavailable;
        const metadata = result.geo_metadata;
        if (metadata.ranges == 0) return self.restoreEmbedded(metadata.revision);
        if (metadata.ranges > geoip.max_ranges or metadata.digest.len != 64)
            return error.InvalidGeneration;
        const ranges = try self.app.gpa.alloc(geoip.Range, metadata.ranges);
        errdefer self.app.gpa.free(ranges);
        var count: usize = 0;
        var ordinal: u32 = 0;
        while (count < ranges.len) : (ordinal += 1) {
            const chunk = try self.app.background(.{ .geo_read = .{
                .digest = metadata.digest,
                .ordinal = ordinal,
            } });
            if (chunk != .geo_bytes or chunk.geo_bytes.len == 0 or chunk.geo_bytes.len % 34 != 0)
                return error.InvalidGeneration;
            geoip.wire.decodeRows(ranges, &count, chunk.geo_bytes.slice()) catch
                return error.InvalidGeneration;
        }
        var digest: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&digest, metadata.digest.slice());
        const provider = geoip.Provider.parse(metadata.provider.slice()) orelse .dbip;
        self.app.geo.active = .{
            .allocator = self.app.gpa,
            .ranges = ranges,
            .allocation = ranges,
            .digest = digest,
            .provider = provider,
            .version = geoip.Version.init(metadata.source_version.slice()) catch .{},
            .file_digests = try fileDigests(metadata.source_digests.slice(), digest),
            .files = provider.fileCount(),
        };
        self.app.geo.revision = metadata.revision;
        self.app.geo.loaded.store(true, .release);
        self.metadata = metadata;
    }

    /// Without a durable generation, an embedded build snapshot serves lookups until the
    /// first import. It keeps storage's revision, so any import replaces it.
    fn restoreEmbedded(self: *Job, revision: u64) !void {
        const embedded = @import("geoip_embedded.zig");
        if (!embedded.present) return;
        const database = (try embedded.load(self.app.gpa)) orelse return;
        self.app.geo.active = database;
        self.app.geo.revision = revision;
        self.app.geo.loaded.store(true, .release);
        self.embedded = true;
        self.metadata = .{
            .revision = revision,
            .digest = try p.Bytes(64).init(&std.fmt.bytesToHex(database.digest, .lower)),
            .provider = try p.Bytes(p.geo.max_provider).init(database.provider.name()),
            .source_version = try p.Bytes(p.geo.max_version).init(database.version.slice()),
            .source_digests = try sourceDigests(&database),
            .ranges = @intCast(database.ranges.len),
            .loaded_at = 0,
        };
    }

    pub fn start(self: *Job, input: Input) !void {
        const provider = geoip.Provider.parse(input.provider.slice()) orelse
            return error.InvalidRequest;
        if (!provider.versionValid(input.source_version.slice())) return error.InvalidRequest;
        if (input.checksum.len != 0 and input.checksum.len != 64) return error.InvalidRequest;
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        if (self.running.load(.acquire)) return error.Busy;
        try self.app.geo.begin();
        errdefer self.app.geo.end();
        if (self.thread) |thread| thread.join();
        self.thread = null;
        self.input = input;
        self.progress.store(0, .release);
        self.status.store(.validating, .release);
        self.running.store(true, .release);
        errdefer self.running.store(false, .release);
        self.thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, run, .{self});
    }

    pub fn stop(self: *Job) void {
        if (self.thread) |thread| thread.join();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.input));
    }

    fn run(self: *Job) void {
        defer self.running.store(false, .release);
        defer self.app.geo.end();
        self.execute() catch |err| {
            std.log.warn("console GeoIP import: {t}", .{err});
            self.status.store(.failed, .release);
        };
    }

    fn sourceProvider(self: *const Job) geoip.Provider {
        return geoip.Provider.parse(self.input.provider.slice()) orelse .dbip;
    }

    fn stage(self: *Job) !geoip.Database {
        const version = self.input.source_version.slice();
        const source = self.sourceProvider();
        if (self.input.csv.len != 0)
            return geoip.fromCsv(self.app.gpa, source, version, self.input.csv.slice());
        if (source.compression() == .gzip) return self.stageArchive(source, version);
        return self.stageFiles(source, version);
    }

    fn stageArchive(self: *Job, source: geoip.Provider, version: []const u8) !geoip.Database {
        self.status.store(.downloading, .release);
        const buffer = try self.app.gpa.alloc(u8, geoip.gzip.max_compressed_bytes);
        defer self.app.gpa.free(buffer);
        const bytes = try download.fetch(self.app, source, 0, version, buffer);
        self.status.store(.validating, .release);
        const stopping = &self.app.stopping;
        return geoip.gzip.decode(self.app.gpa, self.app.io, source, version, bytes, stopping);
    }

    /// Uncompressed providers publish one file per family with a digest file each. Every
    /// file is verified against its publisher digest before a row enters the loader.
    fn stageFiles(self: *Job, source: geoip.Provider, version: []const u8) !geoip.Database {
        const buffer = try self.app.gpa.alloc(u8, download.max_source_bytes);
        defer self.app.gpa.free(buffer);
        var loader = try geoip.Loader.init(self.app.gpa);
        errdefer loader.abandon();
        var file: u8 = 0;
        while (file < source.fileCount()) : (file += 1) {
            self.status.store(.downloading, .release);
            const expected = try download.fetchChecksum(self.app, source, file, version);
            const bytes = try download.fetch(self.app, source, file, version, buffer);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
            if (!std.mem.eql(u8, &digest, &expected)) return error.ChecksumMismatch;
            self.status.store(.validating, .release);
            try loader.feed(bytes);
            try loader.endFile();
            self.progress.store(@intCast(loader.builder.count), .release);
        }
        return loader.finish(source, version);
    }

    fn execute(self: *Job) !void {
        var staged = try self.stage();
        var transferred = false;
        defer if (!transferred) staged.deinit();
        const digest_hex = std.fmt.bytesToHex(staged.digest, .lower);
        if (self.input.checksum.len != 0 and
            !std.ascii.eqlIgnoreCase(self.input.checksum.slice(), &digest_hex))
            return error.ChecksumMismatch;
        const digest = try p.Bytes(64).init(&digest_hex);
        const source_digests = try sourceDigests(&staged);
        self.status.store(.storing, .release);
        const begin = try self.app.background(.{ .geo_begin = .{
            .auth = self.input.auth,
            .expected_revision = self.input.expected_revision,
            .digest = digest,
            .provider = self.input.provider,
            .source_version = self.input.source_version,
            .source_digests = source_digests,
            .ranges = @intCast(staged.ranges.len),
        } });
        if (begin != .command_recorded) return error.ImportConflict;
        try self.storeRanges(digest, staged.ranges);
        const result = try self.app.background(.{ .geo_activate = .{
            .auth = self.input.auth,
            .expected_revision = self.input.expected_revision,
            .digest = digest,
        } });
        if (result != .geo_activated) return error.ActivationRejected;
        try self.app.geo.activate(self.app.io, staged, self.input.expected_revision);
        transferred = true;
        self.mutex.lockUncancelable(self.app.io);
        self.embedded = false;
        self.metadata = .{
            .revision = self.input.expected_revision + 1,
            .digest = digest,
            .provider = self.input.provider,
            .source_version = self.input.source_version,
            .source_digests = source_digests,
            .ranges = @intCast(staged.ranges.len),
            .loaded_at = result.geo_activated,
        };
        self.mutex.unlock(self.app.io);
        self.status.store(.applied, .release);
    }

    fn storeRanges(self: *Job, digest: p.Bytes(64), ranges: []const geoip.Range) !void {
        var offset: usize = 0;
        var ordinal: u32 = 0;
        while (offset < ranges.len) : (ordinal += 1) {
            if (self.app.stopping.load(.acquire)) return error.Canceled;
            const count: usize = @min(geoip.wire.batch_rows, ranges.len - offset);
            var bytes: p.Bytes(geoip.wire.batch_bytes) = .{};
            bytes.len = geoip.wire.encodeBatch(ranges[offset..][0..count], &bytes.data);
            const result = try self.app.background(.{ .geo_batch = .{
                .auth = self.input.auth,
                .digest = digest,
                .ordinal = ordinal,
                .bytes = bytes,
            } });
            if (result != .command_recorded) return error.BatchRejected;
            offset += count;
            self.progress.store(@intCast(offset), .release);
        }
    }
};

/// "hex" or "hex:hex" for the generation's source files, in provider file order.
fn sourceDigests(db: *const geoip.Database) !p.Bytes(p.geo.max_source_digests) {
    var text: p.Bytes(p.geo.max_source_digests) = .{};
    for (db.file_digests[0..db.files], 0..) |digest, index| {
        if (index != 0) text.data[text.len] = ':';
        if (index != 0) text.len += 1;
        const hex = std.fmt.bytesToHex(digest, .lower);
        @memcpy(text.data[text.len..][0..64], &hex);
        text.len += 64;
    }
    return text;
}

fn fileDigests(text: []const u8, fallback: [32]u8) ![2][32]u8 {
    var digests: [2][32]u8 = .{ fallback, @splat(0) };
    if (!p.geo.validSourceDigests(text)) return error.InvalidGeneration;
    if (text.len >= 64) _ = try std.fmt.hexToBytes(&digests[0], text[0..64]);
    if (text.len == p.geo.max_source_digests) _ = try std.fmt.hexToBytes(&digests[1], text[65..]);
    return digests;
}
