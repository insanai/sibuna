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
    source_version: p.Bytes(7),
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

    /// Startup restores only the durable active pointer; incomplete staging is invisible.
    pub fn restore(self: *Job) !void {
        const result = try self.app.background(.geo_metadata);
        if (result != .geo_metadata) return error.StorageUnavailable;
        const metadata = result.geo_metadata;
        if (metadata.ranges == 0) return;
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
        self.app.geo.active = .{
            .allocator = self.app.gpa,
            .ranges = ranges,
            .allocation = ranges,
            .digest = digest,
            .provider = .dbip,
            .version = geoip.Version.init(metadata.source_version.slice()) catch .{},
            .file_digests = .{ digest, @splat(0) },
            .files = 1,
        };
        self.app.geo.revision = metadata.revision;
        self.app.geo.loaded.store(true, .release);
        self.metadata = metadata;
    }

    pub fn start(self: *Job, input: Input) !void {
        if (!geoip.Provider.dbip.versionValid(input.source_version.slice()))
            return error.InvalidRequest;
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

    fn stage(self: *Job) !geoip.Database {
        const version = self.input.source_version.slice();
        if (self.input.csv.len != 0)
            return geoip.fromCsv(self.app.gpa, .dbip, version, self.input.csv.slice());
        self.status.store(.downloading, .release);
        const buffer = try self.app.gpa.alloc(u8, geoip.gzip.max_compressed_bytes);
        defer self.app.gpa.free(buffer);
        const bytes = try download.fetch(self.app, version, buffer);
        self.status.store(.validating, .release);
        const stopping = &self.app.stopping;
        return geoip.gzip.decode(self.app.gpa, self.app.io, .dbip, version, bytes, stopping);
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
        self.status.store(.storing, .release);
        const begin = try self.app.background(.{ .geo_begin = .{
            .auth = self.input.auth,
            .expected_revision = self.input.expected_revision,
            .digest = digest,
            .source_version = self.input.source_version,
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
        self.metadata = .{
            .revision = self.input.expected_revision + 1,
            .digest = digest,
            .source_version = self.input.source_version,
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
