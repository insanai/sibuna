//! Off-path updater preparation, shared by CLI and console management jobs. The
//! signed artifact remains owned for durable staging; publication is a later step.
const std = @import("std");
const crs = @import("crs");
const fetch = @import("net").fetch;
const urls = crs.release_urls;
const Io = std.Io;
pub const Error = fetch.Error || crs.release_package.Error || urls.Error ||
    std.json.ParseError(std.json.Scanner) || error{ InvalidClock, InvalidDownloadDeadline };
pub const Config = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stopping: *const std.atomic.Value(bool),
    deadline_ms: u32 = 120_000,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    archive_buffer: []u8,
    signature_buffer: []u8,
    archive: []const u8,
    signature: []const u8,
    package: ?*crs.release_package.Package,

    /// Transfers the stable package to a generation; the artifact remains owned here.
    pub fn takePackage(self: *Prepared) *crs.release_package.Package {
        const result = self.package.?;
        self.package = null;
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        if (self.package) |package| package.deinit();
        self.allocator.free(self.signature_buffer);
        self.allocator.free(self.archive_buffer);
        self.* = undefined;
    }
};
const Metadata = struct { tag_name: []const u8, draft: bool, prerelease: bool };
const Download = struct {
    config: Config,
    started: i96,

    fn check(self: Download) Error!u32 {
        if (self.config.stopping.load(.acquire)) return error.Canceled;
        const elapsed = Io.Clock.awake.now(self.config.io).nanoseconds - self.started;
        const limit = @as(i96, self.config.deadline_ms) * std.time.ns_per_ms;
        if (elapsed >= limit) return error.DownloadDeadline;
        return @intCast(@divFloor(limit - elapsed, std.time.ns_per_ms));
    }

    fn receive(self: Download, url: []const u8, output: []u8, metadata: bool) Error![]const u8 {
        const remaining = try self.check();
        if (remaining == 0) return error.DownloadDeadline;
        return fetch.fetch(.{
            .allocator = self.config.allocator,
            .io = self.config.io,
            .stopping = self.config.stopping,
            .initial_hosts = if (metadata) &.{"api.github.com"} else &.{"github.com"},
            .redirect_hosts = if (metadata) &.{} else &.{
                "release-assets.githubusercontent.com",
                "objects.githubusercontent.com",
            },
            .deadline_ms = remaining,
        }, url, output);
    }

    fn latestVersion(self: Download) Error!crs.release_version.Version {
        const output = try self.config.allocator.alloc(u8, urls.metadata_capacity);
        defer self.config.allocator.free(output);
        const received = try self.receive(urls.latest, output, true);
        const parsed = try std.json.parseFromSlice(Metadata, self.config.allocator, received, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();
        return urls.fromMetadata(
            parsed.value.tag_name,
            parsed.value.draft,
            parsed.value.prerelease,
        );
    }
};

/// A missing version resolves the latest stable tag over TLS. Both subsequent URLs
/// are reconstructed locally and the pinned signer authenticates the archive itself.
pub fn prepare(config: Config, version: ?crs.release_version.Version) Error!Prepared {
    if (config.deadline_ms == 0 or config.deadline_ms > 300_000)
        return error.InvalidDownloadDeadline;
    const job: Download = .{
        .config = config,
        .started = Io.Clock.awake.now(config.io).nanoseconds,
    };
    _ = try job.check();
    const selected = version orelse try job.latestVersion();
    const archive_buffer = try config.allocator.alloc(u8, urls.archive_capacity);
    errdefer config.allocator.free(archive_buffer);
    const signature_buffer = try config.allocator.alloc(u8, urls.signature_capacity);
    errdefer config.allocator.free(signature_buffer);
    var url_buffer: [urls.maximum_url]u8 = undefined;
    const archive = try job.receive(
        try urls.url(selected, .archive, &url_buffer),
        archive_buffer,
        false,
    );
    const signature = try job.receive(
        try urls.url(selected, .signature, &url_buffer),
        signature_buffer,
        false,
    );
    _ = try job.check();
    const seconds = @divFloor(Io.Clock.real.now(config.io).nanoseconds, std.time.ns_per_s);
    if (seconds < 0 or seconds > std.math.maxInt(u64)) return error.InvalidClock;
    const package = try crs.release_package.prepare(config.allocator, .{
        .archive = archive,
        .signature = signature,
        .version = selected,
        .now = @intCast(seconds),
    });
    errdefer package.deinit();
    _ = try job.check();
    return .{
        .allocator = config.allocator,
        .archive_buffer = archive_buffer,
        .signature_buffer = signature_buffer,
        .archive = archive,
        .signature = signature,
        .package = package,
    };
}

test "canceled updater creates no artifact or candidate generation" {
    var stopping: std.atomic.Value(bool) = .init(true);
    const config: Config = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .stopping = &stopping,
    };
    try std.testing.expectError(error.Canceled, prepare(config, null));
    var invalid = config;
    invalid.deadline_ms = 300_001;
    try std.testing.expectError(error.InvalidDownloadDeadline, prepare(invalid, null));
}
