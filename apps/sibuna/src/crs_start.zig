//! Startup owns a stable publisher. Verified files are prepared before listeners;
//! shutdown joins every reader before closing and freeing their generations.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
pub const http_policy = @import("crs_http_policy.zig");
pub const options = @import("crs_options.zig");
const local_reload = @import("crs_local_reload.zig");
pub const Error = options.Error || http_policy.Error || updater.artifact.Error ||
    crs.generation.Error ||
    crs.publication.Error || local_reload.Error || std.Io.Dir.OpenError || error{InvalidCrsClock};
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    publisher: crs.publication.Publisher = .{},
    source: ?crs.artifact_manifest.Manifest = null,
    reload: ?*local_reload.Owner = null,

    /// Console management needs a stable address even before its first selection.
    /// No generation or transaction pool is allocated until a reviewed activation.
    pub fn empty(allocator: std.mem.Allocator) std.mem.Allocator.Error!*Runtime {
        const self = try allocator.create(Runtime);
        self.* = .{ .allocator = allocator };
        return self;
    }

    pub fn startReloading(
        allocator: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
        observation: crs.config.Observation,
    ) Error!*Runtime {
        const self = try empty(allocator);
        errdefer self.stop();
        self.reload = try local_reload.Owner.start(
            allocator,
            io,
            path,
            &self.publisher,
            observation,
        );
        return self;
    }

    /// Off returns without touching files, allocating a pool or publishing a pin.
    pub fn start(
        allocator: std.mem.Allocator,
        io: std.Io,
        config: options.Config,
        observation: crs.config.Observation,
    ) Error!?*Runtime {
        try config.validate(observation);
        if (config.choice.resolved() == .off) return null;
        const seconds = @divFloor(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
        if (seconds < 0 or seconds > std.math.maxInt(u64)) return error.InvalidCrsClock;
        const directory = try std.Io.Dir.cwd().openDir(io, config.directory.?, .{
            .follow_symlinks = false,
        });
        defer directory.close(io);
        return load(allocator, io, directory, config, observation, @intCast(seconds));
    }

    /// The directory is borrowed through this call. Authenticity and all bounds
    /// are checked again, regardless of a previous successful candidate check.
    pub fn load(
        allocator: std.mem.Allocator,
        io: std.Io,
        directory: std.Io.Dir,
        config: options.Config,
        observation: crs.config.Observation,
        now: u64,
    ) Error!*Runtime {
        try config.validate(observation);
        if (config.choice.resolved() == .off) return error.DisabledGeneration;
        var candidate = try updater.artifact.load(.{
            .allocator = allocator,
            .io = io,
            .directory = directory,
            .now = now,
            .observation = .request_response,
        });
        defer candidate.deinit();
        var selected = try candidate.manifest.options(.request_response);
        selected.observation = observation;
        try config.apply(&selected);
        try http_policy.validate(&candidate.prepared.package.?.program, selected.activation);
        const self = try allocator.create(Runtime);
        errdefer allocator.destroy(self);
        const source = try crs.artifact_manifest.Manifest.create(
            candidate.prepared.package.?,
            selected,
            .{
                .previous_revision = candidate.manifest.previous_revision,
                .signature_bytes = candidate.prepared.signature.value.len,
                .configuration_bytes = candidate.prepared.configuration.value.len,
            },
        );
        self.* = .{ .allocator = allocator, .source = source };
        const generation = try crs.generation.Generation.create(
            allocator,
            candidate.prepared.package.?,
            selected,
        );
        _ = candidate.prepared.takePackage();
        errdefer generation.deinit();
        try self.publisher.publish(generation);
        return self;
    }

    /// The owner must already have joined listener, console and reload workers.
    pub fn stop(self: *Runtime) void {
        self.stopReload();
        self.publisher.close() catch unreachable;
        self.publisher.deinit();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    /// Stop new local work while retaining published generations for readers and
    /// storage teardown. Final destruction still requires every reader to join.
    pub fn stopReload(self: *Runtime) void {
        if (self.reload) |reload| reload.stop();
        self.reload = null;
    }
};

test "disabled CRS startup never loads a directory or allocates" {
    var choice: crs.config.Choice = .{};
    try choice.select(.off);
    const config: options.Config = .{ .choice = choice, .directory = "/missing/crs" };
    const result = try Runtime.start(
        std.testing.failing_allocator,
        std.testing.io,
        config,
        .request_metadata,
    );
    try std.testing.expect(result == null);
}

test "empty local reload owns no generation and joins its exclusive worker before restart" {
    const t = std.testing;
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    var path: [1024]u8 = undefined;
    const directory = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}", .{temporary.sub_path});
    const first = try Runtime.startReloading(
        t.allocator,
        t.io,
        directory,
        .request_response,
    );
    var stopped = false;
    defer if (!stopped) first.stop();
    try t.expect(!first.publisher.enabled.load(.acquire));
    try t.expectError(error.NoGeneration, first.publisher.snapshot());
    try t.expectError(error.LocalStoreBusy, Runtime.startReloading(
        t.allocator,
        t.io,
        directory,
        .request_response,
    ));
    first.stop();
    stopped = true;
    const restarted = try Runtime.startReloading(
        t.allocator,
        t.io,
        directory,
        .request_response,
    );
    defer restarted.stop();
    try t.expectError(error.NoGeneration, restarted.publisher.snapshot());
}

test {
    _ = options;
    _ = http_policy;
}
