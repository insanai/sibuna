//! One joined worker prepares candidates and converges this node's publication.
//! The storage owner commits intent first. Failed effects retain the last usable
//! generation and receive a separate, boot-fenced completion record.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
const p = @import("console_protocol");
const m = p.crs_management;
const App = @import("app.zig").App;
const candidate = @import("crs_candidate.zig");
const private_test = @import("crs_test_worker.zig");
const sources = @import("crs_sources.zig");
pub const Input = candidate.Input;
pub const Overrides = struct {
    mode: ?crs.config.Mode = null,
    profile: ?crs.config.Profile = null,
    blocking_paranoia: ?u8 = null,
    detection_paranoia: ?u8 = null,
    inbound: ?u16 = null,
    outbound: ?u16 = null,
    request: ?usize = null,
    response: ?usize = null,
    work: ?u64 = null,
    slots: ?usize = null,

    fn matches(self: Overrides, manifest: crs.artifact_manifest.Manifest) bool {
        inline for (.{ "mode", "profile", "blocking_paranoia", "detection_paranoia" }) |name| {
            if (@field(self, name)) |value| {
                if (@field(manifest.activation, name) != value) return false;
            }
        }
        inline for (.{ "inbound", "outbound" }) |name| {
            if (@field(self, name)) |value| {
                if (@field(manifest.thresholds, name) != value) return false;
            }
        }
        inline for (.{ "request", "response", "work" }) |name| {
            if (@field(self, name)) |value| {
                if (@field(manifest.limits, name) != value) return false;
            }
        }
        if (self.slots) |value| if (manifest.slots != value) return false;
        return true;
    }
};
pub const Seed = struct {
    publisher: ?*crs.publication.Publisher = null,
    initial: ?crs.artifact_manifest.Manifest = null,
    overrides: Overrides = .{},
    directory: p.Bytes(1024) = .{},
};
pub const Stage = m.Stage;
pub const Job = struct {
    app: *App = undefined,
    publisher: ?*crs.publication.Publisher = null,
    mutex: std.Io.Mutex = .init,
    thread: ?std.Thread = null,
    pending: ?Input = null,
    tester: private_test.Task = .{},
    running: bool = false,
    last_id: m.Id = .{},
    stage: Stage = .idle,
    reason: m.Reason = .none,
    confirmed_revision: u64 = 0,
    attempted_revision: u64 = 0,
    retry_after: u64 = 0,
    retry_seconds: u64 = 1,
    next_poll: u64 = 0,
    next_maintenance: u64 = 0,

    pub fn start(self: *Job, app: *App, seed: Seed) !void {
        self.app = app;
        self.publisher = seed.publisher;
        if (seed.publisher == null) return;
        try self.restore(seed);
        self.thread = try std.Thread.spawn(.{
            .stack_size = @import("serve").stack.bytes(1024 * 1024),
        }, run, .{self});
    }

    pub fn stop(self: *Job) void {
        // Cancellation reaches bounded TLS downloads and every source chunk loop.
        self.app.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        self.thread = null;
        if (self.pending) |*input| input.deinit(self.app.gpa);
        self.pending = null;
        self.tester.deinit(self.app.gpa);
    }

    pub fn enqueue(self: *Job, input: Input) !m.Id {
        if (self.publisher == null) return error.CrsManagementUnavailable;
        _ = try candidate.options(input, candidate.observation(self.app));
        if ((input.kind == .mode or input.kind == .rollback) != (input.clone != null) or
            (input.clone != null and input.configuration != null)) return error.InvalidRequest;
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        if (self.running or self.pending != null or self.tester.pending != null)
            return error.Busy;
        if (self.app.stopping.load(.acquire)) return error.Canceled;
        const result = try self.app.request(.{ .crs_management = .{ .begin = .{
            .auth = input.auth,
            .id = input.id,
            .kind = input.kind,
            .expected_revision = input.expected_revision,
            .expires = self.app.now() + m.preparation_seconds,
            .clone = if (input.clone) |job| job.id else null,
        } } });
        if (result == .failed) return switch (result.failed) {
            .unauthorized, .forbidden => error.CrsPreparationForbidden,
            .conflict => error.CrsSelectionConflict,
            .invalid_input => error.InvalidRequest,
            .capacity => error.CrsPreparationCapacity,
            else => error.StorageUnavailable,
        };
        if (result != .crs_job or result.crs_job == null) return error.CrsPreparationRejected;
        self.pending = input;
        self.last_id = input.id;
        self.stage = .preparing;
        self.reason = .none;
        return input.id;
    }

    pub fn enqueueTest(self: *Job, input: private_test.Input) !void {
        if (self.publisher == null) return error.CrsManagementUnavailable;
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        if (self.running or self.pending != null) return error.Busy;
        if (self.app.stopping.load(.acquire)) return error.Canceled;
        try self.tester.enqueue(self.app.gpa, input, self.app.now());
    }

    pub fn testSnapshot(self: *Job, auth: p.users.Auth, id: m.Id) !p.crs_tests.Status {
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        return self.tester.snapshot(auth, id, self.app.now());
    }

    pub fn exclusionPage(
        self: *Job,
        auth: p.users.Auth,
        id: m.Id,
        side: p.crs_tasks.review.exclusions.Side,
        offset: u32,
        out: *p.crs_tasks.review.exclusions.Page,
    ) !void {
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        const result = try self.tester.snapshot(auth, id, self.app.now());
        if (result.kind != .review or result.state != .complete) return error.InvalidRequest;
        try self.tester.exclusions.read(side, offset, out);
    }

    pub fn renewReview(self: *Job, auth: p.users.Auth, id: m.Id) !u64 {
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        return self.tester.renew(auth, id, self.app.now());
    }

    pub fn snapshot(self: *Job) struct { id: m.Id, stage: Stage, reason: m.Reason } {
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        return .{ .id = self.last_id, .stage = self.stage, .reason = self.reason };
    }

    fn restore(self: *Job, seed: Seed) !void {
        const selected = try self.selection();
        if (selected.current) |job| {
            const manifest = try crs.artifact_manifest.decode(job.manifest.slice());
            if (!seed.overrides.matches(manifest)) return error.CrsStartupConflict;
        }
        if (selected.revision == 0) {
            if (seed.initial) |manifest| try self.adopt(seed.directory.slice(), manifest);
        }
        try self.apply();
    }

    fn adopt(self: *Job, path: []const u8, manifest: crs.artifact_manifest.Manifest) !void {
        const app = self.app;
        const directory = try std.Io.Dir.cwd().openDir(
            app.io,
            path,
            .{ .follow_symlinks = false },
        );
        defer directory.close(app.io);
        var loaded = try updater.artifact.load(.{
            .allocator = app.gpa,
            .io = app.io,
            .directory = directory,
            .now = app.now(),
            .observation = .request_response,
        });
        defer loaded.deinit();
        try manifest.bind(loaded.prepared.package.?);
        var encoded: [crs.artifact_manifest.capacity]u8 = undefined;
        const id = identifier(app.io);
        const result = try app.request(.{ .crs_management = .{ .startup_begin = .{
            .id = id,
            .manifest = try m.Manifest.init(try manifest.encode(&encoded)),
        } } });
        if (result != .command_recorded) return error.CrsStartupConflict;
        try sources.store(app, id, null, &loaded.prepared);
        const committed = try app.request(.{ .crs_management = .{ .startup_commit = id } });
        if (committed != .crs_selection) return error.CrsStartupConflict;
    }

    fn run(self: *Job) void {
        while (!self.app.stopping.load(.acquire)) {
            if (self.take()) |owned| {
                var input = owned;
                defer input.deinit(self.app.gpa);
                var diagnostic: ?m.Diagnostic = null;
                self.prepare(input, &diagnostic) catch |err| self.fail(input.id, err, diagnostic);
                self.mutex.lockUncancelable(self.app.io);
                self.running = false;
                self.mutex.unlock(self.app.io);
            }
            self.runTest();
            const now = self.app.now();
            self.mutex.lockUncancelable(self.app.io);
            self.tester.expire(self.app.gpa, now);
            self.mutex.unlock(self.app.io);
            if (now >= self.next_maintenance) {
                self.next_maintenance = now + 60;
                self.maintain() catch |err| {
                    std.log.warn("CRS candidate maintenance unavailable: {t}", .{err});
                };
            }
            if (now >= self.next_poll) {
                self.next_poll = now + 1;
                self.apply() catch |err| self.deferApplication(now, err);
            }
            std.Io.sleep(self.app.io, .fromMilliseconds(250), .awake) catch return;
        }
    }

    fn runTest(self: *Job) void {
        self.mutex.lockUncancelable(self.app.io);
        var input = self.tester.pending orelse {
            self.mutex.unlock(self.app.io);
            return;
        };
        self.tester.pending = null;
        self.running = true;
        self.tester.result.?.state = .running;
        self.mutex.unlock(self.app.io);
        defer input.deinit(self.app.gpa);
        var result: p.crs_tests.Status = undefined;
        var inventory: private_test.Inventory = .{};
        private_test.execute(self.app, input, &result, &inventory);
        self.mutex.lockUncancelable(self.app.io);
        self.tester.result = result;
        self.tester.exclusions.deinit(self.app.gpa);
        self.tester.exclusions = inventory;
        self.tester.retained_until = self.app.now() + 15 * 60;
        self.running = false;
        self.mutex.unlock(self.app.io);
    }

    fn take(self: *Job) ?Input {
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        const input = self.pending orelse return null;
        self.pending = null;
        self.running = true;
        return input;
    }

    fn prepare(self: *Job, input: Input, diagnostic: *?m.Diagnostic) !void {
        var prepared = try candidate.prepare(self.app, input, diagnostic);
        defer prepared.deinit();
        const manifest = try candidate.verify(self.app, input, &prepared);
        self.progress(.storing, .none);
        if (input.clone == null) try sources.store(self.app, input.id, input.auth, &prepared);
        const result = try self.app.request(.{ .crs_management = .{ .verify = .{
            .auth = input.auth,
            .id = input.id,
            .manifest = manifest,
        } } });
        if (result != .crs_job or result.crs_job == null or
            result.crs_job.?.state != .verified) return error.CrsPreparationRejected;
        self.progress(.verified, .none);
    }

    fn progress(self: *Job, stage: Stage, reason: m.Reason) void {
        self.mutex.lockUncancelable(self.app.io);
        defer self.mutex.unlock(self.app.io);
        self.stage = stage;
        self.reason = reason;
    }

    fn fail(self: *Job, id: m.Id, err: anyerror, diagnostic: ?m.Diagnostic) void {
        const reason = failure(err);
        self.progress(.failed, reason);
        if (self.app.stopping.load(.acquire)) return;
        const result = self.app.request(.{ .crs_management = .{ .failed = .{
            .id = id,
            .reason = reason,
            .diagnostic = diagnostic,
        } } }) catch |record_error| {
            std.log.warn("CRS candidate failure receipt unavailable: {t}", .{record_error});
            return;
        };
        if (result != .crs_job) std.log.warn("CRS candidate failure receipt rejected", .{});
    }

    fn selection(self: *Job) !m.Selection {
        const result = try self.app.background(.{ .crs_management = .selected });
        if (result != .crs_selection) return error.CrsSelectionUnavailable;
        return result.crs_selection;
    }

    fn maintain(self: *Job) !void {
        const result = try self.app.background(.{ .crs_management = .maintenance });
        if (result != .command_recorded) return error.CrsMaintenanceUnavailable;
    }

    fn apply(self: *Job) !void {
        const selected = try self.selection();
        const job = selected.current orelse return;
        if (selected.revision == self.confirmed_revision) return;
        if (selected.revision != self.attempted_revision) {
            self.retry_after = 0;
            self.retry_seconds = 1;
        }
        if (self.app.now() < self.retry_after) return;
        self.retry_after = self.app.now() + 1;
        self.attempted_revision = selected.revision;
        const manifest = try crs.artifact_manifest.decode(job.manifest.slice());
        if (self.publisher.?.snapshot()) |current| {
            if (current.revision >= selected.revision) {
                if (!manifest.matchesCurrent(current)) return error.CrsStartupConflict;
                return self.confirm(selected.revision);
            }
        } else |err| if (err != error.NoGeneration) return err;
        var prepared = try sources.load(self.app, job);
        defer prepared.deinit();
        const settings = try manifest.options(candidate.observation(self.app));
        try crs.http_policy.validate(&prepared.package.?.program, settings.activation);
        const generation = try crs.generation.Generation.create(
            self.app.gpa,
            prepared.package.?,
            settings,
        );
        _ = prepared.takePackage();
        var transferred = false;
        defer if (!transferred) generation.deinit();
        const current = try self.selection();
        if (current.revision != selected.revision) return error.CrsSelectionChanged;
        if (self.app.stopping.load(.acquire)) return error.Canceled;
        try self.publisher.?.publish(generation);
        transferred = true;
        try self.confirm(selected.revision);
    }

    fn confirm(self: *Job, revision: u64) !void {
        const result = try self.app.request(.{ .crs_management = .{ .applied = .{
            .revision = revision,
            .applied = true,
        } } });
        if (result != .command_recorded) return error.CrsReceiptUnavailable;
        self.confirmed_revision = revision;
        self.retry_seconds = 1;
    }

    fn deferApplication(self: *Job, now: u64, err: anyerror) void {
        self.retry_after = now + self.retry_seconds;
        self.retry_seconds = @min(60, self.retry_seconds * 2);
        if (self.app.stopping.load(.acquire) or self.attempted_revision == 0) return;
        // A lost storage reply cannot turn an already applied generation into a
        // failed runtime effect. Re-observe identity and retry its true receipt.
        const selected = self.selection() catch |read_error| {
            std.log.warn("CRS completion state unavailable: {t}", .{read_error});
            return;
        };
        if (selected.revision != self.attempted_revision) return;
        const manifest = crs.artifact_manifest.decode(selected.current.?.manifest.slice()) catch
            unreachable; // Selection reads already validate this owned manifest.
        if (self.publisher.?.snapshot()) |current| {
            if (manifest.matchesCurrent(current)) {
                self.confirm(selected.revision) catch |record_error| {
                    std.log.warn("CRS applied receipt unavailable: {t}", .{record_error});
                };
                return;
            }
        } else |snapshot_error| {
            if (snapshot_error != error.NoGeneration) {
                std.log.warn("CRS completion observation unavailable: {t}", .{snapshot_error});
                return;
            }
        }
        const result = self.app.request(.{ .crs_management = .{ .applied = .{
            .revision = self.attempted_revision,
            .applied = false,
            .reason = failure(err),
        } } }) catch |record_error| {
            std.log.warn("CRS application receipt unavailable: {t}", .{record_error});
            return;
        };
        if (result != .command_recorded) std.log.warn("CRS application receipt rejected", .{});
    }
};

pub fn identifier(io: std.Io) m.Id {
    var bytes: [16]u8 = @splat(0);
    while (std.mem.allEqual(u8, &bytes, 0)) io.random(&bytes);
    return m.Id.init(&std.fmt.bytesToHex(bytes, .lower)) catch unreachable;
}

pub fn failure(err: anyerror) m.Reason {
    if (err == error.Canceled or err == error.CrsPreparationRejected) return .canceled;
    if (err == error.OutOfMemory or err == error.ReservationLimit or
        err == error.CompiledLimit or err == error.ExclusionReviewLimit) return .capacity;
    if (err == error.CrsSourceRejected or err == error.CrsSourceUnavailable or
        err == error.CrsSelectionUnavailable or err == error.CrsReceiptUnavailable or
        err == error.StorageTimeout) return .storage;
    if (err == error.PublicationBusy or err == error.PublicationClosed or
        err == error.CrsSelectionChanged or err == error.CrsStartupConflict) return .publication;
    const name = @errorName(err);
    if (std.mem.indexOf(u8, name, "Signature") != null or
        std.mem.indexOf(u8, name, "Signer") != null) return .signature;
    if (err == error.Transport or err == error.DownloadDeadline or
        err == error.Deadline or err == error.HttpStatus) return .download;
    return .incompatible;
}
