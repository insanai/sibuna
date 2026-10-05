//! The joined CRS worker owns the submitted JSON through private compilation and
//! evaluation. One bounded result belongs to its issuing session and expires.
const std = @import("std");
const p = @import("console_protocol");
const crs = @import("crs");
const App = @import("app.zig").App;
const m = p.crs_management;
const api = p.crs_tests;
pub const Input = struct {
    auth: p.users.Auth,
    id: m.Id,
    body: []u8,
    length: usize,

    pub fn deinit(self: *Input, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.body);
        allocator.free(self.body);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};
pub const Task = struct {
    pending: ?Input = null,
    session: [32]u8 = @splat(0),
    result: ?api.Status = null,

    pub fn deinit(self: *Task, allocator: std.mem.Allocator) void {
        if (self.pending) |*input| input.deinit(allocator);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    /// Called under the shared worker mutex. Complete results cannot let another
    /// session monopolize or read this caller's unexpired review.
    pub fn enqueue(self: *Task, input: Input, now: u64) !void {
        if (input.length == 0 or input.length > input.body.len or
            input.body.len > api.sample.sample_json_bytes)
            return error.InvalidRequest;
        if (self.pending != null) return error.Busy;
        if (self.result) |result| {
            if (result.expires > now and !std.crypto.timing_safe.eql(
                [32]u8,
                self.session,
                input.auth.session_digest,
            )) return error.Busy;
        }
        self.pending = input;
        self.session = input.auth.session_digest;
        self.result = .{ .id = input.id, .state = .queued, .expires = now + 300 };
    }

    pub fn snapshot(self: *const Task, auth: p.users.Auth, id: m.Id, now: u64) !api.Status {
        const result = self.result orelse return error.InvalidRequest;
        if (result.expires <= now or !std.mem.eql(u8, id.slice(), result.id.slice()) or
            !std.crypto.timing_safe.eql([32]u8, self.session, auth.session_digest))
            return error.InvalidRequest;
        return result;
    }
};

pub fn execute(app: *App, input: Input, result: *api.Status) void {
    result.* = .{ .id = input.id, .state = .running, .expires = app.now() + 60 };
    run(app, input, result) catch |err| {
        result.state = .failed;
        const name = @errorName(err);
        result.failure = p.Bytes(64).init(name[0..@min(name.len, 64)]) catch unreachable;
        result.report = null;
    };
    result.expires = app.now() + 60;
}

fn run(app: *App, input: Input, result: *api.Status) !void {
    const memory = try app.gpa.alloc(u8, api.sample.parser_bytes);
    defer app.gpa.free(memory);
    defer std.crypto.secureZero(u8, memory);
    var fixed: std.heap.FixedBufferAllocator = .init(memory);
    const body = input.body[0..input.length];
    const parsed = try std.json.parseFromSlice(api.Request, fixed.allocator(), body, .{
        .allocate = .alloc_always,
        .max_value_len = api.sample.entity_bytes * 2,
    });
    defer parsed.deinit();
    const request = parsed.value;
    try request.validate();
    result.source = try m.Id.init(request.source);
    result.expected_revision = try std.fmt.parseInt(u64, request.expected_revision, 10);
    const authorized = try app.request(.{ .crs_management = .{ .test_begin = .{
        .auth = input.auth,
        .id = result.source,
        .expected_revision = result.expected_revision,
    } } });
    if (authorized == .failed and authorized.failed == .forbidden)
        return error.CrsPreparationForbidden;
    if (authorized != .crs_job or authorized.crs_job == null) return error.CrsSelectionConflict;
    const job = authorized.crs_job.?;
    var prepared = try @import("crs_sources.zig").loadDiagnosed(app, job, &result.diagnostic);
    defer prepared.deinit();
    const manifest = try crs.artifact_manifest.decode(job.manifest.slice());
    var execution: crs.config.Execution = .{
        .activation = manifest.activation,
        .thresholds = manifest.thresholds,
    };
    if (request.mode) |mode| execution.activation.mode = switch (mode) {
        .off => .off,
        .audit => .audit,
        .enforce => .enforce,
    };
    var report: api.sample.Report = undefined;
    try crs.scenario.evaluate(.{
        .allocator = app.gpa,
        .program = &prepared.package.?.program,
        .execution = execution,
        .limits = manifest.limits,
        .sample = request.sample,
    }, &report);
    result.report = report;
    try recheck(app, input.auth, result);
    result.artifact = (try @import("crs_views.zig").candidate(job)).artifact;
    result.state = .complete;
}

fn recheck(app: *App, auth: p.users.Auth, result: *const api.Status) !void {
    if (app.stopping.load(.acquire)) return error.Canceled;
    const selected = try app.request(.{ .crs_management = .{ .status = auth } });
    if (selected != .crs_selection or selected.crs_selection.revision != result.expected_revision)
        return error.CrsSelectionConflict;
    const retained = try app.request(.{ .crs_management = .{ .job = .{
        .auth = auth,
        .id = result.source,
    } } });
    if (retained != .crs_job or retained.crs_job == null or
        (retained.crs_job.?.state != .verified and retained.crs_job.?.state != .selected))
        return error.CrsPreparationForbidden;
}

test "private test jobs own queued bytes and bind pollable results to session and expiry" {
    const t = std.testing;
    var memory: [256]u8 = @splat(0x44);
    var fixed: std.heap.FixedBufferAllocator = .init(&memory);
    var task: Task = .{};
    const bytes = try fixed.allocator().dupe(u8, "private sample");
    const input: Input = .{
        .auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) },
        .id = try m.Id.init("11111111111111111111111111111111"),
        .body = bytes,
        .length = bytes.len,
    };
    try task.enqueue(input, 100);
    const result = try task.snapshot(input.auth, input.id, 101);
    try t.expectEqual(api.State.queued, result.state);
    try t.expectError(error.Busy, task.enqueue(input, 101));
    var other = input.auth;
    other.session_digest = @splat(3);
    try t.expectError(error.InvalidRequest, task.snapshot(other, input.id, 101));
    try t.expectError(error.InvalidRequest, task.snapshot(input.auth, input.id, 400));
    task.deinit(fixed.allocator());
    // Debug allocators may poison released memory after erasure. It must never
    // retain the submitted sample in this caller-owned backing array.
    try t.expect(!std.mem.eql(u8, bytes, "private sample"));
}
