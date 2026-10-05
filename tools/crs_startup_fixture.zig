//! The actual daemon startup owner loads authenticated files and owns their pool.
const std = @import("std");
const crs = @import("crs");
const startup = @import("crs-start");

pub fn qualify(
    init: std.process.Init,
    directory: std.Io.Dir,
    manifest: crs.artifact_manifest.Manifest,
    now: u64,
) !void {
    var choice: crs.config.Choice = .{};
    try choice.select(.enforce);
    var config: startup.options.Config = .{
        .choice = choice,
        .directory = "borrowed-fixture",
        .request = 8192,
        .response = 4096,
        .slots = 1,
    };
    const running = try startup.Runtime.load(
        init.gpa,
        init.io,
        directory,
        config,
        .request_response,
        now,
    );
    defer running.stop();
    const snapshot = try running.publisher.snapshot();
    if (snapshot.revision != manifest.revision or snapshot.activation.mode != .enforce or
        !std.mem.eql(u8, &snapshot.digest.?, &manifest.archive_digest))
        return error.StartupIdentityMismatch;
    try evaluate(running, .full);
    // Forward-auth is a distinct observation contract. Its explicit override is
    // validated after authentication, without changing the signed rule sources.
    config.profile = .headers;
    const metadata = try startup.Runtime.load(
        init.gpa,
        init.io,
        directory,
        config,
        .request_metadata,
        now,
    );
    defer metadata.stop();
    try evaluate(metadata, .headers);
    // A failed replacement cannot disturb an already leased generation. The
    // failure allocator also verifies private load cleanup under exhaustion.
    if (startup.Runtime.load(std.testing.failing_allocator, init.io, directory, config, .request_metadata, now)) |unexpected| {
        unexpected.stop();
        return error.StartupAcceptedExhaustedAllocator;
    } else |err| if (err != error.OutOfMemory) return err;
    try evaluate(running, .full);
}

fn evaluate(running: *startup.Runtime, profile: crs.config.Profile) !void {
    for ([_][]const u8{ "/?q=ordinary", "/?q=1%27%20OR%20%271%27=%271" }, 0..) |target, index| {
        var lease = try running.publisher.lease();
        defer lease.release();
        if (running.publisher.lease()) |value| {
            var unexpected = value;
            unexpected.release();
            return error.StartupPoolWasNotBounded;
        } else |err| if (err != error.PoolBusy) return err;
        var line: [256]u8 = undefined;
        var transaction = try lease.begin(.{
            .method = "GET",
            .target = target,
            .protocol = "HTTP/1.1",
            .line = try std.fmt.bufPrint(&line, "GET {s} HTTP/1.1", .{target}),
            .client = "192.0.2.1",
            .id = "startup-probe",
            .headers = &.{
                .{ .name = "Host", .value = "example.test" },
                .{ .name = "User-Agent", .value = "Mozilla/5.0" },
                .{ .name = "Accept", .value = "text/html" },
            },
        });
        if (profile == .headers) {
            try transaction.finish(.headers_profile);
            continue;
        }
        const result = try transaction.requestBody("");
        if ((result == .denied) != (index == 1)) return error.StartupDecisionMismatch;
        if (index == 1) {
            try transaction.finish(.local_response);
        } else {
            _ = try transaction.responseHeaders(.{ .status = 200, .headers = &.{} });
            _ = try transaction.responseBody("ordinary page");
            try transaction.finish(.inspected);
        }
    }
}
