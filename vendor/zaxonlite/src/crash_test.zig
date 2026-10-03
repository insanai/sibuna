//! Abrupt one-process crash matrix for the durable host ordering contract.
//!
//! Every case starts from a committed baseline, spawns the real CLI with one
//! exact failpoint, observes `_exit` without cleanup, then reopens through the
//! library and checks integrity. Unknown client fate permits either absence or
//! durable completion at the early boundaries; once the accept prefix is synced
//! in a one-voter configuration, recovery must complete the value. The legacy
//! commit-named failpoint now denotes chosen-before-materialized-apply.

const std = @import("std");
const zaxonlite = @import("zaxonlite");

const Operation = enum { write, anchor };

const Case = struct {
    failpoint: []const u8,
    operation: Operation = .write,
    minimum_count: i64,
    maximum_count: i64,
};

/// One anchor-ladder crash case: the committed baseline row survives.
fn anchorCase(comptime failpoint: []const u8) Case {
    return .{
        .failpoint = failpoint,
        .operation = .anchor,
        .minimum_count = 1,
        .maximum_count = 1,
    };
}

const cases = [_]Case{
    .{ .failpoint = "before_payload_sync", .minimum_count = 0, .maximum_count = 0 },
    .{ .failpoint = "after_payload_sync", .minimum_count = 0, .maximum_count = 0 },
    // Process death does not emulate power loss: an unsynced append may still
    // reach disk. Both outcomes are safe because the client saw no success.
    .{ .failpoint = "after_accept_append", .minimum_count = 0, .maximum_count = 1 },
    .{ .failpoint = "after_accept_sync", .minimum_count = 1, .maximum_count = 1 },
    .{
        .failpoint = "after_commit_sync_before_apply",
        .minimum_count = 1,
        .maximum_count = 1,
    },
    // The anchor cases crash a single-node `anchor` maintenance command,
    // which traverses the whole durable-anchor ladder: WAL checkpoint and
    // database sync, the alternating APPLIED publish, the inline chosen
    // trim, segment reclamation, and payload GC (ZDS 0011). The baseline
    // row was committed before the crash, so recovery must always present
    // exactly one row, pass integrity, and keep accepting writes and
    // anchors afterwards.
    anchorCase("before_db_sync"),
    anchorCase("after_db_sync"),
    anchorCase("before_applied_write"),
    anchorCase("after_applied_barrier"),
    anchorCase("before_trim_file"),
    anchorCase("after_trim_file"),
    anchorCase("before_segment_unlink"),
    anchorCase("after_segment_unlink"),
    anchorCase("before_payload_gc_publish"),
    anchorCase("after_payload_gc_publish"),
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var arguments = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer arguments.deinit();
    _ = arguments.next();
    const zaxon = arguments.next() orelse {
        std.debug.print("usage: crash-test <zaxon>\n", .{});
        return 2;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    const root = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/zx-crash-{x}",
        .{nonce},
    );
    defer gpa.free(root);
    try std.Io.Dir.cwd().createDirPath(io, root);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

    for (cases, 0..) |case, index| {
        try runCase(gpa, io, zaxon, root, case, index);
        std.debug.print("ok   crash at {s}\n", .{case.failpoint});
    }
    std.debug.print("crash matrix: all {d} cases passed\n", .{cases.len});
    return 0;
}

/// Fills the crashed child's command line into caller-owned storage.
/// Process-kill recovery is identical under both sync policies, so every
/// case runs with `--sync os`.
fn caseArgv(
    operation: Operation,
    assignment: []const u8,
    zaxon: []const u8,
    directory: []const u8,
    storage: *[10][]const u8,
) []const []const u8 {
    switch (operation) {
        .write => {
            storage.* = .{
                "/usr/bin/env", assignment,
                zaxon,          "exec",
                "--data",       directory,
                "--sql",        "insert into t(v) values ('crash')",
                "--sync",       "os",
            };
            return storage[0..10];
        },
        .anchor => {
            storage[0..8].* = .{
                "/usr/bin/env", assignment,
                zaxon,          "anchor",
                "--data",       directory,
                "--sync",       "os",
            };
            return storage[0..8];
        },
    }
}

fn runCase(
    gpa: std.mem.Allocator,
    io: std.Io,
    zaxon: []const u8,
    root: []const u8,
    case: Case,
    index: usize,
) !void {
    const directory = try std.fmt.allocPrint(gpa, "{s}/case-{d}", .{ root, index });
    defer gpa.free(directory);
    {
        const node = try zaxonlite.Node.open(gpa, io, .{ .directory = directory });
        defer node.close();
        _ = try node.exec("create table t(id integer primary key, v text)");
        if (case.operation == .anchor) {
            _ = try node.exec("insert into t(v) values ('base')");
        }
    }

    const assignment = try std.fmt.allocPrint(
        gpa,
        "ZAXON_FAILPOINT={s}",
        .{case.failpoint},
    );
    defer gpa.free(assignment);
    var argv_storage: [10][]const u8 = undefined;
    const argv = caseArgv(case.operation, assignment, zaxon, directory, &argv_storage);
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const termination = try child.wait(io);
    const code = switch (termination) {
        .exited => |value| value,
        else => 0,
    };
    if (code != 137) return error.FailpointDidNotCrash;

    const recovered = try zaxonlite.Node.open(gpa, io, .{ .directory = directory });
    defer recovered.close();
    var result = try recovered.query(gpa, "select count(*) from t");
    defer result.deinit();
    const count = try std.fmt.parseInt(i64, result.rows[0][0].?, 10);
    if (count < case.minimum_count or count > case.maximum_count) {
        return error.UnexpectedRecoveredCount;
    }
    const report = try recovered.integrityCheck();
    if (!report.ok()) return error.IntegrityFailure;
    if (case.operation == .anchor) {
        // A crash anywhere on the anchor ladder must never wedge the
        // node: writes and the next anchor still succeed.
        _ = try recovered.exec("insert into t(v) values ('post')");
        try recovered.createStateAnchor();
    }
}
