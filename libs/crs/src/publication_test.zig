const std = @import("std");
const publications = @import("publication.zig");
const generations = @import("generation.zig");
const packages = @import("release_package.zig");
const compiler = @import("compiler.zig");
const rules = @import("rule_program.zig");
const limits = blk: {
    var selected = @import("transaction_slot_test.zig").limits;
    selected.entries = 128;
    selected.bytes = 8192;
    break :blk selected;
};

fn package(revision: u64) !*packages.Package {
    const allocator = std.testing.allocator;
    const result = try allocator.create(packages.Package);
    errdefer allocator.destroy(result);
    result.* = .{
        .allocator = allocator,
        .bounded = .{ .parent = allocator, .limit = packages.compiled_capacity },
        .program = undefined,
        .receipt = .{ .digest = @splat(@intCast(revision)), .created = 1, .archive_bytes = 1 },
        .version = .{ .major = 4, .minor = 30, .patch = 0 },
        .operator_digest = @splat(@intCast(revision + 16)),
    };
    var source: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&source, "SecAction \"id:1,setvar:tx.revision={d}\"", .{
        revision,
    });
    var builder = compiler.Compiler.init(allocator, .{});
    defer builder.deinit();
    try builder.addSource("rules/test.conf", text);
    var plan = try builder.finish();
    defer plan.deinit();
    result.program = try rules.compile(result.bounded.allocator(), &plan, &.{}, .{});
    return result;
}

fn generation(revision: u64) !*generations.Generation {
    const prepared = try package(revision);
    errdefer prepared.deinit();
    return generations.Generation.create(std.testing.allocator, prepared, .{
        .revision = revision,
        .activation = .{ .mode = .enforce },
        .observation = .request_response,
        .limits = limits,
        .slots = 1,
        .reservation = 1024 * 1024,
    });
}

fn shutdown(publisher: *publications.Publisher) void {
    publisher.close() catch unreachable;
    publisher.deinit();
}

test "leased transaction keeps its operator tuning after a concurrent publication" {
    var publisher: publications.Publisher = .{};
    defer shutdown(&publisher);
    const first = try generation(1);
    first.options.activation = .{
        .mode = .audit,
        .blocking_paranoia = 2,
        .detection_paranoia = 3,
    };
    first.options.thresholds = .{ .inbound = 7, .outbound = 9 };
    try publisher.publish(first);
    var old = try publisher.lease();
    defer old.release();
    try publisher.publish(try generation(2));
    var transaction = try old.begin(.{
        .method = "GET",
        .target = "/",
        .protocol = "HTTP/1.1",
        .line = "GET / HTTP/1.1",
        .client = "192.0.2.1",
        .id = "pinned-tuning",
        .headers = &.{.{ .name = "Host", .value = "example.test" }},
    });
    try std.testing.expectEqualStrings("7", (try old.work.slot().store.get(
        "inbound_anomaly_score_threshold",
        &old.work.slot().budget,
    )).?);
    try std.testing.expectEqualStrings("3", (try old.work.slot().store.get(
        "detection_paranoia_level",
        &old.work.slot().budget,
    )).?);
    try transaction.finish(.local_response);
    const current = try publisher.snapshot();
    try std.testing.expectEqual(@as(u16, 5), current.thresholds.inbound);
    try std.testing.expectEqual(.enforce, current.activation.mode);
}

test "publication retains leased generations and bounds outstanding replacement" {
    var publisher: publications.Publisher = .{};
    defer shutdown(&publisher);
    try std.testing.expectError(error.NoGeneration, publisher.lease());
    try publisher.publish(try generation(1));
    var old = try publisher.lease();
    try publisher.publish(try generation(2));
    const next = try generation(3);
    try std.testing.expectError(error.PublicationBusy, publisher.publish(next));
    var evaluation = try old.work.slot().begin(.{
        .entries = &.{},
        .coverage = @splat(.complete),
    }, true);
    _ = try evaluation.run(.request_body);
    try std.testing.expectEqualStrings("1", (try old.work.slot().store.get(
        "revision",
        &old.work.slot().budget,
    )).?);
    try std.testing.expectEqual(@as(u64, 1), old.generation().options.revision);
    old.release();
    publisher.publish(next) catch |err| {
        next.deinit();
        return err;
    };
    const metadata = try publisher.snapshot();
    try std.testing.expectEqual(@as(u64, 3), metadata.revision);
    try std.testing.expectEqual(@as(u8, 3), metadata.digest.?[0]);
    try std.testing.expectEqual(@as(u8, 19), metadata.operator_digest.?[0]);
    try std.testing.expect(metadata.reservation > 0);
}

test "failed publication keeps ownership and exhausted slots do not leak pins" {
    var publisher: publications.Publisher = .{};
    defer shutdown(&publisher);
    try publisher.publish(try generation(2));
    const stale = try generation(1);
    defer stale.deinit();
    try std.testing.expectError(error.StaleGenerationRevision, publisher.publish(stale));
    var lease = try publisher.lease();
    try std.testing.expectError(error.PoolBusy, publisher.lease());
    lease.release();
    try publisher.publish(try generation(3));
    try publisher.publish(try generation(4));
    try std.testing.expectEqual(@as(u64, 4), (try publisher.snapshot()).revision);
}

test "disabled publication reserves no pool and shutdown retains acquired work" {
    var publisher: publications.Publisher = .{};
    defer publisher.deinit();
    try publisher.publish(try generations.Generation.create(std.testing.allocator, null, .{
        .revision = 1,
        .activation = .{},
        .observation = .request_metadata,
    }));
    try std.testing.expectError(error.DisabledGeneration, publisher.lease());
    try std.testing.expectEqual(@as(usize, 0), (try publisher.snapshot()).reservation);
    try publisher.publish(try generation(2));
    var lease = try publisher.lease();
    try publisher.close();
    try std.testing.expectError(error.PublicationClosed, publisher.lease());
    try std.testing.expectError(error.PublicationClosed, publisher.snapshot());
    const refused = try generation(3);
    defer refused.deinit();
    try std.testing.expectError(error.PublicationClosed, publisher.publish(refused));
    var evaluation = try lease.work.slot().begin(.{ .entries = &.{} }, true);
    _ = try evaluation.run(.request_body);
    lease.release();
}

fn failCreate(allocator: std.mem.Allocator, prepared: *packages.Package) !void {
    var fixed = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });
    const created = try generations.Generation.create(fixed.allocator(), prepared, .{
        .revision = 1,
        .activation = .{ .mode = .audit },
        .observation = .request_response,
        .limits = limits,
        .slots = 2,
        .reservation = 2 * 1024 * 1024,
    });
    // Return fixture ownership so the failure enumerator can reuse the same package.
    created.package = null;
    created.retire();
    created.deinit();
}

test "failed generation construction releases slots and retains caller package ownership" {
    const prepared = try package(1);
    defer prepared.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, failCreate, .{prepared});
    try std.testing.expect(prepared.bounded.used > 0);
}

const Concurrent = struct {
    publisher: *publications.Publisher,
    ready: std.atomic.Value(u32) = .init(0),
    stopping: std.atomic.Value(bool) = .init(false),
    failures: std.atomic.Value(u32) = .init(0),
    completed: std.atomic.Value(u32) = .init(0),

    fn run(self: *Concurrent) void {
        _ = self.ready.fetchAdd(1, .release);
        while (!self.stopping.load(.acquire)) {
            const metadata = self.publisher.snapshot() catch |err| switch (err) {
                error.PublicationBusy => continue,
                else => unreachable,
            };
            if (metadata.digest.?[0] != metadata.revision)
                _ = self.failures.fetchAdd(1, .monotonic);
            _ = self.completed.fetchAdd(1, .monotonic);
        }
    }
};

test "concurrent metadata readers cannot mix revision and package generations" {
    var publisher: publications.Publisher = .{};
    defer shutdown(&publisher);
    try publisher.publish(try generation(1));
    var concurrent: Concurrent = .{ .publisher = &publisher };
    var threads: [4]std.Thread = undefined;
    var spawned: usize = 0;
    defer {
        concurrent.stopping.store(true, .release);
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Concurrent.run, .{&concurrent});
        spawned += 1;
    }
    while (concurrent.ready.load(.acquire) < threads.len) std.atomic.spinLoopHint();
    for (2..32) |revision| {
        const candidate = try generation(revision);
        while (true) {
            publisher.publish(candidate) catch |err| switch (err) {
                error.PublicationBusy => {
                    std.atomic.spinLoopHint();
                    continue;
                },
                else => {
                    candidate.deinit();
                    return err;
                },
            };
            break;
        }
    }
    try std.testing.expect(concurrent.completed.load(.acquire) > 0);
    try std.testing.expectEqual(@as(u32, 0), concurrent.failures.load(.acquire));
}
