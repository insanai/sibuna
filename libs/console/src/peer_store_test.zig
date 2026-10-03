const repeat = @import("text").repeat;
const std = @import("std");
const p = @import("console_protocol");
const peers = @import("peer_store.zig");
const config = @import("peer_config.zig");
const auth = @import("peer_auth.zig");
const t = std.testing;

fn fixture() !peers.Store {
    var options: config.Config = .{ .count = 1 };
    options.targets[0] = .{ .node = 2, .origin = try p.Bytes(255).init("https://peer.test") };
    return peers.Store.init(t.io, options, 1, @splat(7));
}

fn observation(boot: [16]u8, uptime: u64) p.StatsSnapshot {
    return .{
        .node = 2,
        .boot = boot,
        .outcomes_version = 1,
        .uptime_ms = uptime,
        .requests = uptime,
        .admitted = uptime,
        .challenged = 0,
        .denied = 0,
        .origin_4xx = 0,
        .origin_5xx = 0,
        .incidents = 0,
        .incidents_dropped = 0,
        .sample_loss = 0,
        .unknown_samples = 0,
        .timestamp = 100,
    };
}

test "peer observations fence old connections and deduplicate node, boot, sequence and interval" {
    var store = try fixture();
    defer store.deinit();
    const first = try store.activate(0, @splat(1));
    var value = observation(first.boot, 1000);
    var ratio = "1/64".*;
    value.sample_probability = &ratio;
    var copied: [config.max_peers]peers.Observation = undefined;
    var update: peers.Update = .{
        .value = &value,
        .watermark = 1,
        .sequence = 2,
        .received_at = 100,
    };
    try t.expect(try store.publish(first, update));
    ratio[0] = '2';
    _ = store.snapshot(&copied);
    try t.expectEqualStrings("1/64", copied[0].value.sample_probability);
    value.sample_probability = "1/64";
    try t.expect(!try store.publish(first, update));
    value.uptime_ms = 2000;
    update.sequence = 3;
    try t.expect(!try store.publish(first, update));
    update.watermark = 2;
    try t.expect(try store.publish(first, update));
    value.uptime_ms = 3000;
    update.watermark = 3;
    update.sequence = 2;
    try t.expect(!try store.publish(first, update));
    const reconnected = try store.activate(0, first.boot);
    try t.expect(try store.publish(reconnected, update));
    update.watermark = 4;
    update.sequence = 4;
    try t.expect(!try store.publish(first, update));
    const restarted = try store.activate(0, @splat(2));
    value = observation(restarted.boot, 100);
    update.watermark = 1;
    update.sequence = 2;
    try t.expect(try store.publish(restarted, update));
    try t.expect(!try store.publish(reconnected, update));
    try t.expectEqual(@as(u8, 1), store.snapshot(&copied));
    try t.expectEqual(@as(u64, 1), copied[0].resets);
    try t.expectEqual(@as(u64, 100), copied[0].value.uptime_ms);
    store.failed(0, false);
    _ = store.snapshot(&copied);
    try t.expectEqual(.stale, copied[0].status);
    try t.expectEqual(@as(u64, 100), copied[0].value.uptime_ms);
    value.node = 3;
    try t.expectError(error.InvalidObservation, store.publish(restarted, update));
    store.stop();
    try t.expectError(error.Stopping, store.activate(0, @splat(3)));
}

test "peer admission is membership-bound, replay-safe and limited to one inbound link per node" {
    var store = try fixture();
    defer store.deinit();
    const request: auth.Request = .{
        .from = 2,
        .to = 1,
        .timestamp = 100,
        .nonce = @splat(0),
        .websocket_key = @splat(0),
    };
    const proof = auth.requestProof(store.key.?, request);
    const index = try store.admit(request, proof, 100);
    try t.expectError(error.DuplicateConnection, store.admit(request, proof, 100));
    store.release(index);
    try t.expectError(error.Replay, store.admit(request, proof, 100));
    var unknown = request;
    unknown.from = 3;
    try t.expectError(error.UnknownPeer, store.admit(
        unknown,
        auth.requestProof(store.key.?, unknown),
        100,
    ));
    var wrong_target = request;
    wrong_target.to = 3;
    try t.expectError(error.InvalidIdentity, store.admit(
        wrong_target,
        auth.requestProof(store.key.?, wrong_target),
        100,
    ));
}

test "peer reports preserve unavailable values, boot text, exact counters and stale age" {
    var store = try fixture();
    defer store.deinit();
    var reports: [config.max_peers]peers.Report = undefined;
    try t.expectEqual(@as(u8, 1), store.reports(100, &reports));
    try t.expect(reports[0].requests == null and reports[0].age_seconds == null);
    const handle = try store.activate(0, @splat(1));
    const value = observation(handle.boot, 9007199254740993);
    try t.expect(try store.publish(handle, .{
        .value = &value,
        .watermark = 1,
        .sequence = 2,
        .received_at = 103,
    }));
    _ = store.reports(113, &reports);
    try t.expectEqual(.stale, reports[0].status);
    try t.expectEqual(@as(?u64, 10), reports[0].age_seconds);
    try t.expectEqual(@as(?u64, 3), reports[0].clock_skew_seconds);
    var bytes: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(reports[0], .{}, &writer);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer parsed.deinit();
    try t.expectEqualStrings(&repeat("01", 16), parsed.value.object.get("boot").?.string);
    try t.expectEqualStrings("9007199254740993", parsed.value.object.get("requests").?.string);
}

test "peer geography accepts packed publisher codes and rejects invalid or duplicated rows" {
    var store = try fixture();
    defer store.deinit();
    const handle = try store.activate(0, @splat(1));
    var value = observation(handle.boot, 1000);
    value.countries[0] = .{ .code = 0x5553, .samples = 3 };
    value.countries[1] = .{ .code = 0x4155, .samples = 2 };
    value.incident_geo = .{};
    value.incident_geo.?.countries[0] = .{ .code = 0x4742, .samples = 1 };
    const update: peers.Update = .{
        .value = &value,
        .watermark = 1,
        .sequence = 2,
        .received_at = 100,
    };
    try t.expect(try store.publish(handle, update));
    for ([_]u16{ 0, 675, 0x4141, 0x7573, 0x5a5a, 0x4155 }) |invalid| {
        value.countries[0].code = invalid;
        try t.expectError(error.InvalidObservation, store.publish(handle, update));
    }
    value.countries[0].code = 0x5553;
    value.incident_geo.?.version = 2;
    try t.expectError(error.InvalidObservation, store.publish(handle, update));
    value.incident_geo.?.version = 1;
    value.incident_geo.?.countries[0].code = 675;
    try t.expectError(error.InvalidObservation, store.publish(handle, update));
    var copied: [config.max_peers]peers.Observation = undefined;
    _ = store.snapshot(&copied);
    try t.expectEqual(@as(u16, 0x5553), copied[0].value.countries[0].code);
    try t.expectEqual(@as(u16, 0x4742), copied[0].value.incident_geo.?.countries[0].code);
}

test "authenticated reconnects keep retained observations stale until a new sample" {
    var store = try fixture();
    defer store.deinit();
    const first = try store.activate(0, @splat(1));
    var value = observation(first.boot, 1000);
    try t.expect(try store.publish(first, .{
        .value = &value,
        .watermark = 1,
        .sequence = 1,
        .received_at = 100,
    }));
    const replacement = try store.activate(0, first.boot);
    var reports: [config.max_peers]peers.Report = undefined;
    _ = store.reports(111, &reports);
    try t.expectEqual(.stale, reports[0].status);
    try t.expectEqual(@as(?u64, 1000), reports[0].requests);
    try t.expectEqual(@as(?u64, 11), reports[0].age_seconds);
    var snapshots: [config.max_peers]peers.Observation = undefined;
    _ = store.snapshot(&snapshots);
    try t.expectEqual(.stale, snapshots[0].status);
    value.uptime_ms = 2000;
    try t.expect(try store.publish(replacement, .{
        .value = &value,
        .watermark = 2,
        .sequence = 1,
        .received_at = 112,
    }));
    _ = store.reports(112, &reports);
    try t.expectEqual(.current, reports[0].status);
    try t.expectEqual(@as(?u64, 0), reports[0].age_seconds);
}
