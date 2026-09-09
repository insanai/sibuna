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
