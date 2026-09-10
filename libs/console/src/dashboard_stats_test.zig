const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const Frame = @import("dashboard_stats.zig").Frame;

const fixture = @import("dashboard_fixture.zig").fixture;
const sample = @import("dashboard_fixture.zig").sample;
const publish = @import("dashboard_fixture.zig").publish;

test "dashboard excludes missing stale and skewed nodes and fences contributor changes" {
    var store = try fixture();
    defer store.deinit();
    const frame = try t.allocator.create(Frame);
    defer t.allocator.destroy(frame);
    frame.* = .{};
    var local = sample(1, 10);
    frame.collect(&local, &store, 100);
    try t.expect(frame.scope.available);
    try t.expectEqual(@as(u8, 1), frame.scope.contributing);
    try t.expectEqual(@as(u8, 3), frame.scope.count);
    try t.expect(frame.view(2).value == null);
    const alone = frame.combined.boot;
    var remote = sample(2, 20);
    try publish(&store, &remote, 100);
    frame.collect(&local, &store, 100);
    try t.expectEqual(@as(u64, 30), frame.combined.requests);
    try t.expect(!std.mem.eql(u8, &alone, &frame.combined.boot));
    const both = frame.combined.boot;
    frame.collect(&local, &store, 109);
    try t.expectEqualSlices(u8, &both, &frame.combined.boot);
    frame.collect(&local, &store, 110);
    try t.expectEqual(@as(u64, 10), frame.combined.requests);
    try t.expectEqualSlices(u8, &alone, &frame.combined.boot);
    try t.expect(frame.view(2).scope.stale);
    try t.expectEqual(@as(u64, 20), frame.view(2).value.?.requests);
    remote.timestamp = 103;
    remote.uptime_ms += 1;
    try publish(&store, &remote, 100);
    frame.collect(&local, &store, 100);
    try t.expectEqual(@as(u8, 1), frame.scope.contributing);
    try t.expectEqual(@as(?u64, 3), frame.scope.sources[1].?.clock_skew_seconds);
    try t.expect(frame.view(99).value == null);
}

test "dashboard geography keeps omitted counts uncertainty and destination ownership" {
    var store = try fixture();
    defer store.deinit();
    const frame = try t.allocator.create(Frame);
    defer t.allocator.destroy(frame);
    frame.* = .{};
    var local = sample(1, 10);
    local.countries[0] = .{ .code = 0x5553, .samples = 10 };
    local.other_country_samples = 4;
    local.proxy_mode = .reverse_proxy;
    var remote = sample(2, 20);
    remote.proxy_mode = .forward_auth;
    remote.countries[0] = .{ .code = 0x5553, .samples = 20 };
    remote.other_country_samples = 5;
    remote.unknown_samples = 2;
    remote.server_location = .{ .lat = 1, .lon = 103 };
    remote.incident_geo = .{};
    remote.incident_geo.?.countries[0] = .{ .code = 0x4155, .samples = 3 };
    try publish(&store, &remote, 100);
    frame.collect(&local, &store, 100);
    try t.expectEqual(@as(u64, 30), frame.combined.countries[0].samples);
    try t.expectEqual(@as(u64, 9), frame.scope.traffic_uncertainty);
    try t.expectEqual(@as(u64, 9), frame.combined.other_country_samples);
    try t.expectEqual(@as(u64, 2), frame.combined.unknown_samples);
    try t.expectEqual(@as(u8, 1), frame.scope.incident_contributing);
    try t.expect(frame.combined.proxy_mode == null);
    try t.expect(frame.combined.server_location == null);
    try t.expectEqual(@as(u32, 2), frame.scope.traffic_flows[0].?.node);
    try t.expectEqual(@as(u64, 20), frame.scope.traffic_flows[0].?.samples);
    try t.expect(frame.scope.traffic_flows[1] == null);
    try t.expectEqual(@as(u16, 0x4155), frame.scope.incident_flows[0].?.country);
}

test "dashboard overflow withholds counters and selected browser views cannot become peers" {
    var store = try fixture();
    defer store.deinit();
    const frame = try t.allocator.create(Frame);
    defer t.allocator.destroy(frame);
    frame.* = .{};
    var local = sample(1, std.math.maxInt(u64));
    var remote = sample(2, 1);
    try publish(&store, &remote, 100);
    frame.collect(&local, &store, 100);
    try t.expect(frame.scope.overflow and !frame.scope.available);
    try t.expect(frame.view(null).value == null);
    var bytes: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(frame.view(2), .{}, &writer);
    try t.expectError(error.UnknownField, std.json.parseFromSlice(
        p.StatsSnapshot,
        t.allocator,
        writer.buffered(),
        .{},
    ));
    local.requests = 0;
    local.admitted = 0;
    local.countries[0] = .{ .code = 0x5553, .samples = std.math.maxInt(u64) };
    local.other_country_samples = 1;
    frame.collect(&local, &store, 100);
    try t.expect(frame.scope.overflow);
}

test "maximum dashboard view fits bounded subscribers and preserves counter precision" {
    var store = try @import("dashboard_fixture.zig").configured(8);
    defer store.deinit();
    const frame = try t.allocator.create(Frame);
    defer t.allocator.destroy(frame);
    frame.* = .{};
    var local = try @import("dashboard_fixture.zig").maximum(&store);
    frame.collect(&local, &store, 100);
    try t.expect(frame.scope.available);
    try t.expectEqual(@as(u8, 9), frame.scope.contributing);
    var bytes: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(frame.view(null), .{}, &writer);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer parsed.deinit();
    try t.expectEqualStrings(
        "81064793292668937",
        parsed.value.object.get("requests").?.string,
    );
    const scope = parsed.value.object.get("scope").?.object;
    try t.expectEqual(@as(usize, 9), scope.get("sources").?.array.items.len);
    try t.expectEqual(@as(usize, 16), scope.get("traffic_flows").?.array.items.len);
    try t.expectEqualStrings("9007199254740993", scope.get("traffic_flows").?
        .array.items[0].object.get("samples").?.string);
}

test "cluster rates use source elapsed time and gaps cannot become delayed traffic spikes" {
    var store = try fixture();
    defer store.deinit();
    const frame = try t.allocator.create(Frame);
    defer t.allocator.destroy(frame);
    frame.* = .{};
    var local = sample(1, 10);
    var remote = sample(2, 20);
    try publish(&store, &remote, 100);
    frame.collect(&local, &store, 100);
    try t.expect(frame.scope.request_rate == null);
    local.timestamp = 101;
    local.uptime_ms += 500;
    local.requests += 2;
    remote.timestamp = 101;
    remote.uptime_ms += 1500;
    remote.requests += 3;
    try publish(&store, &remote, 101);
    frame.collect(&local, &store, 101);
    try t.expectEqual(@as(?f64, 6), frame.scope.request_rate);
    local.timestamp = 102;
    local.uptime_ms += 1000;
    local.requests += 2;
    frame.collect(&local, &store, 102);
    try t.expect(frame.scope.request_rate == null);
    local.timestamp = 103;
    local.uptime_ms += 1000;
    remote.timestamp = 103;
    remote.uptime_ms += 2000;
    remote.requests += 100;
    try publish(&store, &remote, 103);
    frame.collect(&local, &store, 103);
    try t.expect(frame.scope.request_rate == null);
}
