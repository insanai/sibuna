//! Health probes for explicitly configured peer data-plane listeners. One console-owned
//! thread, sequential probes every five seconds, two-second bound per probe, results copied
//! under a mutex. Nothing here runs on a request thread or reads engine state.
const std = @import("std");
const p = @import("console_protocol");
const net = @import("net");
const Config = @import("config.zig").ConsoleConfig;
pub const max_targets = Config.max_probes;
pub const interval_ms = 5000;
pub const probe_ns = 2 * std.time.ns_per_s;
const response_bytes = 4096;

pub const Target = struct { node: u32, address: std.Io.net.IpAddress, host: p.Bytes(255) };

pub const Probe = struct {
    io: std.Io = undefined,
    targets: [max_targets]Target = undefined,
    count: u8 = 0,
    mutex: std.Io.Mutex = .init,
    results: [max_targets]p.nodes.Probe = undefined,
    requests: [max_targets]u64 = @splat(0),
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    notifier: ?*@import("notifier_job.zig").Job = null,

    pub fn init(self: *Probe, io: std.Io, config: *const Config) !void {
        self.io = io;
        self.count = 0;
        for (config.probes[0..config.probe_count]) |entry| {
            const parsed = try Config.parseProbe(entry.url.slice());
            self.targets[self.count] = .{
                .node = entry.node,
                .address = parsed.address,
                .host = try p.Bytes(255).init(parsed.host),
            };
            self.results[self.count] = .{ .node = entry.node };
            self.count += 1;
        }
    }

    pub fn start(self: *Probe) !void {
        if (self.count == 0) return;
        self.thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, run, .{self});
    }

    pub fn stop(self: *Probe) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        self.thread = null;
    }

    /// Copies current results; `out` receives at most `count` entries.
    pub fn snapshot(self: *Probe, out: *[max_targets]p.nodes.Probe) u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        @memcpy(out[0..self.count], self.results[0..self.count]);
        return self.count;
    }

    fn run(self: *Probe) void {
        while (!self.stopping.load(.acquire)) {
            const started = std.Io.Clock.awake.now(self.io).nanoseconds;
            for (self.targets[0..self.count], 0..) |target, index| {
                if (self.stopping.load(.acquire)) return;
                const observed = self.probeOne(target, index);
                self.mutex.lockUncancelable(self.io);
                const previous = self.results[index].health;
                self.results[index] = observed;
                self.mutex.unlock(self.io);
                if (self.notifier) |job| if (previous == .healthy and observed.health == .down) {
                    var text: [48]u8 = undefined;
                    const detail = std.fmt.bufPrint(&text, "node {d} unreachable", .{
                        target.node,
                    }) catch "";
                    job.raise(.node_unhealthy, observed.observed_at, detail);
                };
            }
            const budget: i96 = interval_ms * std.time.ns_per_ms;
            while (!self.stopping.load(.acquire) and
                std.Io.Clock.awake.now(self.io).nanoseconds - started < budget)
            {
                std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(100), .awake) catch return;
            }
        }
    }

    fn probeOne(self: *Probe, target: Target, index: usize) p.nodes.Probe {
        var result = self.results[index];
        const now = nowSeconds(self.io);
        result.observed_at = now;
        const started = std.Io.Clock.awake.now(self.io).nanoseconds;
        const health = request(self.io, target, "/__sibuna/health") catch {
            result.health = .down;
            return result;
        };
        const elapsed = std.Io.Clock.awake.now(self.io).nanoseconds - started;
        result.latency_ms = @intCast(@max(0, @divTrunc(elapsed, std.time.ns_per_ms)));
        result.health = switch (health.status) {
            200 => .healthy,
            503 => .degraded,
            else => .down,
        };
        if (result.health == .down) return result;
        result.last_seen = now;
        result.draining = health.status == 503;
        if (request(self.io, target, "/__sibuna/metrics")) |metrics| {
            if (counter(metrics.body, "sibuna_requests_total ")) |total| {
                const previous = self.requests[index];
                if (previous != 0 and total >= previous) result.requests = total - previous;
                self.requests[index] = total;
            }
        } else |_| {}
        return result;
    }
};

const Reply = struct { status: u16, body: []const u8 };

/// One bounded HTTP/1.1 GET: connect within the deadline, write the request, read until
/// close or the deadline into a fixed buffer, and parse the status line.
fn request(io: std.Io, target: Target, path: []const u8) !Reply {
    const deadline = std.Io.Clock.awake.now(io).nanoseconds + probe_ns;
    const stream = try net.connect.boundedDeadline(io, target.address, deadline);
    defer stream.close(io);
    var head: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(
        &head,
        "GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n" ++
            "User-Agent: sibuna-console-probe\r\n\r\n",
        .{ path, target.host.slice() },
    );
    try net.connect.writeBounded(io, stream, line, deadline);
    const Static = struct {
        threadlocal var body: [response_bytes]u8 = undefined;
    };
    const length = try net.connect.readBounded(io, stream, &Static.body, deadline);
    const received = Static.body[0..length];
    const parsed = net.proxy.parseResponseHead(received, false) orelse return error.BadReply;
    const split = std.mem.indexOf(u8, received, "\r\n\r\n") orelse return error.BadReply;
    return .{ .status = parsed.status, .body = received[split + 4 ..] };
}

fn counter(body: []const u8, name: []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, name)) continue;
        const value = std.mem.trim(u8, line[name.len..], " \r");
        return std.fmt.parseInt(u64, value, 10) catch null;
    }
    return null;
}

fn nowSeconds(io: std.Io) u64 {
    const ns = std.Io.Clock.real.now(io).nanoseconds;
    return @intCast(@max(0, @divTrunc(ns, std.time.ns_per_s)));
}

test "prometheus counters are located by exact family name" {
    const t = std.testing;
    const body = "# HELP x\nsibuna_requests_total 42\nsibuna_requests_total_other 7\n";
    try t.expectEqual(@as(?u64, 42), counter(body, "sibuna_requests_total "));
    try t.expect(counter(body, "sibuna_denied_total ") == null);
}
