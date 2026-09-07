const std = @import("std");
const Io = std.Io;

pub const Metrics = struct {
    incidents_persisted: std.atomic.Value(u64) = .init(0),
    incidents_dropped: std.atomic.Value(u64) = .init(0),
    incident_write_failures: std.atomic.Value(u64) = .init(0),
    incident_batches: std.atomic.Value(u64) = .init(0),
    requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    allowed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    denied: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    challenged: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    challenges_issued: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    solutions_accepted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    solutions_rejected: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    rate_limited: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    banned: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    proxied: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    upstream_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    parse_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    overloaded: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn bump(counter: *std.atomic.Value(u64)) void {
        _ = counter.fetchAdd(1, .monotonic);
    }

    pub fn writePrometheus(self: *const Metrics, w: *Io.Writer) !void {
        inline for (std.meta.fields(Metrics)) |field| {
            try w.print(
                "# TYPE sibuna_{s}_total counter\nsibuna_{s}_total {d}\n",
                .{ field.name, field.name, @field(self, field.name).load(.monotonic) },
            );
        }
    }
};
