//! Boot-local coverage, charged once after the final phase and before lease release.
const std = @import("std");
const crs = @import("crs");
pub const Counters = struct {
    inspected: std.atomic.Value(u64) = .init(0),
    headers: std.atomic.Value(u64) = .init(0),
    handshake: std.atomic.Value(u64) = .init(0),
    streaming: std.atomic.Value(u64) = .init(0),
    incomplete: std.atomic.Value(u64) = .init(0),
    denied: std.atomic.Value(u64) = .init(0),
    would_deny: std.atomic.Value(u64) = .init(0),

    /// Internal metrics route uses caller-owned output; request instrumentation
    /// itself performs atomic increments and never formats or allocates.
    pub fn writePrometheus(self: *const Counters, writer: *std.Io.Writer) !void {
        inline for (@typeInfo(Counters).@"struct".field_names) |name| {
            try writer.print("# TYPE sibuna_crs_{s}_total counter\n" ++
                "sibuna_crs_{s}_total {d}\n", .{
                name, name, @field(self, name).load(.monotonic),
            });
        }
    }

    pub fn finish(self: *Counters, transaction: *const crs.http_transaction.Transaction) void {
        const state = &transaction.slot.state;
        if (state.denied) increment(&self.denied);
        if (state.would_deny and !state.enforce) increment(&self.would_deny);
        if (state.failed or transaction.end == null) {
            increment(&self.incomplete);
            return;
        }
        switch (transaction.end.?) {
            .inspected => increment(&self.inspected),
            .headers_profile => increment(&self.headers),
            .handshake_only => increment(&self.handshake),
            .streaming_excluded => increment(&self.streaming),
            .local_response, .origin_unavailable => {},
        }
    }
};

pub fn increment(value: *std.atomic.Value(u64)) void {
    _ = value.fetchAdd(1, .monotonic);
}
