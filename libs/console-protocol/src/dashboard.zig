//! Bounded dashboard coverage. Each source remains distinguishable from the combined view;
//! flow lines describe country aggregates toward declared nodes, never client coordinates.
const std = @import("std");
const p = @import("root.zig");
pub const max_sources = p.nodes.max_members;
pub const max_flows = 16;
pub const Rates = struct {
    requests: f64 = 0,
    admitted: f64 = 0,
    challenged: f64 = 0,
    denied: f64 = 0,
    banned: f64 = 0,
    rate_limited: f64 = 0,
    other: f64 = 0,
    origin_4xx: f64 = 0,
    origin_5xx: f64 = 0,
};

/// Pure interval arithmetic shared by native aggregation and the browser. Every rate
/// uses its own issuer's monotonic denominator; counters from different boots never mix.
pub fn intervalRates(previous: *const p.StatsSnapshot, next: *const p.StatsSnapshot) ?Rates {
    if (previous.outcomes_version != 1 or next.outcomes_version != 1 or
        previous.node != next.node or std.mem.allEqual(u8, &next.boot, 0) or
        !std.mem.eql(u8, &previous.boot, &next.boot) or
        next.timestamp <= previous.timestamp or next.timestamp - previous.timestamp != 1 or
        next.uptime_ms <= previous.uptime_ms) return null;
    const elapsed = next.uptime_ms - previous.uptime_ms;
    if (elapsed > 2000) return null;
    var result: Rates = .{};
    inline for (@typeInfo(Rates).@"struct".fields) |field| {
        const before = @field(previous, field.name);
        const after = @field(next, field.name);
        if (after < before) return null;
        @field(result, field.name) = @as(f64, @floatFromInt(after - before)) * 1000 /
            @as(f64, @floatFromInt(elapsed));
    }
    return result;
}
pub const Source = struct {
    node: u32,
    status: p.nodes.PeerStatus = .unobserved,
    age_seconds: ?u64 = null,
    window_end: ?u64 = null,
    clock_skew_seconds: ?u64 = null,
    resets: u64 = 0,
    contributing: bool = false,
    geoip_available: bool = false,
    incident_geo_available: bool = false,
    proxy_mode: ?p.ProxyMode = null,
    location: ?p.Location = null,

    pub fn jsonStringify(self: Source, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, writer);
    }
};
pub const Flow = struct {
    node: u32,
    country: u16,
    samples: u64,

    pub fn jsonStringify(self: Flow, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, writer);
    }
};
pub const Scope = struct {
    /// Zero selects the aggregate. A node selection can retain its last observation stale.
    selected: u32 = 0,
    available: bool = false,
    stale: bool = false,
    overflow: bool = false,
    /// Replicated minute-history service on the observing console.
    history_available: bool = false,
    count: u8 = 0,
    contributing: u8 = 0,
    incident_contributing: u8 = 0,
    /// Sum of node rates only when every contributing node has a consecutive interval.
    request_rate: ?f64 = null,
    outcome_rates: ?Rates = null,
    /// Source top lists omit some countries. Report a conservative error bound for each
    /// displayed aggregate country; omitted source rows are never assigned a country.
    traffic_uncertainty: u64 = 0,
    incident_uncertainty: u64 = 0,
    sources: [max_sources]?Source = @splat(null),
    traffic_flows: [max_flows]?Flow = @splat(null),
    incident_flows: [max_flows]?Flow = @splat(null),

    pub fn jsonStringify(self: Scope, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, writer);
    }
};

// Counter precision follows the shared browser contract even inside coverage metadata.
fn fields(value: anytype, writer: *std.json.Stringify) std.json.Stringify.Error!void {
    try writer.beginObject();
    inline for (@typeInfo(@TypeOf(value)).@"struct".fields) |field| {
        try writer.objectField(field.name);
        const item = @field(value, field.name);
        if (field.type == u64) {
            try p.writeCounter(writer, item);
        } else if (field.type == ?u64) {
            if (item) |number| try p.writeCounter(writer, number) else try writer.write(null);
        } else try writer.write(item);
    }
    try writer.endObject();
}

/// A browser envelope is deliberately not a peer StatsSnapshot. Strict peer parsing rejects
/// its scope field, even when a single node is selected. No parser-owned slices escape.
pub const View = struct {
    scope: Scope,
    value: ?*const p.StatsSnapshot,

    pub fn jsonStringify(self: View, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        try writer.beginObject();
        try writer.objectField("scope");
        try writer.write(self.scope);
        try writer.objectField("available");
        try writer.write(self.scope.available);
        if (self.value) |value| try value.writeFields(writer);
        try writer.endObject();
    }
};
