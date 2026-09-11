//! Dashboard arithmetic uses copied local-only observations. Missing, stale and skewed
//! sources never become healthy zeroes; aggregate overflow makes the view unavailable.
const std = @import("std");
const p = @import("console_protocol");
const d = p.dashboard;
const peers = @import("peer_store.zig");
const country = @import("geoip").country;
pub const Error = error{ Overflow, InvalidSource };
const counters = [_][]const u8{
    "requests",        "admitted",       "challenged",               "denied",
    "banned",          "rate_limited",   "other",                    "origin_4xx",
    "origin_5xx",      "incidents",      "incidents_dropped",        "sample_loss",
    "expired_samples", "future_samples", "geo_maintenance_failures", "unknown_samples",
};

pub const Frame = struct {
    values: [d.max_sources]p.StatsSnapshot = undefined,
    present: [d.max_sources]bool = @splat(false),
    active: [d.max_sources]bool = @splat(false),
    rates: [d.max_sources]?d.Rates = @splat(null),
    observations: [8]peers.Observation = undefined,
    scope: d.Scope = .{},
    initialized: bool = false,
    combined: p.StatsSnapshot = undefined,
    traffic: [676]u64 = @splat(0),
    incidents: [676]u64 = @splat(0),
    traffic_total: u64 = 0,
    incident_total: u64 = 0,

    /// The composing feeder owns Frame. No pointer to a peer slot survives its mutex.
    pub fn collect(
        self: *Frame,
        local: *const p.StatsSnapshot,
        store: *peers.Store,
        now: u64,
    ) void {
        self.initialized = true;
        self.scope = .{ .count = 1, .history_available = local.minute_history.available };
        self.record(0, local, true);
        self.scope.sources[0] = .{
            .node = local.node,
            .status = .current,
            .age_seconds = 0,
            .window_end = local.timestamp,
            .clock_skew_seconds = 0,
            .contributing = true,
            .geoip_available = local.geoip_available,
            .incident_geo_available = local.incident_geo != null,
            .proxy_mode = local.proxy_mode,
            .location = local.server_location,
        };
        const count = store.snapshot(&self.observations);
        self.scope.count += count;
        for (self.observations[0..count], 0..) |*observation, index|
            self.source(index + 1, store.config.targets[index].node, observation, now);
        self.combine(local) catch |err| {
            self.scope.available = false;
            self.scope.overflow = err == error.Overflow;
            return;
        };
        self.scope.available = true;
    }

    /// Selection copies only small coverage metadata; source snapshots remain feeder-owned.
    pub fn view(self: *const Frame, node: ?u32) d.View {
        var scope = self.scope;
        scope.selected = node orelse 0;
        if (node == null and scope.count == 1) return self.view(self.values[0].node);
        if (node == null) return .{
            .scope = scope,
            .value = if (scope.available) &self.combined else null,
        };
        scope.available = false;
        scope.overflow = false;
        scope.traffic_flows = @splat(null);
        scope.incident_flows = @splat(null);
        scope.traffic_uncertainty = 0;
        scope.incident_uncertainty = 0;
        for (scope.sources[0..scope.count], 0..) |entry, index| {
            const info = entry.?;
            if (info.node != node.? or !self.present[index]) continue;
            scope.available = true;
            scope.stale = !info.contributing;
            scope.outcome_rates = if (info.contributing) self.rates[index] else null;
            scope.request_rate = if (scope.outcome_rates) |rates| rates.requests else null;
            return .{ .scope = scope, .value = &self.values[index] };
        }
        return .{ .scope = scope, .value = null };
    }

    fn source(
        self: *Frame,
        index: usize,
        node: u32,
        sample: *const peers.Observation,
        now: u64,
    ) void {
        var info: d.Source = .{ .node = node, .status = sample.status, .resets = sample.resets };
        if (sample.has_value) {
            const value = &sample.value;
            info.age_seconds = now -| sample.received_at;
            info.window_end = value.timestamp;
            info.clock_skew_seconds = @max(
                value.timestamp -| sample.received_at,
                sample.received_at -| value.timestamp,
            );
            if (info.status == .current and (info.age_seconds.? >= 10 or now < sample.received_at))
                info.status = .stale;
            info.contributing = info.status == .current and info.clock_skew_seconds.? <= 2;
            info.geoip_available = value.geoip_available;
            info.incident_geo_available = value.incident_geo != null;
            info.proxy_mode = value.proxy_mode;
            info.location = value.server_location;
            self.record(index, value, info.contributing);
        } else {
            self.present[index] = false;
            self.active[index] = false;
            self.rates[index] = null;
        }
        self.scope.sources[index] = info;
    }

    fn record(self: *Frame, index: usize, value: *const p.StatsSnapshot, active: bool) void {
        self.rates[index] = if (self.present[index] and self.active[index] and active)
            d.intervalRates(&self.values[index], value)
        else
            null;
        self.values[index] = value.*;
        self.present[index] = true;
        self.active[index] = active;
    }

    fn combine(self: *Frame, local: *const p.StatsSnapshot) Error!void {
        self.combined = local.*;
        self.combined.node = 0;
        self.combined.server_location = null;
        self.combined.minute_history = .{};
        self.combined.incident_geo = .{};
        self.combined.geoip_available = false;
        self.combined.geoip_attribution = false;
        self.combined.retention_failures = 0;
        self.combined.active_bans = 0;
        self.combined.rss_kib = null;
        self.combined.cpu_permille = null;
        self.combined.other_country_samples = 0;
        inline for (counters) |name| @field(self.combined, name) = 0;
        self.traffic = @splat(0);
        self.incidents = @splat(0);
        self.traffic_total = 0;
        self.incident_total = 0;
        self.scope.outcome_rates = .{};
        self.scope.request_rate = 0;
        var identity = std.crypto.hash.sha2.Sha256.init(.{});
        identity.update("sibuna-dashboard-contributors-v1");
        // Bind the observer too: equal peer sets on different consoles are separate clocks.
        identity.update(&local.boot);
        for (self.scope.sources[0..self.scope.count], 0..) |entry, index| {
            const info = entry.?;
            if (!info.contributing) continue;
            const value = &self.values[index];
            if (value.node != info.node or value.outcomes_version != 1)
                return error.InvalidSource;
            var node: [4]u8 = undefined;
            std.mem.writeInt(u32, &node, info.node, .big);
            identity.update(&node);
            identity.update(&value.boot);
            if (self.scope.outcome_rates) |*rates| {
                if (self.rates[index]) |amount| {
                    inline for (@typeInfo(d.Rates).@"struct".fields) |field|
                        @field(rates, field.name) += @field(amount, field.name);
                } else self.scope.outcome_rates = null;
            }
            try self.add(value);
            self.scope.contributing += 1;
        }
        self.scope.request_rate = if (self.scope.outcome_rates) |rates| rates.requests else null;
        var digest: [32]u8 = undefined;
        identity.final(&digest);
        self.combined.boot = digest[0..16].*;
        const traffic = @import("stats.zig").rank(&self.traffic);
        self.combined.countries = traffic.top;
        try sum(&self.combined.other_country_samples, traffic.other);
        if (self.scope.incident_contributing == 0) {
            self.combined.incident_geo = null;
            return;
        }
        const incidents = @import("stats.zig").rank(&self.incidents);
        self.combined.incident_geo.?.countries = incidents.top;
        try sum(&self.combined.incident_geo.?.other, incidents.other);
    }

    fn add(self: *Frame, value: *const p.StatsSnapshot) Error!void {
        inline for (counters) |name| try sum(&@field(self.combined, name), @field(value, name));
        if (self.combined.proxy_mode != value.proxy_mode) self.combined.proxy_mode = null;
        self.combined.geoip_available = self.combined.geoip_available or value.geoip_available;
        self.combined.geoip_attribution = self.combined.geoip_attribution or
            value.geoip_attribution;
        if (self.combined.retention_failures) |*total| {
            if (value.retention_failures) |count| {
                try sum(total, count);
            } else self.combined.retention_failures = null;
        }
        if (self.combined.active_bans) |*total| {
            if (value.active_bans) |count| {
                try sum(total, count);
            } else self.combined.active_bans = null;
        }
        try sum(&self.combined.other_country_samples, value.other_country_samples);
        try sum(&self.scope.traffic_uncertainty, value.other_country_samples);
        try sum(&self.traffic_total, value.other_country_samples);
        try sum(&self.traffic_total, value.unknown_samples);
        try addCountries(&self.traffic, &self.traffic_total, &value.countries);
        flows(&self.scope.traffic_flows, value.node, value.server_location, &value.countries);
        if (value.incident_geo) |*recorded| {
            self.scope.incident_contributing += 1;
            try sum(&self.incident_total, recorded.other);
            try sum(&self.incident_total, recorded.unknown);
            const out = &self.combined.incident_geo.?;
            out.started_at = @max(out.started_at, recorded.started_at);
            inline for (.{ "other", "unknown", "dropped", "expired", "future" }) |name|
                try sum(&@field(out, name), @field(recorded, name));
            try sum(&self.scope.incident_uncertainty, recorded.other);
            try addCountries(&self.incidents, &self.incident_total, &recorded.countries);
            flows(
                &self.scope.incident_flows,
                value.node,
                value.server_location,
                &recorded.countries,
            );
        }
    }
};

fn sum(total: *u64, amount: u64) Error!void {
    const result = @addWithOverflow(total.*, amount);
    if (result[1] != 0) return error.Overflow;
    total.* = result[0];
}

fn addCountries(counts: *[676]u64, total: *u64, rows: *const [32]p.CountryCount) Error!void {
    for (rows) |row| {
        if (row.samples == 0) continue;
        const code = [2]u8{ @truncate(row.code >> 8), @truncate(row.code) };
        const index = country.index(code) orelse return error.InvalidSource;
        try sum(total, row.samples);
        try sum(&counts[index], row.samples);
    }
}

fn flows(
    output: *[d.max_flows]?d.Flow,
    node: u32,
    location: ?p.Location,
    rows: *const [32]p.CountryCount,
) void {
    if (location == null) return;
    for (rows) |row| {
        if (row.samples == 0) continue;
        var next: ?d.Flow = .{ .node = node, .country = row.code, .samples = row.samples };
        for (output) |*item| {
            if (item.* == null or next.?.samples > item.*.?.samples)
                std.mem.swap(?d.Flow, item, &next);
            if (next == null) break;
        }
    }
}
