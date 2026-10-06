//! Shared session-bound worker results. Source selection has one validation
//! contract; reports contain owned scalar metadata and no executable witness.
const std = @import("std");
const p = @import("root.zig");
const m = p.crs_management;
pub const review = @import("crs-protocol").review;
pub const Kind = enum { sample, review };
pub const State = enum { queued, running, complete, failed };
pub const ExclusionPage = struct {
    id: m.Id,
    expected_revision: u64,
    expires: u64 = 0,
    page: review.exclusions.Page,

    pub fn validate(self: *const ExclusionPage) error{InvalidResponse}!void {
        if (!m.validId(self.id) or self.expected_revision >= std.math.maxInt(i64) or
            self.expires == 0)
            return error.InvalidResponse;
        self.page.validate() catch return error.InvalidResponse;
    }

    pub fn jsonStringify(
        self: ExclusionPage,
        w: *std.json.Stringify,
    ) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};

test "widest exclusion page fits the HTTP envelope and preserves exact opaque name identity" {
    const t = std.testing;
    const api = review.exclusions;
    const name = api.Text.init(&@as([64 * 1024]u8, @splat(0xff)));
    var output: ExclusionPage = .{
        .id = try m.Id.init("11111111111111111111111111111111"),
        .expected_revision = std.math.maxInt(i64) - 1,
        .expires = std.math.maxInt(u64),
        .page = .{
            .side = .after,
            .total = 4096,
            .offset = 0,
            .count = api.page_capacity,
            .next = api.page_capacity,
        },
    };
    for (&output.page.rows) |*row| row.* = .{
        .rule_id = std.math.maxInt(u32),
        .phase = 5,
        .chain_link = 255,
        .scope = .conditional_target,
        .selector = .tag,
        .tag = name,
        .collection = try p.Bytes(32).init(&@as([32]u8, @splat('x'))),
        .selection = .exact,
        .key = name,
    };
    try output.validate();
    var bytes: [16 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(output, .{}, &writer);
    try t.expect(writer.buffered().len < bytes.len);
    const wire = writer.buffered();
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, wire, .{});
    defer parsed.deinit();
    var decoded: ExclusionPage = undefined;
    try p.json_value.into(&decoded, parsed.value, t.allocator);
    try decoded.validate();
    try t.expectEqualDeep(output, decoded);
    decoded.page.next = 0;
    try t.expectError(error.InvalidResponse, decoded.validate());
}
pub const sample_details = @import("crs-protocol").test_details;
pub const DetailPage = struct {
    pub const Wire = DetailWire;
    id: m.Id,
    expected_revision: u64,
    expires: u64,
    page: sample_details.Page,

    pub fn validate(self: *const DetailPage) error{InvalidResponse}!void {
        if (!m.validId(self.id) or self.expected_revision >= std.math.maxInt(i64) or
            self.expires == 0) return error.InvalidResponse;
        self.page.validate() catch return error.InvalidResponse;
    }

    pub fn jsonStringify(self: DetailPage, w: *std.json.Stringify) !void {
        return @import("json_counters.zig").object(self, w);
    }
};

pub const Source = struct {
    source: []const u8,
    expected_revision: []const u8,

    pub fn validate(self: Source) error{InvalidRequest}!void {
        const id = m.Id.init(self.source) catch return error.InvalidRequest;
        if (!m.validId(id) or self.expected_revision.len == 0) return error.InvalidRequest;
        for (self.expected_revision) |byte|
            if (!std.ascii.isDigit(byte)) return error.InvalidRequest;
        const revision = std.fmt.parseInt(u64, self.expected_revision, 10) catch
            return error.InvalidRequest;
        if (revision >= std.math.maxInt(i64)) return error.InvalidRequest;
    }
};
pub const Status = struct {
    id: m.Id,
    kind: Kind = .sample,
    state: State,
    expires: u64,
    source: m.Id = .{},
    expected_revision: u64 = 0,
    artifact: ?p.crs_api.Artifact = null,
    baseline: ?p.crs_api.Artifact = null,
    report: ?@import("crs-protocol").tests.Report = null,
    comparison: ?review.Report = null,
    diagnostic: ?m.Diagnostic = null,
    failure: ?p.Bytes(64) = null,

    pub fn validate(self: *const Status) error{InvalidResponse}!void {
        if (!m.validId(self.id) or self.expected_revision >= std.math.maxInt(i64))
            return error.InvalidResponse;
        if (self.report) |report| report.validate() catch return error.InvalidResponse;
        if (self.comparison) |report| report.validate() catch return error.InvalidResponse;
        if (self.diagnostic) |diagnostic|
            diagnostic.validate() catch return error.InvalidResponse;
        if (self.artifact) |artifact|
            artifact.settings.validate() catch return error.InvalidResponse;
        if (self.baseline) |artifact|
            artifact.settings.validate() catch return error.InvalidResponse;
        const complete = if (self.kind == .sample)
            self.report != null and self.comparison == null and self.baseline == null
        else
            self.comparison != null and self.report == null;
        if (self.state == .complete and (!complete or self.artifact == null or
            self.failure != null or !m.validId(self.source))) return error.InvalidResponse;
        if (self.state == .complete and self.kind == .review) {
            const report = self.comparison.?;
            if (report.after.rules == 0 or report.after.rules > self.artifact.?.conditions)
                return error.InvalidResponse;
            if (self.baseline) |baseline| {
                if (baseline.revision != self.expected_revision or report.before.rules == 0 or
                    report.before.rules > baseline.conditions) return error.InvalidResponse;
            } else if (self.expected_revision != 0 or report.before.rules != 0)
                return error.InvalidResponse;
        }
        if (self.state == .failed and (self.failure == null or self.report != null or
            self.comparison != null)) return error.InvalidResponse;
    }

    pub fn jsonStringify(self: Status, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};

test "widest rule review fits the shared HTTP envelope and rejects mixed task reports" {
    const t = std.testing;
    const artifact: p.crs_api.Artifact = .{
        .revision = std.math.maxInt(i64) - 1,
        .previous_revision = std.math.maxInt(i64) - 2,
        .release = try p.Bytes(17).init("99999.99999.99999"),
        .source_digest = try p.Bytes(64).init(&@as([64]u8, @splat('f'))),
        .operator_digest = try p.Bytes(64).init(&@as([64]u8, @splat('f'))),
        .conditions = 4096,
        .compiled_peak = std.math.maxInt(u64),
        .settings = .{ .work_budget = 1_000_000_000 },
    };
    var status: Status = .{
        .id = try m.Id.init("11111111111111111111111111111111"),
        .source = try m.Id.init("22222222222222222222222222222222"),
        .kind = .review,
        .state = .complete,
        .expires = std.math.maxInt(u64),
        .expected_revision = artifact.revision,
        .artifact = artifact,
        .baseline = artifact,
        .comparison = .{
            .before = .{ .rules = 4096, .target_exclusions = review.exclusions.capacity },
            .after = .{ .rules = 4096, .runtime_exclusions = review.exclusions.capacity },
            .modified = 4096,
            .count = review.change_capacity,
            .omitted = 4096 - review.change_capacity,
        },
    };
    for (status.comparison.?.changes[0..review.change_capacity], 0..) |*item, index| {
        item.* = .{
            .id = std.math.maxInt(u32) - review.change_capacity + @as(u32, @intCast(index)),
            .kind = .modified,
            .before_phase = 5,
            .after_phase = 5,
            .moved = true,
        };
    }
    try status.validate();
    var bytes: [16 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(status, .{}, &writer);
    try t.expect(writer.buffered().len < bytes.len);
    status.kind = .sample;
    try t.expectError(error.InvalidResponse, status.validate());
    status.kind = .review;
    status.baseline.?.revision -= 1;
    try t.expectError(error.InvalidResponse, status.validate());
}

pub const DetailWire = struct {
    id: m.Id,
    expected_revision: u64,
    expires: u64,
    page: sample_details.Wire,

    pub fn into(self: DetailWire, output: *DetailPage) !void {
        output.id = self.id;
        output.expected_revision = self.expected_revision;
        output.expires = self.expires;
        try self.page.into(&output.page);
        try output.validate();
    }
};

test "widest owned private detail envelope preserves signed values and full revisions" {
    const t = std.testing;
    var output: DetailPage = .{
        .id = try m.Id.init("11111111111111111111111111111111"),
        .expected_revision = std.math.maxInt(i64) - 1,
        .expires = std.math.maxInt(u64),
        .page = .{ .total = 64, .offset = 0, .count = 2, .next = 2 },
    };
    const api = @import("security-evidence").detail;
    for (&output.page.rows) |*row| {
        row.* = .{ .rule_id = std.math.maxInt(u32), .phase = 5 };
        row.*.?.message = api.Preview(96).copy(&@as([65536]u8, @splat(255)));
        row.*.?.tags = @splat(api.Preview(64).copy(&@as([65536]u8, @splat(254))));
        row.*.?.tag_count = 4;
        row.*.?.omitted_tags = 65532;
        row.*.?.score = .{};
        for (&row.*.?.score.?.buckets) |*bucket| bucket.* = .{
            .writes = std.math.maxInt(u32),
            .delta = std.math.minInt(i64),
        };
    }
    try output.validate();
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, output, .{});
    defer t.allocator.free(bytes);
    try t.expect(bytes.len < 16 * 1024);
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, bytes, .{});
    defer parsed.deinit();
    var wire: DetailWire = undefined;
    try p.json_value.into(&wire, parsed.value, t.allocator);
    var decoded: DetailPage = undefined;
    try wire.into(&decoded);
    try t.expectEqualDeep(output, decoded);
}
