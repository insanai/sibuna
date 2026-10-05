//! Shared session-bound worker results. Source selection has one validation
//! contract; reports contain owned scalar metadata and no executable witness.
const std = @import("std");
const p = @import("root.zig");
const m = p.crs_management;
pub const review = @import("crs-protocol").review;
pub const Kind = enum { sample, review };
pub const State = enum { queued, running, complete, failed };
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
            .before = .{ .rules = 4096, .target_exclusions = std.math.maxInt(u32) },
            .after = .{ .rules = 4096, .runtime_exclusions = std.math.maxInt(u32) },
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
