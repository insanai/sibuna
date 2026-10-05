//! Private-test samples borrow their decoder owner. Pollable results own scalar
//! metadata and never contain a sample, expanded message or matched value.
const std = @import("std");
const p = @import("root.zig");
const m = p.crs_management;
pub const sample = @import("crs-test-protocol");
pub const Request = struct {
    source: []const u8,
    expected_revision: []const u8,
    mode: ?sample.Mode = null,
    sample: sample.Sample,

    pub fn validate(self: Request) error{InvalidRequest}!void {
        const id = m.Id.init(self.source) catch return error.InvalidRequest;
        if (!m.validId(id) or self.expected_revision.len == 0) return error.InvalidRequest;
        for (self.expected_revision) |byte|
            if (!std.ascii.isDigit(byte)) return error.InvalidRequest;
        const revision = std.fmt.parseInt(u64, self.expected_revision, 10) catch
            return error.InvalidRequest;
        if (revision >= std.math.maxInt(i64)) return error.InvalidRequest;
        self.sample.validate() catch return error.InvalidRequest;
    }
};
pub const State = enum { queued, running, complete, failed };
pub const Status = struct {
    id: m.Id,
    state: State,
    expires: u64,
    source: m.Id = .{},
    expected_revision: u64 = 0,
    artifact: ?p.crs_api.Artifact = null,
    report: ?sample.Report = null,
    diagnostic: ?m.Diagnostic = null,
    failure: ?p.Bytes(64) = null,

    pub fn validate(self: *const Status) error{InvalidResponse}!void {
        if (!m.validId(self.id) or self.expected_revision >= std.math.maxInt(i64))
            return error.InvalidResponse;
        if (self.report) |report| report.validate() catch return error.InvalidResponse;
        if (self.diagnostic) |diagnostic|
            diagnostic.validate() catch return error.InvalidResponse;
        if (self.artifact) |artifact|
            artifact.settings.validate() catch return error.InvalidResponse;
        if (self.state == .complete and (self.artifact == null or self.report == null or
            self.failure != null or !m.validId(self.source))) return error.InvalidResponse;
        if (self.state == .failed and (self.failure == null or self.report != null))
            return error.InvalidResponse;
    }

    pub fn jsonStringify(self: Status, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};
