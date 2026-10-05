//! Retained editor text is private operator configuration, erased on leaving the
//! page and on session reset. JSON event bytes never become retained references.
const std = @import("std");
const p = @import("console_protocol");
pub const Kind = enum {
    idle,
    status,
    configuration,
    prepare,
    select,
    discard,
    test_submit,
    test_read,
    review_submit,
    review_read,
};
pub const Model = struct {
    snapshot: ?p.crs_api.Status = null,
    editor: p.Bytes(p.crs_api.editor_bytes) = .{},
    editor_revision: u64 = 0,
    editor_loaded: bool = false,
    reviewed: ?p.crs_api.Candidate = null,
    review_job: ?p.crs_management.Id = null,
    review_result: ?p.crs_tasks.Status = null,
    test_id: ?p.crs_management.Id = null,
    test_result: ?p.crs_tests.Status = null,
    ticket: p.Bytes(48) = .{},
    busy: Kind = .idle,
    attempted_at: u64 = 0,
    received_at: u64 = 0,
    stale: bool = true,

    pub fn clear(self: *Model) void {
        self.snapshot = null;
        self.editor_revision = 0;
        self.editor_loaded = false;
        self.reviewed = null;
        self.review_job = null;
        self.review_result = null;
        self.test_id = null;
        self.test_result = null;
        self.ticket = .{};
        self.busy = .idle;
        self.attempted_at = 0;
        self.received_at = 0;
        self.stale = true;
        std.crypto.secureZero(u8, &self.editor.data);
        self.editor.len = 0;
    }

    pub fn accept(self: *Model, value: std.json.Value, alloc: std.mem.Allocator) !void {
        var observed: p.crs_api.Status = undefined;
        try @import("json_value.zig").into(&observed, value, alloc);
        try observed.validate();
        if (self.snapshot) |previous| {
            if (previous.revision != observed.revision) self.reviewed = null;
        }
        if (self.reviewed) |reviewed| {
            var present = false;
            for (observed.candidates[0..observed.count]) |row| {
                const candidate = row.?;
                if (std.mem.eql(u8, candidate.id.slice(), reviewed.id.slice()) and
                    candidate.state == .verified) present = true;
            }
            if (!present) self.reviewed = null;
        }
        self.snapshot = observed;
        self.stale = false;
        if (self.reviewed == null) {
            self.review_job = null;
            self.review_result = null;
        }
    }

    pub fn reviewPending(self: *const Model) bool {
        if (self.review_job == null) return false;
        const result = self.review_result orelse return true;
        return result.state == .queued or result.state == .running;
    }

    pub fn reviewReady(self: *const Model) bool {
        const snapshot = self.snapshot orelse return false;
        const candidate = self.reviewed orelse return false;
        const result = self.review_result orelse return false;
        const artifact = result.artifact orelse return false;
        const expected = candidate.artifact orelse return false;
        if (snapshot.current) |current| {
            const baseline = result.baseline orelse return false;
            const saved = current.artifact orelse return false;
            if (baseline.revision != snapshot.revision or !sameArtifact(baseline, saved))
                return false;
        } else if (result.baseline != null) return false;
        return !self.stale and result.kind == .review and result.state == .complete and
            result.comparison != null and result.expected_revision == snapshot.revision and
            std.mem.eql(u8, result.source.slice(), candidate.id.slice()) and
            sameArtifact(artifact, expected);
    }
};

fn sameArtifact(left: p.crs_api.Artifact, right: p.crs_api.Artifact) bool {
    return left.revision == right.revision and
        std.mem.eql(u8, left.release.slice(), right.release.slice()) and
        std.mem.eql(u8, left.source_digest.slice(), right.source_digest.slice()) and
        std.mem.eql(u8, left.operator_digest.slice(), right.operator_digest.slice()) and
        std.meta.eql(left.settings, right.settings);
}
