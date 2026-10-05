//! Public management views omit signed source and internal verification messages.
const std = @import("std");
const p = @import("root.zig");
const m = p.crs_management;
const json = @import("json_counters.zig");
pub const Stage = m.Stage;
pub const editor_bytes = 64 * 1024;
pub const body_bytes = 6 * editor_bytes + 4096;
pub const Artifact = struct {
    revision: u64,
    previous_revision: u64,
    release: p.Bytes(17),
    source_digest: p.Bytes(64),
    operator_digest: p.Bytes(64),
    conditions: u32,
    compiled_peak: u64,
    settings: m.Settings,

    pub fn jsonStringify(self: Artifact, w: *std.json.Stringify) json.Error!void {
        return json.object(self, w);
    }
};
pub const Candidate = struct {
    id: m.Id,
    kind: m.Kind,
    state: m.State,
    expected_revision: u64,
    created_at: u64,
    expires: u64,
    verified_at: ?u64,
    completed_at: ?u64,
    reason: m.Reason,

    artifact: ?Artifact,

    pub fn jsonStringify(self: Candidate, w: *std.json.Stringify) json.Error!void {
        return json.object(self, w);
    }
};
pub const Status = struct {
    available: bool,
    next_id: m.Id,
    revision: u64,
    selected_at: u64,
    current: ?Candidate,
    previous: ?Candidate,
    candidates: [m.candidate_capacity]?Candidate = @splat(null),
    count: usize = 0,
    nodes: [p.nodes.max_members]?m.Node = @splat(null),
    node_count: usize = 0,
    local: p.crs.Status,
    job: m.Id,
    stage: Stage,
    reason: m.Reason,

    pub fn validate(self: *const Status) error{InvalidResponse}!void {
        if (self.count > self.candidates.len or self.node_count > self.nodes.len or
            !m.validId(self.next_id)) return error.InvalidResponse;
        if (self.current) |current| {
            const artifact = current.artifact orelse return error.InvalidResponse;
            if (current.state != .selected or artifact.revision != self.revision)
                return error.InvalidResponse;
            artifact.settings.validate() catch return error.InvalidResponse;
        } else if (self.revision != 0) return error.InvalidResponse;
        if (self.previous) |previous| {
            const artifact = previous.artifact orelse return error.InvalidResponse;
            if (previous.state != .selected or artifact.revision >= self.revision)
                return error.InvalidResponse;
            artifact.settings.validate() catch return error.InvalidResponse;
        }
        for (self.candidates[0..self.count]) |row| {
            const candidate = row orelse return error.InvalidResponse;
            if (!m.validId(candidate.id)) return error.InvalidResponse;
            if (candidate.artifact) |artifact|
                artifact.settings.validate() catch return error.InvalidResponse;
        }
        if (self.local.selection) |local| local.validate() catch return error.InvalidResponse;
    }

    pub fn jsonStringify(self: Status, w: *std.json.Stringify) json.Error!void {
        return json.object(self, w);
    }
};

test "CRS clients reject missing candidates, invalid IDs and unbounded views" {
    const t = std.testing;
    var status: Status = .{
        .available = true,
        .next_id = try m.Id.init("11111111111111111111111111111111"),
        .revision = 0,
        .selected_at = 0,
        .current = null,
        .previous = null,
        .local = .{},
        .job = .{},
        .stage = .idle,
        .reason = .none,
    };
    try status.validate();
    status.count = 1;
    try t.expectError(error.InvalidResponse, status.validate());
    status.count = m.candidate_capacity + 1;
    try t.expectError(error.InvalidResponse, status.validate());
    status.count = 0;
    status.node_count = p.nodes.max_members + 1;
    try t.expectError(error.InvalidResponse, status.validate());
    status.node_count = 0;
    status.next_id = .{};
    try t.expectError(error.InvalidResponse, status.validate());
}
