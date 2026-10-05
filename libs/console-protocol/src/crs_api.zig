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

    pub fn jsonStringify(self: Status, w: *std.json.Stringify) json.Error!void {
        return json.object(self, w);
    }
};
