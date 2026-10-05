//! Owned management messages. Candidate verification, durable selection and a
//! node's local publication are distinct facts; no program pointer crosses here.
const std = @import("std");
const p = @import("root.zig");
pub const Diagnostic = @import("text").source_diagnostic.Diagnostic;
pub const Id = p.Bytes(32);
pub const Manifest = p.Bytes(512);
pub const chunk_bytes = 2048;
pub const candidate_capacity = 4;
pub const preparation_seconds = 300;
pub const review_seconds = 86400;
pub const Kind = enum { check, update, mode, rollback };
pub const State = enum { preparing, verified, selected, failed, canceled, retired };
pub const Stage = enum(u8) { idle, preparing, storing, verified, failed };
pub const Reason = enum {
    none,
    canceled,
    download,
    signature,
    incompatible,
    capacity,
    publication,
    storage,
};
pub const File = enum { archive, signature, configuration };
pub const Settings = struct {
    mode: p.crs.Mode = .audit,
    profile: p.crs.Profile = .full,
    blocking_paranoia: u8 = 1,
    detection_paranoia: u8 = 1,
    inbound_threshold: u16 = 5,
    outbound_threshold: u16 = 4,
    request_bytes: u32 = 4 * 1024 * 1024,
    response_bytes: u32 = 1024 * 1024,
    work_budget: u64 = 16_000_000,
    slots: u8 = 8,
    reservation: u64 = 1024 * 1024 * 1024,

    pub fn jsonStringify(self: Settings, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }

    pub fn validate(self: Settings) error{InvalidLimit}!void {
        if (self.blocking_paranoia < 1 or self.blocking_paranoia > 4 or
            self.detection_paranoia < self.blocking_paranoia or self.detection_paranoia > 4 or
            self.inbound_threshold == 0 or self.outbound_threshold == 0 or
            self.request_bytes == 0 or self.request_bytes > 64 * 1024 * 1024 or
            self.response_bytes == 0 or self.response_bytes > 64 * 1024 * 1024 or
            self.work_budget == 0 or self.work_budget > 1_000_000_000 or
            self.slots == 0 or self.slots > 31 or self.reservation == 0 or
            self.reservation > std.math.maxInt(u32)) return error.InvalidLimit;
    }
};
pub const Job = struct {
    id: Id,
    kind: Kind,
    state: State,
    expected_revision: u64,
    created_at: u64,
    expires: u64,
    verified_at: ?u64 = null,
    completed_at: ?u64 = null,
    manifest: Manifest = .{},
    reason: Reason = .none,
    diagnostic: ?Diagnostic = null,
};
pub const Jobs = struct {
    rows: [candidate_capacity]?Job = @splat(null),
    count: usize = 0,
};
pub const Selection = struct {
    revision: u64 = 0,
    selected_at: u64 = 0,
    current: ?Job = null,
    previous: ?Job = null,
};
pub const Begin = struct {
    auth: p.users.Auth,
    id: Id,
    kind: Kind,
    expected_revision: u64,
    expires: u64,
    /// Mode changes and rollbacks copy an immutable retained source, not an
    /// operator-supplied filesystem path or an unverified package identifier.
    clone: ?Id = null,
};
pub const Read = struct { auth: p.users.Auth, id: Id };
pub const SourceWrite = struct {
    id: Id,
    file: File,
    ordinal: u32,
    bytes: p.Bytes(chunk_bytes),
};
pub const Startup = struct { id: Id, manifest: Manifest };
pub const Chunk = struct {
    auth: p.users.Auth,
    id: Id,
    file: File,
    ordinal: u32,
    bytes: p.Bytes(chunk_bytes),
};
pub const Verify = struct { auth: p.users.Auth, id: Id, manifest: Manifest };
pub const Select = struct { auth: p.users.Auth, id: Id, expected_revision: u64 };
pub const Source = struct { id: Id, file: File, ordinal: u32 };
pub const Failed = struct { id: Id, reason: Reason, diagnostic: ?Diagnostic = null };
pub const Applied = struct {
    revision: u64,
    applied: bool,
    reason: Reason = .none,
};
pub const Node = struct {
    node: u32 = 0,
    boot: Id = .{},
    revision: u64 = 0,
    applied: bool = false,
    reason: Reason = .none,
    observed_at: u64 = 0,

    pub fn jsonStringify(self: Node, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};
pub const Nodes = struct {
    rows: [p.nodes.max_members]Node = @splat(.{}),
    count: usize = 0,
};
pub const Request = union(enum) {
    status: p.users.Auth,
    job: Read,
    jobs: p.users.Auth,
    begin: Begin,
    chunk: Chunk,
    verify: Verify,
    select: Select,
    discard: Read,
    // These are daemon service operations, never decoded from an HTTP body.
    selected,
    maintenance,
    startup_begin: Startup,
    startup_chunk: SourceWrite,
    startup_commit: Id,
    source: Source,
    failed: Failed,
    applied: Applied,
    nodes: p.users.Auth,
};

pub fn validId(id: Id) bool {
    if (id.len != 32) return false;
    var nonzero = false;
    for (id.slice()) |byte| {
        if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return false;
        nonzero = nonzero or byte != '0';
    }
    return nonzero;
}

pub fn fileLimit(file: File) usize {
    return switch (file) {
        .archive => 8 * 1024 * 1024,
        .signature => 16 * 1024,
        .configuration => 64 * 1024,
    };
}

pub fn validate(request: Request) error{InvalidLimit}!void {
    switch (request) {
        .begin => |input| {
            if (!validId(input.id) or input.expected_revision >= std.math.maxInt(i64) or
                input.expires > std.math.maxInt(i64)) return error.InvalidLimit;
            if (input.clone) |id| if (!validId(id) or
                std.mem.eql(u8, id.slice(), input.id.slice())) return error.InvalidLimit;
            if ((input.kind == .mode or input.kind == .rollback) != (input.clone != null))
                return error.InvalidLimit;
        },
        inline .chunk, .startup_chunk => |input| {
            if (!validId(input.id) or input.bytes.len == 0 or input.bytes.len > chunk_bytes or
                input.ordinal >= fileLimit(input.file) / chunk_bytes) return error.InvalidLimit;
        },
        inline .verify, .startup_begin => |input| if (!validId(input.id) or
            input.manifest.len == 0 or
            input.manifest.len > Manifest.byte_capacity) return error.InvalidLimit,
        .select => |input| if (!validId(input.id) or
            input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit,
        .startup_commit => |id| if (!validId(id)) return error.InvalidLimit,
        .job, .discard => |input| if (!validId(input.id)) return error.InvalidLimit,
        .source => |input| if (!validId(input.id) or
            input.ordinal >= fileLimit(input.file) / chunk_bytes) return error.InvalidLimit,
        .failed => |input| {
            if (!validId(input.id) or input.reason == .none) return error.InvalidLimit;
            if (input.diagnostic) |diagnostic|
                diagnostic.validate() catch return error.InvalidLimit;
        },
        .applied => |input| if (input.revision == 0 or input.revision > std.math.maxInt(i64) or
            input.applied != (input.reason == .none)) return error.InvalidLimit,
        else => {},
    }
}
