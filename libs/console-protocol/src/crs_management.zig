//! Owned management messages. Candidate verification, durable selection and a
//! node's local publication are distinct facts; no program pointer crosses here.
const std = @import("std");
const p = @import("root.zig");
pub const Id = p.Bytes(32);
pub const Manifest = p.Bytes(512);
pub const chunk_bytes = 2048;
pub const candidate_capacity = 4;
pub const preparation_seconds = 300;
pub const review_seconds = 86400;
pub const Kind = enum { check, update, mode, rollback };
pub const State = enum { preparing, verified, selected, failed, canceled, retired };
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
pub const Failed = struct { id: Id, reason: Reason };
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
        .chunk => |input| {
            if (!validId(input.id) or input.bytes.len == 0 or input.bytes.len > chunk_bytes or
                input.ordinal >= fileLimit(input.file) / chunk_bytes) return error.InvalidLimit;
        },
        .verify => |input| if (!validId(input.id) or input.manifest.len == 0 or
            input.manifest.len > Manifest.byte_capacity) return error.InvalidLimit,
        .select => |input| if (!validId(input.id) or
            input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit,
        .job, .discard => |input| if (!validId(input.id)) return error.InvalidLimit,
        .source => |input| if (!validId(input.id) or
            input.ordinal >= fileLimit(input.file) / chunk_bytes) return error.InvalidLimit,
        .failed => |input| if (!validId(input.id) or input.reason == .none)
            return error.InvalidLimit,
        .applied => |input| if (input.revision == 0 or input.revision > std.math.maxInt(i64) or
            input.applied != (input.reason == .none)) return error.InvalidLimit,
        else => {},
    }
}
