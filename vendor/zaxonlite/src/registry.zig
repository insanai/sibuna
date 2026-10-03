//! The canonical decided registry: the durable, consensus-decided mapping
//! from configuration ID to node IDs, roles, and transport endpoints.
//!
//! Bootstrap options create configuration 1. From then on the persisted
//! registry is authoritative; startup flags cannot override it. Each epoch
//! rollover produces the successor registry as a pure function of the
//! current registry and the chosen stop sign, so every survivor rebuilds
//! the same bytes locally and verifies the same digest without the network.
//!
//! The registry also carries two bounded monotonic fences: the node-ID
//! allocation fence (`highest_allocated_node_id`, retiring node IDs forever
//! in four bytes) and the operation ring (the 32 newest replacement
//! records, whose newest entry is the operation-ID high-water mark).
//!
//! On disk a registry blob is the canonical encoding followed by its
//! SHA-256 digest; the `REGISTRY` pointer file names the active blob by
//! configuration ID, with the same pointer-file shape and strict length
//! check the retired `CURRENT` pointer used (that name now survives only
//! as a legacy-artifact tripwire).

const std = @import("std");
const paxos = @import("paxos");
const types = @import("types.zig");
const roles = @import("roles.zig");
const durability = @import("durability.zig");

const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Total registry bound: voters plus runtime-sized learners and gateways,
/// matching the embedded facade's registry bound.
pub const max_nodes = 4 * types.log_options.max_members;
/// Endpoint text bound; also keeps the zx2 stop-metadata seed bounded.
pub const max_endpoint_bytes = 64;
/// Fixed operation-history depth: the 32 newest decided replacements.
pub const ring_size = 32;

pub const magic = "ZXRG";
pub const format_version: u16 = 1;

pub const pointer_file_name = "REGISTRY";
/// Blob directory. Deliberately not `registry`: common macOS and Windows
/// filesystems are case-insensitive, so that name would collide with the
/// `REGISTRY` pointer file.
pub const directory_name = "registries";

const header_size = magic.len + 2 + 16 + 8 + 8 + 4;
const node_record_size = 4 + 1 + 1 + max_endpoint_bytes;
const operation_record_size = 8 + 8 + 4 + 4 + 32 + 8;

/// Worst-case canonical encoding; the on-disk blob adds a 32-byte digest.
pub const max_encoded_bytes = header_size +
    2 + max_nodes * node_record_size +
    2 + ring_size * operation_record_size;

pub const Error = error{
    CorruptRegistry,
    RegistryTooLarge,
    InvalidNodeId,
    DuplicateNodeId,
    InvalidEndpoint,
    DuplicateEndpoint,
    InvalidVoterSet,
    FenceRegression,
    InvalidOperationRing,
    StaleConfiguration,
    UnknownVoter,
    NodeIdNotFresh,
    NodeIdExhausted,
    EndpointInUse,
    TooFewVoters,
    OperationConflict,
    OperationHistoryExpired,
    OperationIdExhausted,
    ConfigurationIdExhausted,
};

/// One registered node: identity, product role, and transport endpoint.
pub const NodeRecord = struct {
    id: paxos.NodeId,
    role: roles.Role,
    endpoint: [max_endpoint_bytes]u8,
    endpoint_len: u8,

    pub fn init(
        id: paxos.NodeId,
        role: roles.Role,
        endpoint: []const u8,
    ) Error!NodeRecord {
        if (id == 0) return error.InvalidNodeId;
        try validateEndpoint(endpoint);
        var record = NodeRecord{
            .id = id,
            .role = role,
            .endpoint = @as([max_endpoint_bytes]u8, @splat(0)),
            .endpoint_len = @intCast(endpoint.len),
        };
        @memcpy(record.endpoint[0..endpoint.len], endpoint);
        return record;
    }

    pub fn endpointSlice(self: *const NodeRecord) []const u8 {
        return self.endpoint[0..self.endpoint_len];
    }
};

/// One immutable decided replacement outcome retained in the ring.
pub const OperationRecord = struct {
    operation_id: u64,
    expected_configuration_id: u64,
    old_node_id: paxos.NodeId,
    new_node_id: paxos.NodeId,
    request_digest: [32]u8,
    result_configuration_id: u64,
};

/// One administrative replacement request, before consensus chooses it.
pub const ReplacementRequest = struct {
    operation_id: u64,
    expected_configuration_id: u64,
    old_node_id: paxos.NodeId,
    new_node_id: paxos.NodeId,
    new_endpoint: []const u8,

    /// Canonical digest binding every request argument; a retained
    /// operation ID with a different digest is a conflicting reuse.
    pub fn digestOf(self: *const ReplacementRequest) [32]u8 {
        var hasher = Sha256.init(.{});
        hasher.update("zaxonlite.replace.v1");
        var scratch: [8]u8 = undefined;
        std.mem.writeInt(u64, &scratch, self.operation_id, .little);
        hasher.update(&scratch);
        std.mem.writeInt(u64, &scratch, self.expected_configuration_id, .little);
        hasher.update(&scratch);
        std.mem.writeInt(u32, scratch[0..4], self.old_node_id, .little);
        hasher.update(scratch[0..4]);
        std.mem.writeInt(u32, scratch[0..4], self.new_node_id, .little);
        hasher.update(scratch[0..4]);
        hasher.update(self.new_endpoint);
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        return digest;
    }
};

/// How a validated request relates to the decided history.
pub const Disposition = union(enum) {
    /// A new operation; the caller may prepare and propose it.
    fresh,
    /// An idempotent retry of a decided operation.
    retry: struct { result_configuration_id: u64 },
};

/// The canonical decided registry for one configuration.
pub const Decided = struct {
    database_id: u128,
    configuration_id: u64,
    predecessor_configuration_id: u64,
    highest_allocated_node_id: u32,
    node_count: u16,
    nodes: [max_nodes]NodeRecord,
    ring_count: u16,
    /// Physical index of the oldest retained operation. The canonical
    /// encoder walks logical order, so internal rotation never changes
    /// registry bytes or digests.
    ring_start: u8,
    ring: [ring_size]OperationRecord,

    /// Builds configuration 1 from bootstrap records. Input order does not
    /// matter; the canonical form sorts nodes by ID.
    pub fn bootstrap(database_id: u128, records: []const NodeRecord) Error!Decided {
        return bootstrapAt(database_id, 1, records);
    }

    /// Builds the first persisted registry at a specific configuration. A
    /// directory created before the registry feature adopts the registry
    /// at its current configuration rather than pretending it is fresh.
    pub fn bootstrapAt(
        database_id: u128,
        configuration_id: u64,
        records: []const NodeRecord,
    ) Error!Decided {
        if (database_id == 0) return error.CorruptRegistry;
        if (configuration_id == 0) return error.CorruptRegistry;
        if (records.len == 0 or records.len > max_nodes) {
            return error.CorruptRegistry;
        }
        var decided = Decided{
            .database_id = database_id,
            .configuration_id = configuration_id,
            .predecessor_configuration_id = configuration_id - 1,
            .highest_allocated_node_id = 0,
            .node_count = @intCast(records.len),
            .nodes = undefined,
            .ring_count = 0,
            .ring_start = 0,
            .ring = undefined,
        };
        @memcpy(decided.nodes[0..records.len], records);
        std.mem.sort(NodeRecord, decided.nodes[0..records.len], {}, nodeLessThan);
        for (decided.nodes[0..records.len]) |record| {
            decided.highest_allocated_node_id =
                @max(decided.highest_allocated_node_id, record.id);
        }
        try decided.validate();
        return decided;
    }

    pub fn nodesSlice(self: *const Decided) []const NodeRecord {
        return self.nodes[0..self.node_count];
    }

    pub fn operationAt(self: *const Decided, logical_index: usize) *const OperationRecord {
        std.debug.assert(logical_index < self.ring_count);
        const physical = (@as(usize, self.ring_start) + logical_index) % ring_size;
        return &self.ring[physical];
    }

    pub fn newestOperation(self: *const Decided) ?*const OperationRecord {
        if (self.ring_count == 0) return null;
        return self.operationAt(self.ring_count - 1);
    }

    pub fn findNode(self: *const Decided, id: paxos.NodeId) ?*const NodeRecord {
        for (self.nodesSlice()) |*record| {
            if (record.id == id) return record;
        }
        return null;
    }

    pub fn voterCount(self: *const Decided) u16 {
        var count: u16 = 0;
        for (self.nodesSlice()) |record| {
            if (record.role.capabilities().votes) count += 1;
        }
        return count;
    }

    /// Copies the voting member IDs, ascending, into `buffer`. This is the
    /// exact member array a stop sign for this registry must carry.
    pub fn voterIds(
        self: *const Decided,
        buffer: *[types.log_options.max_members]paxos.NodeId,
    ) []const paxos.NodeId {
        var count: usize = 0;
        for (self.nodesSlice()) |record| {
            if (record.role.capabilities().votes) {
                buffer[count] = record.id;
                count += 1;
            }
        }
        return buffer[0..count];
    }

    /// Rejects anything the canonical form forbids. Decode calls this, so
    /// a hand-edited or corrupt blob cannot become authoritative.
    pub fn validate(self: *const Decided) Error!void {
        if (self.database_id == 0) return error.CorruptRegistry;
        if (self.configuration_id == 0) return error.CorruptRegistry;
        if (self.predecessor_configuration_id >= self.configuration_id) {
            return error.CorruptRegistry;
        }
        if (self.node_count == 0 or self.node_count > max_nodes) {
            return error.CorruptRegistry;
        }
        if (self.ring_count > ring_size) return error.InvalidOperationRing;
        if (self.ring_start >= ring_size) return error.InvalidOperationRing;

        var voters: u16 = 0;
        var campaigners: u16 = 0;
        for (self.nodesSlice(), 0..) |*record, index| {
            if (record.id == 0) return error.InvalidNodeId;
            if (index > 0 and self.nodes[index - 1].id >= record.id) {
                return error.DuplicateNodeId;
            }
            if (record.id > self.highest_allocated_node_id) {
                return error.FenceRegression;
            }
            try validateEndpoint(record.endpointSlice());
            for (self.nodes[0..index]) |*previous| {
                if (std.mem.eql(u8, previous.endpointSlice(), record.endpointSlice())) {
                    return error.DuplicateEndpoint;
                }
            }
            const capabilities = record.role.capabilities();
            if (capabilities.votes) voters += 1;
            if (capabilities.campaigns) campaigners += 1;
        }
        if (voters == 0 or voters > types.log_options.max_members) {
            return error.InvalidVoterSet;
        }
        if (campaigners == 0) return error.InvalidVoterSet;

        for (0..self.ring_count) |index| {
            const record = self.operationAt(index);
            if (index > 0 and
                self.operationAt(index - 1).operation_id >= record.operation_id)
            {
                return error.InvalidOperationRing;
            }
            if (record.result_configuration_id == 0 or
                record.result_configuration_id > self.configuration_id)
            {
                return error.InvalidOperationRing;
            }
        }
    }

    /// Canonically encodes this registry. Two equal registries encode to
    /// identical bytes; the digest is SHA-256 over exactly these bytes.
    pub fn encode(self: *const Decided, buffer: *[max_encoded_bytes]u8) []const u8 {
        var cursor = types.Cursor{ .buffer = buffer };
        cursor.bytes(magic);
        cursor.int(u16, format_version);
        cursor.int(u128, self.database_id);
        cursor.int(u64, self.configuration_id);
        cursor.int(u64, self.predecessor_configuration_id);
        cursor.int(u32, self.highest_allocated_node_id);
        cursor.int(u16, self.node_count);
        for (self.nodesSlice()) |*record| {
            cursor.int(u32, record.id);
            cursor.byte(@backingInt(record.role));
            cursor.byte(record.endpoint_len);
            cursor.bytes(record.endpointSlice());
        }
        cursor.int(u16, self.ring_count);
        for (0..self.ring_count) |index| {
            const record = self.operationAt(index);
            cursor.int(u64, record.operation_id);
            cursor.int(u64, record.expected_configuration_id);
            cursor.int(u32, record.old_node_id);
            cursor.int(u32, record.new_node_id);
            cursor.bytes(&record.request_digest);
            cursor.int(u64, record.result_configuration_id);
        }
        return buffer[0..cursor.offset];
    }

    /// Decodes and fully validates one canonical registry encoding.
    pub fn decode(bytes: []const u8) Error!Decided {
        var reader = types.ReadCursor{ .buffer = bytes };
        const seen_magic = reader.take(magic.len) catch return error.CorruptRegistry;
        if (!std.mem.eql(u8, seen_magic, magic)) return error.CorruptRegistry;
        const version = reader.int(u16) catch return error.CorruptRegistry;
        if (version != format_version) return error.CorruptRegistry;

        var decided = Decided{
            .database_id = reader.int(u128) catch return error.CorruptRegistry,
            .configuration_id = reader.int(u64) catch return error.CorruptRegistry,
            .predecessor_configuration_id = reader.int(u64) catch
                return error.CorruptRegistry,
            .highest_allocated_node_id = reader.int(u32) catch
                return error.CorruptRegistry,
            .node_count = 0,
            .nodes = undefined,
            .ring_count = 0,
            .ring_start = 0,
            .ring = undefined,
        };
        const node_count = reader.int(u16) catch return error.CorruptRegistry;
        if (node_count == 0 or node_count > max_nodes) return error.CorruptRegistry;
        decided.node_count = node_count;
        for (decided.nodes[0..node_count]) |*record| {
            const id = reader.int(u32) catch return error.CorruptRegistry;
            const role_byte = reader.byte() catch return error.CorruptRegistry;
            const role = std.enums.fromInt(roles.Role, role_byte) orelse
                return error.CorruptRegistry;
            const endpoint_len = reader.byte() catch return error.CorruptRegistry;
            if (endpoint_len > max_endpoint_bytes) return error.CorruptRegistry;
            const endpoint = reader.take(endpoint_len) catch
                return error.CorruptRegistry;
            record.* = NodeRecord.init(id, role, endpoint) catch
                return error.CorruptRegistry;
        }
        const ring_count = reader.int(u16) catch return error.CorruptRegistry;
        if (ring_count > ring_size) return error.CorruptRegistry;
        decided.ring_count = ring_count;
        for (decided.ring[0..ring_count]) |*record| {
            record.* = .{
                .operation_id = reader.int(u64) catch return error.CorruptRegistry,
                .expected_configuration_id = reader.int(u64) catch
                    return error.CorruptRegistry,
                .old_node_id = reader.int(u32) catch return error.CorruptRegistry,
                .new_node_id = reader.int(u32) catch return error.CorruptRegistry,
                .request_digest = ((reader.take(32) catch
                    return error.CorruptRegistry)[0..32]).*,
                .result_configuration_id = reader.int(u64) catch
                    return error.CorruptRegistry,
            };
        }
        if (reader.offset != bytes.len) return error.CorruptRegistry;
        try decided.validate();
        return decided;
    }

    /// SHA-256 over the complete canonical bytes. This digest is bound
    /// into zx2 stop metadata and checkpoint proof v2.
    pub fn digest(self: *const Decided) [32]u8 {
        var buffer: [max_encoded_bytes]u8 = undefined;
        const encoded = self.encode(&buffer);
        var out: [32]u8 = undefined;
        Sha256.hash(encoded, &out, .{});
        return out;
    }

    /// Validates one replacement request against the decided history and
    /// the current membership. Read-only; `successor` applies it.
    pub fn validateRequest(
        self: *const Decided,
        request: *const ReplacementRequest,
    ) Error!Disposition {
        for (0..self.ring_count) |index| {
            const record = self.operationAt(index);
            if (record.operation_id != request.operation_id) continue;
            const request_digest = request.digestOf();
            if (!std.mem.eql(u8, &record.request_digest, &request_digest)) {
                return error.OperationConflict;
            }
            return .{ .retry = .{
                .result_configuration_id = record.result_configuration_id,
            } };
        }
        if (self.newestOperation()) |record| {
            const newest = record.operation_id;
            if (newest == std.math.maxInt(u64)) return error.OperationIdExhausted;
            if (request.operation_id <= newest) {
                return error.OperationHistoryExpired;
            }
        }
        if (request.expected_configuration_id != self.configuration_id) {
            return error.StaleConfiguration;
        }
        const old = self.findNode(request.old_node_id) orelse
            return error.UnknownVoter;
        if (old.role != .data_voter) return error.UnknownVoter;
        if (self.highest_allocated_node_id == std.math.maxInt(u32)) {
            return error.NodeIdExhausted;
        }
        if (request.new_node_id <= self.highest_allocated_node_id) {
            return error.NodeIdNotFresh;
        }
        try validateEndpoint(request.new_endpoint);
        for (self.nodesSlice()) |*record| {
            if (record.id == request.old_node_id) continue;
            if (std.mem.eql(u8, record.endpointSlice(), request.new_endpoint)) {
                return error.EndpointInUse;
            }
        }
        if (self.voterCount() < 3) return error.TooFewVoters;
        if (self.configuration_id == std.math.maxInt(u64)) {
            return error.ConfigurationIdExhausted;
        }
        return .fresh;
    }

    /// The next registry for a same-member checkpoint rollover: identical
    /// nodes, fence, and ring under the successor configuration ID.
    pub fn checkpointSuccessor(self: *const Decided) Error!Decided {
        if (self.configuration_id == std.math.maxInt(u64)) {
            return error.ConfigurationIdExhausted;
        }
        var next = self.*;
        next.predecessor_configuration_id = self.configuration_id;
        next.configuration_id = self.configuration_id + 1;
        try next.validate();
        return next;
    }

    /// The next registry for a decided one-for-one voter replacement: a
    /// pure function of this registry and the request, so every survivor
    /// reconstructs identical bytes. The request must be `fresh`.
    pub fn successor(
        self: *const Decided,
        request: *const ReplacementRequest,
    ) Error!Decided {
        switch (try self.validateRequest(request)) {
            .fresh => {},
            .retry => return error.OperationConflict,
        }
        var next = self.*;
        next.predecessor_configuration_id = self.configuration_id;
        next.configuration_id = self.configuration_id + 1;
        next.highest_allocated_node_id = request.new_node_id;

        for (next.nodes[0..next.node_count]) |*record| {
            if (record.id != request.old_node_id) continue;
            record.* = NodeRecord.init(
                request.new_node_id,
                .data_voter,
                request.new_endpoint,
            ) catch return error.InvalidEndpoint;
            break;
        }
        std.mem.sort(NodeRecord, next.nodes[0..next.node_count], {}, nodeLessThan);

        const record = OperationRecord{
            .operation_id = request.operation_id,
            .expected_configuration_id = request.expected_configuration_id,
            .old_node_id = request.old_node_id,
            .new_node_id = request.new_node_id,
            .request_digest = request.digestOf(),
            .result_configuration_id = next.configuration_id,
        };
        if (next.ring_count == ring_size) {
            next.ring[next.ring_start] = record;
            next.ring_start = (next.ring_start + 1) % ring_size;
        } else {
            const index =
                (@as(usize, next.ring_start) + @as(usize, next.ring_count)) % ring_size;
            next.ring[index] = record;
            next.ring_count += 1;
        }
        try next.validate();
        return next;
    }
};

fn nodeLessThan(_: void, a: NodeRecord, b: NodeRecord) bool {
    return a.id < b.id;
}

/// Endpoint text must stay printable, space-free ASCII with a port
/// separator: it travels inside space-tokenized zx2 stop metadata.
pub fn validateEndpoint(endpoint: []const u8) Error!void {
    if (endpoint.len == 0 or endpoint.len > max_endpoint_bytes) {
        return error.InvalidEndpoint;
    }
    var has_separator = false;
    for (endpoint) |byte| {
        if (byte <= ' ' or byte > '~') return error.InvalidEndpoint;
        if (byte == ':') has_separator = true;
    }
    if (!has_separator) return error.InvalidEndpoint;
}

/// Formats the blob path for one configuration: `registry/<16 hex>`.
pub fn blobPath(buffer: *[32]u8, configuration_id: u64) []const u8 {
    return std.fmt.bufPrint(
        buffer,
        directory_name ++ "/{x:0>16}",
        .{configuration_id},
    ) catch unreachable;
}

/// Writes one registry blob (canonical bytes plus digest trailer) under
/// `registry/`, without touching the pointer. Idempotent per configuration.
pub fn storeBlob(io: Io, dir: Io.Dir, decided: *const Decided) !void {
    var registry_dir = try dir.createDirPathOpen(io, directory_name, .{});
    defer registry_dir.close(io);
    var encode_buffer: [max_encoded_bytes + 32]u8 = undefined;
    const encoded = decided.encode(encode_buffer[0..max_encoded_bytes]);
    var trailer: [32]u8 = undefined;
    Sha256.hash(encoded, &trailer, .{});
    @memcpy(encode_buffer[encoded.len..][0..32], &trailer);
    var name_buffer: [16]u8 = undefined;
    const name = std.fmt.bufPrint(
        &name_buffer,
        "{x:0>16}",
        .{decided.configuration_id},
    ) catch unreachable;
    try atomicWriteFile(io, registry_dir, name, encode_buffer[0 .. encoded.len + 32]);
}

/// Atomically points `REGISTRY` at one stored configuration blob.
pub fn activatePointer(io: Io, dir: Io.Dir, configuration_id: u64) !void {
    var name_buffer: [16]u8 = undefined;
    const name = std.fmt.bufPrint(
        &name_buffer,
        "{x:0>16}",
        .{configuration_id},
    ) catch unreachable;
    try atomicWriteFile(io, dir, pointer_file_name, name);
}

/// Reads the pointed-to configuration ID, or null before bootstrap. A
/// present but malformed pointer is an error, never a fallback.
pub fn loadPointer(io: Io, dir: Io.Dir, gpa: std.mem.Allocator) !?u64 {
    const bytes = dir.readFileAlloc(io, pointer_file_name, gpa, .limited(64)) catch |err|
        switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
    defer gpa.free(bytes);
    const trimmed = std.mem.trim(u8, bytes, " \n");
    if (trimmed.len != 16) return error.CorruptRegistryPointer;
    return std.fmt.parseInt(u64, trimmed, 16) catch
        return error.CorruptRegistryPointer;
}

/// Loads and verifies the active decided registry, or null before
/// bootstrap. Every failure past a present pointer is fatal: the server
/// must stop rather than fall back to startup flags or re-derivation.
pub fn load(io: Io, dir: Io.Dir, gpa: std.mem.Allocator) !?Decided {
    const configuration_id = (try loadPointer(io, dir, gpa)) orelse return null;
    var path_buffer: [32]u8 = undefined;
    const path = blobPath(&path_buffer, configuration_id);
    const bytes = try dir.readFileAlloc(
        io,
        path,
        gpa,
        .limited(max_encoded_bytes + 32),
    );
    defer gpa.free(bytes);
    if (bytes.len < 32) return error.CorruptRegistry;
    const encoded = bytes[0 .. bytes.len - 32];
    var trailer: [32]u8 = undefined;
    Sha256.hash(encoded, &trailer, .{});
    if (!std.mem.eql(u8, &trailer, bytes[bytes.len - 32 ..])) {
        return error.CorruptRegistry;
    }
    const decided = try Decided.decode(encoded);
    if (decided.configuration_id != configuration_id) {
        return error.CorruptRegistry;
    }
    return decided;
}

fn atomicWriteFile(io: Io, dir: Io.Dir, name: []const u8, contents: []const u8) !void {
    var atomic = try dir.createFileAtomic(io, name, .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writePositionalAll(io, contents, 0);
    try durability.syncFile(io, atomic.file);
    try atomic.replace(io);
    try durability.syncPathnameTransition(io, dir, name);
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

fn testRecords() [4]NodeRecord {
    return .{
        NodeRecord.init(3, .data_voter, "127.0.0.1:9903") catch unreachable,
        NodeRecord.init(1, .data_voter, "127.0.0.1:9901") catch unreachable,
        NodeRecord.init(2, .data_voter, "127.0.0.1:9902") catch unreachable,
        NodeRecord.init(7, .read_replica, "127.0.0.1:9907") catch unreachable,
    };
}

fn testRegistry() Decided {
    const records = testRecords();
    return Decided.bootstrap(0xabc123, &records) catch unreachable;
}

fn testRequest() ReplacementRequest {
    return .{
        .operation_id = 10,
        .expected_configuration_id = 1,
        .old_node_id = 3,
        .new_node_id = 8,
        .new_endpoint = "127.0.0.1:9908",
    };
}

test "canonical encoding is stable across input order" {
    const records = testRecords();
    var shuffled = records;
    std.mem.swap(NodeRecord, &shuffled[0], &shuffled[2]);
    std.mem.swap(NodeRecord, &shuffled[1], &shuffled[3]);
    const a = try Decided.bootstrap(0xabc123, &records);
    const b = try Decided.bootstrap(0xabc123, &shuffled);
    var buffer_a: [max_encoded_bytes]u8 = undefined;
    var buffer_b: [max_encoded_bytes]u8 = undefined;
    try testing.expectEqualSlices(u8, a.encode(&buffer_a), b.encode(&buffer_b));
    try testing.expectEqualSlices(u8, &a.digest(), &b.digest());
}

test "bootstrap sets the fence to the largest initial node id" {
    const decided = testRegistry();
    try testing.expectEqual(@as(u32, 7), decided.highest_allocated_node_id);
    try testing.expectEqual(@as(u64, 1), decided.configuration_id);
    try testing.expectEqual(@as(u16, 3), decided.voterCount());
    var voters: [types.log_options.max_members]paxos.NodeId = undefined;
    try testing.expectEqualSlices(
        paxos.NodeId,
        &.{ 1, 2, 3 },
        decided.voterIds(&voters),
    );
}

test "registry round trips through the canonical encoding" {
    const decided = testRegistry();
    var buffer: [max_encoded_bytes]u8 = undefined;
    const encoded = decided.encode(&buffer);
    const restored = try Decided.decode(encoded);
    // Digest equality proves the canonical bytes, and therefore all
    // defined content, round-tripped exactly.
    try testing.expectEqualSlices(u8, &decided.digest(), &restored.digest());
    try testing.expectEqual(decided.node_count, restored.node_count);
    try testing.expectEqual(decided.ring_count, restored.ring_count);
    try testing.expectEqualDeep(decided.nodesSlice(), restored.nodesSlice());
}

test "decode rejects corruption, duplicates, and trailing bytes" {
    const decided = testRegistry();
    var buffer: [max_encoded_bytes]u8 = undefined;
    const encoded = decided.encode(&buffer);

    // Truncation and trailing garbage are rejected.
    try testing.expectError(
        error.CorruptRegistry,
        Decided.decode(encoded[0 .. encoded.len - 1]),
    );
    var extended: [max_encoded_bytes]u8 = undefined;
    @memcpy(extended[0..encoded.len], encoded);
    extended[encoded.len] = 0;
    try testing.expectError(
        error.CorruptRegistry,
        Decided.decode(extended[0 .. encoded.len + 1]),
    );

    // A duplicated node ID violates the canonical sorted order.
    var duplicated = decided;
    duplicated.nodes[1].id = duplicated.nodes[0].id;
    var duplicate_buffer: [max_encoded_bytes]u8 = undefined;
    const duplicate_encoded = duplicated.encode(&duplicate_buffer);
    try testing.expectError(
        error.DuplicateNodeId,
        Decided.decode(duplicate_encoded),
    );

    // A node above the fence is rejected.
    var above_fence = decided;
    above_fence.highest_allocated_node_id = 2;
    var fence_buffer: [max_encoded_bytes]u8 = undefined;
    try testing.expectError(
        error.FenceRegression,
        Decided.decode(above_fence.encode(&fence_buffer)),
    );
}

test "validate rejects duplicate endpoints and empty voter sets" {
    var decided = testRegistry();
    decided.nodes[1].endpoint = decided.nodes[0].endpoint;
    decided.nodes[1].endpoint_len = decided.nodes[0].endpoint_len;
    try testing.expectError(error.DuplicateEndpoint, decided.validate());

    var no_voters = testRegistry();
    for (no_voters.nodes[0..no_voters.node_count]) |*record| {
        record.role = .read_replica;
    }
    try testing.expectError(error.InvalidVoterSet, no_voters.validate());
}

test "endpoint validation enforces the bounded seed alphabet" {
    try validateEndpoint("10.0.0.7:4400");
    try validateEndpoint("db-3.internal:44");
    try testing.expectError(error.InvalidEndpoint, validateEndpoint(""));
    try testing.expectError(error.InvalidEndpoint, validateEndpoint("no-port"));
    try testing.expectError(error.InvalidEndpoint, validateEndpoint("a b:1"));
    const long = &@as([70]u8, @splat(104)) ++ ":1";
    try testing.expectError(error.InvalidEndpoint, validateEndpoint(long));
}

test "successor replaces one voter and advances the fence" {
    const decided = testRegistry();
    const request = testRequest();
    try testing.expectEqual(Disposition.fresh, try decided.validateRequest(&request));

    const next = try decided.successor(&request);
    try testing.expectEqual(decided.database_id, next.database_id);
    try testing.expectEqual(@as(u64, 2), next.configuration_id);
    try testing.expectEqual(@as(u64, 1), next.predecessor_configuration_id);
    try testing.expectEqual(@as(u32, 8), next.highest_allocated_node_id);
    try testing.expect(next.findNode(3) == null);
    const replacement = next.findNode(8).?;
    try testing.expectEqual(roles.Role.data_voter, replacement.role);
    try testing.expectEqualStrings("127.0.0.1:9908", replacement.endpointSlice());
    try testing.expectEqual(@as(u16, 1), next.ring_count);
    try testing.expectEqual(@as(u64, 10), next.operationAt(0).operation_id);
    try testing.expectEqual(@as(u64, 2), next.operationAt(0).result_configuration_id);

    var voters: [types.log_options.max_members]paxos.NodeId = undefined;
    try testing.expectEqualSlices(
        paxos.NodeId,
        &.{ 1, 2, 8 },
        next.voterIds(&voters),
    );
}

test "successor is a pure function of registry and request" {
    const decided = testRegistry();
    const request = testRequest();
    const a = try decided.successor(&request);
    const b = try decided.successor(&request);
    try testing.expectEqualSlices(u8, &a.digest(), &b.digest());
}

test "checkpoint successor keeps nodes, fence, and ring" {
    const decided = testRegistry();
    const next = try decided.checkpointSuccessor();
    try testing.expectEqual(@as(u64, 2), next.configuration_id);
    try testing.expectEqual(@as(u64, 1), next.predecessor_configuration_id);
    try testing.expectEqual(decided.highest_allocated_node_id, next.highest_allocated_node_id);
    try testing.expectEqualDeep(decided.nodesSlice(), next.nodesSlice());
    try testing.expectEqual(decided.ring_count, next.ring_count);
}

test "retained operation retries are idempotent, conflicts rejected" {
    const decided = testRegistry();
    const request = testRequest();
    const next = try decided.successor(&request);

    const retry = try next.validateRequest(&request);
    try testing.expectEqual(@as(u64, 2), retry.retry.result_configuration_id);

    var conflicting = request;
    conflicting.new_endpoint = "127.0.0.1:9999";
    try testing.expectError(
        error.OperationConflict,
        next.validateRequest(&conflicting),
    );
}

test "request validation enforces fence, endpoint, and quorum rules" {
    const decided = testRegistry();

    var stale = testRequest();
    stale.expected_configuration_id = 9;
    try testing.expectError(error.StaleConfiguration, decided.validateRequest(&stale));

    var unknown = testRequest();
    unknown.old_node_id = 42;
    try testing.expectError(error.UnknownVoter, decided.validateRequest(&unknown));

    var not_voter = testRequest();
    not_voter.old_node_id = 7;
    try testing.expectError(error.UnknownVoter, decided.validateRequest(&not_voter));

    var reused = testRequest();
    reused.new_node_id = 5;
    try testing.expectError(error.NodeIdNotFresh, decided.validateRequest(&reused));

    var endpoint_in_use = testRequest();
    endpoint_in_use.new_endpoint = "127.0.0.1:9901";
    try testing.expectError(
        error.EndpointInUse,
        decided.validateRequest(&endpoint_in_use),
    );

    // Replacing the old voter's own endpoint is allowed: the hardware may
    // return at the same address under the fresh identity.
    var same_address = testRequest();
    same_address.new_endpoint = "127.0.0.1:9903";
    try testing.expectEqual(
        Disposition.fresh,
        try decided.validateRequest(&same_address),
    );

    const two_voters = [_]NodeRecord{
        NodeRecord.init(1, .data_voter, "127.0.0.1:9901") catch unreachable,
        NodeRecord.init(2, .data_voter, "127.0.0.1:9902") catch unreachable,
    };
    const small = try Decided.bootstrap(0xabc123, &two_voters);
    var small_request = testRequest();
    small_request.old_node_id = 2;
    small_request.new_node_id = 3;
    try testing.expectError(
        error.TooFewVoters,
        small.validateRequest(&small_request),
    );
}

test "node id fence never wraps" {
    var decided = testRegistry();
    decided.highest_allocated_node_id = std.math.maxInt(u32);
    const request = testRequest();
    try testing.expectError(error.NodeIdExhausted, decided.validateRequest(&request));
}

test "operation ids expire out of the ring and never wrap" {
    var decided = testRegistry();
    var operation_id: u64 = 100;
    var old_id: paxos.NodeId = 3;
    var new_id: paxos.NodeId = 100;
    var endpoint_buffer: [32]u8 = undefined;
    // Decide 33 operations so the first record is evicted.
    var index: usize = 0;
    while (index < ring_size + 1) : (index += 1) {
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "10.0.0.9:{d}",
            .{20_000 + index},
        ) catch unreachable;
        const request = ReplacementRequest{
            .operation_id = operation_id,
            .expected_configuration_id = decided.configuration_id,
            .old_node_id = old_id,
            .new_node_id = new_id,
            .new_endpoint = endpoint,
        };
        decided = try decided.successor(&request);
        old_id = new_id;
        operation_id += 1;
        new_id += 1;
    }
    try testing.expectEqual(@as(u16, ring_size), decided.ring_count);
    try testing.expectEqual(@as(u64, 101), decided.operationAt(0).operation_id);

    // The evicted operation ID can no longer start or retry anything.
    const expired = ReplacementRequest{
        .operation_id = 100,
        .expected_configuration_id = decided.configuration_id,
        .old_node_id = decided.newestOperation().?.new_node_id,
        .new_node_id = new_id,
        .new_endpoint = "10.0.0.9:30000",
    };
    try testing.expectError(
        error.OperationHistoryExpired,
        decided.validateRequest(&expired),
    );

    // A ring whose newest ID is the maximum refuses new operations.
    var exhausted = decided;
    const newest_index =
        (@as(usize, exhausted.ring_start) + exhausted.ring_count - 1) % ring_size;
    exhausted.ring[newest_index].operation_id = std.math.maxInt(u64);
    const fresh = ReplacementRequest{
        .operation_id = 1,
        .expected_configuration_id = exhausted.configuration_id,
        .old_node_id = expired.old_node_id,
        .new_node_id = new_id,
        .new_endpoint = "10.0.0.9:30000",
    };
    try testing.expectError(
        error.OperationIdExhausted,
        exhausted.validateRequest(&fresh),
    );
}

test "registry blobs and pointer survive a store/load round trip" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const dir = tmp.dir;

    try testing.expectEqual(@as(?u64, null), try loadPointer(io, dir, testing.allocator));
    try testing.expect((try load(io, dir, testing.allocator)) == null);

    const decided = testRegistry();
    try storeBlob(io, dir, &decided);
    // Blob stored but pointer untouched: still pre-bootstrap.
    try testing.expect((try load(io, dir, testing.allocator)) == null);

    try activatePointer(io, dir, decided.configuration_id);
    const loaded = (try load(io, dir, testing.allocator)).?;
    try testing.expectEqualSlices(u8, &decided.digest(), &loaded.digest());
    try testing.expectEqual(decided.configuration_id, loaded.configuration_id);

    // A flipped byte in the blob fails closed instead of loading.
    var path_buffer: [32]u8 = undefined;
    const path = blobPath(&path_buffer, decided.configuration_id);
    const bytes = try dir.readFileAlloc(
        io,
        path,
        testing.allocator,
        .limited(max_encoded_bytes + 32),
    );
    defer testing.allocator.free(bytes);
    bytes[header_size + 3] ^= 0x40;
    try dir.writeFile(io, .{ .sub_path = path, .data = bytes });
    try testing.expectError(
        error.CorruptRegistry,
        load(io, dir, testing.allocator),
    );
}

/// The voter-replacement seed carried in zx3 stop metadata: the
/// operation id plus the retiring node, the joining node, and its
/// endpoint, from which every survivor rebuilds the next registry.
pub const StopSeed = struct {
    operation_id: u64,
    old_node_id: u32,
    new_node_id: u32,
    endpoint: [max_endpoint_bytes]u8,
    endpoint_len: u8,

    pub fn endpointSlice(self: *const StopSeed) []const u8 {
        return self.endpoint[0..self.endpoint_len];
    }
};

pub const StopMetadata = struct {
    /// Digest of the canonical next decided registry.
    registry_digest: [32]u8,
    /// Present only for a decided voter replacement.
    seed: ?StopSeed,
};

pub const StopMetadataText = struct {
    buffer: [types.log_options.max_metadata_bytes]u8,
    len: usize,

    pub fn slice(self: *const StopMetadataText) []const u8 {
        return self.buffer[0..self.len];
    }
};

/// Renders zx3 stop metadata: the next registry digest plus the
/// replacement seed every survivor reconstructs the registry from.
pub fn renderStopMetadata(
    digest: [32]u8,
    request: *const ReplacementRequest,
) StopMetadataText {
    var text = StopMetadataText{ .buffer = undefined, .len = 0 };
    const digest_hex = std.fmt.bytesToHex(digest, .lower);
    const rendered = std.fmt.bufPrint(
        &text.buffer,
        "zx3 {s} {x:0>16} {x:0>8} {x:0>8} {s}",
        .{
            &digest_hex,
            request.operation_id,
            request.old_node_id,
            request.new_node_id,
            request.new_endpoint,
        },
    ) catch unreachable;
    text.len = rendered.len;
    return text;
}

pub fn parseStopMetadata(metadata: []const u8) !StopMetadata {
    var parts = std.mem.tokenizeScalar(u8, metadata, ' ');
    const tag = parts.next() orelse return error.CorruptStopSign;
    if (!std.mem.eql(u8, tag, "zx3")) return error.CorruptStopSign;
    const registry_hex = parts.next() orelse return error.CorruptStopSign;
    if (registry_hex.len != 64) return error.CorruptStopSign;
    var result = StopMetadata{ .registry_digest = undefined, .seed = null };
    _ = std.fmt.hexToBytes(&result.registry_digest, registry_hex) catch
        return error.CorruptStopSign;
    if (parts.next()) |operation_hex| {
        if (operation_hex.len != 16) return error.CorruptStopSign;
        const old_hex = parts.next() orelse return error.CorruptStopSign;
        if (old_hex.len != 8) return error.CorruptStopSign;
        const new_hex = parts.next() orelse return error.CorruptStopSign;
        if (new_hex.len != 8) return error.CorruptStopSign;
        const endpoint = parts.next() orelse return error.CorruptStopSign;
        validateEndpoint(endpoint) catch
            return error.CorruptStopSign;
        var seed = StopSeed{
            .operation_id = std.fmt.parseInt(u64, operation_hex, 16) catch
                return error.CorruptStopSign,
            .old_node_id = std.fmt.parseInt(u32, old_hex, 16) catch
                return error.CorruptStopSign,
            .new_node_id = std.fmt.parseInt(u32, new_hex, 16) catch
                return error.CorruptStopSign,
            .endpoint = @as([max_endpoint_bytes]u8, @splat(0)),
            .endpoint_len = @intCast(endpoint.len),
        };
        @memcpy(seed.endpoint[0..endpoint.len], endpoint);
        result.seed = seed;
    }
    if (parts.next() != null) return error.CorruptStopSign;
    return result;
}
