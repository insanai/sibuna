//! Public server configuration types, separated from the transport host.

const std = @import("std");
const paxos = @import("paxos");
const roles = @import("roles.zig");
const tls = @import("tls.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");

pub const PeerAddress = struct {
    id: paxos.NodeId,
    host: []const u8,
    port: u16,
    role: roles.Role = .data_voter,
};

pub const ServeOptions = struct {
    directory: []const u8,
    node_id: paxos.NodeId,
    listen_host: []const u8 = "127.0.0.1",
    listen_port: u16 = 0,
    /// Unix-domain socket path for a single local node.
    listen_unix: ?[]const u8 = null,
    listen_unix_mode: u16 = 0o600,
    members: []const PeerAddress = &.{},
    database_id: ?u128 = null,
    auth_secret: ?[]const u8 = null,
    allow_psk_only_loopback: bool = false,
    tls: ?tls.Config = null,
    enrollment_ca_key: ?[]const u8 = null,
    revocation_file: ?[]const u8 = null,
    admin_principals: []const []const u8 = &.{},
    allow_insecure_test_tcp: bool = false,
    max_connections: usize = 0,
    handshake_timeout_ms: u64 = 10_000,
    shutdown_flag: ?*std.atomic.Value(bool) = null,
    /// Optional embedding-owned first-failure publication. Bytes are written
    /// before the nonzero length is published with release ordering.
    failure_name_buffer: ?*[128]u8 = null,
    failure_name_len: ?*std.atomic.Value(u8) = null,
    idle_timeout_ms: u64 = 300_000,
    max_connections_per_peer: usize = 2,
    max_transfer_bytes: u64 = wire.max_transfer_bytes,
    max_query_rows: usize = 10_000,
    max_query_bytes: usize = 16 * 1024 * 1024,
    max_query_vm_steps: u64 = 10_000_000,
    mmap_size: u64 = 0,
    retention_slots: u64 = 0,
    journal_cap_bytes: u64 = 64 * 1024 * 1024 * 1024,
    enable_failpoints: bool = false,
    tick_ms: u64 = 25,
    test_faults: TestFaults = .{},
};

pub const TestFaults = struct {
    drop_every: u32 = 0,
    duplicate_every: u32 = 0,
    reorder_pairs: bool = false,
    fragment_bytes: u32 = 0,
    storage_delay_ms: u64 = 0,
    /// Holds outgoing phase-two votes without delaying elections or heartbeats.
    vote_delay_ms: u64 = 0,

    pub fn enabled(self: TestFaults) bool {
        return self.drop_every != 0 or self.duplicate_every != 0 or
            self.reorder_pairs or self.fragment_bytes != 0 or
            self.storage_delay_ms != 0 or self.vote_delay_ms != 0;
    }
};

/// Derives the stable shared database identity from the sorted voter IDs and
/// optional operator cluster name.
pub fn deriveDatabaseId(members: []const PeerAddress, cluster_id: ?[]const u8) u128 {
    var ids: [types.log_options.max_members]paxos.NodeId = undefined;
    var count: usize = 0;
    for (members) |member| {
        if (!member.role.capabilities().votes) continue;
        if (count == ids.len) break;
        ids[count] = member.id;
        count += 1;
    }
    std.mem.sort(paxos.NodeId, ids[0..count], {}, std.sort.asc(paxos.NodeId));
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("zaxonlite.cluster.v1");
    for (ids[0..count]) |id| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, id, .little);
        hasher.update(&bytes);
    }
    if (cluster_id) |text| hasher.update(text);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.mem.readInt(u128, digest[0..16], .little);
}
