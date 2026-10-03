//! The `zaxon serve` transport host: one node behind a TCP endpoint.
//!
//! Thread shape: the serve thread accepts connections; every accepted
//! connection gets a reader thread; every peer gets one sender thread that
//! owns the outgoing connection and its bounded frame queue; one tick
//! thread advances protocol timers. One mutex guards the node and all
//! host bookkeeping; blocking work under it (journal fsync, SQLite) is the
//! write path's natural serialization.
//!
//! Ordering guarantees preserved here:
//! * `Node.consumeEffects` keeps every durable claim behind the journal
//!   barrier. Phase-two `accept` requests are the narrow exception: the
//!   server queues them after append and while the leader barrier runs, so
//!   follower barriers overlap it. The node mutex prevents their replies
//!   from being processed until the leader vote is durable.
//! * A payload is queued immediately before any dependent envelope on the
//!   ordered stream. The receiver stores it before reading the envelope and
//!   independently gates any reordered/missing-payload envelope, so Phase-1
//!   recovery and every counted vote have recoverable bytes.
//! * A client write is acknowledged only after its slot commits and the
//!   decided value at that slot is the client's own batch.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const paxos = @import("paxos");

const command = @import("command.zig");
const types = @import("types.zig");
const trim = @import("trim.zig");
const wire = @import("wire.zig");
const transport_auth = @import("transport_auth.zig");
const tls = @import("tls.zig");
const node_mod = @import("node.zig");
const sqlite = @import("sqlite.zig");
const prepared = @import("prepared.zig");
const search_api = @import("search_api.zig");
const payload_store_mod = @import("payload_store.zig");
const enrollment = @import("enrollment.zig");
const failpoint = @import("failpoint.zig");
const status_json = @import("status_json.zig");
const server_open_hint = @import("server_open_hint.zig");
const roles = @import("roles.zig");
const diagnostic = @import("diagnostic.zig");
const durability = @import("durability.zig");
const configuration = @import("configuration.zig");
const registry = @import("registry.zig");
const replacement_error = @import("replacement_error.zig");
const leader_frontier = @import("leader_frontier.zig");
const deadlines = @import("net_deadline.zig");
const server_options = @import("server_options.zig");
const server_test_control = @import("server_test_control.zig");

const Node = node_mod.Node;
const Log = types.Log;

pub const PeerAddress = server_options.PeerAddress;
pub const ServeOptions = server_options.ServeOptions;
pub const TestFaults = server_options.TestFaults;
pub const deriveDatabaseId = server_options.deriveDatabaseId;

/// Bounded copy of one administrator principal name.
pub const AdminName = struct {
    bytes: [tls.max_admin_name]u8 = undefined,
    len: u8 = 0,

    pub fn slice(self: *const AdminName) []const u8 {
        return self.bytes[0..self.len];
    }

    fn from(name: []const u8) AdminName {
        var result = AdminName{ .len = @intCast(name.len) };
        @memcpy(result.bytes[0..name.len], name);
        return result;
    }
};

/// Authenticated identity of one connection, fixed at the TLS handshake.
/// PSK and unix-socket connections carry no certificate and stay
/// anonymous, which keeps privileged membership operations structurally
/// unreachable in development modes.
pub const Principal = union(enum) {
    anonymous,
    /// A cluster node certificate, `zaxon-node-<id>`.
    node: paxos.NodeId,
    /// An administrator certificate, `zaxon-admin-<name>`.
    admin: AdminName,
};

/// One immutable transport-membership generation, derived from the decided
/// registry (or from startup flags on registry-less hosts). Readers load
/// the current generation with one atomic pointer read; superseded
/// generations stay allocated until shutdown so borrowed member records
/// can never dangle across an in-process swap.
const MemberGeneration = struct {
    configuration_id: u64,
    members: []PeerAddress,
    hosts: [][]u8,

    fn destroy(self: *MemberGeneration, gpa: std.mem.Allocator) void {
        for (self.hosts) |host| gpa.free(host);
        gpa.free(self.hosts);
        gpa.free(self.members);
        gpa.destroy(self);
    }
};

/// True when a transport generation reflects exactly the decided
/// registry's IDs, roles, and endpoints.
fn membershipMatchesRegistry(
    generation: *const MemberGeneration,
    decided: *const registry.Decided,
) bool {
    const records = decided.nodesSlice();
    if (generation.members.len != records.len) return false;
    for (generation.members, records) |member, *record| {
        if (member.id != record.id or member.role != record.role) return false;
        const parsed = parseEndpoint(record.endpointSlice()) catch return false;
        if (member.port != parsed.port or
            !std.mem.eql(u8, member.host, parsed.host))
        {
            return false;
        }
    }
    return true;
}

/// Splits a registry endpoint (`host:port`) at its last colon.
fn parseEndpoint(endpoint: []const u8) !struct { host: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse
        return error.InvalidEndpoint;
    if (colon == 0 or colon + 1 == endpoint.len) return error.InvalidEndpoint;
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch
        return error.InvalidEndpoint;
    return .{ .host = endpoint[0..colon], .port = port };
}

/// Builds one generation from the node's decided registry, or from the
/// startup flags when the host keeps flag-fixed membership.
fn buildMemberGeneration(
    gpa: std.mem.Allocator,
    node: *Node,
    fallback: []const PeerAddress,
) !*MemberGeneration {
    const generation = try gpa.create(MemberGeneration);
    errdefer gpa.destroy(generation);
    if (node.decidedRegistry()) |decided| {
        const records = decided.nodesSlice();
        const members = try gpa.alloc(PeerAddress, records.len);
        errdefer gpa.free(members);
        const hosts = try gpa.alloc([]u8, records.len);
        errdefer gpa.free(hosts);
        var host_count: usize = 0;
        errdefer for (hosts[0..host_count]) |host| gpa.free(host);
        for (records, 0..) |*record, index| {
            const parsed = try parseEndpoint(record.endpointSlice());
            hosts[index] = try gpa.dupe(u8, parsed.host);
            host_count += 1;
            members[index] = .{
                .id = record.id,
                .host = hosts[index],
                .port = parsed.port,
                .role = record.role,
            };
        }
        generation.* = .{
            .configuration_id = decided.configuration_id,
            .members = members,
            .hosts = hosts,
        };
        return generation;
    }
    const members = try gpa.alloc(PeerAddress, fallback.len);
    errdefer gpa.free(members);
    const hosts = try gpa.alloc([]u8, fallback.len);
    errdefer gpa.free(hosts);
    var host_count: usize = 0;
    errdefer for (hosts[0..host_count]) |host| gpa.free(host);
    for (fallback, 0..) |member, index| {
        hosts[index] = try gpa.dupe(u8, member.host);
        host_count += 1;
        members[index] = .{
            .id = member.id,
            .host = hosts[index],
            .port = member.port,
            .role = member.role,
        };
    }
    generation.* = .{
        .configuration_id = node.identity.configuration_id,
        .members = members,
        .hosts = hosts,
    };
    return generation;
}

/// Milliseconds a client operation may wait before reporting a timeout.
const op_timeout_ms: u64 = 10_000;
const held_hash_limit = 64;
const held_per_hash = 8;
const sender_queue_limit = 4096;
const sender_queue_byte_limit: usize = 128 * 1024 * 1024;
const snapshot_chunk_bytes: usize = 1024 * 1024;
const max_revoked_nodes: usize = 4 * types.log_options.max_members;

pub fn serve(
    gpa: std.mem.Allocator,
    io: Io,
    options: ServeOptions,
    err_out: *Io.Writer,
) !u8 {
    if (options.mmap_size > sqlite.max_mmap_bytes) {
        return reportMmapSize(err_out, options.mmap_size);
    }
    if (options.test_faults.enabled() and !options.enable_failpoints) {
        return reportConfig(err_out, "test fault schedules require --enable-failpoints");
    }
    if (options.allow_insecure_test_tcp and !options.enable_failpoints) {
        return reportConfig(
            err_out,
            "insecure test TCP requires --enable-failpoints",
        );
    }
    if (options.allow_psk_only_loopback and options.allow_insecure_test_tcp) {
        return reportConfig(
            err_out,
            "choose either development PSK or insecure test TCP, not both",
        );
    }
    if (options.auth_secret) |secret| {
        if (secret.len < 32) {
            return reportConfig(
                err_out,
                "transport secret must contain at least 32 bytes",
            );
        }
    }
    if (options.allow_psk_only_loopback) {
        if (options.auth_secret == null) {
            return reportConfig(err_out, "--dev-psk requires --auth-file");
        }
        if (options.tls != null) {
            return reportConfig(
                err_out,
                "--dev-psk is PSK-only; omit it when mTLS is configured",
            );
        }
        if (options.listen_unix != null or
            !isNumericLoopback(options.listen_host))
        {
            return reportConfig(
                err_out,
                "--dev-psk is loopback-only; use 127.0.0.1 or ::1",
            );
        }
        for (options.members) |member| {
            if (!isNumericLoopback(member.host)) {
                return reportConfig(
                    err_out,
                    "--dev-psk accepts only loopback peer addresses",
                );
            }
        }
    }
    if (options.tls) |config| {
        configuration.validatePrivateFile(io, config.key_path) catch |err| {
            try diagnostic.write(
                err_out,
                "unsafe TLS private key",
                @errorName(err),
                "Use a regular, non-symlink key file with mode 0600.",
            );
            try err_out.flush();
            return 4;
        };
    }
    if (options.enrollment_ca_key) |ca_key_path| {
        if (options.tls == null or options.listen_unix != null) {
            return reportConfig(
                err_out,
                "enrollment requires a TLS TCP listener",
            );
        }
        configuration.validatePrivateFile(io, ca_key_path) catch |err| {
            try diagnostic.write(
                err_out,
                "unsafe enrollment CA private key",
                @errorName(err),
                "Use a regular, non-symlink CA key file with mode 0600.",
            );
            try err_out.flush();
            return 4;
        };
        tls.validateIssuer(options.tls.?.ca_path, ca_key_path) catch |err| {
            try diagnostic.write(
                err_out,
                "enrollment issuer failed",
                @errorName(err),
                "Use the private key matching --tls-ca, or omit " ++
                    "--enrollment-ca-key on nodes that do not issue tokens.",
            );
            try err_out.flush();
            return 4;
        };
    }
    if (options.listen_unix != null and options.members.len > 1) {
        return reportConfig(
            err_out,
            "a unix socket serves one local node; peers require TCP",
        );
    }
    if (comptime builtin.os.tag == .windows) {
        if (options.listen_unix != null) {
            return reportConfig(
                err_out,
                "unix socket listeners are not available on Windows",
            );
        }
    }
    if (options.listen_unix == null) {
        if (options.tls == null and !options.allow_insecure_test_tcp and
            !options.allow_psk_only_loopback)
        {
            try diagnostic.write(
                err_out,
                "mutual TLS required",
                "Every production TCP listener requires a node certificate " ++
                    "from the cluster CA. A PSK alone does not provide " ++
                    "confidentiality or a unique node identity.",
                "Provide --tls-cert/--tls-key/--tls-ca. For a local tutorial, " ++
                    "pair an owner-only --auth-file with --dev-psk, or serve " ++
                    "one local node through --listen unix:<path>.",
            );
            try err_out.flush();
            return 4;
        }
    }

    var member_ids: [types.log_options.max_members]paxos.NodeId = undefined;
    var member_count: usize = 0;
    var campaigner_count: usize = 0;
    var self_role: roles.Role = .data_voter;
    var found_self = options.members.len == 0;
    var seen_ids = std.AutoHashMap(paxos.NodeId, void).init(gpa);
    defer seen_ids.deinit();
    for (options.members) |member| {
        if (member.id == 0) return reportConfig(err_out, "node IDs must be non-zero");
        const inserted = seen_ids.getOrPut(member.id) catch
            return reportConfig(err_out, "cannot allocate the node registry");
        if (inserted.found_existing) {
            return reportConfig(err_out, "node ID appears more than once");
        }
        if (member.id == options.node_id) {
            if (found_self) return reportConfig(err_out, "node ID appears more than once");
            found_self = true;
            self_role = member.role;
        }
        if (!member.role.capabilities().votes) continue;
        if (member.role.capabilities().campaigns) campaigner_count += 1;
        if (member_count >= member_ids.len) {
            return reportConfig(err_out, "too many Paxos voters (maximum is 9)");
        }
        member_ids[member_count] = member.id;
        member_count += 1;
    }
    if (!found_self) return reportConfig(err_out, "this node is absent from --node registry");
    if (options.members.len > 0 and member_count == 0) {
        return reportConfig(err_out, "at least one Paxos voter is required");
    }
    if (options.members.len > 0 and campaigner_count == 0) {
        return reportConfig(err_out, "at least one data voter must be able to campaign");
    }
    if (self_role == .gateway) {
        return reportConfig(err_out, "gateway nodes use the gateway command");
    }
    if (member_count == 0) {
        member_ids[0] = options.node_id;
        member_count = 1;
    }
    std.mem.sort(paxos.NodeId, member_ids[0..member_count], {}, std.sort.asc(paxos.NodeId));

    // Network-hosted nodes persist the product registry; the durable
    // decided registry is the membership authority from the first boot on.
    // A unix-socket local node keeps flag-fixed membership and no registry.
    var registry_records: [registry.max_nodes]registry.NodeRecord = undefined;
    var registry_count: usize = 0;
    const registry_nodes: ?[]const registry.NodeRecord = blk: {
        if (options.listen_unix != null) break :blk null;
        if (options.members.len > registry.max_nodes) {
            return reportConfig(err_out, "node registry exceeds the registry bound");
        }
        if (options.members.len == 0) {
            var endpoint_buffer: [registry.max_endpoint_bytes]u8 = undefined;
            const endpoint = std.fmt.bufPrint(
                &endpoint_buffer,
                "{s}:{d}",
                .{ options.listen_host, options.listen_port },
            ) catch return reportConfig(err_out, "listen endpoint is too long");
            registry_records[0] = registry.NodeRecord.init(
                options.node_id,
                self_role,
                endpoint,
            ) catch return reportConfig(err_out, "listen endpoint is invalid");
            registry_count = 1;
            break :blk registry_records[0..registry_count];
        }
        for (options.members) |member| {
            var endpoint_buffer: [registry.max_endpoint_bytes]u8 = undefined;
            const endpoint = std.fmt.bufPrint(
                &endpoint_buffer,
                "{s}:{d}",
                .{ member.host, member.port },
            ) catch return reportConfig(err_out, "peer endpoint is too long");
            registry_records[registry_count] = registry.NodeRecord.init(
                member.id,
                member.role,
                endpoint,
            ) catch return reportConfig(err_out, "peer endpoint is invalid");
            registry_count += 1;
        }
        break :blk registry_records[0..registry_count];
    };

    const node = Node.open(gpa, io, .{
        .directory = options.directory,
        .node_id = options.node_id,
        .members = member_ids[0..member_count],
        .leader_priority = options.node_id,
        .database_id = options.database_id,
        .role = self_role,
        .registry_nodes = registry_nodes,
        .test_storage_delay_ms = options.test_faults.storage_delay_ms,
        .mmap_size = options.mmap_size,
        .retention_slots = options.retention_slots,
        .journal_cap_bytes = options.journal_cap_bytes,
    }) catch |err| {
        try diagnostic.write(
            err_out,
            "node open failed",
            @errorName(err),
            server_open_hint.forError(err),
        );
        try err_out.flush();
        return 4;
    };

    const initial_generation = buildMemberGeneration(
        gpa,
        node,
        options.members,
    ) catch |err| {
        node.close();
        try diagnostic.write(
            err_out,
            "member registry invalid",
            @errorName(err),
            "Check the decided registry endpoints before retrying.",
        );
        try err_out.flush();
        return 4;
    };

    var server = Server{
        .gpa = gpa,
        .io = io,
        .node = node,
        .options = options,
        .membership = .init(initial_generation),
        .transport_configuration_id = initial_generation.configuration_id,
        .held = std.AutoHashMap(command.HashBytes, Held).init(gpa),
    };
    defer server.deinit();
    try server.member_generations.append(gpa, initial_generation);
    if (options.revocation_file != null) {
        server.reloadRevocationsLocked() catch |err| {
            try diagnostic.write(
                err_out,
                "revocation file invalid",
                @errorName(err),
                "Use one configured non-zero node ID per line; comments " ++
                    "start with #.",
            );
            try err_out.flush();
            return 4;
        };
    }

    if (options.tls) |tls_config| {
        server.tls_server = (if (options.enrollment_ca_key != null)
            tls.Context.initEnrollmentServer(tls_config)
        else
            tls.Context.initServer(tls_config)) catch |err| {
            try diagnostic.write(
                err_out,
                "tls identity failed",
                @errorName(err),
                "Check that --tls-cert, --tls-key, and --tls-ca name " ++
                    "readable PEM files and that the key matches the " ++
                    "certificate.",
            );
            try err_out.flush();
            return 4;
        };
        server.tls_client = tls.Context.initClient(tls_config) catch |err| {
            try diagnostic.write(
                err_out,
                "tls identity failed",
                @errorName(err),
                "Check that --tls-cert, --tls-key, and --tls-ca name " ++
                    "readable PEM files and that the key matches the " ++
                    "certificate.",
            );
            try err_out.flush();
            return 4;
        };
    }

    if (options.listen_unix) |socket_path| {
        server.listener = listenUnixSocket(
            io,
            socket_path,
            options.listen_unix_mode,
        ) catch |err| {
            try diagnostic.write(
                err_out,
                "unix socket listen failed",
                @errorName(err),
                "Remove a stale socket path only after confirming no server " ++
                    "owns it, and check the directory's permissions.",
            );
            try err_out.flush();
            return 4;
        };
    } else {
        const address = std.Io.net.IpAddress.parse(
            options.listen_host,
            options.listen_port,
        ) catch {
            try diagnostic.write(
                err_out,
                "invalid listen address",
                options.listen_host,
                "Use a numeric loopback or network address and a valid port.",
            );
            try err_out.flush();
            return 2;
        };
        server.listener = address.listen(io, .{ .reuse_address = true }) catch |err| {
            try diagnostic.write(
                err_out,
                "listen failed",
                @errorName(err),
                "Check address ownership, port availability, and permissions.",
            );
            try err_out.flush();
            return 4;
        };
    }
    // Orderly shutdown removes the socket path so the next start does not
    // find a stale one; an unlink-refusing crash leaves it for the
    // operator, which the listen diagnostic above explains.
    defer if (options.listen_unix) |socket_path| {
        Io.Dir.cwd().deleteFile(io, socket_path) catch {};
    };

    try writeStartupSummary(&server, self_role, err_out);

    // One sender per peer of the active membership generation.
    try server.buildSenders();
    server.node.setPreDurableOutboxHook(.{
        .context = &server,
        .run = drainPreDurableOutbox,
    });
    errdefer {
        server.shutdown();
        for (server.senders.items) |sender| {
            if (sender.spawned) sender.thread.join();
        }
    }
    try server.spawnSenders();
    const ticker = try std.Thread.spawn(.{}, Server.tickLoop, .{&server});

    // Accept loop. The `stop` RPC sets the shutdown flag and then dials
    // the listener once (`wakeAcceptLoop`) so a blocked `accept` returns
    // on every platform; the admission gate refuses that connection.
    var listener = server.listener.?;
    while (!server.isShutdown()) {
        const stream = listener.accept(io) catch |err| switch (err) {
            error.SocketNotListening, error.Canceled => break,
            error.ConnectionAborted => continue,
            else => break,
        };
        server.noteHandlerStarted(stream) catch {
            stream.close(io);
            continue;
        };
        const handler = std.Thread.spawn(
            .{},
            Server.handleConnectionTracked,
            .{ &server, stream },
        ) catch {
            server.noteHandlerClosing(stream);
            var s = stream;
            s.close(io);
            server.noteHandlerFinished();
            continue;
        };
        handler.detach();
    }

    std.log.info("node {d}: shutting down", .{options.node_id});
    server.listener.?.deinit(io);
    server.listener = null;
    server.shutdown();
    ticker.join();
    for (server.senders.items) |sender| {
        if (sender.spawned) sender.thread.join();
    }
    server.waitForHandlers();
    if (server.first_failure) |err| {
        const hint = if (err == error.TrimRegression)
            "Inspect the TRIM file and the journal trim anchors; a diverged " ++
                "history at one slot needs replacement (ZDS 0008)."
        else
            "Read this node's log for the first failure; restart after the " ++
                "durable files are repaired.";
        try diagnostic.write(err_out, "node failed", @errorName(err), hint);
        try err_out.flush();
    }
    std.log.info("node {d}: stopped", .{options.node_id});
    return if (server.failed) 4 else 0;
}

fn isNumericLoopback(host: []const u8) bool {
    return std.mem.eql(u8, host, "127.0.0.1") or
        std.mem.eql(u8, host, "::1");
}

fn writeStartupSummary(
    server: *const Server,
    role: roles.Role,
    err_out: *Io.Writer,
) !void {
    const options = server.options;
    const member_count = if (options.members.len == 0) 1 else options.members.len;
    const transport = if (options.listen_unix != null)
        "owner-only Unix socket"
    else if (options.tls != null and options.auth_secret != null)
        "mTLS 1.3 + PSK"
    else if (options.tls != null)
        "mTLS 1.3"
    else if (options.allow_psk_only_loopback)
        "development PSK (loopback only)"
    else
        "INSECURE TEST TCP";

    try err_out.print(
        "\n" ++
            "zaxon node {d}\n" ++
            "  state       starting; waiting for a leader\n" ++
            "  role        {s}\n" ++
            "  data        {s}\n",
        .{ options.node_id, role.name(), options.directory },
    );
    if (options.listen_unix) |path| {
        try err_out.print("  listen      unix:{s}\n", .{path});
    } else {
        try err_out.print(
            "  listen      {s}:{d}\n",
            .{ options.listen_host, options.listen_port },
        );
    }
    try err_out.print(
        "  transport   {s}\n" ++
            "  cluster     {d} member(s), configuration {d}\n" ++
            "  durability  {s} sync\n\n",
        .{
            transport,
            member_count,
            server.node.identity.configuration_id,
            @tagName(durability.syncMode()),
        },
    );
    try err_out.flush();
}

/// Runs from `Node.consumeEffects` while the caller already owns the server
/// mutex. `drainOutbox` only takes per-sender queue locks, allowing sender
/// threads to put the accept requests on the wire during the journal barrier.
fn drainPreDurableOutbox(context: *anyopaque) anyerror!void {
    const server: *Server = @ptrCast(@alignCast(context));
    try server.drainOutbox();
}

/// Binds the local Unix-domain service socket. A pre-existing path is
/// refused rather than unlinked: silently replacing it could hijack a
/// live server's clients or delete an unrelated file, so a stale socket
/// needs explicit operator removal. `bind` remains the authoritative
/// existence check (`AddressInUse`); the probe only improves the
/// diagnostic. Permissions are narrowed immediately after binding, so
/// the socket should still live in an operator-owned directory.
fn listenUnixSocket(
    io: Io,
    path: []const u8,
    mode: u16,
) !std.Io.net.Server {
    // Windows has AF_UNIX but no file mode on it: access is governed by a
    // DACL the narrowing below cannot express, so a socket bound here
    // would be reachable by every local account. Refusing is the safe
    // answer until the DACL work is done; loopback TCP still serves.
    if (comptime builtin.os.tag == .windows) return error.UnixSocketUnsupported;
    const address = try std.Io.net.UnixAddress.init(path);
    var exists = true;
    Io.Dir.cwd().access(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => exists = false,
        else => return err,
    };
    if (exists) return error.SocketPathExists;
    var listener = try address.listen(io, .{});
    errdefer listener.deinit(io);
    var path_z_buffer: [std.Io.net.UnixAddress.max_len + 1]u8 = undefined;
    const path_z = std.mem.printSentinel(&path_z_buffer, "{s}", .{path}, 0) catch
        return error.NameTooLong;
    if (std.c.fchmodat(std.posix.AT.FDCWD, path_z, mode, 0) != 0) {
        return error.PermissionChangeFailed;
    }
    return listener;
}

fn reportConfig(err_out: *Io.Writer, message: []const u8) !u8 {
    try diagnostic.write(
        err_out,
        "invalid cluster configuration",
        message,
        "Give every node the same role registry and a unique non-zero ID.",
    );
    try err_out.flush();
    return 2;
}

fn reportMmapSize(err_out: *Io.Writer, requested: u64) !u8 {
    var message_buffer: [160]u8 = undefined;
    const message = std.fmt.bufPrint(
        &message_buffer,
        "The requested mmap limit is {d} bytes; the maximum is {d} bytes.",
        .{ requested, sqlite.max_mmap_bytes },
    ) catch unreachable;
    try diagnostic.write(
        err_out,
        "invalid mmap size",
        message,
        "Use --mmap-size 0 to disable mapped I/O, or choose at most 1073741824.",
    );
    try err_out.flush();
    return 2;
}

const Held = struct {
    envelopes: [held_per_hash]Log.Envelope = undefined,
    count: usize = 0,
    from: paxos.NodeId = 0,
};

const wait_types = @import("server_waiters.zig");
const WriteWaiter = wait_types.WriteWaiter;
const FenceWaiter = wait_types.FenceWaiter;
const HistoryProbeWaiter = wait_types.HistoryProbeWaiter;
const WaitWaiter = wait_types.WaitWaiter;

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: Io,
    node: *Node,
    options: ServeOptions,
    mutex: std.Io.Mutex = .init,
    /// Kept separate from `mutex`: history vouches must be recordable
    /// while the transfer receiver waits for its voter read quorum.
    proof_mutex: std.Io.Mutex = .init,
    proof_waiter: ?*HistoryProbeWaiter = null,
    next_proof_nonce: u64 = 1,
    /// Set once a decided stop sign replaced this voter: the node stays
    /// permanently sealed and the server stops attempting rollover.
    retired: bool = false,
    /// This node's own snapshot-install lifecycle while it joins as a
    /// decided replacement; `not_applicable` on every other node.
    installation: enum {
        not_applicable,
        transferring,
        verifying,
        installed,
        active,
        failed,
    } = .not_applicable,
    installation_failure: ?anyerror = null,
    /// Explicit durable-readiness evidence received from the replacement.
    /// Connection state alone never changes installation status.
    replacement_ready_node: ?paxos.NodeId = null,
    replacement_ready_configuration: u64 = 0,
    listener: ?std.Io.net.Server = null,
    senders: std.ArrayList(*PeerSender) = .empty,
    /// The active transport-membership generation; swapped atomically by
    /// `rebuildTransport` after a decided membership change.
    membership: std.atomic.Value(*const MemberGeneration),
    /// Configuration whose sender and admission generation is published.
    /// Paxos envelopes are held while Node rollover runs ahead of it.
    transport_configuration_id: u64,
    /// Every generation ever published, owned until shutdown so borrowed
    /// member records never dangle across a swap.
    member_generations: std.ArrayList(*MemberGeneration) = .empty,
    held: std.AutoHashMap(command.HashBytes, Held),
    held_total: usize = 0,
    write_waiter: ?*WriteWaiter = null,
    /// FIFO writer-gate admission (ZDS 0010): the gate owner runs one
    /// replicated write; contending writers park a ticket in an intrusive
    /// queue and are granted strictly in arrival order, so a sustained
    /// stream of writers cannot starve one caller into its deadline.
    writer_gate_busy: bool = false,
    writer_queue_head: ?*WriterTicket = null,
    writer_queue_tail: ?*WriterTicket = null,
    writer_cond: std.Io.Condition = .init,
    fences: std.ArrayList(*FenceWaiter) = .empty,
    next_fence_id: u64 = 1,
    waiters: std.ArrayList(*WaitWaiter) = .empty,
    rollover_cond: std.Io.Condition = .init,
    checkpoint_started: bool = false,
    observed_leader_decided: paxos.Slot = 0,
    /// Last voter that supplied a certified chosen value to this learner.
    /// Learners do not participate in leader election, so the Paxos core
    /// intentionally has no local leader observation for them.
    learner_leader: ?paxos.NodeId = null,
    learner_last_contact_tick: ?u64 = null,
    last_learner_heartbeat_tick: ?u64 = null,
    snapshot_source: ?paxos.NodeId = null,
    /// Rotating cursor over registry peers for leaderless joiner
    /// recovery probes.
    recovery_probe: usize = 0,
    snapshot_requested_tick: u64 = 0,
    catch_up_last_decided: paxos.Slot = 0,
    catch_up_stalled: u32 = 0,
    /// Signalled when the applied frontier moves while a client waits for
    /// the leader to finish applying what it inherited (issue #5).
    frontier_cond: std.Io.Condition = .init,
    frontier_waiters: u32 = 0,
    frontier_last_applied: paxos.Slot = 0,
    /// Set while parked votes are re-queued so the drain does not park
    /// them again.
    releasing_votes: bool = false,
    /// Phase-two votes parked by the `vote_delay_ms` test fault.
    held_votes: std.ArrayList(struct { envelope: Log.Envelope, release_tick: u64 }) = .empty,
    /// Latest per-peer progress reports for trim coordination (ZDS 0011).
    frontiers: [types.log_options.max_members]?trim.Frontier =
        @as([types.log_options.max_members]?trim.Frontier, @splat(null)),
    last_reported_durable: paxos.Slot = 0,
    tick_count: u64 = 0,
    failed: bool = false,
    /// First terminal host error. Protected by `mutex` and never cleared.
    first_failure: ?anyerror = null,
    fatal_shutdown_requested: bool = false,
    shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop_response_requested: bool = false, // Protected by mutex; only the first stop wins.
    stop_response_sent: Io.Event = .unset,
    handler_count: usize = 0,
    handler_cond: std.Io.Condition = .init,
    /// Prevents handlers from closing descriptors while shutdown performs
    /// its off-lock interruption pass over a stable snapshot.
    connection_interrupting: bool = false,
    active_connections: std.ArrayList(TrackedConnection) = .empty,
    /// Present when `options.tls` is set: responder identity for accepted
    /// connections and initiator identity for peer dialing.
    tls_server: ?tls.Context = null,
    tls_client: ?tls.Context = null,
    revoked_nodes: [max_revoked_nodes]paxos.NodeId =
        @as([max_revoked_nodes]paxos.NodeId, @splat(0)),
    revoked_count: usize = 0,
    /// Last leadership state already reported to the operator. Startup
    /// prints the initial waiting state; later transitions are concise.
    reported_leader: ?paxos.NodeId = null,
    leader_candidate: ?paxos.NodeId = null,
    leader_candidate_ticks: u8 = 0,

    const TrackedConnection = struct {
        stream: std.Io.net.Stream,
        /// Absolute tick-clock millisecond by which hello and
        /// authentication must have completed; 0 once established (or
        /// when the deadline is disabled).
        handshake_deadline_ms: u64,
        idle_deadline_ms: u64 = 0,
        credential_node_id: ?paxos.NodeId = null,
        /// Shut down by newest-wins eviction and awaiting its handler's
        /// reap; excluded from the live count so concurrent handshakes
        /// cannot evict one victim twice and overshoot the limit.
        closing: bool = false,
    };

    fn deinit(self: *Server) void {
        std.debug.assert(self.active_connections.items.len == 0);
        for (self.senders.items) |sender| {
            sender.deinit();
            self.gpa.destroy(sender);
        }
        self.senders.deinit(self.gpa);
        for (self.member_generations.items) |generation| {
            generation.destroy(self.gpa);
        }
        self.member_generations.deinit(self.gpa);
        self.fences.deinit(self.gpa);
        self.waiters.deinit(self.gpa);
        self.held_votes.deinit(self.gpa);
        self.active_connections.deinit(self.gpa);
        self.held.deinit();
        if (self.listener) |*listener| listener.deinit(self.io);
        if (self.tls_server) |*context| context.deinit();
        if (self.tls_client) |*context| context.deinit();
        self.node.close();
    }

    fn isShutdown(self: *Server) bool {
        return self.shutdown_flag.load(.acquire);
    }

    fn peerRevokedLocked(self: *const Server, peer: paxos.NodeId) bool {
        for (self.revoked_nodes[0..self.revoked_count]) |revoked| {
            if (revoked == peer) return true;
        }
        return false;
    }

    fn peerRevoked(self: *Server, peer: paxos.NodeId) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.peerRevokedLocked(peer);
    }

    /// Replaces revocation state atomically from a small, deliberately
    /// boring text file. Called with `mutex` held after startup.
    fn reloadRevocationsLocked(self: *Server) !void {
        const path = self.options.revocation_file orelse return;
        const bytes = try Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.gpa,
            .limited(16 * 1024),
        );
        defer self.gpa.free(bytes);
        var next = @as([max_revoked_nodes]paxos.NodeId, @splat(0));
        var count: usize = 0;
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |raw_line| {
            const before_comment = if (std.mem.indexOfScalar(u8, raw_line, '#')) |index|
                raw_line[0..index]
            else
                raw_line;
            const line = std.mem.trim(u8, before_comment, " \t\r");
            if (line.len == 0) continue;
            const id = std.fmt.parseInt(paxos.NodeId, line, 10) catch
                return error.InvalidRevocationFile;
            if (id == 0 or id == self.options.node_id) {
                return error.InvalidRevocationFile;
            }
            if (self.addressOf(id) == null or count == next.len) {
                return error.InvalidRevocationFile;
            }
            for (next[0..count]) |seen| {
                if (seen == id) return error.InvalidRevocationFile;
            }
            next[count] = id;
            count += 1;
        }
        self.revoked_nodes = next;
        self.revoked_count = count;
    }

    /// The decided registry owns consensus membership. This transport denylist
    /// is the immediate operational override for a compromised node.
    fn evictRevokedLocked(self: *Server) void {
        for (self.active_connections.items) |connection| {
            const peer = connection.credential_node_id orelse continue;
            if (self.peerRevokedLocked(peer)) {
                connection.stream.shutdown(self.io, .both) catch {};
            }
        }
        for (self.senders.items) |sender| {
            if (self.peerRevokedLocked(sender.peer.id)) sender.disconnect();
        }
    }

    /// Milliseconds elapsed since `start_tick`, measured in ticks.
    fn elapsedMs(self: *const Server, start_tick: u64) u64 {
        return (self.tick_count -| start_tick) * self.options.tick_ms;
    }

    /// Wakes every blocked waiter so it re-checks its condition and its
    /// deadline. Called once per tick with the mutex held.
    fn wakeWaiters(self: *Server) void {
        self.writer_cond.broadcast(self.io);
        self.rollover_cond.broadcast(self.io);
        self.frontier_cond.broadcast(self.io);
        if (self.write_waiter) |waiter| waiter.cond.signal(self.io);
        for (self.fences.items) |fence| fence.cond.signal(self.io);
        for (self.waiters.items) |waiter| waiter.cond.signal(self.io);
    }

    /// Wakes the serve thread out of a blocked `accept`. Closing the
    /// listening socket interrupts `accept` only on BSD kernels; Linux
    /// leaves the thread blocked forever. Connecting to our own listener
    /// and hanging up wakes it everywhere: the admission gate refuses the
    /// connection during shutdown and the serve loop re-checks the flag
    /// before the next accept. The serve thread closes the listener before
    /// draining handlers, so no other thread races its descriptor.
    fn wakeAcceptLoop(self: *Server) void {
        if (self.options.listen_unix) |path| {
            const stream = deadlines.connectUnix(
                self.io,
                path,
                deadlines.after(self.io, 1000),
            ) catch return;
            stream.close(self.io);
            return;
        }
        const address = std.Io.net.IpAddress.parse(
            self.options.listen_host,
            self.options.listen_port,
        ) catch return;
        const stream = deadlines.connectIp(
            self.io,
            address,
            deadlines.after(self.io, 1000),
        ) catch return;
        stream.close(self.io);
    }

    fn requestShutdown(self: *Server, source: enum { local, rpc }) void {
        self.mutex.lockUncancelable(self.io);
        const already_requested = self.shutdown_flag.swap(true, .acq_rel);
        if (!already_requested) self.stop_response_requested = source == .rpc;
        self.wakeWaiters();
        self.mutex.unlock(self.io);
        if (!already_requested) self.wakeAcceptLoop();
    }

    fn shutdown(self: *Server) void {
        self.mutex.lockUncancelable(self.io);
        self.shutdown_flag.store(true, .release);
        const response_pending = self.stop_response_requested and !self.failed;
        self.wakeWaiters();
        self.mutex.unlock(self.io);
        // Only RPC shutdown has a reply to flush. A sleep count is not a deadline:
        // scheduler delays can stretch each nominal millisecond substantially.
        const end = deadlines.after(self.io, 250);
        while (response_pending and !self.stop_response_sent.isSet() and
            !deadlines.expired(self.io, end))
        {
            self.stop_response_sent.waitTimeout(self.io, .{ .deadline = end }) catch {};
        }
        self.mutex.lockUncancelable(self.io);
        self.connection_interrupting = true;
        // Handler removal waits while interruption owns the list, and shutdown
        // admission is already closed. Copy one descriptor at a time so this
        // terminal path neither allocates nor performs socket I/O under mutex.
        const connection_count = self.active_connections.items.len;
        var connection_index: usize = 0;
        while (connection_index < connection_count) : (connection_index += 1) {
            const connection = self.active_connections.items[connection_index];
            self.mutex.unlock(self.io);
            connection.stream.shutdown(self.io, .both) catch {};
            self.mutex.lockUncancelable(self.io);
        }
        self.connection_interrupting = false;
        self.handler_cond.broadcast(self.io);
        self.mutex.unlock(self.io);
        for (self.senders.items) |sender| {
            sender.requestStop();
        }
    }

    /// Admission limit for concurrent connections. The default is sized
    /// from the configured registry — every peer link plus headroom for
    /// operator clients and transfer streams — never from internet-scale
    /// assumptions.
    fn connectionLimit(self: *const Server) usize {
        if (self.options.max_connections != 0) return self.options.max_connections;
        return 4 * self.currentMembers().len + 16;
    }

    /// The active membership generation's records. Lock-free: one atomic
    /// pointer load of an immutable generation.
    fn currentMembers(self: *const Server) []const PeerAddress {
        return self.membership.load(.acquire).members;
    }

    /// Creates one sender per peer of the active generation. Voters
    /// distribute chosen values to every storage node; learners only need
    /// return paths to voters for payload ACKs and requests.
    fn buildSenders(self: *Server) !void {
        try self.buildSendersFor(
            self.membership.load(.acquire),
            &self.senders,
        );
    }

    fn buildSendersFor(
        self: *Server,
        generation: *const MemberGeneration,
        senders: *std.ArrayList(*PeerSender),
    ) !void {
        const self_votes = self.node.capabilities.votes;
        const self_id = self.node.identity.node_id;
        for (generation.members) |member| {
            if (member.id == self_id) continue;
            if (!member.role.capabilities().stores_log) continue;
            if (!self_votes and !member.role.capabilities().votes) continue;
            const sender = try self.gpa.create(PeerSender);
            sender.* = .{ .server = self, .peer = member };
            sender.stored_payloads =
                std.AutoHashMap(command.HashBytes, void).init(self.gpa);
            senders.append(self.gpa, sender) catch |err| {
                sender.deinit();
                self.gpa.destroy(sender);
                return err;
            };
        }
    }

    fn spawnSenders(self: *Server) !void {
        for (self.senders.items) |sender| {
            if (sender.spawned) continue;
            sender.thread = try std.Thread.spawn(.{}, PeerSender.run, .{sender});
            sender.spawned = true;
        }
    }

    /// True when the node's decided registry no longer matches the active
    /// transport generation. Same-member epoch rollovers keep the
    /// generation; only a decided membership change makes it stale.
    /// Caller holds `mutex`.
    fn transportStaleLocked(self: *Server) bool {
        const decided = self.node.decidedRegistry() orelse return false;
        const generation = self.membership.load(.acquire);
        return !membershipMatchesRegistry(generation, decided);
    }

    /// Housekeeping after the node entered a new configuration: reset
    /// per-epoch peer progress and wake rollover waiters. A same-member
    /// advance keeps the transport generation valid, so its traffic is
    /// released by adopting the new configuration id here; a decided
    /// membership change leaves the transport stale until
    /// `rebuildTransport` swaps it. Caller holds `mutex`.
    fn enterConfigurationLocked(self: *Server) void {
        if (!self.transportStaleLocked()) {
            self.transport_configuration_id =
                self.node.identity.configuration_id;
        }
        for (self.senders.items) |sender| sender.learned_through = 0;
        self.learner_leader = null;
        self.learner_last_contact_tick = null;
        self.rollover_cond.broadcast(self.io);
    }

    /// Rebuilds the transport boundary from the decided registry after an
    /// in-process rollover: publishes the next membership generation,
    /// tears down and rebuilds peer senders, and closes connections from
    /// nodes the registry removed. Client TCP connections stay open. Runs
    /// without `mutex` held; sender threads take that mutex themselves.
    fn rebuildTransport(self: *Server) !void {
        self.mutex.lockUncancelable(self.io);
        if (self.isShutdown()) {
            self.mutex.unlock(self.io);
            return;
        }
        const decided = self.node.decidedRegistry() orelse {
            self.mutex.unlock(self.io);
            return;
        };
        const previous = self.membership.load(.acquire);
        if (membershipMatchesRegistry(previous, decided)) {
            self.mutex.unlock(self.io);
            return;
        }
        const next = buildMemberGeneration(
            self.gpa,
            self.node,
            self.options.members,
        ) catch |err| {
            self.mutex.unlock(self.io);
            return err;
        };
        var next_senders: std.ArrayList(*PeerSender) = .empty;
        self.buildSendersFor(next, &next_senders) catch |err| {
            for (next_senders.items) |sender| {
                sender.deinit();
                self.gpa.destroy(sender);
            }
            next_senders.deinit(self.gpa);
            next.destroy(self.gpa);
            self.mutex.unlock(self.io);
            return err;
        };
        self.member_generations.append(self.gpa, next) catch |err| {
            for (next_senders.items) |sender| {
                sender.deinit();
                self.gpa.destroy(sender);
            }
            next_senders.deinit(self.gpa);
            next.destroy(self.gpa);
            self.mutex.unlock(self.io);
            return err;
        };
        failpoint.hit("before_transport_swap");

        // Publish the complete next generation in one locked transition.
        // New-epoch Paxos remains disabled until the old senders stop.
        var old_senders = self.senders;
        self.senders = next_senders;
        self.membership.store(next, .release);
        self.transport_configuration_id = next.configuration_id;
        self.replacement_ready_node = null;
        self.replacement_ready_configuration = 0;

        // Close inbound connections from nodes the registry removed, and
        // from stale anonymous peers; established client connections keep
        // their identity and stay open.
        for (self.active_connections.items) |connection| {
            const credential = connection.credential_node_id orelse continue;
            var still_registered = false;
            for (next.members) |member| {
                if (member.id == credential) still_registered = true;
            }
            if (!still_registered) {
                connection.stream.shutdown(self.io, .both) catch {};
            }
        }
        self.mutex.unlock(self.io);

        // Stop and join the old senders off-lock: a sender thread takes
        // the server mutex during its handshake, so joining under it
        // could deadlock.
        for (old_senders.items) |sender| sender.requestStop();
        for (old_senders.items) |sender| {
            if (sender.spawned) sender.thread.join();
            sender.deinit();
            self.gpa.destroy(sender);
        }
        old_senders.deinit(self.gpa);
        failpoint.hit("after_transport_teardown");

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.isShutdown()) return;
        if (self.installation == .installed) self.installation = .active;
        try self.spawnSenders();
        self.pump();
        failpoint.hit("after_transport_swap");
        std.log.info(
            "node {d}: transport rebuilt for configuration {d}",
            .{ self.node.identity.node_id, next.configuration_id },
        );
    }

    fn noteHandlerStarted(self: *Server, stream: std.Io.net.Stream) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        // Refusing at admission keeps every accepted connection's thread
        // and descriptors accountable to the documented limit, and stops
        // new work from starting during shutdown.
        if (self.isShutdown()) return error.ShuttingDown;
        if (self.handler_count >= self.connectionLimit()) {
            return error.ConnectionLimit;
        }
        const deadline = if (self.options.handshake_timeout_ms == 0)
            0
        else
            self.tick_count * self.options.tick_ms + self.options.handshake_timeout_ms;
        try self.active_connections.append(self.gpa, .{
            .stream = stream,
            .handshake_deadline_ms = deadline,
        });
        self.handler_count += 1;
    }

    /// Marks a connection as established after hello and authentication,
    /// clearing its handshake deadline.
    fn noteHandshakeComplete(
        self: *Server,
        stream: std.Io.net.Stream,
        credential_node_id: ?paxos.NodeId,
    ) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (credential_node_id) |id| {
            var count: usize = 0;
            var oldest: ?*TrackedConnection = null;
            for (self.active_connections.items) |*connection| {
                if (connection.credential_node_id == id and !connection.closing) {
                    count += 1;
                    if (oldest == null) oldest = connection;
                }
            }
            if (self.options.max_connections_per_peer != 0 and
                count >= self.options.max_connections_per_peer)
            {
                // Newest wins: a fresh reconnect must never lose to its
                // own not-yet-reaped predecessor, or a crash-restart
                // cycle churns forever with every new connection
                // rejected while stale entries hold the slots. Shut the
                // oldest down; its handler reaps it on the failed read.
                std.log.info(
                    "node {d}: evicting oldest connection of peer {d} " ++
                        "({d} at limit)",
                    .{ self.node.identity.node_id, id, count },
                );
                oldest.?.closing = true;
                oldest.?.stream.shutdown(self.io, .both) catch {};
            }
        }
        const now_ms = self.tick_count * self.options.tick_ms;
        for (self.active_connections.items) |*connection| {
            if (connection.stream.socket.handle == stream.socket.handle) {
                connection.handshake_deadline_ms = 0;
                connection.idle_deadline_ms = if (self.options.idle_timeout_ms == 0)
                    0
                else
                    now_ms + self.options.idle_timeout_ms;
                connection.credential_node_id = credential_node_id;
                break;
            }
        }
    }

    fn noteConnectionActivity(self: *Server, stream: std.Io.net.Stream) void {
        if (self.options.idle_timeout_ms == 0) return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const deadline = self.tick_count * self.options.tick_ms +
            self.options.idle_timeout_ms;
        for (self.active_connections.items) |*connection| {
            if (connection.stream.socket.handle == stream.socket.handle) {
                connection.idle_deadline_ms = deadline;
                break;
            }
        }
    }

    fn noteHandlerClosing(self: *Server, stream: std.Io.net.Stream) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.connection_interrupting) {
            self.handler_cond.waitUncancelable(self.io, &self.mutex);
        }
        for (self.active_connections.items, 0..) |connection, index| {
            if (connection.stream.socket.handle == stream.socket.handle) {
                _ = self.active_connections.swapRemove(index);
                return;
            }
        }
    }

    fn noteHandlerFinished(self: *Server) void {
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(self.handler_count > 0);
        self.handler_count -= 1;
        self.handler_cond.signal(self.io);
        self.mutex.unlock(self.io);
    }

    /// Shuts down sockets that have not completed hello and
    /// authentication before their deadline; the blocked handler thread
    /// then fails its read and releases the connection. Runs once per
    /// tick with the mutex held.
    fn closeExpiredConnections(self: *Server) void {
        const now_ms = self.tick_count * self.options.tick_ms;
        for (self.active_connections.items) |connection| {
            const handshake_expired = connection.handshake_deadline_ms != 0 and
                now_ms >= connection.handshake_deadline_ms;
            const idle_expired = connection.handshake_deadline_ms == 0 and
                connection.idle_deadline_ms != 0 and
                now_ms >= connection.idle_deadline_ms;
            if (handshake_expired or idle_expired) {
                connection.stream.shutdown(self.io, .both) catch {};
            }
        }
    }

    fn waitForHandlers(self: *Server) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.handler_count > 0) {
            self.handler_cond.waitUncancelable(self.io, &self.mutex);
        }
    }

    fn senderFor(self: *Server, peer: paxos.NodeId) ?*PeerSender {
        for (self.senders.items) |sender| {
            if (sender.peer.id == peer) return sender;
        }
        return null;
    }

    fn addressOf(self: *Server, peer: paxos.NodeId) ?PeerAddress {
        for (self.currentMembers()) |member| {
            if (member.id == peer) return member;
        }
        return null;
    }

    fn knownLeader(self: *const Server) ?paxos.NodeId {
        return self.node.currentLeader() orelse self.learner_leader;
    }

    // ------------------------------------------------------------------
    // The pump: reconcile host state after any node transition.
    // Must run with `mutex` held.
    // ------------------------------------------------------------------

    fn pump(self: *Server) void {
        self.pumpFallible() catch |err| {
            self.failLocked(err);
        };
    }

    /// First-failure-wins terminal transition. The caller holds `mutex`.
    /// Socket interruption and listener wakeup are deliberately left to
    /// teardown/ticker code running without the mutex.
    fn failLocked(self: *Server, err: anyerror) void {
        if (self.first_failure != null) return;
        self.first_failure = err;
        if (!builtin.is_test) {
            std.log.err(
                "node {d} failed: {s}",
                .{ self.node.identity.node_id, @errorName(err) },
            );
        }
        if (self.options.failure_name_buffer) |buffer| {
            const name = @errorName(err);
            const len: u8 = @intCast(@min(name.len, buffer.len));
            @memcpy(buffer[0..len], name[0..len]);
            if (self.options.failure_name_len) |published| {
                published.store(len, .release);
            }
        }
        self.failed = true;
        self.node.markFailed();
        self.failEverything();
        self.fatal_shutdown_requested = true;
    }

    fn failForTest(self: *Server) void {
        self.failLocked(error.TestHostFailure);
    }

    fn pumpFallible(self: *Server) !void {
        const previous_configuration = self.node.identity.configuration_id;

        try self.drainOutbox();
        try self.drainLearners();
        try self.heartbeatLearners();

        if (self.node.needsResync()) {
            // Any in-flight write is now of unknown fate.
            if (self.write_waiter) |waiter| {
                if (waiter.outcome == .pending) {
                    waiter.outcome = .conflict;
                    waiter.cond.signal(self.io);
                }
                self.write_waiter = null;
            }
            try self.node.resyncImage();
        }

        // Periodic durable-state anchoring (ZDS 0011): bounded, dirty-page
        // work in place of the old epoch rollover.
        if (!self.retired and self.node.capabilities.materializes) {
            _ = self.node.maybeCreateStateAnchor() catch |err| switch (err) {
                error.TransactionOpen, error.WriteInFlight => {},
                else => return err,
            };
        }

        // Broadcast a fresh progress report when the durable frontier
        // moved; peers use only authenticated reports for trimming.
        if (!self.retired and
            self.node.durable_state_slot > self.last_reported_durable)
        {
            self.broadcastStateReport();
        }

        // The leader proposes a conservative trim when every data replica
        // has reported and the minimum durable frontier advanced. The
        // candidate only moves on anchor publishes, so this is naturally
        // cadence-limited (ZDS 0011).
        if (!self.retired and self.node.isLeader()) {
            try self.maybeProposeTrim();
        }

        // Physical reclamation is off the commit path and retries on the next
        // pump. A failed unlink must not turn an otherwise healthy replica
        // into a terminal consensus failure.
        if (!self.retired) {
            self.node.reclaim() catch |err| std.log.warn(
                "reclamation failed: {s}",
                .{@errorName(err)},
            );
        }

        // A decided membership stop completes here: the survivor installs
        // the next registry and continues on the same global slot line; a
        // removed voter retires on its final configuration (ZDS 0008).
        if (!self.retired and self.node.membership_change_pending) {
            self.node.completeMembershipChange() catch |err| switch (err) {
                error.RetiredByReconfiguration => {
                    self.retired = true;
                    self.failEverything();
                },
                error.StopNotApplied => {},
                else => std.log.warn(
                    "membership completion failed: {s}",
                    .{@errorName(err)},
                ),
            };
        }

        if (self.node.identity.configuration_id != previous_configuration) {
            self.enterConfigurationLocked();
        }

        // Clients parked on the leader frontier wake as soon as catch-up
        // applies something, not on the next tick.
        if (self.node.applied_slot != self.frontier_last_applied) {
            self.frontier_last_applied = self.node.applied_slot;
            if (self.frontier_waiters > 0) self.frontier_cond.broadcast(self.io);
        }

        // Write waiter resolution.
        if (self.write_waiter) |waiter| {
            if (waiter.outcome == .pending and self.node.applied_slot >= waiter.slot) {
                waiter.outcome = .conflict;
                if (self.node.batchAtSlot(waiter.slot)) |batch_id| {
                    if (batch_id == waiter.batch_id) {
                        waiter.outcome = .committed;
                    }
                }
                waiter.cond.signal(self.io);
                self.write_waiter = null;
            }
        }

        // Fence resolution: a fence fails as soon as the ballot moves.
        var index: usize = 0;
        while (index < self.fences.items.len) {
            const fence = self.fences.items[index];
            if (!fence.ballot.eql(self.node.log.core.ballot) or
                self.node.log.core.role != .leader)
            {
                fence.failed = true;
            }
            const complete = fence.failed or
                (fence.ack_count >= fence.needed and
                    self.node.applied_slot >= fence.fence_slot);
            if (complete) {
                fence.done = true;
                fence.cond.signal(self.io);
                _ = self.fences.swapRemove(index);
                continue;
            }
            index += 1;
        }

        // Observable-condition waiters.
        index = 0;
        while (index < self.waiters.items.len) {
            const waiter = self.waiters.items[index];
            if (waiter.satisfied(self.node)) {
                waiter.done = true;
                waiter.cond.signal(self.io);
                _ = self.waiters.swapRemove(index);
                continue;
            }
            index += 1;
        }
        for (self.senders.items) |sender| {
            self.advertiseInstallationReady(sender);
        }
    }

    fn failEverything(self: *Server) void {
        self.wakeWaiters();
        if (self.write_waiter) |waiter| {
            if (waiter.outcome == .pending) waiter.outcome = .conflict;
            waiter.cond.signal(self.io);
            self.write_waiter = null;
        }
        for (self.fences.items) |fence| {
            fence.failed = true;
            fence.done = true;
            fence.cond.signal(self.io);
        }
        self.fences.clearRetainingCapacity();
        for (self.waiters.items) |waiter| {
            waiter.done = true;
            waiter.cond.signal(self.io);
        }
        self.waiters.clearRetainingCapacity();
    }

    /// Moves every outbox envelope into its peer's sender. A missing payload
    /// is queued immediately before its dependent envelope on the ordered TCP
    /// stream, allowing follower storage work to overlap the leader barrier.
    /// The receiver remains authoritative: a separately arriving or reordered
    /// envelope stays in its bounded missing-payload gate until storage ends.
    fn drainOutbox(self: *Server) !void {
        const configuration_id = self.node.identity.configuration_id;
        if (configuration_id != self.transport_configuration_id) return;
        for (self.node.outbox.items) |envelope| {
            const sender = self.senderFor(envelope.to) orelse continue;
            const vote_delay = self.options.test_faults.vote_delay_ms;
            if (vote_delay != 0 and envelope.message == .accepted and !self.releasing_votes) {
                try self.held_votes.append(self.gpa, .{
                    .envelope = envelope,
                    .release_tick = self.tick_count + vote_delay / self.options.tick_ms,
                });
                continue;
            }
            var payload_precedes_envelope = false;
            if (wire.envelopePayloadHash(envelope)) |hash| {
                if (sender.hasPayloadAck(hash)) {
                    payload_precedes_envelope = true;
                } else {
                    if (self.node.store.load(self.gpa, hash)) |payload| {
                        defer self.gpa.free(payload);
                        const frame = try wire.frameAlloc(
                            self.gpa,
                            .payload_data,
                            &.{ &hash, payload },
                        );
                        if (!sender.enqueueChecked(frame)) continue;
                        payload_precedes_envelope = true;
                    } else |_| {
                        // Never send a descriptor whose bytes we cannot
                        // serve; the peer would stall. Skip the envelope;
                        // retransmission retries once the store recovers.
                        continue;
                    }
                }
            }
            var envelope_buffer: [wire.max_envelope_size]u8 = undefined;
            const encoded = wire.encodeEnvelope(envelope, &envelope_buffer);
            var config_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &config_bytes, configuration_id, .little);
            const frame = try wire.frameAlloc(
                self.gpa,
                .envelope,
                &.{ &config_bytes, encoded },
            );
            if (wire.envelopePayloadHash(envelope)) |hash| {
                if (payload_precedes_envelope) {
                    sender.enqueue(frame);
                } else {
                    _ = sender.gatePayload(hash, frame);
                }
            } else {
                sender.enqueue(frame);
            }
        }
        self.node.outbox.clearRetainingCapacity();
    }

    /// Re-queues votes the `vote_delay_ms` fault parked once their tick
    /// comes; the ordinary drain sends them.
    fn releaseHeldVotes(self: *Server) void {
        var index: usize = 0;
        while (index < self.held_votes.items.len) {
            if (self.held_votes.items[index].release_tick > self.tick_count) {
                index += 1;
                continue;
            }
            const held = self.held_votes.swapRemove(index);
            self.node.outbox.append(self.gpa, held.envelope) catch {};
        }
        if (self.node.outbox.items.len == 0) return;
        self.releasing_votes = true;
        defer self.releasing_votes = false;
        self.pump();
    }

    /// Streams the chosen prefix to non-voting storage nodes. These frames
    /// are not votes: a learner accepts them only from a configured voter,
    /// journals them durably, and applies them in contiguous slot order.
    fn drainLearners(self: *Server) !void {
        if (!self.node.isLeader()) return;
        for (self.senders.items) |sender| {
            if (sender.peer.role.capabilities().votes) continue;
            if (!sender.peer.role.capabilities().stores_log) continue;
            while (sender.learned_through < self.node.applied_slot) {
                const slot = sender.learned_through + 1;
                const entry = self.node.log.read(slot) orelse break;
                if (entryPayloadHash(entry)) |hash| {
                    if (!sender.hasPayloadAck(hash)) {
                        const payload = self.node.store.load(self.gpa, hash) catch break;
                        const offer = blk: {
                            defer self.gpa.free(payload);
                            break :blk try wire.frameAlloc(
                                self.gpa,
                                .payload_data,
                                &.{ &hash, payload },
                            );
                        };
                        if (!sender.enqueueChecked(offer)) break;
                    }
                }
                var commit_buffer: [wire.LearnerCommit.encoded_max]u8 = undefined;
                const encoded = (wire.LearnerCommit{
                    .configuration_id = self.node.identity.configuration_id,
                    .slot = slot,
                    .entry = entry,
                }).encode(&commit_buffer);
                const frame = try wire.frameAlloc(
                    self.gpa,
                    .learner_commit,
                    &.{encoded},
                );
                const accepted = if (entryPayloadHash(entry)) |hash|
                    sender.gatePayload(hash, frame)
                else
                    sender.enqueueChecked(frame);
                if (!accepted) break;
                sender.learned_through = slot;
            }
        }
    }

    fn heartbeatLearners(self: *Server) !void {
        if (!self.node.isLeader()) return;
        if (self.last_learner_heartbeat_tick == self.tick_count) return;
        if (self.tick_count % 20 != 0) return;
        self.last_learner_heartbeat_tick = self.tick_count;
        var buffer: [wire.LearnerHeartbeat.encoded_size]u8 = undefined;
        const encoded = (wire.LearnerHeartbeat{
            .configuration_id = self.node.identity.configuration_id,
            .decided_through = self.node.log.decidedThrough(),
        }).encode(&buffer);
        for (self.senders.items) |sender| {
            if (sender.peer.role.capabilities().votes or
                !sender.peer.role.capabilities().stores_log)
            {
                continue;
            }
            const frame = try wire.frameAlloc(
                self.gpa,
                .learner_heartbeat,
                &.{encoded},
            );
            sender.enqueue(frame);
        }
    }

    fn entryPayloadHash(entry: types.Entry) ?command.HashBytes {
        return switch (entry) {
            .command => |cmd| switch (cmd) {
                .transaction_batch => |batch| batch.payload_hash,
                else => null,
            },
            .stop => null,
        };
    }

    /// Sends this node's progress report to every peer. Caller holds the
    /// mutex (pump context).
    fn broadcastStateReport(self: *Server) void {
        const local = self.node.frontier();
        self.last_reported_durable = local.durable_state_slot;
        self.recordFrontier(local);
        const report = wire.StateReport{
            .configuration_id = local.configuration_id,
            .durable_state_slot = local.durable_state_slot,
            .history_hash = local.history_hash,
            .executed_slot = local.executed_slot,
            .persisted_slot = local.persisted_slot,
            .local_delete_floor = local.local_delete_floor,
            .retained_first_slot = self.node.journal.retainedFirstSlot(),
        };
        var buffer: [wire.StateReport.encoded_size]u8 = undefined;
        const encoded = report.encode(&buffer);
        for (self.node.memberIds()) |member| {
            if (member == self.node.identity.node_id) continue;
            const sender = self.senderFor(member) orelse continue;
            const frame = wire.frameAlloc(self.gpa, .state_report, &.{encoded}) catch
                continue;
            sender.enqueue(frame);
        }
    }

    fn recordFrontier(self: *Server, frontier: trim.Frontier) void {
        for (&self.frontiers) |*slot| {
            if (slot.*) |held| {
                if (held.node_id == frontier.node_id) {
                    slot.* = frontier;
                    return;
                }
            }
        }
        for (&self.frontiers) |*slot| {
            if (slot.* == null) {
                slot.* = frontier;
                return;
            }
        }
    }

    fn onStateReport(self: *Server, body: []const u8, from: paxos.NodeId) void {
        const report = wire.StateReport.decode(body) catch return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.recordFrontier(.{
            .node_id = from,
            .configuration_id = report.configuration_id,
            .durable_state_slot = report.durable_state_slot,
            .history_hash = report.history_hash,
            .executed_slot = report.executed_slot,
            .persisted_slot = report.persisted_slot,
            .local_delete_floor = report.local_delete_floor,
        });
    }

    /// The v1 conservative trim: propose the minimum durable frontier of
    /// every data replica once it passes the chosen trim. Frozen while a
    /// membership change is pending or any data replica is silent.
    fn maybeProposeTrim(self: *Server) !void {
        if (self.node.membership_change_pending or
            self.node.log.stop_pending) return;
        // Serialize maintenance behind the applied proposal frontier. The
        // candidate is intentionally computed only after this check so a
        // newer report cannot queue a second trim behind an unresolved one.
        if (!self.node.proposalFrontierSettled()) return;
        self.recordFrontier(self.node.frontier());
        var data_buffer: [types.log_options.max_members]paxos.NodeId = undefined;
        const data = self.dataReplicaIds(&data_buffer);
        if (data.len == 0) return;
        const candidate = (try trim.candidate(
            &self.frontiers,
            data,
            self.node.identity.configuration_id,
        )) orelse return;
        if (candidate.through_slot <= self.node.trim_state.through_slot) return;
        try self.node.proposeTrim(candidate);
    }

    /// The current data replicas: every voter the decided registry maps
    /// to a materializing role, or every voter on flag-based clusters.
    fn dataReplicaIds(
        self: *Server,
        buffer: *[types.log_options.max_members]paxos.NodeId,
    ) []const paxos.NodeId {
        var count: usize = 0;
        for (self.node.memberIds()) |member| {
            if (self.node.decidedRegistry()) |decided| {
                if (decided.findNode(member)) |record| {
                    if (!record.role.capabilities().materializes) continue;
                }
            }
            buffer[count] = member;
            count += 1;
        }
        return buffer[0..count];
    }

    /// Undoes the last rotation advance so the same peer is probed
    /// again; used when the probe could not actually be sent.
    fn retreatRecoveryProbe(self: *Server) void {
        const count = self.node.member_count;
        if (count == 0) return;
        self.recovery_probe = (self.recovery_probe + count - 1) % count;
    }

    /// The next registry peer to probe for joiner recovery, rotating so
    /// a dead or unhelpful peer never wedges the join.
    fn nextRecoveryPeer(self: *Server) ?paxos.NodeId {
        const members = self.node.members[0..self.node.member_count];
        if (members.len <= 1) return null;
        var index: usize = 0;
        while (index < members.len) : (index += 1) {
            const pick = members[(self.recovery_probe + index) % members.len];
            if (pick == self.node.identity.node_id) continue;
            self.recovery_probe = (self.recovery_probe + index + 1) % members.len;
            return pick;
        }
        return null;
    }

    fn requestSnapshot(self: *Server, from: paxos.NodeId) void {
        _ = self.requestSnapshotSent(from);
    }

    /// Like `requestSnapshot`, but reports whether a request actually
    /// went out: a peer whose sender connection is not up yet must not
    /// consume a recovery probe.
    fn requestSnapshotSent(self: *Server, from: paxos.NodeId) bool {
        if (self.snapshot_source != null and
            self.tick_count < self.snapshot_requested_tick + 400)
        {
            return true;
        }
        const sender = self.senderFor(from) orelse return false;
        self.snapshot_source = from;
        self.snapshot_requested_tick = self.tick_count;
        var body: [wire.SnapshotRequest.encoded_size]u8 = undefined;
        const encoded = (wire.SnapshotRequest{
            .applied_slot = if (self.node.join_descriptor != null) 0 else self.node.applied_slot,
        }).encode(&body);
        const frame = wire.frameAlloc(self.gpa, .snapshot_request, &.{encoded}) catch
            return false;
        sender.enqueue(frame);
        return true;
    }

    // ------------------------------------------------------------------
    // Tick thread
    // ------------------------------------------------------------------

    fn tickLoop(self: *Server) void {
        defer self.wakeAcceptLoop();
        while (true) {
            self.io.sleep(.fromMilliseconds(@intCast(self.options.tick_ms)), .awake) catch {};
            // Fatal transitions request shutdown while holding the host
            // mutex. Wake the accept loop here, outside it, within one tick.
            if (self.isShutdown()) break;
            if (self.options.shutdown_flag) |flag| {
                if (flag.load(.acquire)) self.requestShutdown(.local);
            }
            var transport_stale = false;
            {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                if (self.isShutdown()) break;
                if (self.fatal_shutdown_requested) {
                    self.shutdown_flag.store(true, .release);
                    self.wakeWaiters();
                    break;
                }
                self.tick_count += 1;
                self.wakeWaiters();
                self.closeExpiredConnections();
                if (self.failed) continue;
                if (self.options.revocation_file != null and
                    self.tick_count % 40 == 0)
                {
                    self.reloadRevocationsLocked() catch |err| {
                        std.log.warn(
                            "revocation reload retained prior state: {s}",
                            .{@errorName(err)},
                        );
                    };
                    self.evictRevokedLocked();
                }
                self.node.tickProtocol() catch |err| {
                    self.failLocked(err);
                    continue;
                };
                self.releaseHeldVotes();
                self.pump();
                self.reportLeaderChangeLocked();
                const join = self.node.join_descriptor;

                // A joining replacement fetches the decided registry it
                // was enrolled against before it can participate.
                if (self.tick_count % 20 == 0 and
                    join != null and
                    self.node.identity.configuration_id < join.?.configuration_id)
                {
                    self.requestJoinRegistry();
                }
                self.node.releaseCampaignHold();

                // A stateless joiner cannot learn the leader from
                // heartbeats: they are ignored above its zero promise
                // until a first accepted vote arrives, and an idle
                // cluster sends no accepts. Recovery must not wait for
                // an application write, so the joiner probes the decided
                // registry's peers directly; the sender side arbitrates
                // between range recovery and an image transfer.
                if (self.tick_count % 20 == 10 and
                    self.node.join_campaign_hold and
                    join != null and
                    self.node.identity.configuration_id == join.?.configuration_id)
                {
                    if (self.nextRecoveryPeer()) |peer| {
                        self.node.requestCatchUp(peer) catch {};
                        if (!self.requestSnapshotSent(peer)) {
                            // The peer's sender is not connected yet;
                            // retry the same peer on the next probe
                            // instead of burning the rotation slot.
                            self.retreatRecoveryProbe();
                        }
                        self.pump();
                    }
                }

                // Every 20 ticks a member that is missing decided slots asks
                // for them: a follower from the leader it observed ahead, a
                // leader from any peer while it still owes itself slots
                // chosen under an earlier ballot (phase one sends the learn
                // request once). Repeated stalls mean the gap is below
                // retention and only a transfer closes it; installing one
                // demotes a leader, so a caught-up voter leads instead.
                if (self.tick_count % 20 == 0) {
                    if (self.node.isLeader()) {
                        if (!self.node.inheritedPrefixApplied()) {
                            if (self.nextRecoveryPeer()) |peer| self.recoverFromPeer(peer);
                        }
                    } else if (self.node.currentLeader()) |leader| {
                        if (leader != self.node.identity.node_id and
                            self.observed_leader_decided > self.node.log.decidedThrough())
                        {
                            self.recoverFromPeer(leader);
                        }
                    }
                }
                transport_stale = self.transportStaleLocked();
            }
            if (transport_stale) {
                // The decided registry is already durable. If this
                // in-process swap cannot complete, the process stops and
                // a clean restart converges from the same durable files;
                // it never continues on a mixed transport generation.
                self.rebuildTransport() catch |err| {
                    std.log.err(
                        "in-process transport swap failed: {s}; restart to recover",
                        .{@errorName(err)},
                    );
                    std.c._exit(1);
                };
            }
        }
    }

    /// Asks `peer` for the decided suffix this node is missing; after ten
    /// probes without progress it requests a full-image transfer instead.
    fn recoverFromPeer(self: *Server, peer: paxos.NodeId) void {
        const decided = self.node.log.decidedThrough();
        if (decided > self.catch_up_last_decided) {
            self.catch_up_last_decided = decided;
            self.catch_up_stalled = 0;
        } else {
            self.catch_up_stalled += 1;
        }
        if (self.catch_up_stalled >= 10) {
            self.catch_up_stalled = 0;
            self.requestSnapshot(peer);
        }
        self.node.requestCatchUp(peer) catch {};
        self.pump();
    }

    /// Called with the server mutex held after a protocol transition.
    fn reportLeaderChangeLocked(self: *Server) void {
        const leader = self.knownLeader();
        if (leader != self.leader_candidate) {
            self.leader_candidate = leader;
            self.leader_candidate_ticks = 1;
            return;
        }
        if (self.leader_candidate_ticks < 3) {
            self.leader_candidate_ticks += 1;
            if (self.leader_candidate_ticks < 3) return;
        }
        if (leader == self.reported_leader) return;
        self.reported_leader = leader;
        if (leader) |id| {
            if (id == self.node.identity.node_id) {
                std.log.info(
                    "node {d}: became leader; writes are ready",
                    .{self.node.identity.node_id},
                );
            } else {
                std.log.info(
                    "node {d}: leader is node {d}; follower is ready",
                    .{ self.node.identity.node_id, id },
                );
            }
        } else {
            std.log.warn(
                "node {d}: leader lost; waiting for voter quorum",
                .{self.node.identity.node_id},
            );
        }
    }

    // ------------------------------------------------------------------
    // Connection handling
    // ------------------------------------------------------------------

    fn handleConnection(self: *Server, stream_const: std.Io.net.Stream) void {
        var stream = stream_const;
        var read_buffer: [64 * 1024]u8 = undefined;
        var write_buffer: [64 * 1024]u8 = undefined;

        if (self.tls_server) |*context| {
            var tls_stream = if (self.options.enrollment_ca_key != null)
                tls.Stream.acceptOptionalPeer(
                    context,
                    stream,
                    &read_buffer,
                    &write_buffer,
                ) catch return
            else
                tls.Stream.accept(
                    context,
                    stream,
                    &read_buffer,
                    &write_buffer,
                ) catch return;
            defer tls_stream.deinit();
            self.serveConnection(
                stream,
                &tls_stream.reader,
                &tls_stream.writer,
                if (tls_stream.hasPeerCertificate())
                    tls_stream.peerCommonName()
                else
                    null,
            );
            return;
        }
        var stream_reader = stream.reader(self.io, &read_buffer);
        var stream_writer = stream.writer(self.io, &write_buffer);
        self.serveConnection(
            stream,
            &stream_reader.interface,
            &stream_writer.interface,
            null,
        );
    }

    /// Speaks the frame protocol over an established transport.
    /// `peer_certificate_name` is the verified TLS common name, when TLS
    /// is active; a peer hello must claim exactly the node id the
    /// certificate was issued for.
    fn serveConnection(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        writer: *Io.Writer,
        peer_certificate_name: ?[]const u8,
    ) void {
        const header = wire.readFrameHeader(reader) catch return;
        if (header.kind != .hello or header.body_len != wire.Hello.encoded_size) return;
        const hello_body = wire.readFrameBody(self.gpa, reader, header) catch return;
        defer self.gpa.free(hello_body);
        const hello = wire.Hello.decode(hello_body) catch {
            return;
        };
        if (self.tls_server != null and peer_certificate_name == null and
            hello.kind != .enrollment)
        {
            return;
        }
        if (hello.kind == .enrollment and self.options.enrollment_ca_key == null) {
            return;
        }
        const credential_node_id = if (peer_certificate_name) |certificate_name|
            tls.parseNodeCommonName(certificate_name)
        else
            null;
        var principal: Principal = .anonymous;
        if (peer_certificate_name) |certificate_name| {
            if (credential_node_id) |id| {
                principal = .{ .node = id };
            } else if (tls.parseAdminCommonName(certificate_name)) |admin| {
                principal = .{ .admin = AdminName.from(admin) };
            }
        }
        if (hello.kind == .peer and self.peerRevoked(hello.node_id)) return;
        if (hello.kind == .client and credential_node_id != null and
            self.peerRevoked(credential_node_id.?))
        {
            return;
        }
        if (peer_certificate_name) |certificate_name| {
            if (hello.kind == .peer) {
                var expected_buffer: [tls.max_common_name]u8 = undefined;
                const expected = tls.nodeCommonName(&expected_buffer, hello.node_id);
                if (!std.mem.eql(u8, certificate_name, expected)) return;
            }
        }

        var authenticated = if (hello.kind != .enrollment and self.options.auth_secret != null)
            transport_auth.accept(
                self.gpa,
                self.io,
                reader,
                writer,
                self.options.auth_secret.?,
                hello_body,
            ) catch return
        else
            null;
        self.noteHandshakeComplete(
            stream,
            switch (hello.kind) {
                .peer => hello.node_id,
                .client => credential_node_id,
                .enrollment => null,
            },
        ) catch return;

        switch (hello.kind) {
            .peer => self.peerLoop(stream, reader, hello, if (authenticated) |*session|
                session
            else
                null) catch {},
            .client => self.clientLoop(stream, reader, writer, if (authenticated) |*session|
                session
            else
                null, principal) catch {},
            .enrollment => self.enrollmentExchange(stream, reader, writer, hello) catch {},
        }
    }

    /// A certificate-less connection can execute exactly this one exchange.
    /// The CSR is verified before the token is consumed; consumption is an
    /// atomic, directory-synced rename before signing or returning a cert.
    fn enrollmentExchange(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        writer: *Io.Writer,
        hello: wire.Hello,
    ) !void {
        const header = wire.readFrameHeader(reader) catch {
            return self.writeEnrollmentRefused(writer);
        };
        if (header.kind != .enrollment_request or
            header.body_len > wire.EnrollmentRequest.max_encoded_size)
        {
            return self.writeEnrollmentRefused(writer);
        }
        const body = wire.readFrameBody(self.gpa, reader, header) catch {
            return self.writeEnrollmentRefused(writer);
        };
        defer self.gpa.free(body);
        self.noteConnectionActivity(stream);
        const request = wire.EnrollmentRequest.decode(body) catch {
            return self.writeEnrollmentRefused(writer);
        };
        if (hello.node_id != request.node_id or
            hello.database_id != request.database_id or
            request.database_id != self.node.identity.database_id or
            !self.isConfiguredNode(request.node_id) or
            self.peerRevoked(request.node_id))
        {
            return self.writeEnrollmentRefused(writer);
        }
        tls.validateNodeCsr(request.csr, request.node_id) catch {
            return self.writeEnrollmentRefused(writer);
        };
        enrollment.consumeToken(
            self.gpa,
            self.io,
            self.options.directory,
            request.secret,
            request.node_id,
            self.node.identity.node_id,
            self.node.identity.database_id,
        ) catch return self.writeEnrollmentRefused(writer);

        var serial_bytes: [8]u8 = undefined;
        self.io.random(&serial_bytes);
        const certificate = tls.issueNodeCertificate(
            self.gpa,
            request.csr,
            request.node_id,
            self.options.tls.?.ca_path,
            self.options.enrollment_ca_key.?,
            std.mem.readInt(u64, &serial_bytes, .little),
            enrollment.certificate_validity_seconds,
        ) catch return self.writeEnrollmentRefused(writer);
        defer self.gpa.free(certificate);
        var response_buffer: [wire.EnrollmentResponse.max_encoded_size]u8 = undefined;
        self.mutex.lockUncancelable(self.io);
        const decided_configuration: u64 = if (self.node.decidedRegistry()) |decided|
            decided.configuration_id
        else
            self.node.identity.configuration_id;
        const decided_digest: [32]u8 = if (self.node.decidedRegistry()) |decided|
            decided.digest()
        else
            @as([32]u8, @splat(0));
        self.mutex.unlock(self.io);
        const response = wire.EnrollmentResponse{
            .status = .ok,
            .node_id = request.node_id,
            .database_id = self.node.identity.database_id,
            .configuration_id = decided_configuration,
            .registry_digest = decided_digest,
            .certificate = certificate,
        };
        try wire.writeFrame(
            writer,
            .enrollment_response,
            try response.encode(&response_buffer),
        );
        try writer.flush();
    }

    fn writeEnrollmentRefused(self: *Server, writer: *Io.Writer) !void {
        _ = self;
        var response_buffer: [wire.EnrollmentResponse.max_encoded_size]u8 = undefined;
        const response = wire.EnrollmentResponse{ .status = .refused };
        try wire.writeFrame(
            writer,
            .enrollment_response,
            try response.encode(&response_buffer),
        );
        try writer.flush();
    }

    fn isConfiguredNode(self: *const Server, node_id: paxos.NodeId) bool {
        const members = self.currentMembers();
        for (members) |member| {
            if (member.id == node_id and member.role != .gateway) return true;
        }
        return members.len == 0 and self.node.identity.node_id == node_id;
    }

    fn handleConnectionTracked(self: *Server, stream: std.Io.net.Stream) void {
        // Remove the descriptor from the shutdown set before closing it,
        // but keep the handler counted until close completes.
        defer self.noteHandlerFinished();
        var owned_stream = stream;
        defer owned_stream.close(self.io);
        defer self.noteHandlerClosing(stream);
        self.handleConnection(stream);
    }

    // ------------------------------------------------------------------
    // Peer connections (inbound: we receive what the peer sends)
    // ------------------------------------------------------------------

    const InstallState = struct {
        dir: ?Io.Dir = null,
        file: ?Io.File = null,
        configuration_id: u64 = 0,
        db_size: u64 = 0,
        received: u64 = 0,
        name: [16]u8 = undefined,
        manifest: ?[]u8 = null,
        proof: ?[]u8 = null,
        /// Fetched decided-registry blob for a joining replacement. It may
        /// arrive before, during, or after the snapshot frames, so it
        /// survives transfer resets and is verified against the proof's
        /// registry digest before installation.
        registry_blob: ?[]u8 = null,
        registry_blob_configuration: u64 = 0,

        fn reset(self: *InstallState, io: Io, gpa: std.mem.Allocator) void {
            if (self.file) |file| file.close(io);
            if (self.dir) |*dir| dir.close(io);
            if (self.manifest) |manifest| gpa.free(manifest);
            if (self.proof) |proof| gpa.free(proof);
            const blob = self.registry_blob;
            const blob_configuration = self.registry_blob_configuration;
            self.* = .{};
            self.registry_blob = blob;
            self.registry_blob_configuration = blob_configuration;
        }

        fn deinit(self: *InstallState, io: Io, gpa: std.mem.Allocator) void {
            self.reset(io, gpa);
            if (self.registry_blob) |blob| gpa.free(blob);
            self.* = .{};
        }
    };

    fn peerLoop(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        hello: wire.Hello,
        authenticated: ?*transport_auth.Session,
    ) !void {
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (hello.database_id != self.node.identity.database_id) {
                return error.DatabaseMismatch;
            }
            // Admission follows the exact current membership generation: a
            // node the decided registry removed cannot rejoin, even with a
            // certificate that is otherwise still valid.
            var known = false;
            for (self.currentMembers()) |member| {
                if (member.id == hello.node_id) known = true;
            }
            if (!known) return error.NotMember;
            if (hello.configuration_id > self.node.identity.configuration_id) {
                self.requestSnapshot(hello.node_id);
            }
        }

        var install = InstallState{};
        defer install.deinit(self.io, self.gpa);

        while (!self.isShutdown()) {
            const frame = try self.readConnectionFrame(
                stream,
                reader,
                authenticated,
            );
            const body = frame.body;
            defer self.gpa.free(body);
            switch (frame.kind) {
                .envelope => try self.onEnvelopeFrame(body, hello.node_id),
                .payload_data => try self.onPayloadData(body, hello.node_id),
                .payload_stored => self.onPayloadStored(body, hello.node_id),
                .payload_request => self.onPayloadRequest(body, hello.node_id),
                .fence_request => self.onFenceRequest(body, hello.node_id),
                .fence_ack => self.onFenceAck(body, hello.node_id),
                .snapshot_request => self.onSnapshotRequest(body, hello.node_id),
                .snapshot_begin => try self.onSnapshotBegin(
                    body,
                    &install,
                    hello.node_id,
                ),
                .snapshot_chunk => try self.onSnapshotChunk(body, &install),
                .snapshot_end => try self.onSnapshotEnd(&install, hello.node_id),
                .checkpoint_proof_request => self.onCheckpointProofRequest(
                    body,
                    hello.node_id,
                ),
                .checkpoint_proof_reply => self.onCheckpointProofReply(
                    body,
                    hello.node_id,
                ),
                .learner_commit => try self.onLearnerCommit(body, hello.node_id),
                .learner_heartbeat => try self.onLearnerHeartbeat(
                    body,
                    hello.node_id,
                ),
                .state_report => self.onStateReport(body, hello.node_id),
                .registry_request => self.onRegistryRequest(body, hello.node_id),
                .registry_data => try self.onRegistryData(body, &install),
                .installation_ready => try self.onInstallationReady(body, hello.node_id),
                else => return error.InvalidFrame,
            }
        }
    }

    fn onInstallationReady(self: *Server, body: []const u8, from: paxos.NodeId) !void {
        const ready = try wire.InstallationReady.decode(body);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const decided = self.node.decidedRegistry() orelse return error.InvalidFrame;
        const replacement = self.currentReplacement() orelse return error.InvalidFrame;
        if (from != replacement or ready.configuration_id != decided.configuration_id or
            !std.mem.eql(u8, &ready.registry_digest, &decided.digest()))
        {
            return error.InvalidFrame;
        }
        self.replacement_ready_node = from;
        self.replacement_ready_configuration = ready.configuration_id;
    }

    fn onEnvelopeFrame(self: *Server, body: []const u8, from: paxos.NodeId) !void {
        if (body.len < 8) return error.InvalidFrame;
        const frame_configuration = std.mem.readInt(u64, body[0..8], .little);
        const envelope = try wire.decodeEnvelope(body[8..]);
        if (envelope.from != from or envelope.to != self.node.identity.node_id) {
            return error.InvalidFrame;
        }

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) return;

        const local_configuration = self.node.identity.configuration_id;
        if (frame_configuration < local_configuration) return;
        if (frame_configuration > local_configuration) {
            // The cluster moved to a configuration this node has not
            // completed; recovery rides the transfer-lease state install.
            self.requestSnapshot(from);
            return;
        }
        if (local_configuration != self.transport_configuration_id) return;

        // An enrolled replacement must establish its materialized and
        // protocol base from the certified transfer anchor before it can
        // consume or vote on the retained suffix. Peers may send ordinary
        // envelopes as soon as the fetched registry rebuilds transport;
        // ignore those until installing the image durably clears JOIN.
        if (self.node.join_descriptor != null) return;

        switch (envelope.message) {
            .heartbeat => |m| {
                if (m.decided_through > self.observed_leader_decided) {
                    self.observed_leader_decided = m.decided_through;
                }
            },
            else => {},
        }

        // Payload-before-vote: never process an accept or commit whose
        // payload bytes are not durable locally.
        if (wire.envelopePayloadHash(envelope)) |hash| {
            if (self.node.store.verify(hash)) |_| {} else |_| {
                self.holdEnvelope(hash, envelope, from);
                if (self.senderFor(from)) |sender| {
                    const frame = wire.frameAlloc(
                        self.gpa,
                        .payload_request,
                        &.{&hash},
                    ) catch return;
                    sender.enqueue(frame);
                }
                return;
            }
        }

        self.node.stepEnvelope(envelope) catch |err| {
            self.failLocked(err);
            return;
        };
        self.pump();
    }

    fn onLearnerCommit(self: *Server, body: []const u8, from: paxos.NodeId) !void {
        const commit = try wire.LearnerCommit.decode(body);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed or self.node.isVoter()) return error.InvalidFrame;
        // Only a configured voter may certify a chosen slot to a learner; a
        // standby or read replica replays state but never certifies it.
        const source = self.addressOf(from) orelse return error.NotMember;
        if (!source.role.capabilities().votes) return error.InvalidFrame;
        if (commit.configuration_id < self.node.identity.configuration_id) return;
        if (commit.configuration_id > self.node.identity.configuration_id) {
            self.requestSnapshot(from);
            return;
        }
        if (entryPayloadHash(commit.entry)) |hash| {
            self.node.store.verify(hash) catch return error.PayloadMissing;
        }
        try self.node.learnChosen(from, commit.slot, commit.entry);
        self.learner_leader = from;
        self.learner_last_contact_tick = self.tick_count;
        self.pump();
    }

    fn onLearnerHeartbeat(
        self: *Server,
        body: []const u8,
        from: paxos.NodeId,
    ) !void {
        const heartbeat = try wire.LearnerHeartbeat.decode(body);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed or self.node.isVoter()) return error.InvalidFrame;
        const source = self.addressOf(from) orelse return error.NotMember;
        if (!source.role.capabilities().votes) return error.InvalidFrame;
        if (heartbeat.configuration_id < self.node.identity.configuration_id) return;
        if (heartbeat.configuration_id > self.node.identity.configuration_id) {
            self.requestSnapshot(from);
            return;
        }
        if (heartbeat.decided_through > self.observed_leader_decided) {
            self.observed_leader_decided = heartbeat.decided_through;
        }
        self.learner_leader = from;
        self.learner_last_contact_tick = self.tick_count;
    }

    fn holdEnvelope(
        self: *Server,
        hash: command.HashBytes,
        envelope: Log.Envelope,
        from: paxos.NodeId,
    ) void {
        if (!self.held.contains(hash)) {
            // Bounded queue: drop; retransmission recovers.
            if (self.held_total >= held_hash_limit) return;
            self.held.put(hash, .{}) catch return;
            self.held_total += 1;
        }
        const held_entry = self.held.getPtr(hash) orelse return;
        held_entry.from = from;
        if (held_entry.count < held_entry.envelopes.len) {
            held_entry.envelopes[held_entry.count] = envelope;
            held_entry.count += 1;
        }
    }

    fn onPayloadData(self: *Server, body: []const u8, from: paxos.NodeId) !void {
        if (body.len < 32) return error.InvalidFrame;
        const payload = body[32..];
        const digest = payload_store_mod.PayloadStore.hashOf(payload);
        if (!std.mem.eql(u8, body[0..32], &digest)) return error.InvalidFrame;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) return;
        _ = self.node.store.put(payload) catch |err| {
            self.failLocked(err);
            return;
        };

        // Emitted only after PayloadStore.put has flushed and atomically
        // installed (or verified) the content-addressed object. Power-loss
        // durability follows at this node's next journal barrier, which
        // precedes any vote or recovered value referencing the payload;
        // the ack itself only gates the sender's envelope release.
        if (self.senderFor(from)) |sender| {
            const ack = wire.frameAlloc(self.gpa, .payload_stored, &.{&digest}) catch
                return;
            sender.enqueue(ack);
        }
        if (self.held.fetchRemove(digest)) |entry| {
            self.held_total -= 1;
            for (entry.value.envelopes[0..entry.value.count]) |envelope| {
                self.node.stepEnvelope(envelope) catch |err| {
                    self.failLocked(err);
                    return;
                };
            }
            self.pump();
        }
    }

    fn onPayloadStored(self: *Server, body: []const u8, from: paxos.NodeId) void {
        if (body.len != 32) return;
        var hash: command.HashBytes = undefined;
        @memcpy(&hash, body[0..32]);
        const sender = self.senderFor(from) orelse return;
        sender.ackPayload(hash);
    }

    fn onPayloadRequest(self: *Server, body: []const u8, from: paxos.NodeId) void {
        if (body.len != 32) return;
        var hash: command.HashBytes = undefined;
        @memcpy(&hash, body[0..32]);
        const sender = self.senderFor(from) orelse return;

        self.mutex.lockUncancelable(self.io);
        const payload = self.node.store.load(self.gpa, hash) catch {
            self.mutex.unlock(self.io);
            return;
        };
        self.mutex.unlock(self.io);
        defer self.gpa.free(payload);
        const frame = wire.frameAlloc(self.gpa, .payload_data, &.{ &hash, payload }) catch
            return;
        sender.enqueue(frame);
    }

    fn onFenceRequest(self: *Server, body: []const u8, from: paxos.NodeId) void {
        const request = wire.FenceRequest.decode(body) catch return;
        const sender = self.senderFor(from) orelse return;

        self.mutex.lockUncancelable(self.io);
        const promised = self.node.log.core.durable.promised;
        const ok = request.ballot.eql(promised);
        self.mutex.unlock(self.io);

        const ack = wire.FenceAck{
            .fence_id = request.fence_id,
            .ok = ok,
            .promised = promised,
        };
        var ack_buffer: [wire.FenceAck.encoded_size]u8 = undefined;
        const encoded = ack.encode(&ack_buffer);
        const frame = wire.frameAlloc(self.gpa, .fence_ack, &.{encoded}) catch return;
        sender.enqueue(frame);
    }

    fn onFenceAck(self: *Server, body: []const u8, from: paxos.NodeId) void {
        const ack = wire.FenceAck.decode(body) catch return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.fences.items) |fence| {
            if (fence.id != ack.fence_id) continue;
            if (ack.ok and ack.promised.eql(fence.ballot)) {
                fence.noteAck(from);
            } else {
                fence.failed = true;
            }
            break;
        }
        self.pump();
    }

    fn onSnapshotRequest(self: *Server, body: []const u8, from: paxos.NodeId) void {
        const request = wire.SnapshotRequest.decode(body) catch return;
        const sender = self.senderFor(from) orelse return;

        // Serve a full-image transfer only when the retained journal can
        // no longer cover the peer's gap; otherwise range recovery over
        // ordinary commit envelopes is cheaper and does the same job.
        self.mutex.lockUncancelable(self.io);
        const fresh_later_configuration = request.applied_slot == 0 and
            self.node.identity.configuration_id > 1;
        if (!self.node.capabilities.materializes or
            (!fresh_later_configuration and
                self.node.journal.retainedFirstSlot() <= request.applied_slot + 1))
        {
            self.mutex.unlock(self.io);
            std.log.info(
                "node {d}: declining transfer for peer {d}; range recovery covers it",
                .{ self.node.identity.node_id, from },
            );
            return;
        }
        std.log.info(
            "node {d}: pinning transfer image for peer {d}",
            .{ self.node.identity.node_id, from },
        );
        var pin = self.node.pinTransferImage() catch |err| {
            self.mutex.unlock(self.io);
            std.log.warn("transfer pin failed: {s}", .{@errorName(err)});
            return;
        };
        const registry_digest: [32]u8 = if (self.node.decidedRegistry()) |decided|
            decided.digest()
        else
            @as([32]u8, @splat(0));
        const registry_blob: ?[]u8 = if (self.node.decidedRegistry()) |decided|
            self.node.readRegistryBlob(self.gpa, decided.configuration_id) catch null
        else
            null;
        self.mutex.unlock(self.io);
        defer pin.close();

        // The decided registry blob goes ahead of the image: a joining
        // replacement needs it first, and a receiver that already holds
        // it verifies and ignores the duplicate.
        if (registry_blob) |blob| {
            defer self.gpa.free(blob);
            if (blob.len > 0 and blob.len <= wire.RegistryData.max_blob_bytes) {
                var body_buffer: [wire.RegistryData.max_encoded_size]u8 = undefined;
                if ((wire.RegistryData{
                    .configuration_id = pin.anchor.configuration_id,
                    .blob = blob,
                }).encode(&body_buffer)) |encoded| {
                    if (wire.frameAlloc(self.gpa, .registry_data, &.{encoded})) |frame| {
                        _ = sender.enqueueBackpressure(frame);
                    } else |_| {}
                } else |_| {}
            }
        }

        const begin = wire.SnapshotBegin{
            .configuration_id = pin.anchor.configuration_id,
            .anchor_slot = pin.anchor.global_slot,
            .history_hash = pin.anchor.history_hash,
            .db_size = pin.size,
            .image_sha256 = pin.sha256,
            .sqlite_page_size = pin.anchor.sqlite_page_size,
            .last_data_slot = pin.anchor.last_data_slot,
            .last_batch_id = pin.anchor.last_batch_id,
            .last_chain = pin.anchor.last_chain,
            .registry_digest = registry_digest,
        };
        var begin_buffer: [wire.SnapshotBegin.encoded_size]u8 = undefined;
        const begin_encoded = begin.encode(&begin_buffer);
        const begin_frame = wire.frameAlloc(
            self.gpa,
            .snapshot_begin,
            &.{begin_encoded},
        ) catch return;
        if (!sender.enqueueBackpressure(begin_frame)) return;

        var offset: u64 = 0;
        const chunk = self.gpa.alloc(u8, snapshot_chunk_bytes) catch return;
        defer self.gpa.free(chunk);
        while (offset < pin.size) {
            const read = pin.file.readPositionalAll(self.io, chunk, offset) catch
                return;
            if (read == 0) break;
            var offset_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &offset_bytes, offset, .little);
            const frame = wire.frameAlloc(
                self.gpa,
                .snapshot_chunk,
                &.{ &offset_bytes, chunk[0..read] },
            ) catch return;
            if (!sender.enqueueBackpressure(frame)) return;
            offset += read;
        }
        const end_frame = wire.frameAlloc(self.gpa, .snapshot_end, &.{}) catch return;
        _ = sender.enqueueBackpressure(end_frame);
    }

    fn onSnapshotBegin(
        self: *Server,
        body: []const u8,
        install: *InstallState,
        from: paxos.NodeId,
    ) !void {
        const begin = try wire.SnapshotBegin.decode(body);
        install.reset(self.io, self.gpa);

        self.mutex.lockUncancelable(self.io);
        const stale = begin.configuration_id != self.node.identity.configuration_id or
            begin.anchor_slot <= self.node.applied_slot;
        const oversized = begin.db_size > self.options.max_transfer_bytes;
        self.mutex.unlock(self.io);
        if (stale) return;
        if (oversized) return error.InvalidFrame;

        // Never trust a single sender for base state: a read quorum of
        // the current voters must vouch the anchor's history binding
        // before any image byte is staged (ZDS 0011).
        try self.confirmHistoryQuorum(begin.anchor_slot, begin.history_hash, from);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (begin.anchor_slot <= self.node.applied_slot) return;
        self.node.dir.deleteFile(self.io, node_mod.transfer_install_name) catch {};
        const file = try self.node.dir.createFile(
            self.io,
            node_mod.transfer_install_name,
            .{ .read = true },
        );
        install.file = file;
        install.configuration_id = begin.configuration_id;
        install.db_size = begin.db_size;
        install.received = 0;
        install.manifest = try self.gpa.dupe(u8, body);
        if (self.installation == .not_applicable or self.installation == .failed) {
            self.installation = .transferring;
        }
    }

    fn onRegistryRequest(self: *Server, body: []const u8, from: paxos.NodeId) void {
        const request = wire.RegistryRequest.decode(body) catch return;
        const sender = self.senderFor(from) orelse return;
        self.mutex.lockUncancelable(self.io);
        const blob = self.node.readRegistryBlob(
            self.gpa,
            request.configuration_id,
        ) catch {
            self.mutex.unlock(self.io);
            return;
        };
        self.mutex.unlock(self.io);
        defer self.gpa.free(blob);
        if (blob.len == 0 or blob.len > wire.RegistryData.max_blob_bytes) return;
        var body_buffer: [wire.RegistryData.max_encoded_size]u8 = undefined;
        const encoded = (wire.RegistryData{
            .configuration_id = request.configuration_id,
            .blob = blob,
        }).encode(&body_buffer) catch return;
        const frame = wire.frameAlloc(self.gpa, .registry_data, &.{encoded}) catch
            return;
        sender.enqueue(frame);
    }

    fn onRegistryData(
        self: *Server,
        body: []const u8,
        install: *InstallState,
    ) !void {
        const data = wire.RegistryData.decode(body) catch return error.InvalidFrame;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.node.join_descriptor) |join| {
                // A joining replacement adopts the registry it enrolled
                // against, then joins its configuration at slot zero and
                // catches up through the retained journal (ZDS 0011).
                if (self.node.identity.configuration_id == join.configuration_id)
                    return;
                self.node.installFetchedRegistry(data.blob) catch |err| {
                    std.log.warn(
                        "fetched registry rejected: {s}",
                        .{@errorName(err)},
                    );
                    return;
                };
                self.enterConfigurationLocked();
                self.pump();
                return;
            }
        }
        if (install.registry_blob) |old| self.gpa.free(old);
        install.registry_blob = try self.gpa.dupe(u8, data.blob);
        install.registry_blob_configuration = data.configuration_id;
    }

    /// Asks every connected peer for the decided registry blob named by
    /// this node's join descriptor.
    fn requestJoinRegistry(self: *Server) void {
        const join = self.node.join_descriptor orelse return;
        var request_buffer: [wire.RegistryRequest.encoded_size]u8 = undefined;
        const encoded = (wire.RegistryRequest{
            .configuration_id = join.configuration_id,
        }).encode(&request_buffer);
        for (self.senders.items) |sender| {
            if (!sender.isConnected()) continue;
            const frame = wire.frameAlloc(
                self.gpa,
                .registry_request,
                &.{encoded},
            ) catch return;
            sender.enqueue(frame);
        }
    }

    fn onSnapshotChunk(self: *Server, body: []const u8, install: *InstallState) !void {
        const chunk = try wire.SnapshotChunk.decode(body);
        const file = install.file orelse return;
        const chunk_end = std.math.add(u64, chunk.offset, chunk.bytes.len) catch
            return error.InvalidFrame;
        if (chunk.offset != install.received or
            chunk.bytes.len == 0 or
            chunk.bytes.len > snapshot_chunk_bytes or
            chunk_end > install.db_size)
        {
            return error.InvalidFrame;
        }
        try file.writePositionalAll(self.io, chunk.bytes, chunk.offset);
        install.received += chunk.bytes.len;
        failpoint.hit("after_transfer_chunk");
    }

    fn onSnapshotEnd(self: *Server, install: *InstallState, from: paxos.NodeId) !void {
        const file = install.file orelse return;
        if (install.received != install.db_size) return error.InvalidFrame;
        try durability.syncFile(self.io, file);
        failpoint.hit("after_transfer_stage");
        file.close(self.io);
        install.file = null;
        const manifest = install.manifest orelse return;
        defer {
            self.gpa.free(manifest);
            install.manifest = null;
        }
        const begin = try wire.SnapshotBegin.decode(manifest);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.snapshot_source = null;
        if (self.installation == .transferring) self.installation = .verifying;
        self.node.installTransferredState(begin) catch |err| {
            std.log.warn("state install failed: {s}", .{@errorName(err)});
            if (self.installation != .not_applicable) {
                self.installation = .failed;
                self.installation_failure = err;
            }
            return;
        };
        if (self.installation != .not_applicable) self.installation = .installed;
        if (self.installation != .not_applicable) self.installation_failure = null;
        self.observed_leader_decided = 0;
        self.node.requestCatchUp(from) catch {};
        self.pump();
    }

    fn onCheckpointProofRequest(
        self: *Server,
        body: []const u8,
        from: paxos.NodeId,
    ) void {
        const probe = wire.HistoryProbe.decode(body) catch return;
        const sender = self.senderFor(from) orelse return;
        self.mutex.lockUncancelable(self.io);
        const local = self.node.historyHashAt(probe.slot);
        self.mutex.unlock(self.io);
        const hash = local orelse return;
        if (!std.mem.eql(u8, &hash, &probe.hash)) return;

        var reply_buffer: [wire.HistoryProbe.encoded_size]u8 = undefined;
        const encoded = probe.encode(&reply_buffer);
        const frame = wire.frameAlloc(
            self.gpa,
            .checkpoint_proof_reply,
            &.{encoded},
        ) catch return;
        sender.enqueue(frame);
    }

    fn onCheckpointProofReply(
        self: *Server,
        body: []const u8,
        from: paxos.NodeId,
    ) void {
        const vouch = wire.HistoryProbe.decode(body) catch return;
        self.proof_mutex.lockUncancelable(self.io);
        defer self.proof_mutex.unlock(self.io);
        const waiter = self.proof_waiter orelse return;
        if (waiter.nonce != vouch.nonce or waiter.slot != vouch.slot or
            !std.mem.eql(u8, &waiter.hash, &vouch.hash))
        {
            return;
        }
        waiter.noteAck(from);
    }

    /// Blocks until a read quorum of the current voters vouches that the
    /// chosen history through `slot` has hash `hash`. The transfer sender
    /// counts as the first vouch; the local node vouches for itself when
    /// it can.
    fn confirmHistoryQuorum(
        self: *Server,
        slot: paxos.Slot,
        hash: [32]u8,
        source: paxos.NodeId,
    ) !void {
        self.mutex.lockUncancelable(self.io);
        const members = self.node.memberIds();
        var waiter = HistoryProbeWaiter{
            .nonce = 0,
            .slot = slot,
            .hash = hash,
            .needed = members.len / 2 + 1,
        };
        @memcpy(waiter.voters[0..members.len], members);
        waiter.voter_count = @intCast(members.len);
        self.mutex.unlock(self.io);
        if (waiter.voter_count == 0) return error.HistoryQuorum;

        self.proof_mutex.lockUncancelable(self.io);
        if (self.proof_waiter != null) {
            self.proof_mutex.unlock(self.io);
            return error.HistoryProbeBusy;
        }
        var nonce = self.next_proof_nonce;
        self.next_proof_nonce +%= 1;
        if (self.next_proof_nonce == 0) self.next_proof_nonce = 1;
        if (nonce == 0) nonce = 1;
        waiter.nonce = nonce;
        waiter.noteAck(source);
        self.proof_waiter = &waiter;
        self.proof_mutex.unlock(self.io);
        defer {
            self.proof_mutex.lockUncancelable(self.io);
            if (self.proof_waiter == &waiter) self.proof_waiter = null;
            self.proof_mutex.unlock(self.io);
        }

        var probe_buffer: [wire.HistoryProbe.encoded_size]u8 = undefined;
        const encoded = (wire.HistoryProbe{
            .nonce = nonce,
            .slot = slot,
            .hash = hash,
        }).encode(&probe_buffer);
        for (self.senders.items) |sender| {
            if (!waiter.isVoter(sender.peer.id)) continue;
            const frame = try wire.frameAlloc(
                self.gpa,
                .checkpoint_proof_request,
                &.{encoded},
            );
            sender.enqueue(frame);
        }

        var elapsed_ms: u64 = 0;
        while (elapsed_ms < 2_000) : (elapsed_ms += 1) {
            self.proof_mutex.lockUncancelable(self.io);
            const confirmed = waiter.ack_count >= waiter.needed;
            self.proof_mutex.unlock(self.io);
            if (confirmed) return;
            if (self.isShutdown()) return error.Shutdown;
            self.io.sleep(.fromMilliseconds(1), .awake) catch
                return error.HistoryQuorum;
        }
        return error.HistoryQuorum;
    }

    // ------------------------------------------------------------------
    // Client connections
    // ------------------------------------------------------------------

    fn clientLoop(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        writer: *Io.Writer,
        authenticated: ?*transport_auth.Session,
        principal: Principal,
    ) !void {
        while (!self.isShutdown()) {
            const frame = try self.readConnectionFrame(
                stream,
                reader,
                authenticated,
            );
            if (frame.kind != .rpc_request) return error.InvalidFrame;
            const body = frame.body;
            defer self.gpa.free(body);

            if (isOperation(self.gpa, body, "backup")) {
                try self.streamBackup(writer, authenticated);
                continue;
            }

            var response: std.Io.Writer.Allocating = .init(self.gpa);
            defer {
                @memset(response.writer.buffer, 0);
                response.deinit();
            }
            self.dispatch(body, principal, &response.writer) catch |err| {
                response.clearRetainingCapacity();
                writeErrorResponse(&response.writer, "internal", @errorName(err)) catch {};
            };
            if (authenticated) |session| {
                try session.writeFrame(writer, .rpc_response, response.written());
            } else {
                try wire.writeFrame(writer, .rpc_response, response.written());
            }
            try writer.flush();
            if (self.isShutdown()) {
                if (isOperation(self.gpa, body, "stop")) {
                    self.stop_response_sent.set(self.io);
                }
                return;
            }
        }
    }

    fn readConnectionFrame(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        authenticated: ?*transport_auth.Session,
    ) !transport_auth.Frame {
        const frame = if (authenticated) |session|
            try session.readFrame(self.gpa, reader)
        else blk: {
            const header = try wire.readFrameHeader(reader);
            const body = try wire.readFrameBody(self.gpa, reader, header);
            break :blk transport_auth.Frame{ .kind = header.kind, .body = body };
        };
        self.noteConnectionActivity(stream);
        return frame;
    }

    fn writeConnectionFrame(
        writer: *Io.Writer,
        authenticated: ?*transport_auth.Session,
        kind: wire.FrameKind,
        body: []const u8,
    ) !void {
        if (authenticated) |session| {
            try session.writeFrame(writer, kind, body);
        } else {
            try wire.writeFrame(writer, kind, body);
        }
    }

    fn streamBackup(
        self: *Server,
        writer: *Io.Writer,
        authenticated: ?*transport_auth.Session,
    ) !void {
        self.mutex.lockUncancelable(self.io);
        if (self.failed or !self.node.isLeader()) {
            self.mutex.unlock(self.io);
            return self.writeBackupError(writer, authenticated, "not_leader");
        }
        if (!self.node.single) {
            self.awaitReadFence() catch {
                self.mutex.unlock(self.io);
                return self.writeBackupError(writer, authenticated, "retry");
            };
        }
        var backup = self.node.openBackup() catch |err| {
            self.mutex.unlock(self.io);
            return self.writeBackupError(writer, authenticated, @errorName(err));
        };
        self.mutex.unlock(self.io);
        defer backup.close();

        var begin_buffer: [wire.BackupBegin.encoded_size]u8 = undefined;
        const begin = (wire.BackupBegin{
            .size = backup.size,
            .sha256 = backup.sha256,
        }).encode(&begin_buffer);
        try writeConnectionFrame(writer, authenticated, .backup_begin, begin);
        var bytes: [snapshot_chunk_bytes]u8 = undefined;
        var offset: u64 = 0;
        while (offset < backup.size) {
            const count = try backup.file.readPositionalAll(self.io, &bytes, offset);
            if (count == 0) return error.UnexpectedEndOfStream;
            var offset_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &offset_bytes, offset, .little);
            var frame: [8 + snapshot_chunk_bytes]u8 = undefined;
            @memcpy(frame[0..8], &offset_bytes);
            @memcpy(frame[8..][0..count], bytes[0..count]);
            try writeConnectionFrame(
                writer,
                authenticated,
                .backup_chunk,
                frame[0 .. 8 + count],
            );
            offset += count;
        }
        try writeConnectionFrame(writer, authenticated, .backup_end, &.{});
        try writer.flush();
    }

    fn writeBackupError(
        self: *Server,
        writer: *Io.Writer,
        authenticated: ?*transport_auth.Session,
        code: []const u8,
    ) !void {
        var response: std.Io.Writer.Allocating = .init(self.gpa);
        defer response.deinit();
        try writeErrorResponse(&response.writer, code, "backup unavailable");
        try writeConnectionFrame(
            writer,
            authenticated,
            .rpc_response,
            response.written(),
        );
        try writer.flush();
    }

    const Request = struct {
        op: []const u8 = "",
        sql: ?[]const u8 = null,
        session: ?u64 = null,
        sequence: ?u64 = null,
        level: ?[]const u8 = null,
        applied: ?u64 = null,
        leader: ?bool = null,
        timeout_ms: ?u64 = null,
        delay_ms: ?u64 = null,
        freshness_ms: ?u64 = null,
        retain: ?u64 = null,
        name: ?[]const u8 = null,
        node_id: ?u32 = null,
        ttl_seconds: ?u64 = null,
        operation: ?u64 = null,
        expected_config: ?u64 = null,
        old_node: ?u32 = null,
        new_node: ?u32 = null,
        endpoint: ?[]const u8 = null,
        // Typed hybrid search (ZDS 0009).
        fts_table: ?[]const u8 = null,
        vec_table: ?[]const u8 = null,
        text: ?[]const u8 = null,
        /// Base64-encoded little-endian float32 query embedding.
        embedding: ?[]const u8 = null,
        k: ?u32 = null,
        candidate_count: ?u32 = null,
        fusion: ?[]const u8 = null,
        text_weight: ?f64 = null,
        vector_weight: ?f64 = null,
        metadata_table: ?[]const u8 = null,
        metadata_id_column: ?[]const u8 = null,
        metadata_columns: ?[]const []const u8 = null,
        // Typed client RPC (ZDS 0010). "typed-v1" requests carry tagged
        // prepared parameters and receive tagged result cells; requests
        // that omit `format` keep the legacy string/null contract.
        format: ?[]const u8 = null,
        params: ?[]const WireParam = null,
        /// Atomic batch exec (remote `executemany`): one tagged
        /// parameter array per row, every row binding the same `sql`.
        /// Mutually exclusive with `params`.
        param_batch: ?[]const []const WireParam = null,
    };

    /// One tagged prepared parameter on the wire: `t` is "null", "int",
    /// "real", "text", or "blob"; text travels as a JSON string and blob
    /// as standard base64 in `v`.
    const WireParam = struct {
        t: []const u8,
        i: ?i64 = null,
        r: ?f64 = null,
        v: ?[]const u8 = null,
    };

    fn dispatch(
        self: *Server,
        body: []const u8,
        principal: Principal,
        out: *Io.Writer,
    ) !void {
        const parsed = std.json.parseFromSlice(Request, self.gpa, body, .{
            .ignore_unknown_fields = true,
        }) catch {
            return writeErrorResponse(out, "bad_request", "malformed request");
        };
        defer parsed.deinit();
        const request = parsed.value;
        if (std.mem.eql(u8, request.op, "status")) {
            return self.opStatus(out);
        }
        if (self.isShutdown() and !std.mem.eql(u8, request.op, "stop")) {
            return writeErrorResponse(out, "unavailable", "node shutting down");
        }

        if (std.mem.eql(u8, request.op, "members")) {
            return self.opMembers(out);
        } else if (std.mem.eql(u8, request.op, "leader")) {
            return self.opLeader(out);
        } else if (std.mem.eql(u8, request.op, "exec")) {
            return self.opExec(request, out);
        } else if (std.mem.eql(u8, request.op, "query")) {
            return self.opQuery(request, out);
        } else if (std.mem.eql(u8, request.op, "search")) {
            return self.opSearch(request, out);
        } else if (std.mem.eql(u8, request.op, "session")) {
            return self.opSession(out);
        } else if (std.mem.eql(u8, request.op, "wait")) {
            return self.opWait(request, out);
        } else if (std.mem.eql(u8, request.op, "anchor")) {
            return self.opStateAnchor(out);
        } else if (std.mem.eql(u8, request.op, "enable-search-feature")) {
            return self.opEnableSearchFeature(out);
        } else if (std.mem.eql(u8, request.op, "integrity")) {
            return self.opIntegrity(out);
        } else if (std.mem.eql(u8, request.op, "hash")) {
            return self.opHash(out);
        } else if (std.mem.eql(u8, request.op, "expire-sessions")) {
            return self.opExpireSessions(request, out);
        } else if (std.mem.eql(u8, request.op, "issue-enrollment-token")) {
            return self.opIssueEnrollmentToken(request, out);
        } else if (std.mem.eql(u8, request.op, "membership")) {
            return self.opMembership(out);
        } else if (std.mem.eql(u8, request.op, "replace-voter")) {
            return self.opReplaceVoter(request, principal, out);
        } else if (std.mem.eql(u8, request.op, "failpoint")) {
            return server_test_control.apply(self, .arm_failpoint, request.name, null, out);
        } else if (std.mem.eql(u8, request.op, "test-vote-delay")) {
            return server_test_control.apply(
                self,
                .set_vote_delay,
                null,
                request.delay_ms,
                out,
            );
        } else if (std.mem.eql(u8, request.op, "stop")) {
            self.requestShutdown(.rpc);
            return out.writeAll("{\"ok\":true}");
        }
        return writeErrorResponse(out, "bad_request", "unknown op");
    }

    fn opIssueEnrollmentToken(
        self: *Server,
        request: Request,
        out: *Io.Writer,
    ) !void {
        if (self.options.enrollment_ca_key == null) {
            return writeErrorResponse(
                out,
                "enrollment_disabled",
                "this node is not an enrollment issuer",
            );
        }
        const node_id = request.node_id orelse return writeErrorResponse(
            out,
            "bad_request",
            "node_id is required",
        );
        const ttl_seconds = request.ttl_seconds orelse enrollment.default_ttl_seconds;
        if (ttl_seconds == 0 or ttl_seconds > enrollment.maximum_ttl_seconds or
            !self.isConfiguredNode(node_id) or node_id == self.node.identity.node_id or
            self.peerRevoked(node_id))
        {
            return writeErrorResponse(
                out,
                "bad_request",
                "target must be a non-revoked configured peer and TTL at most 24 hours",
            );
        }
        const issued = enrollment.issueToken(
            self.io,
            self.options.directory,
            node_id,
            self.node.identity.node_id,
            self.node.identity.database_id,
            ttl_seconds,
        ) catch |err| return writeErrorResponse(
            out,
            "enrollment_unavailable",
            @errorName(err),
        );
        const token_hex = std.fmt.bytesToHex(issued.secret, .lower);
        try out.print(
            "{{\"ok\":true,\"node_id\":{d},\"issuer_node_id\":{d}," ++
                "\"database_id\":\"{x:0>32}\",\"expires_unix_seconds\":{d}," ++
                "\"token\":\"{s}\"}}",
            .{
                node_id,
                self.node.identity.node_id,
                self.node.identity.database_id,
                issued.expires_unix_seconds,
                &token_hex,
            },
        );
    }

    /// Returns the admin principal name when this connection may run
    /// privileged membership operations, or writes the refusal and
    /// returns null. Requires mutual TLS, an admin certificate, and an
    /// allow-list entry; development PSK connections are anonymous and
    /// can never pass.
    fn authorizeAdmin(
        self: *Server,
        principal: Principal,
        out: *Io.Writer,
    ) !?AdminName {
        if (self.options.tls == null) {
            try writeErrorResponse(
                out,
                "privileged_unavailable",
                "membership operations require mutual TLS",
            );
            return null;
        }
        const admin = switch (principal) {
            .admin => |admin| admin,
            else => {
                try writeErrorResponse(
                    out,
                    "unauthorized",
                    "membership operations require a zaxon-admin certificate",
                );
                return null;
            },
        };
        for (self.options.admin_principals) |name| {
            if (std.mem.eql(u8, name, admin.slice())) return admin;
        }
        try writeErrorResponse(
            out,
            "unauthorized",
            "administrator is not in this server's allow-list",
        );
        return null;
    }

    fn opMembership(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const decided = self.node.decidedRegistry() orelse {
            return writeErrorResponse(
                out,
                "no_registry",
                "this node keeps flag-fixed membership and no decided registry",
            );
        };
        const digest_hex = std.fmt.bytesToHex(decided.digest(), .lower);
        const pending = try self.node.pendingOperation();
        const phase = try self.membershipPhase();
        const quorum_available = self.quorumAvailable();
        const installation_state = self.installationState();
        const installation_error = self.installationError();
        try out.print(
            "{{\"ok\":true,\"database_id\":\"{x:0>32}\"," ++
                "\"configuration_id\":{d},\"source\":\"decided\"," ++
                "\"registry_digest\":\"{s}\"," ++
                "\"highest_allocated_node_id\":{d},\"phase\":\"{s}\"," ++
                "\"quorum_available\":{},\"installation_state\":\"{s}\",",
            .{
                decided.database_id,
                decided.configuration_id,
                &digest_hex,
                decided.highest_allocated_node_id,
                phase,
                quorum_available,
                installation_state,
            },
        );
        try status_json.writeMembershipOperation(out, pending, installation_error);
        try out.writeAll(",\"nodes\":[");
        for (decided.nodesSlice(), 0..) |*record, index| {
            if (index > 0) try out.writeAll(",");
            try out.print(
                "{{\"id\":{d},\"role\":\"{s}\",\"endpoint\":\"{s}\"}}",
                .{ record.id, record.role.name(), record.endpointSlice() },
            );
        }
        try out.writeAll("]}");
    }

    /// High-level replacement lifecycle phase. `active-degraded` means the
    /// next configuration is active but the replacement is not yet an
    /// active voter; it does not imply quorum health — operators read
    /// `quorum_available` for that fact. Caller holds `mutex`.
    fn membershipPhase(self: *Server) ![]const u8 {
        if (self.retired) return "retired";
        if (self.node.membership_change_pending or
            self.node.log.isReconfigured() != null)
        {
            return "chosen";
        }
        if (try self.node.pendingOperation()) |pending| {
            return switch (pending.phase) {
                .prepared => "prepared",
                .proposed => "proposed",
            };
        }
        if (self.currentReplacement()) |new_node| {
            return if (self.replacementActive(new_node))
                "complete"
            else
                "active-degraded";
        }
        return "idle";
    }

    /// The replacement voter that created the current configuration, if
    /// the newest decided operation did. Caller holds `mutex`.
    fn currentReplacement(self: *Server) ?paxos.NodeId {
        const decided = self.node.decidedRegistry() orelse return null;
        const newest = decided.newestOperation() orelse return null;
        if (newest.result_configuration_id != decided.configuration_id) return null;
        return newest.new_node_id;
    }

    fn replacementActive(self: *Server, new_node: paxos.NodeId) bool {
        if (new_node == self.node.identity.node_id) {
            const decided = self.node.decidedRegistry() orelse return false;
            return self.node.identity.configuration_id == decided.configuration_id and
                self.transport_configuration_id == decided.configuration_id;
        }
        return self.replacement_ready_node == new_node and
            self.replacement_ready_configuration == self.node.identity.configuration_id;
    }

    /// Announces only local durable state. The receiver binds it to the
    /// decided replacement ID, configuration, and registry digest.
    fn advertiseInstallationReady(self: *Server, sender: *PeerSender) void {
        const decided = self.node.decidedRegistry() orelse return;
        const replacement = self.currentReplacement() orelse return;
        if (replacement != self.node.identity.node_id or
            self.node.identity.configuration_id != decided.configuration_id or
            self.transport_configuration_id != decided.configuration_id)
        {
            return;
        }
        if (sender.ready_advertised_configuration == decided.configuration_id) {
            return;
        }
        var body: [wire.InstallationReady.encoded_size]u8 = undefined;
        const ready = wire.InstallationReady{
            .configuration_id = decided.configuration_id,
            .registry_digest = decided.digest(),
        };
        const frame = wire.frameAlloc(
            self.gpa,
            .installation_ready,
            &.{ready.encode(&body)},
        ) catch return;
        if (sender.enqueueChecked(frame)) {
            sender.ready_advertised_configuration = decided.configuration_id;
        }
    }

    /// Operational observation: recent authenticated peers plus this
    /// voter can satisfy the configured read and write quorums. It does
    /// not authorize membership decisions and does not promise that this
    /// server is the leader. Caller holds `mutex`.
    fn quorumAvailable(self: *Server) bool {
        var voters: u16 = 0;
        var reachable: u16 = 0;
        const self_id = self.node.identity.node_id;
        const self_votes = self.node.capabilities.votes;
        const replacement = self.currentReplacement();
        for (self.currentMembers()) |member| {
            if (!member.role.capabilities().votes) continue;
            voters += 1;
            if (member.id == self_id) {
                const ready = replacement == null or
                    self_id != replacement.? or
                    self.replacementActive(self_id);
                if (ready and self_votes and !self.retired) reachable += 1;
                continue;
            }
            if (self.senderFor(member.id)) |sender| {
                const ready = replacement == null or
                    member.id != replacement.? or
                    self.replacementActive(member.id);
                if (ready and sender.isConnected()) reachable += 1;
            }
        }
        if (voters == 0) return self_votes;
        // The default read and write quorums are both the majority.
        return reachable >= voters / 2 + 1;
    }

    /// The replacement voter's installation lifecycle: this node's own
    /// transfer progress when it is the one joining, otherwise the
    /// observed state of the decided replacement. Caller holds `mutex`.
    fn installationState(self: *Server) []const u8 {
        switch (self.installation) {
            .not_applicable => {},
            .transferring => return "transferring",
            .verifying => return "verifying",
            .installed => return "installed",
            .active => return "active",
            .failed => return "failed",
        }
        const new_node = self.currentReplacement() orelse return "not-applicable";
        if (self.replacementActive(new_node)) return "active";
        return "not-started";
    }

    fn installationError(self: *const Server) ?[]const u8 {
        const err = self.installation_failure orelse return null;
        return @errorName(err);
    }

    const ReplacementOutcome = union(enum) {
        not_leader,
        complete: u64,
        proposed: u64,
        rejected: anyerror,
    };

    fn opReplaceVoter(
        self: *Server,
        request: Request,
        principal: Principal,
        out: *Io.Writer,
    ) !void {
        if ((try self.authorizeAdmin(principal, out)) == null) return;
        const operation_id = request.operation orelse
            return writeErrorResponse(out, "bad_request", "operation is required");
        const expected_config = request.expected_config orelse
            return writeErrorResponse(out, "bad_request", "expected_config is required");
        const old_node = request.old_node orelse
            return writeErrorResponse(out, "bad_request", "old_node is required");
        const new_node = request.new_node orelse
            return writeErrorResponse(out, "bad_request", "new_node is required");
        const endpoint = request.endpoint orelse
            return writeErrorResponse(out, "bad_request", "endpoint is required");

        const replacement = registry.ReplacementRequest{
            .operation_id = operation_id,
            .expected_configuration_id = expected_config,
            .old_node_id = old_node,
            .new_node_id = new_node,
            .new_endpoint = endpoint,
        };

        self.mutex.lockUncancelable(self.io);
        const outcome = self.replaceVoterLocked(&replacement);
        self.mutex.unlock(self.io);

        switch (outcome) {
            .not_leader => return self.writeNotLeader(out),
            .rejected => |err| {
                const response = replacement_error.classify(err);
                return writeErrorResponse(out, response.code, response.message);
            },
            .complete => |configuration_id| try out.print(
                "{{\"ok\":true,\"operation\":{d},\"phase\":\"complete\"," ++
                    "\"configuration_id\":{d}}}",
                .{ operation_id, configuration_id },
            ),
            .proposed => |configuration_id| try out.print(
                "{{\"ok\":true,\"operation\":{d},\"phase\":\"proposed\"," ++
                    "\"next_configuration_id\":{d}}}",
                .{ operation_id, configuration_id },
            ),
        }
    }

    fn replaceVoterLocked(
        self: *Server,
        replacement: *const registry.ReplacementRequest,
    ) ReplacementOutcome {
        const decided = self.node.decidedRegistry() orelse
            return .{ .rejected = error.NoDecidedRegistry };
        const disposition = decided.validateRequest(replacement) catch |err|
            return .{ .rejected = err };
        switch (disposition) {
            .retry => |done| return .{
                .complete = done.result_configuration_id,
            },
            .fresh => {},
        }
        if (self.node.log.core.role != .leader) return .not_leader;
        const pending = self.node.pendingOperation() catch |err|
            return .{ .rejected = err };
        if (pending) |record| {
            if (!record.matches(replacement)) {
                const err = if (record.operation_id == replacement.operation_id)
                    error.OperationConflict
                else
                    error.OperationPending;
                return .{ .rejected = err };
            }
            if (record.phase == .proposed) {
                return .{ .proposed = decided.configuration_id + 1 };
            }
        }
        self.node.prepareReplacement(replacement) catch |err|
            return .{ .rejected = err };
        return .{ .proposed = decided.configuration_id + 1 };
    }

    fn opStatus(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const status = self.node.status();
        const leader = self.knownLeader();
        const pending = self.node.pendingOperation() catch |err| {
            self.mutex.unlock(self.io);
            return writeErrorResponse(out, "corrupt_pending_operation", @errorName(err));
        };
        const phase = self.membershipPhase() catch |err| {
            self.mutex.unlock(self.io);
            return writeErrorResponse(out, "corrupt_pending_operation", @errorName(err));
        };
        const quorum_available = !self.failed and self.quorumAvailable();
        const health = if (self.failed)
            "failed"
        else if (self.isShutdown())
            "stopping"
        else
            "healthy";
        const failure = if (self.first_failure) |err| @errorName(err) else null;
        const installation_state = self.installationState();
        const installation_error = self.installationError();
        self.mutex.unlock(self.io);
        try status_json.writeHead(
            out,
            status,
            leader,
            phase,
            quorum_available,
            installation_state,
            health,
            failure,
        );
        try status_json.writeMembershipOperation(out, pending, installation_error);
        try out.writeAll("}");
    }

    fn opMembers(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const leader = self.knownLeader();
        const self_id = self.node.identity.node_id;
        const decided = self.node.decidedRegistry() != null;
        self.mutex.unlock(self.io);
        const source = if (decided) "decided" else "static";
        try out.print(
            "{{\"ok\":true,\"voter_membership\":\"{s}\",\"nodes\":[",
            .{source},
        );
        for (self.currentMembers(), 0..) |member, index| {
            if (index > 0) try out.writeAll(",");
            const capabilities = member.role.capabilities();
            try out.print(
                "{{\"id\":{d},\"host\":\"{s}\",\"port\":{d}," ++
                    "\"role\":\"{s}\",\"votes\":{},\"campaigns\":{}," ++
                    "\"stores_log\":{},\"serves_reads\":{}," ++
                    "\"serves_writes\":{},\"promotion_eligible\":{}," ++
                    "\"self\":{},\"leader\":{}}}",
                .{
                    member.id,
                    member.host,
                    member.port,
                    member.role.name(),
                    capabilities.votes,
                    capabilities.campaigns,
                    capabilities.stores_log,
                    capabilities.serves_reads,
                    capabilities.serves_writes,
                    capabilities.promotion_eligible,
                    member.id == self_id,
                    leader != null and member.id == leader.?,
                },
            );
        }
        try out.writeAll("]}");
    }

    fn opLeader(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const leader = self.knownLeader();
        self.mutex.unlock(self.io);
        if (leader) |id| {
            if (self.addressOf(id)) |address| {
                return out.print(
                    "{{\"ok\":true,\"leader\":{{\"id\":{d},\"host\":\"{s}\",\"port\":{d}}}}}",
                    .{ id, address.host, address.port },
                );
            }
            return out.print("{{\"ok\":true,\"leader\":{{\"id\":{d}}}}}", .{id});
        }
        try out.writeAll("{\"ok\":true,\"leader\":null}");
    }

    fn writeNotLeader(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const leader = self.knownLeader();
        const self_id = self.node.identity.node_id;
        self.mutex.unlock(self.io);
        if (leader) |id| {
            if (id != self_id) {
                if (self.addressOf(id)) |address| {
                    return out.print(
                        "{{\"ok\":false,\"error\":\"not_leader\"," ++
                            "\"leader\":{{\"id\":{d},\"host\":\"{s}\",\"port\":{d}}}}}",
                        .{ id, address.host, address.port },
                    );
                }
            }
        }
        try out.writeAll("{\"ok\":false,\"error\":\"not_leader\",\"leader\":null}");
    }

    const WriteError = error{
        NotLeader,
        Ambiguous,
        OpTimeout,
        /// The deadline expired while the write was still queued before the
        /// gate (or before the epoch rollover completed): the statement
        /// provably never executed, so a plain retry is safe.
        OpTimeoutQueued,
        Unavailable,
    };

    /// One parked writer awaiting FIFO admission. Stack-allocated by the
    /// waiting connection thread; all links are mutated under `mutex`.
    const WriterTicket = struct {
        granted: bool = false,
        next: ?*WriterTicket = null,
    };

    const ExecOutcome = node_mod.ExecResult;

    /// Runs one replicated write to completion: appends under the writer
    /// gate, then blocks until the slot commits and carries our batch.
    fn runWrite(
        self: *Server,
        comptime run: anytype,
        context: anytype,
    ) anyerror!ExecOutcome {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed or self.isShutdown()) return error.Unavailable;

        // One replicated write at a time; a dependent slot is never built
        // before its predecessor is chosen. Admission is first-in-first-out:
        // the releasing owner hands the gate directly to the oldest ticket.
        const queued_tick: u64 = self.tick_count;
        if (self.writer_gate_busy or self.writer_queue_head != null) {
            var ticket = WriterTicket{};
            if (self.writer_queue_tail) |tail| {
                tail.next = &ticket;
            } else {
                self.writer_queue_head = &ticket;
            }
            self.writer_queue_tail = &ticket;
            while (!ticket.granted) {
                if (self.failed or self.isShutdown()) {
                    self.removeWriterTicket(&ticket);
                    return error.Unavailable;
                }
                if (self.elapsedMs(queued_tick) > op_timeout_ms) {
                    self.removeWriterTicket(&ticket);
                    return error.OpTimeoutQueued;
                }
                self.writer_cond.waitUncancelable(self.io, &self.mutex);
            }
        } else {
            self.writer_gate_busy = true;
        }
        defer self.releaseWriterGate();
        if (self.failed or self.isShutdown()) return error.Unavailable;

        if (!self.node.isLeader()) return error.NotLeader;

        // Slots continue globally (ZDS 0011); only a decided membership
        // change seals the log. Waiting here would never unseal it.
        if (self.node.membership_change_pending or self.node.log.stop_pending) {
            return error.LogSealed;
        }

        // A batch's chain base is this node's applied state. Slots still
        // undecided below the proposal frontier (inherited from the
        // previous leader, or a trim in flight) would make it stale, so
        // the write waits here, before any SQL runs. The mutex stays held
        // from this check through the append, so nothing can interleave.
        try self.awaitLeaderFrontier(Node.proposalFrontierSettled, queued_tick);

        self.node.ensureWriter() catch return error.Unavailable;

        const result: ExecOutcome = run(self.node, context) catch |err| {
            if (self.node.needsResync() and !self.node.storageFailed()) {
                self.node.resyncImage() catch |resync_err| {
                    self.failLocked(resync_err);
                };
            }
            if (self.node.storageFailed()) {
                self.failLocked(err);
            }
            return err;
        };
        if (result.replayed) return result;

        if (self.node.single) {
            failpoint.hit("before_client_reply");
            return result;
        }
        self.pump();

        var waiter = WriteWaiter{
            .slot = result.slot,
            .batch_id = self.node.pendingBatchId() orelse {
                // Already decided (accounting ran inside consumeEffects).
                if (self.node.applied_slot >= result.slot) {
                    failpoint.hit("before_client_reply");
                    return result;
                }
                return error.Ambiguous;
            },
        };
        self.write_waiter = &waiter;
        defer if (self.write_waiter == &waiter) {
            self.write_waiter = null;
        };
        self.pump();
        try waiter.awaitOutcome(self, self.tick_count, op_timeout_ms);
        failpoint.hit("before_client_reply");
        return result;
    }

    /// Blocks until `settled(node)` holds on this leader. Returns
    /// `NotLeader` if leadership moves meanwhile, `Unavailable` if the node
    /// fails, and `OpTimeoutQueued` once the deadline measured from
    /// `start_tick` passes: nothing has executed, so a plain retry is safe.
    /// Called with `mutex` held; the wait releases it temporarily.
    fn awaitLeaderFrontier(
        self: *Server,
        comptime settled: fn (*const Node) bool,
        start_tick: u64,
    ) WriteError!void {
        return leader_frontier.awaitReady(self, settled, start_tick, op_timeout_ms);
    }

    /// Releases the writer gate, handing it directly to the oldest queued
    /// ticket so admission stays first-in-first-out. Called under `mutex`.
    fn releaseWriterGate(self: *Server) void {
        if (self.writer_queue_head) |next| {
            self.writer_queue_head = next.next;
            if (self.writer_queue_head == null) self.writer_queue_tail = null;
            next.next = null;
            next.granted = true;
        } else {
            self.writer_gate_busy = false;
        }
        self.writer_cond.broadcast(self.io);
    }

    /// Unlinks an abandoned ticket (deadline expiry or node failure)
    /// without disturbing queue order. Called under `mutex`.
    fn removeWriterTicket(self: *Server, ticket: *WriterTicket) void {
        var previous: ?*WriterTicket = null;
        var cursor = self.writer_queue_head;
        while (cursor) |current| : (cursor = current.next) {
            if (current == ticket) {
                if (previous) |before| {
                    before.next = current.next;
                } else {
                    self.writer_queue_head = current.next;
                }
                if (self.writer_queue_tail == current) {
                    self.writer_queue_tail = previous;
                }
                return;
            }
            previous = current;
        }
    }

    /// Validates the request's `format` field. Returns true for the typed
    /// contract, false for legacy, or null after writing an error response.
    fn typedFormat(request: Request, out: *Io.Writer) !?bool {
        if (request.format) |format| {
            if (!std.mem.eql(u8, format, "typed-v1")) {
                try writeErrorResponse(out, "bad_request", "unknown format");
                return null;
            }
            return true;
        }
        if (request.params != null or request.param_batch != null) {
            try writeErrorResponse(
                out,
                "bad_request",
                "params require format typed-v1",
            );
            return null;
        }
        return false;
    }

    /// Decodes tagged wire parameters into prepared values. Text bytes
    /// reference the parsed request; blob bytes are decoded into `arena`.
    fn decodeWireParams(
        arena: std.mem.Allocator,
        params: []const WireParam,
    ) ![]prepared.Value {
        const values = try arena.alloc(prepared.Value, params.len);
        for (params, values) |param, *value| {
            if (std.mem.eql(u8, param.t, "null")) {
                value.* = .null_value;
            } else if (std.mem.eql(u8, param.t, "int")) {
                value.* = .{ .integer = param.i orelse return error.BadParam };
            } else if (std.mem.eql(u8, param.t, "real")) {
                value.* = .{ .real = param.r orelse return error.BadParam };
            } else if (std.mem.eql(u8, param.t, "text")) {
                value.* = .{ .text = param.v orelse return error.BadParam };
            } else if (std.mem.eql(u8, param.t, "blob")) {
                const encoded = param.v orelse return error.BadParam;
                const decoder = std.base64.standard.Decoder;
                const size = decoder.calcSizeForSlice(encoded) catch
                    return error.BadParam;
                const bytes = try arena.alloc(u8, size);
                decoder.decode(bytes, encoded) catch return error.BadParam;
                value.* = .{ .blob = bytes };
            } else {
                return error.BadParam;
            }
        }
        return values;
    }

    fn opExec(self: *Server, request: Request, out: *Io.Writer) !void {
        const sql_text = request.sql orelse
            return writeErrorResponse(out, "bad_request", "exec needs sql");
        if ((request.session == null) != (request.sequence == null)) {
            return writeErrorResponse(
                out,
                "bad_request",
                "session and sequence go together",
            );
        }
        const typed = (try typedFormat(request, out)) orelse return;
        const sql = try self.gpa.dupeSentinel(u8, sql_text, 0);
        defer self.gpa.free(sql);

        if (try self.ensureSchemaForWrite(out) == null) return;

        if (typed) return self.opExecTyped(request, sql, out);

        const Ctx = struct {
            sql: [:0]const u8,
            session: ?u64,
            sequence: ?u64,
        };
        const outcome = self.runWrite(struct {
            fn run(node: *Node, context: Ctx) !ExecOutcome {
                if (context.session) |session| {
                    return node.execIdempotent(session, context.sequence.?, context.sql);
                }
                return node.exec(context.sql);
            }
        }.run, Ctx{
            .sql = sql,
            .session = request.session,
            .sequence = request.sequence,
        }) catch |err| return self.writeWriteError(err, out);

        try out.print(
            "{{\"ok\":true,\"changes\":{d},\"slot\":{d},\"replayed\":{}}}",
            .{ outcome.changes, outcome.slot, outcome.replayed },
        );
    }

    /// Typed-v1 exec: tagged prepared parameters, structured result with
    /// the optional last insert rowid. Remote `RETURNING` rows stay
    /// unsupported until they can be retained for session replay.
    fn opExecTyped(
        self: *Server,
        request: Request,
        sql: [:0]const u8,
        out: *Io.Writer,
    ) !void {
        var params_arena = std.heap.ArenaAllocator.init(self.gpa);
        defer params_arena.deinit();
        if (request.param_batch != null and request.params != null) {
            return writeErrorResponse(
                out,
                "bad_request",
                "params and param_batch are mutually exclusive",
            );
        }
        if (request.param_batch) |batch| {
            return self.opExecTypedBatch(
                request,
                sql,
                batch,
                params_arena.allocator(),
                out,
            );
        }
        const values = decodeWireParams(
            params_arena.allocator(),
            request.params orelse &.{},
        ) catch {
            return writeErrorResponse(out, "bad_request", "invalid params");
        };

        const Ctx = struct {
            gpa: std.mem.Allocator,
            sql: []const u8,
            values: []const prepared.Value,
            session: ?u64,
            sequence: ?u64,
        };
        const outcome = self.runWrite(struct {
            fn run(node: *Node, context: Ctx) !ExecOutcome {
                if (context.session) |session| {
                    return node.execIdempotentPrepared(
                        session,
                        context.sequence.?,
                        context.sql,
                        context.values,
                    );
                }
                var returning: ?node_mod.TypedResult = null;
                const result = try node.execPreparedResult(
                    context.gpa,
                    context.sql,
                    context.values,
                    &returning,
                );
                if (returning) |*rows| rows.deinit();
                return result;
            }
        }.run, Ctx{
            .gpa = self.gpa,
            .sql = sql,
            .values = values,
            .session = request.session,
            .sequence = request.sequence,
        }) catch |err| return self.writeWriteError(err, out);

        try writeTypedExecResponse(outcome, out);
    }

    /// Atomic typed-v1 batch exec (remote `executemany`): one bounded
    /// batch of tagged parameter vectors, one replicated transaction,
    /// one session sequence. `changes` is the whole batch's total; any
    /// per-row failure rolls the entire batch back.
    fn opExecTypedBatch(
        self: *Server,
        request: Request,
        sql: [:0]const u8,
        batch: []const []const WireParam,
        arena: std.mem.Allocator,
        out: *Io.Writer,
    ) !void {
        if (batch.len == 0) {
            return writeErrorResponse(out, "bad_request", "param_batch is empty");
        }
        if (batch.len > prepared.maximum_statements) {
            return writeErrorResponse(
                out,
                "bad_request",
                "param_batch exceeds the statement limit",
            );
        }
        const rows = try arena.alloc([]const prepared.Value, batch.len);
        for (batch, rows) |wire_row, *row| {
            row.* = decodeWireParams(arena, wire_row) catch {
                return writeErrorResponse(out, "bad_request", "invalid params");
            };
        }

        const Ctx = struct {
            sql: [:0]const u8,
            rows: []const []const prepared.Value,
            session: ?u64,
            sequence: ?u64,
        };
        const outcome = self.runWrite(struct {
            fn run(node: *Node, context: Ctx) !ExecOutcome {
                if (context.session) |session| {
                    return node.execIdempotentPreparedBatch(
                        session,
                        context.sequence.?,
                        context.sql,
                        context.rows,
                    );
                }
                return node.execPreparedBatch(context.sql, context.rows);
            }
        }.run, Ctx{
            .sql = sql,
            .rows = rows,
            .session = request.session,
            .sequence = request.sequence,
        }) catch |err| return self.writeWriteError(err, out);

        try writeTypedExecResponse(outcome, out);
    }

    /// The one typed-v1 exec response shape, shared by the single and
    /// batch paths.
    fn writeTypedExecResponse(outcome: ExecOutcome, out: *Io.Writer) !void {
        try out.print(
            "{{\"ok\":true,\"format\":\"typed-v1\",\"changes\":{d}," ++
                "\"slot\":{d},\"replayed\":{}",
            .{ outcome.changes, outcome.slot, outcome.replayed },
        );
        if (outcome.last_insert_rowid) |rowid| {
            try out.print(",\"last_insert_rowid\":{d}", .{rowid});
        }
        try out.writeAll("}");
    }

    /// Bootstraps the replicated schema when absent. Returns null when a
    /// response was already written (error path).
    fn ensureSchemaForWrite(self: *Server, out: *Io.Writer) !?void {
        self.mutex.lockUncancelable(self.io);
        const ready = self.node.schemaReady() catch false;
        if (ready) {
            self.mutex.unlock(self.io);
            return {};
        }
        if (!self.node.isLeader()) {
            self.mutex.unlock(self.io);
            try self.writeNotLeader(out);
            return null;
        }
        self.mutex.unlock(self.io);

        // Bootstrap must bypass the application authorizer: it creates the
        // reserved `__zaxon_*` tables that application SQL cannot touch.
        _ = self.runWrite(struct {
            fn run(node: *Node, context: void) !ExecOutcome {
                _ = context;
                return node.bootstrapSchemaIfMissing();
            }
        }.run, {}) catch |err| {
            try self.writeWriteError(err, out);
            return null;
        };
        return {};
    }

    fn writeWriteError(self: *Server, err: anyerror, out: *Io.Writer) !void {
        switch (err) {
            error.NotLeader => try self.writeNotLeader(out),
            error.Ambiguous => try writeErrorResponse(
                out,
                "ambiguous",
                "write fate unknown; retry idempotently",
            ),
            error.OpTimeout => try writeErrorResponse(out, "timeout", "operation timed out"),
            // Additive discriminator (ZDS 0010): the statement never
            // executed, so the client may retry without a session replay.
            error.OpTimeoutQueued => try out.writeAll(
                "{\"ok\":false,\"error\":\"timeout\",\"queued\":true," ++
                    "\"message\":\"write queue wait expired before execution\"}",
            ),
            // Unreachable behind the frontier wait; kept so a host path
            // that bypasses it still gets a retryable answer.
            error.LeaderNotReady, error.LeaderCatchingUp => try writeErrorResponse(
                out,
                "retry",
                "leader is still applying inherited slots",
            ),
            error.Unavailable => try writeErrorResponse(out, "unavailable", "node unavailable"),
            error.SqliteError, error.SqliteBusy => {
                self.mutex.lockUncancelable(self.io);
                var message_buffer: [512]u8 = undefined;
                const raw = self.node.lastSqliteMessage();
                const len = @min(raw.len, message_buffer.len);
                @memcpy(message_buffer[0..len], raw[0..len]);
                self.mutex.unlock(self.io);
                try writeSqlError(out, message_buffer[0..len]);
            },
            error.UnknownSession, error.SequenceGap, error.ResultExpired => {
                try writeErrorResponse(out, "session", @errorName(err));
            },
            error.LogSealed => try writeErrorResponse(
                out,
                "retry",
                "membership change in progress",
            ),
            error.TransactionTooLarge => try writeErrorResponse(
                out,
                "too_large",
                "transaction payload exceeds the 64 MiB wire limit",
            ),
            error.StorageFailed => try writeErrorResponse(
                out,
                "unavailable",
                "durable storage failed; node stopped",
            ),
            error.RecoveryRetentionExceeded => try writeErrorResponse(
                out,
                "unavailable",
                "journal storage ceiling reached; awaiting trim or capacity",
            ),
            else => try writeErrorResponse(out, "internal", @errorName(err)),
        }
    }

    fn opQuery(self: *Server, request: Request, out: *Io.Writer) !void {
        const sql = request.sql orelse
            return writeErrorResponse(out, "bad_request", "query needs sql");
        if (sql.len > 1024 * 1024) {
            return writeErrorResponse(out, "too_large", "query SQL exceeds 1 MiB");
        }
        var params_arena = std.heap.ArenaAllocator.init(self.gpa);
        defer params_arena.deinit();
        const values = decodeWireParams(
            params_arena.allocator(),
            request.params orelse &.{},
        ) catch {
            return writeErrorResponse(out, "bad_request", "invalid params");
        };
        return self.runReadQuery(request, sql, values, out);
    }

    /// Typed hybrid search (ZDS 0009): the enforced path for the vector
    /// candidate cap. Validation failures are client errors; the built
    /// statement then follows the same read levels and budgets as query.
    fn opSearch(self: *Server, request: Request, out: *Io.Writer) !void {
        var embedding_buffer: ?[]u8 = null;
        defer if (embedding_buffer) |buffer| self.gpa.free(buffer);
        if (request.embedding) |encoded| {
            const decoder = std.base64.standard.Decoder;
            const size = decoder.calcSizeForSlice(encoded) catch
                return writeErrorResponse(
                    out,
                    "bad_request",
                    "embedding is not valid base64",
                );
            const buffer = try self.gpa.alloc(u8, size);
            embedding_buffer = buffer;
            decoder.decode(buffer, encoded) catch
                return writeErrorResponse(
                    out,
                    "bad_request",
                    "embedding is not valid base64",
                );
        }
        const fusion: search_api.Fusion = blk: {
            const text = request.fusion orelse break :blk .rrf;
            if (std.mem.eql(u8, text, "rrf")) break :blk .rrf;
            if (std.mem.eql(u8, text, "dbsf")) break :blk .dbsf;
            return writeErrorResponse(out, "bad_request", "unknown fusion");
        };
        const plan = search_api.plan(self.gpa, .{
            .fts_table = request.fts_table,
            .vec_table = request.vec_table,
            .text = request.text,
            .embedding = embedding_buffer,
            .k = request.k orelse 10,
            .candidate_count = request.candidate_count,
            .fusion = fusion,
            .text_weight = request.text_weight orelse 1.0,
            .vector_weight = request.vector_weight orelse 1.0,
            .metadata_table = request.metadata_table,
            .metadata_id_column = request.metadata_id_column,
            .metadata_columns = request.metadata_columns orelse &.{},
        }) catch |err| {
            return writeErrorResponse(out, "bad_request", switch (err) {
                error.NoRetriever => "search needs text with fts_table, " ++
                    "embedding with vec_table, or both",
                error.MissingText => "fts_table requires text",
                error.MissingEmbedding => "vec_table requires embedding",
                error.InvalidIdentifier => "table names must be plain " ++
                    "identifiers outside reserved namespaces",
                error.InvalidK => "k must be between 1 and 4096",
                error.InvalidCandidateCount => "candidate_count must be " ++
                    "between 1 and 4096",
                error.InvalidEmbedding => "embedding must be float32 with " ++
                    "a dimension divisible by eight",
                error.InvalidWeight => "weights must be finite and nonnegative",
                error.InvalidMetadata => "metadata needs a table and 1 to 16 " ++
                    "plain identifier columns",
                error.OutOfMemory => return err,
            });
        };
        defer plan.deinit(self.gpa);
        return self.runReadQuery(request, plan.sql, plan.values(), out);
    }

    fn runReadQuery(
        self: *Server,
        request: Request,
        sql: []const u8,
        values: []const prepared.Value,
        out: *Io.Writer,
    ) !void {
        const Level = enum { any, leader, linearizable };
        const level: Level = blk: {
            const text = request.level orelse break :blk .linearizable;
            if (std.mem.eql(u8, text, "any")) break :blk .any;
            if (std.mem.eql(u8, text, "leader")) break :blk .leader;
            if (std.mem.eql(u8, text, "linearizable")) break :blk .linearizable;
            return writeErrorResponse(out, "bad_request", "unknown level");
        };
        const typed = (try typedFormat(request, out)) orelse return;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed or self.isShutdown()) {
            return writeErrorResponse(out, "unavailable", "node unavailable");
        }

        if (level != .any and !self.node.isLeader()) {
            self.mutex.unlock(self.io);
            defer self.mutex.lockUncancelable(self.io);
            return self.writeNotLeader(out);
        }
        // A fresh leader's applied state can miss writes the previous
        // leader acknowledged until the inherited prefix is applied; the
        // `leader` and `linearizable` promises both cover those writes.
        if (level != .any) {
            self.awaitLeaderFrontier(Node.inheritedPrefixApplied, self.tick_count) catch |err| {
                if (err != error.NotLeader) {
                    // A read that waited too long simply retries.
                    const mapped = if (err == error.OpTimeoutQueued) error.LeaderNotReady else err;
                    return self.writeWriteError(mapped, out);
                }
                self.mutex.unlock(self.io);
                defer self.mutex.lockUncancelable(self.io);
                return self.writeNotLeader(out);
            };
        }

        if (request.freshness_ms != null and level != .any) {
            return writeErrorResponse(
                out,
                "bad_request",
                "freshness_ms requires level any",
            );
        }
        if (request.freshness_ms) |maximum| {
            if (!self.node.isVoter()) {
                const contact = self.learner_last_contact_tick orelse
                    return writeErrorResponse(
                        out,
                        "stale",
                        "learner has not contacted a leader",
                    );
                if (self.elapsedMs(contact) > maximum or
                    self.node.applied_slot < self.observed_leader_decided)
                {
                    return writeErrorResponse(
                        out,
                        "stale",
                        "learner exceeds the requested freshness bound",
                    );
                }
            }
        }

        if (level == .linearizable and !self.node.single) {
            self.awaitReadFence() catch |err| switch (err) {
                error.Unavailable => return writeErrorResponse(
                    out,
                    "unavailable",
                    "node unavailable",
                ),
                error.ReadFenceTimeout => return writeErrorResponse(
                    out,
                    "timeout",
                    "fence timed out",
                ),
                error.ReadFenceLeadershipChanged => return writeErrorResponse(
                    out,
                    "retry",
                    "leadership changed during fence",
                ),
                else => return err,
            };
        }

        const limits = node_mod.QueryLimits{
            .max_rows = self.options.max_query_rows,
            .max_bytes = self.options.max_query_bytes,
            .max_vm_steps = self.options.max_query_vm_steps,
        };

        if (typed) {
            var result = self.node.queryPreparedTypedWithLimits(
                self.gpa,
                sql,
                values,
                limits,
            ) catch |err| return self.writeReadQueryError(err, out);
            defer result.deinit();

            try out.writeAll("{\"ok\":true,\"format\":\"typed-v1\",\"columns\":[");
            for (result.columns, 0..) |column, index| {
                if (index > 0) try out.writeAll(",");
                try writeJsonString(out, column);
            }
            try out.writeAll("],\"rows\":[");
            for (result.rows, 0..) |row, row_index| {
                if (row_index > 0) try out.writeAll(",");
                try out.writeAll("[");
                for (row, 0..) |cell, index| {
                    if (index > 0) try out.writeAll(",");
                    try self.writeTypedCell(out, cell);
                }
                try out.writeAll("]");
            }
            try out.print("],\"level\":\"{s}\"}}", .{@tagName(level)});
            return;
        }

        var result = self.node.queryPreparedWithLimits(
            self.gpa,
            sql,
            values,
            limits,
        ) catch |err| return self.writeReadQueryError(err, out);
        defer result.deinit();

        try out.writeAll("{\"ok\":true,\"columns\":[");
        for (result.columns, 0..) |column, index| {
            if (index > 0) try out.writeAll(",");
            try writeJsonString(out, column);
        }
        try out.writeAll("],\"rows\":[");
        for (result.rows, 0..) |row, row_index| {
            if (row_index > 0) try out.writeAll(",");
            try out.writeAll("[");
            for (row, 0..) |cell, index| {
                if (index > 0) try out.writeAll(",");
                if (cell) |text| {
                    try writeJsonString(out, text);
                } else {
                    try out.writeAll("null");
                }
            }
            try out.writeAll("]");
        }
        try out.print("],\"level\":\"{s}\"}}", .{@tagName(level)});
    }

    fn writeReadQueryError(self: *Server, err: anyerror, out: *Io.Writer) !void {
        if (err == error.RoleCannotRead) {
            return writeErrorResponse(
                out,
                "forbidden",
                "this node type does not serve SQLite reads",
            );
        }
        const message = switch (err) {
            error.WriteInReadQuery => "statement is not read-only; use exec",
            error.NoDatabaseImage => "no database image on this member yet",
            error.QueryRowLimit => "query exceeded the remote row limit",
            error.QueryResultTooLarge => "query exceeded the remote byte limit",
            error.SqliteInterrupted => "query exceeded the SQLite VM budget",
            else => self.node.lastSqliteMessage(),
        };
        return writeSqlError(out, message);
    }

    /// One typed-v1 result cell: null, {"t":"i","i":n}, {"t":"r","r":x}
    /// (or {"t":"r","x":"<16 hex>"} for non-finite reals, which JSON
    /// cannot express as numbers), {"t":"t","v":"text"}, or
    /// {"t":"b","v":"<base64>"}.
    fn writeTypedCell(
        self: *Server,
        out: *Io.Writer,
        value: prepared.Value,
    ) !void {
        switch (value) {
            .null_value => try out.writeAll("null"),
            .integer => |number| try out.print(
                "{{\"t\":\"i\",\"i\":{d}}}",
                .{number},
            ),
            .real => |number| {
                if (std.math.isFinite(number)) {
                    try out.print("{{\"t\":\"r\",\"r\":{d}}}", .{number});
                } else {
                    const bits: u64 = @bitCast(number);
                    try out.print("{{\"t\":\"r\",\"x\":\"{x:0>16}\"}}", .{bits});
                }
            },
            .text => |bytes| {
                try out.writeAll("{\"t\":\"t\",\"v\":");
                try writeJsonString(out, bytes);
                try out.writeAll("}");
            },
            .blob => |bytes| {
                const encoder = std.base64.standard.Encoder;
                const encoded = try self.gpa.alloc(
                    u8,
                    encoder.calcSize(bytes.len),
                );
                defer self.gpa.free(encoded);
                _ = encoder.encode(encoded, bytes);
                try out.print("{{\"t\":\"b\",\"v\":\"{s}\"}}", .{encoded});
            },
        }
    }

    /// Confirms this exact Paxos ballot with a distinct-member read quorum.
    /// The server mutex must be held; condition waits release it temporarily.
    fn awaitReadFence(self: *Server) !void {
        if (self.failed or self.isShutdown()) return error.Unavailable;
        var fence = FenceWaiter{
            .id = self.next_fence_id,
            .ballot = self.node.log.core.ballot,
            // The fence must cover every slot chosen before this ballot,
            // including ones this leader inherited and has not delivered.
            .fence_slot = @max(self.node.log.decidedThrough(), self.node.log.leaderBase() - 1),
            .needed = self.node.log.core.membership.readQuorum(),
        };
        fence.noteAck(self.node.identity.node_id);
        self.next_fence_id += 1;
        try self.fences.append(self.gpa, &fence);
        defer self.removeFence(&fence);

        var request_buffer: [wire.FenceRequest.encoded_size]u8 = undefined;
        const encoded = (wire.FenceRequest{
            .ballot = fence.ballot,
            .fence_id = fence.id,
            .fence_slot = fence.fence_slot,
        }).encode(&request_buffer);
        for (self.senders.items) |sender| {
            const frame = try wire.frameAlloc(self.gpa, .fence_request, &.{encoded});
            sender.enqueue(frame);
        }
        self.pump();

        try fence.awaitQuorum(self, self.tick_count, op_timeout_ms);
    }

    fn removeFence(self: *Server, fence: *FenceWaiter) void {
        for (self.fences.items, 0..) |candidate, index| {
            if (candidate == fence) {
                _ = self.fences.swapRemove(index);
                return;
            }
        }
    }

    fn opSession(self: *Server, out: *Io.Writer) !void {
        if (try self.ensureSchemaForWrite(out) == null) return;

        var session_id: u64 = 0;
        _ = self.runWrite(struct {
            fn run(node: *Node, context: *u64) !ExecOutcome {
                context.* = try node.openSession();
                return node.lastAppend();
            }
        }.run, &session_id) catch |err| return self.writeWriteError(err, out);
        try out.print("{{\"ok\":true,\"session_id\":{d}}}", .{session_id});
    }

    fn opExpireSessions(self: *Server, request: Request, out: *Io.Writer) !void {
        const retain = request.retain orelse
            return writeErrorResponse(out, "bad_request", "expire-sessions needs retain");
        if (try self.ensureSchemaForWrite(out) == null) return;
        const outcome = self.runWrite(struct {
            fn run(node: *Node, context: u64) !ExecOutcome {
                return node.expireSessions(context);
            }
        }.run, retain) catch |err| return self.writeWriteError(err, out);
        try out.print("{{\"ok\":true,\"expired\":{d}}}", .{outcome.changes});
    }

    fn opWait(self: *Server, request: Request, out: *Io.Writer) !void {
        const timeout_ms = request.timeout_ms orelse op_timeout_ms;
        var waiter = WaitWaiter{
            .min_applied = @intCast(request.applied orelse 0),
            .need_leader = request.leader orelse false,
        };

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed or self.isShutdown()) {
            return writeErrorResponse(out, "unavailable", "node unavailable");
        }
        if (waiter.satisfied(self.node)) return self.writeWaitResponse(out);
        try self.waiters.append(self.gpa, &waiter);
        defer self.removeWaiter(&waiter);
        const start_tick = self.tick_count;
        while (true) {
            if (self.failed or self.isShutdown()) {
                return writeErrorResponse(out, "unavailable", "node unavailable");
            }
            if (waiter.satisfied(self.node)) return self.writeWaitResponse(out);
            if (self.elapsedMs(start_tick) >= timeout_ms) {
                return writeErrorResponse(out, "timeout", "condition not reached");
            }
            waiter.cond.waitUncancelable(self.io, &self.mutex);
        }
    }

    fn removeWaiter(self: *Server, waiter: *WaitWaiter) void {
        for (self.waiters.items, 0..) |candidate, index| {
            if (candidate == waiter) {
                _ = self.waiters.swapRemove(index);
                return;
            }
        }
    }

    fn writeWaitResponse(self: *Server, out: *Io.Writer) !void {
        // Caller holds the mutex.
        try out.print(
            "{{\"ok\":true,\"applied_slot\":{d},\"decided_slot\":{d}," ++
                "\"leader\":{?d},\"configuration_id\":{d}}}",
            .{
                self.node.applied_slot,
                self.node.log.decidedThrough(),
                self.node.currentLeader(),
                self.node.identity.configuration_id,
            },
        );
    }

    /// Records the search-feature version in an image that predates it,
    /// as one replicated internal write (ZDS 0009). The operator calls
    /// this only after every member runs a compatible binary; new
    /// databases record the version at schema bootstrap.
    fn opEnableSearchFeature(self: *Server, out: *Io.Writer) !void {
        if (try self.ensureSchemaForWrite(out) == null) return;
        const outcome = self.runWrite(struct {
            fn run(node: *Node, context: void) !ExecOutcome {
                _ = context;
                return node.enableSearchFeature();
            }
        }.run, {}) catch |err| return self.writeWriteError(err, out);
        try out.print(
            "{{\"ok\":true,\"slot\":{d},\"search_feature_version\":{d}}}",
            .{ outcome.slot, Node.supported_search_feature_version },
        );
    }

    fn opStateAnchor(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) {
            return writeErrorResponse(out, "unavailable", "node failed");
        }
        self.node.createStateAnchor() catch |err| {
            if (self.node.storageFailed()) self.failLocked(err);
            return writeErrorResponse(out, "internal", @errorName(err));
        };
        return out.print(
            "{{\"ok\":true,\"durable_state_slot\":{d}}}",
            .{self.node.durable_state_slot},
        );
    }

    fn opIntegrity(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const report = self.node.integrityCheck() catch |err| {
            self.mutex.unlock(self.io);
            return writeErrorResponse(out, "internal", @errorName(err));
        };
        self.mutex.unlock(self.io);
        try out.print(
            "{{\"ok\":{},\"sqlite_ok\":{},\"chain_ok\":{},\"payloads_ok\":{}}}",
            .{ report.ok(), report.sqlite_ok, report.chain_ok, report.payloads_ok },
        );
    }

    fn opHash(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const content = self.node.contentHash() catch |err| {
            return writeErrorResponse(out, "internal", @errorName(err));
        };
        const chain_hex = std.fmt.bytesToHex(self.node.last_chain, .lower);
        const content_hex = std.fmt.bytesToHex(content, .lower);
        try out.print(
            "{{\"ok\":true,\"chain\":\"{s}\",\"content\":\"{s}\",\"applied_slot\":{d}}}",
            .{ &chain_hex, &content_hex, self.node.applied_slot },
        );
    }
};

// ----------------------------------------------------------------------
// Peer sender: one outgoing connection per peer
// ----------------------------------------------------------------------

const PeerSender = struct {
    server: *Server,
    peer: PeerAddress,
    thread: std.Thread = undefined,
    spawned: bool = false,
    /// Set by an in-process transport swap; the run loop exits and the
    /// swap joins the thread before the sender is destroyed.
    stopped: std.atomic.Value(bool) = .init(false),
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    queue: std.ArrayList([]u8) = .empty,
    queue_bytes: usize = 0,
    gated: std.ArrayList(GatedFrame) = .empty,
    gated_bytes: usize = 0,
    connected: bool = false,
    active_stream: ?std.Io.net.Stream = null,
    stored_payloads: std.AutoHashMap(command.HashBytes, void) = undefined,
    /// Highest current-epoch chosen slot queued on this connection.
    learned_through: paxos.Slot = 0,
    ready_advertised_configuration: u64 = 0,
    enqueued_count: u64 = 0,

    const GatedFrame = struct {
        hash: command.HashBytes,
        frame: []u8,
    };

    fn deinit(self: *PeerSender) void {
        for (self.queue.items) |frame| self.server.gpa.free(frame);
        for (self.gated.items) |item| self.server.gpa.free(item.frame);
        self.queue.deinit(self.server.gpa);
        self.gated.deinit(self.server.gpa);
        self.stored_payloads.deinit();
    }

    /// Takes ownership of `frame`. Drops when disconnected or over bounds;
    /// protocol retransmission recovers dropped frames.
    fn enqueue(self: *PeerSender, frame: []u8) void {
        _ = self.enqueueChecked(frame);
    }

    /// Takes ownership and reports whether the frame entered the bounded
    /// queue. The caller uses this for payload offers so it never records an
    /// offer that was actually dropped.
    fn enqueueChecked(self: *PeerSender, frame: []u8) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.enqueueLocked(frame);
    }

    /// Snapshot chunks are an ordered stream and cannot rely on Paxos
    /// retransmission. Waits for bounded queue capacity, transferring
    /// ownership on both success and failure.
    fn enqueueBackpressure(self: *PeerSender, frame: []u8) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        while (self.connected and !self.shouldStop() and
            (self.queue.items.len + self.gated.items.len >= sender_queue_limit or
                self.queue_bytes + self.gated_bytes + frame.len > sender_queue_byte_limit))
        {
            self.cond.waitUncancelable(io, &self.mutex);
        }
        if (!self.connected or self.shouldStop()) {
            self.server.gpa.free(frame);
            return false;
        }
        return self.enqueueLocked(frame);
    }

    fn enqueueLocked(self: *PeerSender, frame: []u8) bool {
        self.enqueued_count += 1;
        const faults = self.server.options.test_faults;
        if (faults.drop_every != 0 and
            self.enqueued_count % faults.drop_every == 0)
        {
            self.server.gpa.free(frame);
            return false;
        }
        if (!self.connected or
            self.queue.items.len + self.gated.items.len >= sender_queue_limit or
            self.queue_bytes + self.gated_bytes + frame.len > sender_queue_byte_limit)
        {
            self.server.gpa.free(frame);
            return false;
        }
        self.queue.append(self.server.gpa, frame) catch {
            self.server.gpa.free(frame);
            return false;
        };
        self.queue_bytes += frame.len;
        if (faults.reorder_pairs and self.queue.items.len >= 2 and
            self.enqueued_count % 2 == 0)
        {
            const last = self.queue.items.len - 1;
            std.mem.swap([]u8, &self.queue.items[last - 1], &self.queue.items[last]);
        }
        if (faults.duplicate_every != 0 and
            self.enqueued_count % faults.duplicate_every == 0 and
            self.queue.items.len + self.gated.items.len < sender_queue_limit and
            self.queue_bytes + self.gated_bytes + frame.len <= sender_queue_byte_limit)
        {
            if (self.server.gpa.dupe(u8, frame)) |duplicate| {
                if (self.queue.append(self.server.gpa, duplicate)) |_| {
                    self.queue_bytes += duplicate.len;
                } else |_| {
                    self.server.gpa.free(duplicate);
                }
            } else |_| {}
        }
        self.cond.signal(self.server.io);
        return true;
    }

    /// Holds an encoded Paxos envelope until this connection has received a
    /// durable storage acknowledgement for `hash`.
    fn gatePayload(self: *PeerSender, hash: command.HashBytes, frame: []u8) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.stored_payloads.contains(hash)) {
            return self.enqueueLocked(frame);
        }
        if (!self.connected or
            self.queue.items.len + self.gated.items.len >= sender_queue_limit or
            self.queue_bytes + self.gated_bytes + frame.len > sender_queue_byte_limit)
        {
            self.server.gpa.free(frame);
            return false;
        }
        self.gated.append(self.server.gpa, .{ .hash = hash, .frame = frame }) catch {
            self.server.gpa.free(frame);
            return false;
        };
        self.gated_bytes += frame.len;
        return true;
    }

    /// Records one per-connection storage ACK and releases every matching
    /// envelope. Duplicate ACKs are idempotent.
    fn ackPayload(self: *PeerSender, hash: command.HashBytes) void {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.stored_payloads.put(hash, {}) catch return;
        var index: usize = 0;
        while (index < self.gated.items.len) {
            if (!std.mem.eql(u8, &self.gated.items[index].hash, &hash)) {
                index += 1;
                continue;
            }
            const item = self.gated.orderedRemove(index);
            self.gated_bytes -= item.frame.len;
            _ = self.enqueueLocked(item.frame);
        }
    }

    fn hasPayloadAck(self: *PeerSender, hash: command.HashBytes) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.stored_payloads.contains(hash);
    }

    fn isConnected(self: *PeerSender) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.connected;
    }

    fn disconnect(self: *PeerSender) void {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        self.connected = false;
        if (self.active_stream) |stream| stream.shutdown(io, .both) catch {};
        self.cond.broadcast(io);
        self.mutex.unlock(io);
    }

    /// Asks the run loop to exit so a transport swap can join and destroy
    /// this sender. Wakes both the queue wait and any blocked write.
    fn requestStop(self: *PeerSender) void {
        self.stopped.store(true, .release);
        self.disconnect();
    }

    fn shouldStop(self: *PeerSender) bool {
        return self.server.isShutdown() or self.stopped.load(.acquire);
    }

    fn run(self: *PeerSender) void {
        const io = self.server.io;
        while (!self.shouldStop()) {
            if (self.server.peerRevoked(self.peer.id)) {
                io.sleep(.fromMilliseconds(200), .awake) catch {};
                continue;
            }
            const address = std.Io.net.IpAddress.parse(
                self.peer.host,
                self.peer.port,
            ) catch return;
            var stream = deadlines.connectIp(io, address, deadlines.after(io, 1000)) catch {
                io.sleep(.fromMilliseconds(200), .awake) catch {};
                continue;
            };
            defer stream.close(io);
            self.mutex.lockUncancelable(io);
            if (self.shouldStop()) {
                self.mutex.unlock(io);
                return;
            }
            self.active_stream = stream;
            self.mutex.unlock(io);
            defer {
                self.mutex.lockUncancelable(io);
                self.active_stream = null;
                self.connected = false;
                self.cond.broadcast(io);
                self.mutex.unlock(io);
            }
            // TLS teardown must not block emitting close_notify after a stopped send.
            defer stream.shutdown(io, .both) catch {};
            var read_buffer: [64 * 1024]u8 = undefined;
            var write_buffer: [64 * 1024]u8 = undefined;
            var net_reader: std.Io.net.Stream.Reader = undefined;
            var net_writer: std.Io.net.Stream.Writer = undefined;
            var tls_stream: tls.Stream = undefined;
            var tls_active = false;
            defer if (tls_active) {
                stream.shutdown(io, .both) catch {};
                tls_stream.deinit();
            };
            const reader: *Io.Reader, const writer: *Io.Writer = blk: {
                if (self.server.tls_client) |*context| {
                    tls_stream = tls.Stream.connect(
                        context,
                        stream,
                        &read_buffer,
                        &write_buffer,
                    ) catch {
                        io.sleep(.fromMilliseconds(200), .awake) catch {};
                        continue;
                    };
                    tls_active = true;
                    // The dialed member must present the certificate
                    // issued for its configured node id, not merely any
                    // certificate from the cluster CA.
                    var expected_buffer: [tls.max_common_name]u8 = undefined;
                    const expected = tls.nodeCommonName(
                        &expected_buffer,
                        self.peer.id,
                    );
                    if (!std.mem.eql(u8, tls_stream.peerCommonName(), expected)) {
                        io.sleep(.fromMilliseconds(200), .awake) catch {};
                        continue;
                    }
                    break :blk .{ &tls_stream.reader, &tls_stream.writer };
                }
                net_reader = stream.reader(io, &read_buffer);
                net_writer = stream.writer(io, &write_buffer);
                break :blk .{ &net_reader.interface, &net_writer.interface };
            };

            // Handshake, then repair protocol traffic to this peer.
            var authenticated: ?transport_auth.Session = null;
            {
                self.server.mutex.lockUncancelable(self.server.io);
                const hello = wire.Hello{
                    .version = wire.protocol_version,
                    .kind = .peer,
                    .node_id = self.server.node.identity.node_id,
                    .database_id = self.server.node.identity.database_id,
                    .configuration_id = self.server.node.identity.configuration_id,
                };
                self.server.mutex.unlock(self.server.io);
                var hello_buffer: [wire.Hello.encoded_size]u8 = undefined;
                const encoded = hello.encode(&hello_buffer);
                wire.writeFrame(writer, .hello, encoded) catch continue;
                writer.flush() catch continue;
                if (self.server.options.auth_secret) |secret| {
                    authenticated = transport_auth.connect(
                        self.server.gpa,
                        reader,
                        writer,
                        secret,
                        encoded,
                    ) catch continue;
                }
            }
            if (self.server.peerRevoked(self.peer.id)) continue;

            self.mutex.lockUncancelable(io);
            if (self.shouldStop()) {
                self.mutex.unlock(io);
                return;
            }
            self.connected = true;
            self.stored_payloads.clearRetainingCapacity();
            for (self.gated.items) |item| self.server.gpa.free(item.frame);
            self.gated.clearRetainingCapacity();
            self.gated_bytes = 0;
            self.mutex.unlock(io);

            std.log.info(
                "node {d}: connected to peer {d}",
                .{ self.server.node.identity.node_id, self.peer.id },
            );

            {
                self.server.mutex.lockUncancelable(self.server.io);
                self.ready_advertised_configuration = 0;
                self.learned_through = 0;
                if (self.server.node.isVoter() and
                    self.peer.role.capabilities().votes)
                {
                    self.server.node.peerReconnected(self.peer.id) catch |err| {
                        self.server.failLocked(err);
                    };
                }
                if (!self.server.failed) self.server.pump();
                if (!self.server.failed) {
                    self.server.advertiseInstallationReady(self);
                }
                self.server.mutex.unlock(self.server.io);
            }

            send_loop: while (!self.shouldStop()) {
                self.mutex.lockUncancelable(io);
                while (self.queue.items.len == 0 and self.connected) {
                    if (self.shouldStop()) {
                        self.mutex.unlock(io);
                        break :send_loop;
                    }
                    self.cond.waitUncancelable(io, &self.mutex);
                }
                if (!self.connected) {
                    self.mutex.unlock(io);
                    break :send_loop;
                }
                const frame = self.queue.orderedRemove(0);
                self.queue_bytes -= frame.len;
                const flush_now = self.queue.items.len == 0;
                self.cond.broadcast(io);
                self.mutex.unlock(io);

                defer self.server.gpa.free(frame);
                if (authenticated) |*session| {
                    session.writeSerializedFrame(writer, frame) catch
                        break :send_loop;
                } else {
                    self.writePlainFrame(writer, frame) catch break :send_loop;
                }
                if (flush_now) writer.flush() catch break :send_loop;
            }

            self.mutex.lockUncancelable(io);
            self.connected = false;
            for (self.queue.items) |frame| self.server.gpa.free(frame);
            self.queue.clearRetainingCapacity();
            self.queue_bytes = 0;
            for (self.gated.items) |item| self.server.gpa.free(item.frame);
            self.gated.clearRetainingCapacity();
            self.gated_bytes = 0;
            self.stored_payloads.clearRetainingCapacity();
            self.cond.broadcast(io);
            self.mutex.unlock(io);
            io.sleep(.fromMilliseconds(100), .awake) catch {};
        }
    }

    fn writePlainFrame(
        self: *PeerSender,
        writer: *Io.Writer,
        frame: []const u8,
    ) !void {
        const fragment = self.server.options.test_faults.fragment_bytes;
        if (fragment == 0) return writer.writeAll(frame);
        var offset: usize = 0;
        while (offset < frame.len) {
            const end = @min(frame.len, offset + @as(usize, fragment));
            try writer.writeAll(frame[offset..end]);
            try writer.flush();
            offset = end;
        }
    }
};

// ----------------------------------------------------------------------
// JSON helpers
// ----------------------------------------------------------------------

fn writeErrorResponse(out: *Io.Writer, code: []const u8, message: []const u8) !void {
    try out.print("{{\"ok\":false,\"error\":\"{s}\",\"message\":", .{code});
    try writeJsonString(out, message);
    try out.writeAll("}");
}

fn writeSqlError(out: *Io.Writer, message: []const u8) !void {
    try out.writeAll("{\"ok\":false,\"error\":\"sql\",\"message\":");
    try writeJsonString(out, message);
    try out.writeAll("}");
}

fn isOperation(gpa: std.mem.Allocator, body: []const u8, op: []const u8) bool {
    const Operation = struct { op: []const u8 = "" };
    const parsed = std.json.parseFromSlice(Operation, gpa, body, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();
    return std.mem.eql(u8, parsed.value.op, op);
}

pub fn writeJsonString(out: *Io.Writer, text: []const u8) !void {
    try out.writeAll("\"");
    for (text) |byte| {
        switch (byte) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try out.print("\\u{x:0>4}", .{byte});
                } else {
                    try out.writeAll(&.{byte});
                }
            },
        }
    }
    try out.writeAll("\"");
}

test "derive database id is order independent" {
    const a = [_]PeerAddress{
        .{ .id = 1, .host = "h", .port = 1 },
        .{ .id = 2, .host = "h", .port = 2 },
        .{ .id = 3, .host = "h", .port = 3 },
    };
    const b = [_]PeerAddress{ a[2], a[0], a[1] };
    try std.testing.expectEqual(
        deriveDatabaseId(&a, null),
        deriveDatabaseId(&b, null),
    );
    try std.testing.expect(deriveDatabaseId(&a, "x") != deriveDatabaseId(&a, null));
}

test "invalid mmap size has an Elm-style operator diagnostic" {
    var buffer: [512]u8 = undefined;
    var writer = Io.Writer.fixed(&buffer);
    try std.testing.expectEqual(
        @as(u8, 2),
        try reportMmapSize(&writer, sqlite.max_mmap_bytes + 1),
    );
    const text = writer.buffered();
    try std.testing.expect(std.mem.indexOf(
        u8,
        text,
        "-- INVALID MMAP SIZE --",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "maximum is 1073741824") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Hint: Use --mmap-size 0") != null);
}

test "connection admission is sized for a small cluster" {
    var members = [_]PeerAddress{
        .{ .id = 1, .host = "h", .port = 1 },
        .{ .id = 2, .host = "h", .port = 2 },
        .{ .id = 3, .host = "h", .port = 3 },
    };
    var generation = MemberGeneration{
        .configuration_id = 1,
        .members = &members,
        .hosts = &.{},
    };
    var server: Server = undefined;
    server.options = .{
        .directory = ".",
        .node_id = 1,
        .listen_port = 0,
        .members = &members,
    };
    server.membership = .init(&generation);
    try std.testing.expectEqual(@as(usize, 4 * 3 + 16), server.connectionLimit());
    server.options.max_connections = 5;
    try std.testing.expectEqual(@as(usize, 5), server.connectionLimit());
    var empty_generation = MemberGeneration{
        .configuration_id = 1,
        .members = &.{},
        .hosts = &.{},
    };
    server.membership = .init(&empty_generation);
    server.options.max_connections = 0;
    try std.testing.expectEqual(@as(usize, 16), server.connectionLimit());
}

test "a settled frontier does not admit a failed node or former leader" {
    try @import("server_frontier_test.zig").check(Node, Server, Server.awaitLeaderFrontier);
}

test "shutdown and failure cancel parked host operations without protocol ticks" {
    try @import("server_shutdown_test.zig").check(Server, .{
        .write = Server.runWrite,
        .frontier = Server.awaitLeaderFrontier,
        .wait = Server.opWait,
        .fail = Server.failForTest,
        .wake = Server.wakeWaiters,
        .release = Server.releaseWriterGate,
        .shutdown = Server.shutdown,
        .close = Server.noteHandlerClosing,
    });
}

test "read fence counts each member once" {
    var fence = FenceWaiter{
        .id = 1,
        .ballot = .{ .round = 3, .priority = 1, .node = 1 },
        .fence_slot = 9,
        .needed = 2,
    };
    fence.noteAck(1);
    fence.noteAck(2);
    fence.noteAck(2);
    try std.testing.expectEqual(@as(usize, 2), fence.ack_count);
    try std.testing.expectEqual(@as(paxos.NodeId, 1), fence.acked[0]);
    try std.testing.expectEqual(@as(paxos.NodeId, 2), fence.acked[1]);
}

test "payload gate releases envelopes only after storage ack" {
    var server: Server = undefined;
    server.gpa = std.testing.allocator;
    server.io = std.testing.io;

    var sender = PeerSender{
        .server = &server,
        .peer = .{ .id = 2, .host = "127.0.0.1", .port = 1 },
        .connected = true,
    };
    sender.stored_payloads = std.AutoHashMap(command.HashBytes, void).init(
        std.testing.allocator,
    );
    defer sender.deinit();

    const hash = @as([32]u8, @splat(0xab));
    const frame = try std.testing.allocator.dupe(u8, "encoded envelope");
    _ = sender.gatePayload(hash, frame);
    try std.testing.expectEqual(@as(usize, 0), sender.queue.items.len);
    try std.testing.expectEqual(@as(usize, 1), sender.gated.items.len);

    sender.ackPayload(hash);
    try std.testing.expectEqual(@as(usize, 1), sender.queue.items.len);
    try std.testing.expectEqual(@as(usize, 0), sender.gated.items.len);
    sender.ackPayload(hash);
    try std.testing.expectEqual(@as(usize, 1), sender.queue.items.len);
}

test "history probe quorum counts distinct voters only" {
    var waiter = HistoryProbeWaiter{
        .nonce = 1,
        .slot = 7,
        .hash = @as([32]u8, @splat(9)),
        .needed = 2,
    };
    waiter.voters[0] = 1;
    waiter.voters[1] = 2;
    waiter.voters[2] = 3;
    waiter.voter_count = 3;

    // A non-voter never helps satisfy the read quorum.
    waiter.noteAck(4);
    try std.testing.expectEqual(@as(usize, 0), waiter.ack_count);

    // A voter counts exactly once, however often it vouches.
    waiter.noteAck(1);
    waiter.noteAck(1);
    try std.testing.expectEqual(@as(usize, 1), waiter.ack_count);
    waiter.noteAck(3);
    try std.testing.expectEqual(@as(usize, 2), waiter.ack_count);
    try std.testing.expect(waiter.ack_count >= waiter.needed);
}
