//! Transport-owning embedded Zaxonlite facade.
//!
//! Each facade owns one SQLite/Paxos node, its listener, peer senders, tick
//! loop, and client routing. Applications create one facade in each process;
//! the same API works for one through nine voters plus any number of
//! non-voting replicas. Total node count is a runtime registry concern.

const std = @import("std");
const Io = std.Io;
const deadlines = @import("net_deadline.zig");
const client = @import("client.zig");
const node_mod = @import("node.zig");
const server = @import("server.zig");
const tls = @import("tls.zig");
const roles = @import("roles.zig");
const types = @import("types.zig");
const gateway = @import("gateway.zig");

/// Upper bound for one static member registry, voters plus learners.
/// Callers (the C ABI in particular) check declared counts against this
/// before allocating or copying any list.
pub const max_registry_members = 4 * types.log_options.max_members;

/// One static cluster member. Every process must pass the identical member
/// list to `Embedded.open`; membership cannot change while the cluster runs.
pub const Member = struct {
    /// Non-zero, unique across the list, and never reused for a different
    /// logical member (a reused id could vote twice for one identity).
    id: u32,
    /// `host:port` TCP endpoint this member listens on. Borrowed during
    /// `open` and copied; the caller may free it once `open` returns.
    address: []const u8,
    role: roles.Role = .data_voter,
};

/// Options for `Embedded.open`. All slices are copied into the facade's own
/// arena, so the caller keeps ownership and may free them after `open`.
pub const OpenOptions = struct {
    /// Node data directory (journal, payloads, snapshots, SQLite image);
    /// created when missing. One directory belongs to exactly one node.
    directory: []const u8,
    /// This process's member id; must appear in `members`.
    node_id: u32,
    /// Full static membership including this node. Voter count must be
    /// between one and the compiled maximum, and at least one member must
    /// be able to campaign, or `open` fails before starting anything.
    members: []const Member,
    /// Optional salt for the derived database identity, letting two
    /// clusters with identical member lists refuse each other's peers.
    cluster_id: ?[]const u8 = null,
    /// Optional provider-file secret layered inside TLS for an additional
    /// sequenced HMAC. It is not a substitute for `tls` in production.
    auth_secret: ?[]const u8 = null,
    /// Mutual TLS identity for every TCP connection made or accepted by
    /// this member. Production TCP requires all three provider paths.
    tls: ?tls.Config = null,
    /// Optional CA private-key provider for this member to act as the
    /// one-time-token/CSR enrollment issuer. Most members leave it null.
    enrollment_ca_key: ?[]const u8 = null,
    /// How long `open` waits for the spawned server to accept connections
    /// before failing with `error.ServerStartupTimeout`.
    startup_timeout_ms: u64 = 10_000,
    /// Test-only crash and delay injection; never enable in production.
    enable_test_faults: bool = false,
    /// Test harness escape hatch for plaintext/PSK TCP. Production callers
    /// must use the CLI mTLS host or a local Unix-domain socket.
    allow_insecure_test_tcp: bool = false,
    /// Development-only PSK transport without TLS (ZDS 0010). Requires
    /// `auth_secret`, forbids `tls`, and every member address must be a
    /// numeric loopback endpoint; mirrors the CLI's `--dev-psk` policy.
    allow_psk_only_loopback: bool = false,
    test_faults: server.TestFaults = .{},
};

/// One in-process cluster member: the node (or gateway), its TCP listener,
/// peer senders, and tick loop run on a background thread owned by this
/// facade. Create with `open`, destroy with `close`; the struct is
/// heap-allocated and must not be copied or accessed after `close`.
///
/// Safety comes from the node underneath: every acknowledged write is
/// journaled and fsynced before its reply leaves the process. Liveness is
/// not guaranteed: with no elected leader or no quorum, calls fail or time
/// out rather than weakening durability.
pub const Embedded = struct {
    gpa: std.mem.Allocator,
    io: Io,
    arena: std.heap.ArenaAllocator,
    serve_options: server.ServeOptions,
    gateway_options: gateway.Options,
    gateway_mode: bool,
    gateway_shutdown: std.atomic.Value(bool) = .init(false),
    endpoints: []client.Endpoint,
    self_endpoint: client.Endpoint,
    auth_secret: ?[]const u8,
    tls_client: ?tls.Context,
    client_mutex: std.Io.Mutex = .init,
    cluster: client.ClusterConnection,
    thread: std.Thread,
    finished: std.atomic.Value(bool) = .init(false),
    exit_code: std.atomic.Value(u8) = .init(255),
    failure_name_buffer: [128]u8 = undefined,
    failure_name_len: std.atomic.Value(u8) = .init(0),

    pub const LocalServerState = union(enum) {
        healthy,
        stopping,
        stopped: u8,
        failed: []const u8,
    };

    /// Validates the member list, copies all option slices, spawns the server
    /// thread, and blocks until this member answers on its own endpoint or
    /// `options.startup_timeout_ms` elapses (`error.ServerStartupTimeout`);
    /// a server thread that exits during startup is `error.ServerStartupFailed`.
    /// Membership faults (`InvalidMemberCount`, `InvalidNodeId`,
    /// `DuplicateNodeId`, `DuplicateEndpoint`, `InvalidVoterCount`,
    /// `CampaignerRequired`, `NotMember`) are reported before any thread
    /// or file is touched.
    ///
    /// The returned facade is allocated from `gpa` and owned by the caller;
    /// release it with `close`, never with `gpa.destroy`. `gpa` and `io` must
    /// outlive the facade. Startup replays the local journal, so a node with
    /// existing state is durable-consistent before `open` returns.
    fn validateOpenOptions(gpa: std.mem.Allocator, options: OpenOptions) !void {
        if (options.members.len == 0 or options.members.len > max_registry_members) {
            return error.InvalidMemberCount;
        }
        var voter_count: usize = 0;
        var campaigner_count: usize = 0;
        var ids = std.AutoHashMap(u32, void).init(gpa);
        defer ids.deinit();
        var addresses = std.StringHashMap(void).init(gpa);
        defer addresses.deinit();
        for (options.members) |member| {
            if (member.id == 0) return error.InvalidNodeId;
            const inserted = try ids.getOrPut(member.id);
            if (inserted.found_existing) return error.DuplicateNodeId;
            // Two members sharing one address would be one process
            // answering for two identities; refuse the registry.
            const inserted_address = try addresses.getOrPut(member.address);
            if (inserted_address.found_existing) return error.DuplicateEndpoint;
            if (member.role.capabilities().votes) voter_count += 1;
            if (member.role.capabilities().campaigns) campaigner_count += 1;
        }
        if (voter_count == 0 or voter_count > types.log_options.max_members) {
            return error.InvalidVoterCount;
        }
        if (campaigner_count == 0) return error.CampaignerRequired;
    }

    pub fn open(
        gpa: std.mem.Allocator,
        io: Io,
        options: OpenOptions,
    ) !*Embedded {
        try validateOpenOptions(gpa, options);

        const self = try gpa.create(Embedded);
        errdefer gpa.destroy(self);
        self.* = undefined;
        self.gpa = gpa;
        self.io = io;
        self.arena = std.heap.ArenaAllocator.init(gpa);
        errdefer self.arena.deinit();

        try self.initEmbeddedState(options);
        self.client_mutex = .init;
        self.cluster = client.ClusterConnection.init(
            gpa,
            io,
            self.endpoints,
            self.transport(),
        );
        errdefer self.cluster.deinit();
        self.finished = .init(false);
        self.exit_code = .init(255);
        self.failure_name_len = .init(0);
        self.thread = try std.Thread.spawn(.{}, runServer, .{self});
        errdefer {
            self.requestStop();
            self.thread.join();
        }
        try self.waitUntilListening(options.startup_timeout_ms);
        return self;
    }

    fn initEmbeddedState(self: *Embedded, options: OpenOptions) !void {
        const allocator = self.arena.allocator();
        const directory = try allocator.dupe(u8, options.directory);
        const parsed_members = try parseOpenMembers(allocator, options.members, options.node_id);
        const own = parsed_members.self_endpoint orelse return error.NotMember;
        const own_role = parsed_members.self_role orelse return error.NotMember;
        const peers = parsed_members.peers;
        const endpoints = parsed_members.endpoints;

        try validateTransportOptions(options, endpoints);
        const backends = parsed_members.backends;
        const backend_count = parsed_members.backend_count;
        const secret = if (options.auth_secret) |bytes|
            try allocator.dupe(u8, bytes)
        else
            null;
        const cluster_id = if (options.cluster_id) |text|
            try allocator.dupe(u8, text)
        else
            null;
        const tls_config: ?tls.Config = if (options.tls) |config| .{
            .cert_path = try allocator.dupe(u8, config.cert_path),
            .key_path = try allocator.dupe(u8, config.key_path),
            .ca_path = try allocator.dupe(u8, config.ca_path),
        } else null;
        const enrollment_ca_key = if (options.enrollment_ca_key) |path|
            try allocator.dupe(u8, path)
        else
            null;

        self.serve_options = .{
            .directory = directory,
            .shutdown_flag = &self.gateway_shutdown,
            .failure_name_buffer = &self.failure_name_buffer,
            .failure_name_len = &self.failure_name_len,
            .node_id = options.node_id,
            .listen_host = own.host,
            .listen_port = own.port,
            .listen_unix = own.unix_path,
            .members = peers,
            .database_id = server.deriveDatabaseId(peers, cluster_id),
            .auth_secret = secret,
            .tls = tls_config,
            .enrollment_ca_key = enrollment_ca_key,
            .enable_failpoints = options.enable_test_faults or
                options.allow_insecure_test_tcp,
            .allow_insecure_test_tcp = options.allow_insecure_test_tcp,
            .allow_psk_only_loopback = options.allow_psk_only_loopback,
            .test_faults = options.test_faults,
        };
        self.gateway_shutdown = .init(false);
        self.gateway_options = .{
            .listen_host = own.host,
            .listen_port = own.port,
            .backends = backends[0..backend_count],
            .shutdown_flag = &self.gateway_shutdown,
            .failure_name_buffer = &self.failure_name_buffer,
            .failure_name_len = &self.failure_name_len,
        };
        self.gateway_mode = own_role == .gateway;
        self.endpoints = endpoints;
        self.self_endpoint = own;
        self.auth_secret = secret;
        self.tls_client = null;
        if (tls_config) |config| {
            self.tls_client = try tls.Context.initClient(config);
        }
        errdefer if (self.tls_client) |*context| context.deinit();
    }

    fn validateTransportOptions(
        options: OpenOptions,
        endpoints: []const client.Endpoint,
    ) !void {
        // A unix member address names a single-node local service, never a
        // way to connect Paxos members. This replaces the earlier silent
        // degradation that left the socket path in `host` with port zero.
        for (endpoints, 0..) |endpoint, index| {
            if (endpoint.unix_path) |path| {
                if (options.members.len != 1) return error.UnixSocketNeedsSingleMember;
                if (options.members[index].role == .gateway) {
                    return error.UnixSocketGateway;
                }
                if (path.len == 0 or path[0] != '/') return error.InvalidEndpoint;
                if (std.mem.indexOfScalar(u8, path, 0) != null) {
                    return error.InvalidEndpoint;
                }
                if (options.allow_psk_only_loopback) {
                    return error.DevPskWithUnixSocket;
                }
            }
        }
        if (options.allow_psk_only_loopback) {
            if (options.auth_secret == null) return error.DevPskNeedsSecret;
            if (options.tls != null) return error.DevPskWithTls;
            if (options.allow_insecure_test_tcp) return error.DevPskWithInsecureTcp;
            for (endpoints) |endpoint| {
                if (!isNumericLoopback(endpoint.host)) {
                    return error.DevPskNeedsLoopback;
                }
            }
        }
    }

    /// Matches the server's development-PSK constraint exactly: only the
    /// numeric loopback literals qualify, never hostnames or other ranges.
    fn isNumericLoopback(host: []const u8) bool {
        return std.mem.eql(u8, host, "127.0.0.1") or
            std.mem.eql(u8, host, "::1");
    }

    const ParsedMembers = struct {
        peers: []server.PeerAddress,
        endpoints: []client.Endpoint,
        backends: []client.Endpoint,
        backend_count: usize,
        self_endpoint: ?client.Endpoint,
        self_role: ?roles.Role,
    };

    fn parseOpenMembers(
        allocator: std.mem.Allocator,
        members: []const Member,
        self_node_id: u32,
    ) !ParsedMembers {
        const peers = try allocator.alloc(server.PeerAddress, members.len);
        const endpoints = try allocator.alloc(client.Endpoint, members.len);
        const backends = try allocator.alloc(client.Endpoint, members.len);
        var backend_count: usize = 0;
        var self_endpoint: ?client.Endpoint = null;
        var self_role: ?roles.Role = null;
        for (members, 0..) |member, index| {
            const address = try allocator.dupe(u8, member.address);
            const endpoint = try client.Endpoint.parse(address);
            peers[index] = .{
                .id = member.id,
                .host = endpoint.host,
                .port = endpoint.port,
                .role = member.role,
            };
            endpoints[index] = endpoint;
            const capabilities = member.role.capabilities();
            if (capabilities.serves_reads or capabilities.serves_writes) {
                backends[backend_count] = endpoint;
                backend_count += 1;
            }
            if (member.id == self_node_id) {
                self_endpoint = endpoint;
                self_role = member.role;
            }
        }
        return .{
            .peers = peers,
            .endpoints = endpoints,
            .backends = backends,
            .backend_count = backend_count,
            .self_endpoint = self_endpoint,
            .self_role = self_role,
        };
    }

    fn waitUntilListening(self: *Embedded, timeout_ms: u64) !void {
        const deadline = deadlines.after(self.io, timeout_ms);
        while (!deadlines.expired(self.io, deadline)) {
            if (self.finished.load(.acquire)) return error.ServerStartupFailed;
            if (self.probeListening(deadline)) return;
            const retry = deadlines.after(self.io, 25);
            const until = if (retry.raw.nanoseconds < deadline.raw.nanoseconds) retry else deadline;
            until.wait(self.io) catch {};
        }
        return error.ServerStartupTimeout;
    }

    fn probeListening(self: *Embedded, deadline: Io.Clock.Timestamp) bool {
        if (self.gateway_mode) {
            const address = std.Io.net.IpAddress.parse(
                self.self_endpoint.host,
                self.self_endpoint.port,
            ) catch return false;
            const stream = deadlines.connectIp(self.io, address, deadline) catch return false;
            stream.close(self.io);
            return !deadlines.expired(self.io, deadline);
        }
        const connection = client.Connection.openWithTransportDeadline(
            self.gpa,
            self.io,
            self.self_endpoint,
            self.transport(),
            deadline,
        ) catch return false;
        defer connection.close();
        const response = connection.callWithDeadline(
            "{\"op\":\"status\"}",
            deadline,
        ) catch return false;
        self.gpa.free(response);
        return !deadlines.expired(self.io, deadline);
    }

    fn runServer(self: *Embedded) void {
        var buffer: [1024]u8 = undefined;
        var discarding: Io.Writer.Discarding = .init(&buffer);
        const code = if (self.gateway_mode)
            gateway.serve(
                self.gpa,
                self.io,
                self.gateway_options,
                &discarding.writer,
            ) catch |err| blk: {
                self.publishFailureName(err);
                break :blk 4;
            }
        else
            server.serve(
                self.gpa,
                self.io,
                self.serve_options,
                &discarding.writer,
            ) catch |err| blk: {
                self.publishFailureName(err);
                break :blk 4;
            };
        self.exit_code.store(code, .release);
        self.finished.store(true, .release);
    }

    fn publishFailureName(self: *Embedded, err: anyerror) void {
        if (self.failure_name_len.load(.acquire) != 0) return;
        const name = @errorName(err);
        const len: u8 = @intCast(@min(name.len, self.failure_name_buffer.len));
        @memcpy(self.failure_name_buffer[0..len], name[0..len]);
        self.failure_name_len.store(len, .release);
    }

    fn transport(self: *Embedded) client.Transport {
        return .{
            .secret = self.auth_secret,
            .tls = if (self.tls_client) |*context| context else null,
        };
    }

    fn requestStop(self: *Embedded) void {
        self.gateway_shutdown.store(true, .release);
        if (!self.gateway_mode or self.finished.load(.acquire)) return;
        const address = std.Io.net.IpAddress.parse(
            self.self_endpoint.host,
            self.self_endpoint.port,
        ) catch return;
        const stream = deadlines.connectIp(
            self.io,
            address,
            deadlines.after(self.io, 1000),
        ) catch return;
        stream.close(self.io);
    }

    /// Lock-free view of the local process lifecycle. This never consults a
    /// peer, so callers cannot accidentally hide a failed embedded member by
    /// succeeding through another cluster endpoint.
    pub fn localServerState(self: *const Embedded) LocalServerState {
        const failure_len = self.failure_name_len.load(.acquire);
        if (failure_len != 0) {
            return .{ .failed = self.failure_name_buffer[0..failure_len] };
        }
        if (self.finished.load(.acquire)) {
            const code = self.exit_code.load(.acquire);
            if (code == 4) return .{ .failed = "LocalNodeFailed" };
            return .{ .stopped = code };
        }
        if (self.gateway_shutdown.load(.acquire)) return .stopping;
        return .healthy;
    }

    fn requireLocalHealthy(self: *const Embedded) !void {
        switch (self.localServerState()) {
            .failed => return error.LocalNodeFailed,
            .stopped => return error.LocalNodeStopped,
            .healthy, .stopping => {},
        }
    }

    /// Requests a server stop, joins the background thread, and frees the
    /// facade and everything it copied; `self` is invalid afterwards. There
    /// is nothing to flush here: every acknowledged write was already synced
    /// before its reply, and a request still in flight when `close` runs may
    /// or may not have committed — its caller must treat the outcome as
    /// unknown. Signals the local lifecycle directly, without dialing or
    /// authenticating a control connection, then joins the server.
    pub fn close(self: *Embedded) void {
        self.requestStop();
        self.thread.join();
        self.cluster.deinit();
        if (self.tls_client) |*context| context.deinit();
        self.arena.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Sends one raw JSON RPC request to the cluster: the first reachable
    /// member answers, and when `leader` is true, `not_leader` redirects are
    /// followed to the current leader first. Fails when no member is
    /// reachable (a liveness failure; nothing durable is affected).
    ///
    /// Returns the JSON response body allocated from the `gpa` given to
    /// `open`; the caller must free it with that same allocator. The body is
    /// returned as-is — including `{"ok":false,...}` error responses.
    pub fn call(self: *Embedded, request: []const u8, leader: bool) ![]u8 {
        try self.requireLocalHealthy();
        self.client_mutex.lockUncancelable(self.io);
        defer self.client_mutex.unlock(self.io);
        const result = try self.cluster.call(request, leader);
        return result.body;
    }

    /// Executes `sql` as one replicated write on the leader. Returns only
    /// after the transaction's slot is decided and its journal record is
    /// fsynced, per the write-before-send rule; the result is a plain value
    /// that owns no memory. A server-side refusal is
    /// `error.RemoteOperationFailed` and a malformed reply is
    /// `error.InvalidResponse`.
    ///
    /// A transport failure does not mean the write did not commit: this path
    /// has no session identity, so retrying may apply the statement twice.
    /// Use the session RPCs (via `call`) when exactly-once retries matter.
    pub fn exec(self: *Embedded, sql: []const u8) !node_mod.ExecResult {
        var request: Io.Writer.Allocating = .init(self.gpa);
        defer request.deinit();
        try request.writer.writeAll("{\"op\":\"exec\",\"sql\":");
        try server.writeJsonString(&request.writer, sql);
        try request.writer.writeAll("}");
        const body = try self.call(request.written(), true);
        defer self.gpa.free(body);
        const parsed = try parseObject(self.gpa, body);
        defer parsed.deinit();
        try requireOk(&parsed.value);
        return .{
            .changes = objectInt(&parsed.value, "changes") orelse 0,
            .slot = @intCast(objectInt(&parsed.value, "slot") orelse 0),
            .replayed = objectBool(&parsed.value, "replayed") orelse false,
        };
    }

    /// Runs `sql` at the `linearizable` read level: the leader fences the
    /// read on a quorum, so the result reflects every write acknowledged
    /// before the call began. No journal append or disk sync happens per
    /// read. Reads at weaker levels are not offered here; issue them through
    /// `call` so the staleness label is explicit.
    ///
    /// Columns and rows are copied into an arena inside the returned
    /// `QueryResult`, allocated from the `gpa` argument (which may differ
    /// from the open-time allocator); the caller owns the result and must
    /// call `deinit` exactly once. Cell values arrive as text or null.
    pub fn query(
        self: *Embedded,
        gpa: std.mem.Allocator,
        sql: []const u8,
    ) !node_mod.QueryResult {
        var request: Io.Writer.Allocating = .init(self.gpa);
        defer request.deinit();
        try request.writer.writeAll("{\"op\":\"query\",\"sql\":");
        try server.writeJsonString(&request.writer, sql);
        try request.writer.writeAll(",\"level\":\"linearizable\"}");
        const body = try self.call(request.written(), true);
        defer self.gpa.free(body);
        const parsed = try parseObject(self.gpa, body);
        defer parsed.deinit();
        try requireOk(&parsed.value);
        return copyQueryResult(gpa, &parsed.value);
    }
};

const ParsedObject = std.json.Parsed(std.json.Value);

fn parseObject(gpa: std.mem.Allocator, body: []const u8) !ParsedObject {
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, body, .{});
    if (parsed.value != .object) {
        parsed.deinit();
        return error.InvalidResponse;
    }
    return parsed;
}

fn requireOk(value: *const std.json.Value) !void {
    const ok = value.object.get("ok") orelse return error.InvalidResponse;
    if (ok != .bool or !ok.bool) return error.RemoteOperationFailed;
}

fn objectInt(value: *const std.json.Value, key: []const u8) ?i64 {
    const field = value.object.get(key) orelse return null;
    return if (field == .integer) field.integer else null;
}

fn objectBool(value: *const std.json.Value, key: []const u8) ?bool {
    const field = value.object.get(key) orelse return null;
    return if (field == .bool) field.bool else null;
}

fn copyQueryResult(gpa: std.mem.Allocator, value: *const std.json.Value) !node_mod.QueryResult {
    const source_columns = value.object.get("columns") orelse return error.InvalidResponse;
    const source_rows = value.object.get("rows") orelse return error.InvalidResponse;
    if (source_columns != .array or source_rows != .array) return error.InvalidResponse;
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const columns = try allocator.alloc([]const u8, source_columns.array.items.len);
    for (source_columns.array.items, columns) |source, *destination| {
        if (source != .string) return error.InvalidResponse;
        destination.* = try allocator.dupe(u8, source.string);
    }
    const rows = try allocator.alloc([]const ?[]const u8, source_rows.array.items.len);
    for (source_rows.array.items, rows) |source_row, *destination_row| {
        if (source_row != .array) return error.InvalidResponse;
        const row = try allocator.alloc(?[]const u8, source_row.array.items.len);
        for (source_row.array.items, row) |source, *destination| {
            destination.* = switch (source) {
                .null => null,
                .string => |text| try allocator.dupe(u8, text),
                else => return error.InvalidResponse,
            };
        }
        destination_row.* = row;
    }
    return .{ .arena = arena, .columns = columns, .rows = rows };
}

test "local server state exposes the first failure without peer routing" {
    var embedded: Embedded = undefined;
    embedded.finished = .init(false);
    embedded.exit_code = .init(255);
    embedded.gateway_shutdown = .init(false);
    embedded.failure_name_len = .init(0);
    try std.testing.expect(embedded.localServerState() == .healthy);

    embedded.gateway_shutdown.store(true, .release);
    try std.testing.expect(embedded.localServerState() == .stopping);
    embedded.gateway_shutdown.store(false, .release);

    embedded.finished.store(true, .release);
    embedded.exit_code.store(0, .release);
    switch (embedded.localServerState()) {
        .stopped => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.TestExpectedStopped,
    }
    try std.testing.expectError(error.LocalNodeStopped, embedded.requireLocalHealthy());
    embedded.finished.store(false, .release);

    const failure = "TrimRegression";
    @memcpy(embedded.failure_name_buffer[0..failure.len], failure);
    embedded.failure_name_len.store(@intCast(failure.len), .release);
    switch (embedded.localServerState()) {
        .failed => |name| try std.testing.expectEqualStrings(failure, name),
        else => return error.TestExpectedFailure,
    }
    try std.testing.expectError(error.LocalNodeFailed, embedded.requireLocalHealthy());
}
