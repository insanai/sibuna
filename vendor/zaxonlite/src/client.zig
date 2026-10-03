//! The zaxon RPC client: one JSON request/response per round trip, with
//! leader-redirect following. Shared by the CLI and the integration test
//! controllers.

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");
const transport_auth = @import("transport_auth.zig");
const tls = @import("tls.zig");
const durability = @import("durability.zig");
const deadlines = @import("net_deadline.zig");

/// How a client authenticates its connections: the PSK secret, a mutual
/// TLS identity, both (the PSK handshake then runs inside TLS), or
/// neither for a local Unix-domain socket or failpoint-gated tests.
pub const Transport = struct {
    /// Total socket/TLS/hello/PSK establishment budget. Null disables; zero expires.
    connect_timeout_ms: ?u64 = 10_000,
    secret: ?[]const u8 = null,
    tls: ?*const tls.Context = null,
};

pub const Endpoint = struct {
    host: []const u8,
    port: u16 = 0,
    /// When set, `host`/`port` are unused and the connection dials this
    /// Unix-domain socket path instead of TCP.
    unix_path: ?[]const u8 = null,
    /// When a mutually authenticated follower advertises a leader that was
    /// not one of the caller's seeds, pin the new connection to this node ID.
    /// Parsed/configured endpoints leave it null.
    expected_node_id: ?u32 = null,

    /// Parses `host:port` or `unix:<path>`.
    pub fn parse(text: []const u8) !Endpoint {
        if (std.mem.startsWith(u8, text, "unix:")) {
            const path = text["unix:".len..];
            if (path.len == 0) return error.InvalidEndpoint;
            return .{ .host = path, .unix_path = path };
        }
        const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
            return error.InvalidEndpoint;
        const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch
            return error.InvalidEndpoint;
        if (colon == 0) return error.InvalidEndpoint;
        return .{ .host = text[0..colon], .port = port };
    }
};

/// One connected client conversation with a single server.
pub const Connection = struct {
    gpa: std.mem.Allocator,
    io: Io,
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    read_buffer: []u8,
    write_buffer: []u8,
    authenticated: ?transport_auth.Session = null,
    /// Set when the connection runs over mutual TLS; `reader`/`writer`
    /// are then unused and the TLS interfaces carry all frames.
    tls_stream: ?*tls.Stream = null,

    pub fn open(gpa: std.mem.Allocator, io: Io, endpoint: Endpoint) !*Connection {
        return openWithTransport(gpa, io, endpoint, .{});
    }

    pub fn openWithSecret(
        gpa: std.mem.Allocator,
        io: Io,
        endpoint: Endpoint,
        secret: ?[]const u8,
    ) !*Connection {
        return openWithTransport(gpa, io, endpoint, .{ .secret = secret });
    }

    pub fn openWithTransport(
        gpa: std.mem.Allocator,
        io: Io,
        endpoint: Endpoint,
        transport: Transport,
    ) !*Connection {
        return openWithTransportCancelable(gpa, io, endpoint, transport, null, null);
    }

    /// Uses the earlier of the caller's monotonic deadline and the transport budget.
    pub fn openWithTransportDeadline(
        gpa: std.mem.Allocator,
        io: Io,
        endpoint: Endpoint,
        transport: Transport,
        deadline: Io.Clock.Timestamp,
    ) !*Connection {
        return openWithTransportCancelable(gpa, io, endpoint, transport, null, deadline);
    }

    fn openWithTransportCancelable(
        gpa: std.mem.Allocator,
        io: Io,
        endpoint: Endpoint,
        transport: Transport,
        cancellation: ?*Cancellation,
        outer_deadline: ?Io.Clock.Timestamp,
    ) !*Connection {
        const deadline = deadlines.budget(io, transport.connect_timeout_ms, outer_deadline);
        if (deadline) |end| {
            if (deadlines.expired(io, end)) return error.Timeout;
        }
        if (cancellation) |state| {
            if (state.isRequested(io)) return error.Canceled;
        }
        const self = try gpa.create(Connection);
        errdefer gpa.destroy(self);
        const read_buffer = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(read_buffer);
        const write_buffer = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(write_buffer);

        var stream = if (endpoint.unix_path) |path| blk: {
            break :blk try deadlines.connectUnix(io, path, deadline);
        } else blk: {
            const address = try std.Io.net.IpAddress.parse(
                endpoint.host,
                endpoint.port,
            );
            break :blk try deadlines.connectIp(io, address, deadline);
        };
        errdefer stream.close(io);
        if (cancellation) |state| try state.register(io, stream);
        defer if (cancellation) |state| state.unregister(io, stream);

        var watch = deadlines.SocketWatch{ .io = io, .stream = stream, .deadline = deadline };
        try watch.start();
        defer _ = watch.finish();
        self.* = .{
            .gpa = gpa,
            .io = io,
            .stream = stream,
            .reader = undefined,
            .writer = undefined,
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
        };
        errdefer if (self.tls_stream) |tls_stream| {
            stream.shutdown(io, .both) catch {};
            tls_stream.deinit();
            gpa.destroy(tls_stream);
        };
        self.establish(endpoint, transport) catch |err| {
            const timed_out = watch.finish();
            if (cancellation) |state| {
                if (state.isRequested(io)) return error.Canceled;
            }
            if (timed_out) return error.Timeout;
            return err;
        };
        const timed_out = watch.finish();
        if (cancellation) |state| {
            try state.finishOpen(io, stream);
        }
        if (timed_out) return error.Timeout;
        return self;
    }

    fn establish(self: *Connection, endpoint: Endpoint, transport: Transport) !void {
        if (transport.tls) |context| {
            self.tls_stream = try initTlsStream(
                self.gpa,
                context,
                self.stream,
                self.read_buffer,
                self.write_buffer,
                endpoint,
            );
        } else {
            self.reader = self.stream.reader(self.io, self.read_buffer);
            self.writer = self.stream.writer(self.io, self.write_buffer);
        }
        try performClientHandshake(self, transport);
    }

    fn initTlsStream(
        gpa: std.mem.Allocator,
        context: *const tls.Context,
        stream: std.Io.net.Stream,
        read_buffer: []u8,
        write_buffer: []u8,
        endpoint: Endpoint,
    ) !*tls.Stream {
        const tls_stream = try gpa.create(tls.Stream);
        errdefer gpa.destroy(tls_stream);
        tls_stream.* = try tls.Stream.connect(context, stream, read_buffer, write_buffer);
        const peer_node_id = tls.parseNodeCommonName(tls_stream.peerCommonName()) orelse {
            tls_stream.deinit();
            return error.TlsPeerUnverified;
        };
        if (endpoint.expected_node_id) |expected| {
            if (peer_node_id != expected) {
                tls_stream.deinit();
                return error.TlsPeerUnverified;
            }
        }
        return tls_stream;
    }

    fn performClientHandshake(self: *Connection, transport: Transport) !void {
        const hello = wire.Hello{
            .version = wire.protocol_version,
            .kind = .client,
            .node_id = 0,
            .database_id = 0,
            .configuration_id = 0,
        };
        var hello_buffer: [wire.Hello.encoded_size]u8 = undefined;
        try wire.writeFrame(self.writerInterface(), .hello, hello.encode(&hello_buffer));
        try self.writerInterface().flush();
        if (transport.secret) |bytes| {
            self.authenticated = try transport_auth.connect(
                self.gpa,
                self.readerInterface(),
                self.writerInterface(),
                bytes,
                &hello_buffer,
            );
        }
    }

    fn readerInterface(self: *Connection) *Io.Reader {
        if (self.tls_stream) |tls_stream| return &tls_stream.reader;
        return &self.reader.interface;
    }

    fn writerInterface(self: *Connection) *Io.Writer {
        if (self.tls_stream) |tls_stream| return &tls_stream.writer;
        return &self.writer.interface;
    }

    pub fn close(self: *Connection) void {
        self.stream.shutdown(self.io, .both) catch {};
        if (self.tls_stream) |tls_stream| {
            tls_stream.deinit();
            self.gpa.destroy(tls_stream);
        }
        self.stream.close(self.io);
        self.gpa.free(self.read_buffer);
        self.gpa.free(self.write_buffer);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Sends one JSON request and returns the owned JSON response body.
    pub fn call(self: *Connection, request: []const u8) ![]u8 {
        try self.writeRequest(request);
        const frame = try self.readFrame();
        if (frame.kind != .rpc_response) {
            self.gpa.free(frame.body);
            return error.InvalidFrame;
        }
        return frame.body;
    }

    /// A timed-out exchange invalidates this connection. Close it; the request
    /// may already have executed, so expiry does not make replay safe.
    pub fn callWithDeadline(
        self: *Connection,
        request: []const u8,
        deadline: Io.Clock.Timestamp,
    ) ![]u8 {
        var watch = deadlines.SocketWatch{
            .io = self.io,
            .stream = self.stream,
            .deadline = deadline,
        };
        watch.start() catch |err| {
            self.stream.shutdown(self.io, .both) catch {};
            return err;
        };
        defer _ = watch.finish();
        const body = self.call(request) catch |err| {
            if (watch.finish()) return error.Timeout;
            return err;
        };
        if (watch.finish()) {
            self.gpa.free(body);
            return error.Timeout;
        }
        return body;
    }

    fn writeRequest(self: *Connection, request: []const u8) !void {
        if (self.authenticated) |*session| {
            try session.writeFrame(self.writerInterface(), .rpc_request, request);
        } else {
            try wire.writeFrame(self.writerInterface(), .rpc_request, request);
        }
        try self.writerInterface().flush();
    }

    fn readFrame(self: *Connection) !transport_auth.Frame {
        if (self.authenticated) |*session| {
            return session.readFrame(self.gpa, self.readerInterface());
        }
        const header = try wire.readFrameHeader(self.readerInterface());
        return .{
            .kind = header.kind,
            .body = try wire.readFrameBody(self.gpa, self.readerInterface(), header),
        };
    }

    /// Streams a server-side consistent backup to an atomically installed
    /// destination and verifies its declared SHA-256 before rename.
    pub fn backupTo(self: *Connection, destination: []const u8) !void {
        const directory_name = std.fs.path.dirname(destination) orelse ".";
        const file_name = std.fs.path.basename(destination);
        if (file_name.len == 0) return error.InvalidBackupPath;
        var directory = if (std.fs.path.isAbsolute(directory_name))
            try Io.Dir.openDirAbsolute(self.io, directory_name, .{})
        else
            try Io.Dir.cwd().openDir(self.io, directory_name, .{});
        defer directory.close(self.io);

        var temporary_name: []u8 = undefined;
        var file = try self.createBackupTempFile(&directory, file_name, &temporary_name);
        defer self.gpa.free(temporary_name);
        var file_open = true;
        var keep_temporary = true;
        defer {
            if (file_open) file.close(self.io);
            if (keep_temporary) directory.deleteFile(self.io, temporary_name) catch {};
        }

        try self.streamBackupPayload(&file);
        try durability.syncFile(self.io, file);
        file.close(self.io);
        file_open = false;
        try directory.rename(temporary_name, directory, file_name, self.io);
        try durability.syncPathnameTransition(self.io, directory, file_name);
        keep_temporary = false;
    }

    fn createBackupTempFile(
        self: *Connection,
        directory: *Io.Dir,
        file_name: []const u8,
        temporary_name: *[]u8,
    ) !Io.File {
        if (directory.access(self.io, file_name, .{})) |_| {
            return error.BackupDestinationExists;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        var random_bytes: [8]u8 = undefined;
        self.io.random(&random_bytes);
        const nonce = std.mem.readInt(u64, &random_bytes, .little);
        temporary_name.* = try std.fmt.allocPrint(
            self.gpa,
            ".{s}.zaxon-{x}.tmp",
            .{ file_name, nonce },
        );
        return directory.createFile(self.io, temporary_name.*, .{
            .read = true,
            .exclusive = true,
        });
    }

    fn streamBackupPayload(self: *Connection, file: *Io.File) !void {
        try self.writeRequest("{\"op\":\"backup\"}");
        const begin_frame = try self.readFrame();
        defer self.gpa.free(begin_frame.body);
        if (begin_frame.kind == .rpc_response) return error.RemoteBackupRejected;
        if (begin_frame.kind != .backup_begin) return error.InvalidFrame;
        const begin = try wire.BackupBegin.decode(begin_frame.body);
        if (begin.size == 0 or begin.size > wire.max_transfer_bytes) return error.InvalidBackupSize;

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        var received: u64 = 0;
        while (true) {
            const frame = try self.readFrame();
            defer self.gpa.free(frame.body);
            if (frame.kind == .backup_end) break;
            if (frame.kind != .backup_chunk or frame.body.len <= 8) return error.InvalidFrame;
            const offset = std.mem.readInt(u64, frame.body[0..8], .little);
            const bytes = frame.body[8..];
            const end = std.math.add(u64, offset, bytes.len) catch return error.InvalidFrame;
            if (offset != received or end > begin.size) return error.InvalidFrame;
            try file.writePositionalAll(self.io, bytes, offset);
            hasher.update(bytes);
            received = end;
        }
        if (received != begin.size) return error.UnexpectedEndOfStream;
        var actual: [32]u8 = undefined;
        hasher.final(&actual);
        if (!std.mem.eql(u8, &actual, &begin.sha256)) return error.BackupDigestMismatch;
    }
};

pub const CallResult = struct {
    /// Owned JSON response body.
    body: []u8,
    /// The endpoint that answered after redirects. Configured endpoint storage
    /// remains borrowed for backward compatibility; an authenticated target
    /// outside the seed list is owned in `owned_endpoint_host`.
    endpoint: Endpoint,
    owned_endpoint_host: ?[]u8 = null,

    pub fn deinit(self: *CallResult, gpa: std.mem.Allocator) void {
        if (self.body.len > 0) gpa.free(self.body);
        if (self.owned_endpoint_host) |host| gpa.free(host);
        self.* = undefined;
    }

    /// Transfers only the response body while releasing endpoint storage.
    pub fn takeBody(self: *CallResult, gpa: std.mem.Allocator) []u8 {
        const body = self.body;
        self.body = &.{};
        if (self.owned_endpoint_host) |host| gpa.free(host);
        self.endpoint = undefined;
        self.owned_endpoint_host = null;
        return body;
    }
};

/// Calls `request` against the first reachable endpoint, following
/// `not_leader` redirects up to `max_hops`. When `require_leader` is
/// false the first reachable endpoint's answer is returned as-is.
pub fn callCluster(
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    request: []const u8,
    require_leader: bool,
) !CallResult {
    return callClusterWithSecret(
        gpa,
        io,
        endpoints,
        request,
        require_leader,
        null,
    );
}

pub fn callClusterWithSecret(
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    request: []const u8,
    require_leader: bool,
    secret: ?[]const u8,
) !CallResult {
    return callClusterWithTransport(
        gpa,
        io,
        endpoints,
        request,
        require_leader,
        .{ .secret = secret },
    );
}

pub fn callClusterWithTransport(
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    request: []const u8,
    require_leader: bool,
    transport: Transport,
) !CallResult {
    var cluster = ClusterConnection.init(gpa, io, endpoints, transport);
    defer cluster.deinit();
    return cluster.call(request, require_leader);
}

/// Reusable cluster client for interactive shells and embedded facades. It
/// keeps the last successful connection open, follows seed-confined redirects
/// without mTLS and node-ID-pinned advertised redirects with mTLS, and
/// reconnects on transport failure. One-shot helpers above use the same
/// implementation but immediately deinitialize it.
pub const ClusterConnection = struct {
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    transport: Transport,
    connection: ?*Connection = null,
    endpoint: ?Endpoint = null,
    next_endpoint: usize = 0,
    redirect_host_buffer: [64]u8 = undefined,
    /// Set when the last `call` saw a leader advertisement it refused to
    /// follow because the transport cannot authenticate node identity.
    /// Lets callers explain the policy instead of a generic failure.
    refused_leader_hint: ?RefusedLeaderHint = null,
    cancellation: Cancellation = .{},

    pub fn init(
        gpa: std.mem.Allocator,
        io: Io,
        endpoints: []const Endpoint,
        transport: Transport,
    ) ClusterConnection {
        return .{
            .gpa = gpa,
            .io = io,
            .endpoints = endpoints,
            .transport = transport,
        };
    }

    pub fn deinit(self: *ClusterConnection) void {
        self.disconnect();
        self.* = undefined;
    }

    fn disconnect(self: *ClusterConnection) void {
        if (self.connection) |connection| connection.close();
        self.connection = null;
        self.endpoint = null;
    }

    fn connect(self: *ClusterConnection, endpoint: Endpoint) !void {
        std.debug.assert(self.connection == null);
        self.connection = try Connection.openWithTransportCancelable(
            self.gpa,
            self.io,
            endpoint,
            self.transport,
            &self.cancellation,
            null,
        );
        self.endpoint = endpoint;
    }

    /// Abandons the currently active call by shutting down its socket. The
    /// request may already have reached the server; this only cancels the
    /// local wait. Safe to call from a different thread than `call`.
    pub fn cancelCurrent(self: *ClusterConnection) void {
        self.cancellation.request(self.io);
    }

    pub fn call(
        self: *ClusterConnection,
        request: []const u8,
        require_leader: bool,
    ) !CallResult {
        return self.callInternal(request, require_leader, null);
    }

    /// `call` with a start barrier for an external interrupt waiter. Once the
    /// event is set, `cancelCurrent` is guaranteed to apply to this call.
    pub fn callInterruptible(
        self: *ClusterConnection,
        request: []const u8,
        require_leader: bool,
        started: *std.Io.Event,
    ) !CallResult {
        return self.callInternal(request, require_leader, started);
    }

    fn callInternal(
        self: *ClusterConnection,
        request: []const u8,
        require_leader: bool,
        started: ?*std.Io.Event,
    ) !CallResult {
        if (self.endpoints.len == 0) {
            if (started) |event| event.set(self.io);
            return error.NoEndpoints;
        }
        self.cancellation.begin(self.io);
        if (started) |event| event.set(self.io);
        self.refused_leader_hint = null;
        var redirect: ?Endpoint = null;
        var attempt: usize = 0;
        const max_attempts = 12;
        while (attempt < max_attempts) : (attempt += 1) {
            if (self.connection == null) {
                const endpoint = redirect orelse blk: {
                    const selected = self.endpoints[self.next_endpoint % self.endpoints.len];
                    self.next_endpoint +%= 1;
                    break :blk selected;
                };
                redirect = null;
                self.connect(endpoint) catch |err| {
                    if (err == error.Canceled or self.cancellation.isRequested(self.io)) {
                        return error.Canceled;
                    }
                    try self.retryDelay(.fromMilliseconds(150));
                    continue;
                };
            }

            const endpoint = self.endpoint.?;
            const body = self.callConnected(request) catch |err| {
                self.disconnect();
                if (err == error.Canceled or self.cancellation.isRequested(self.io)) {
                    return error.Canceled;
                }
                // A partial write or lost response leaves execution uncertain.
                // Only explicit redirects (below) establish that replay is safe.
                return err;
            };
            if (!require_leader) return self.result(body, endpoint);

            const leader = leaderRedirect(
                self.gpa,
                self.endpoints,
                body,
                self.transport.tls != null,
                &self.redirect_host_buffer,
                &self.refused_leader_hint,
            ) catch return self.result(body, endpoint);
            switch (leader) {
                .not_redirect => return self.result(body, endpoint),
                .rotate => {
                    self.gpa.free(body);
                    self.disconnect();
                    try self.retryDelay(.fromMilliseconds(25));
                },
                .redirect => |target| {
                    self.gpa.free(body);
                    self.disconnect();
                    redirect = target;
                    try self.retryDelay(.fromMilliseconds(25));
                },
            }
        }
        return error.NoLeaderReachable;
    }

    fn callConnected(self: *ClusterConnection, request: []const u8) ![]u8 {
        const connection = self.connection.?;
        try self.cancellation.register(self.io, connection.stream);
        defer self.cancellation.unregister(self.io, connection.stream);
        return connection.call(request);
    }

    fn retryDelay(self: *ClusterConnection, duration: std.Io.Duration) !void {
        self.io.sleep(duration, .awake) catch |err| {
            if (err == error.Canceled or self.cancellation.isRequested(self.io)) {
                return error.Canceled;
            }
        };
        if (self.cancellation.isRequested(self.io)) return error.Canceled;
    }

    fn result(
        self: *ClusterConnection,
        body: []u8,
        endpoint: Endpoint,
    ) !CallResult {
        errdefer self.gpa.free(body);
        for (self.endpoints) |candidate| {
            const same = if (endpoint.unix_path) |path|
                candidate.unix_path != null and
                    std.mem.eql(u8, candidate.unix_path.?, path)
            else
                candidate.unix_path == null and candidate.port == endpoint.port and
                    std.mem.eql(u8, candidate.host, endpoint.host);
            if (!same) continue;
            var stable = candidate;
            stable.expected_node_id = endpoint.expected_node_id;
            return .{ .body = body, .endpoint = stable };
        }
        const host = try self.gpa.dupe(u8, endpoint.host);
        return .{
            .body = body,
            .endpoint = .{
                .host = host,
                .port = endpoint.port,
                .unix_path = if (endpoint.unix_path != null) host else null,
                .expected_node_id = endpoint.expected_node_id,
            },
            .owned_endpoint_host = host,
        };
    }
};

/// Synchronizes a call's live socket with a cancellation request. It stores a
/// socket value rather than a `Connection` pointer, so the canceling thread
/// never observes or frees mutable client-owned memory.
const Cancellation = struct {
    mutex: std.Io.Mutex = .init,
    requested: bool = false,
    stream: ?std.Io.net.Stream = null,

    fn begin(self: *Cancellation, io: Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(self.stream == null);
        self.requested = false;
    }

    fn register(
        self: *Cancellation,
        io: Io,
        stream: std.Io.net.Stream,
    ) error{Canceled}!void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.requested) {
            stream.shutdown(io, .both) catch {};
            return error.Canceled;
        }
        std.debug.assert(self.stream == null);
        self.stream = stream;
    }

    fn unregister(
        self: *Cancellation,
        io: Io,
        stream: std.Io.net.Stream,
    ) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.stream) |active| {
            std.debug.assert(active.socket.handle == stream.socket.handle);
            self.stream = null;
        }
    }

    /// Completion and cancellation serialize on the socket's registration.
    /// Once removed, a later cancel cannot abort the connection we return.
    fn finishOpen(self: *Cancellation, io: Io, stream: Io.net.Stream) error{Canceled}!void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(self.stream.?.socket.handle == stream.socket.handle);
        self.stream = null;
        if (self.requested) return error.Canceled;
    }

    fn request(self: *Cancellation, io: Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.requested = true;
        if (self.stream) |stream| stream.shutdown(io, .both) catch {};
    }

    fn isRequested(self: *Cancellation, io: Io) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.requested;
    }
};

const Redirect = union(enum) {
    not_redirect,
    rotate,
    redirect: Endpoint,
};

/// A leader advertisement the client saw but refused to follow because the
/// transport cannot authenticate the advertised node's identity.
pub const RefusedLeaderHint = struct {
    node_id: u32,
    port: u16,
    host_length: u8,
    host_buffer: [64]u8,

    pub fn host(self: *const RefusedLeaderHint) []const u8 {
        return self.host_buffer[0..self.host_length];
    }
};

/// Parses a `not_leader` response. Unauthenticated and PSK-only clients only
/// follow configured targets: a shared PSK cannot bind a node identity.
/// With mTLS, an advertised numeric address may leave the seed list because
/// `Connection.openWithTransport` pins its certificate to the advertised
/// node ID before sending the request. A well-formed advertisement outside
/// the seed list that policy forbids following is reported through
/// `refused_hint` so callers can name the leader in diagnostics.
fn leaderRedirect(
    gpa: std.mem.Allocator,
    endpoints: []const Endpoint,
    body: []const u8,
    allow_authenticated_advertisement: bool,
    redirect_host_buffer: *[64]u8,
    refused_hint: ?*?RefusedLeaderHint,
) !Redirect {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, body, .{}) catch
        return .not_redirect;
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |*obj| obj,
        else => return .not_redirect,
    };
    const ok = object.get("ok") orelse return .not_redirect;
    if (ok == .bool and ok.bool) return .not_redirect;
    const code = object.get("error") orelse return .not_redirect;
    if (code != .string or !std.mem.eql(u8, code.string, "not_leader")) {
        return .not_redirect;
    }
    if (object.get("leader")) |leader| switch (leader) {
        .object => |leader_object| {
            return resolveLeaderRedirect(
                endpoints,
                leader_object,
                allow_authenticated_advertisement,
                redirect_host_buffer,
                refused_hint,
            );
        },
        else => {},
    };
    return .rotate;
}

fn resolveLeaderRedirect(
    endpoints: []const Endpoint,
    leader_object: std.json.ObjectMap,
    allow_authenticated_advertisement: bool,
    redirect_host_buffer: *[64]u8,
    refused_hint: ?*?RefusedLeaderHint,
) Redirect {
    const id = leader_object.get("id");
    const host = leader_object.get("host");
    const port = leader_object.get("port");
    if (id == null or host == null or port == null or
        id.? != .integer or id.?.integer <= 0 or id.?.integer > std.math.maxInt(u32) or
        host.? != .string or port.? != .integer or port.?.integer < 0 or
        port.?.integer > std.math.maxInt(u16))
    {
        return .rotate;
    }
    const hinted_id: u32 = @intCast(id.?.integer);
    const hinted_port: u16 = @intCast(port.?.integer);
    for (endpoints) |candidate| {
        if (candidate.unix_path != null) continue;
        if (candidate.port == hinted_port and std.mem.eql(u8, candidate.host, host.?.string)) {
            var target = candidate;
            if (allow_authenticated_advertisement) target.expected_node_id = hinted_id;
            return .{ .redirect = target };
        }
    }
    if (allow_authenticated_advertisement) {
        const copied_host = std.fmt.bufPrint(redirect_host_buffer, "{s}", .{host.?.string}) catch
            return .rotate;
        _ = std.Io.net.IpAddress.parse(copied_host, hinted_port) catch return .rotate;
        return .{ .redirect = .{
            .host = copied_host,
            .port = hinted_port,
            .expected_node_id = hinted_id,
        } };
    }
    if (refused_hint) |slot| {
        if (host.?.string.len <= 64) {
            var record = RefusedLeaderHint{
                .node_id = hinted_id,
                .port = hinted_port,
                .host_length = @intCast(host.?.string.len),
                .host_buffer = undefined,
            };
            @memcpy(record.host_buffer[0..host.?.string.len], host.?.string);
            slot.* = record;
        }
    }
    return .rotate;
}

test "leader redirects leave the seed list only with mTLS identity pinning" {
    const seeds = [_]Endpoint{.{ .host = "127.0.0.1", .port = 7001 }};
    const body =
        "{\"ok\":false,\"error\":\"not_leader\"," ++
        "\"leader\":{\"id\":3,\"host\":\"127.0.0.1\",\"port\":7003}}";
    var host_buffer: [64]u8 = undefined;

    var refused: ?RefusedLeaderHint = null;
    const psk = try leaderRedirect(
        std.testing.allocator,
        &seeds,
        body,
        false,
        &host_buffer,
        &refused,
    );
    try std.testing.expect(psk == .rotate);
    try std.testing.expect(refused != null);
    try std.testing.expectEqual(@as(u32, 3), refused.?.node_id);
    try std.testing.expectEqual(@as(u16, 7003), refused.?.port);
    try std.testing.expectEqualStrings("127.0.0.1", refused.?.host());

    refused = null;
    const mtls = try leaderRedirect(
        std.testing.allocator,
        &seeds,
        body,
        true,
        &host_buffer,
        &refused,
    );
    try std.testing.expect(mtls == .redirect);
    try std.testing.expect(refused == null);
    try std.testing.expectEqual(@as(u16, 7003), mtls.redirect.port);
    try std.testing.expectEqual(@as(?u32, 3), mtls.redirect.expected_node_id);
    try std.testing.expectEqualStrings("127.0.0.1", mtls.redirect.host);
}

test "an advertised leader inside the seed list is followed without refusal" {
    const seeds = [_]Endpoint{
        .{ .host = "127.0.0.1", .port = 7001 },
        .{ .host = "127.0.0.1", .port = 7003 },
    };
    const body =
        "{\"ok\":false,\"error\":\"not_leader\"," ++
        "\"leader\":{\"id\":3,\"host\":\"127.0.0.1\",\"port\":7003}}";
    var host_buffer: [64]u8 = undefined;
    var refused: ?RefusedLeaderHint = null;

    const psk = try leaderRedirect(
        std.testing.allocator,
        &seeds,
        body,
        false,
        &host_buffer,
        &refused,
    );
    try std.testing.expect(psk == .redirect);
    try std.testing.expect(refused == null);
    try std.testing.expectEqual(@as(u16, 7003), psk.redirect.port);
}

test "endpoint parsing" {
    const endpoint = try Endpoint.parse("127.0.0.1:9901");
    try std.testing.expectEqualStrings("127.0.0.1", endpoint.host);
    try std.testing.expectEqual(@as(u16, 9901), endpoint.port);
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse("nope"));
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse(":123"));

    const unix = try Endpoint.parse("unix:/run/zaxon.sock");
    try std.testing.expectEqualStrings("/run/zaxon.sock", unix.unix_path.?);
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse("unix:"));
}

test "interruptible call always releases its start barrier" {
    var cluster = ClusterConnection.init(
        std.testing.allocator,
        std.testing.io,
        &.{},
        .{},
    );
    defer cluster.deinit();
    var started: std.Io.Event = .unset;
    try std.testing.expectError(
        error.NoEndpoints,
        cluster.callInterruptible("{}", true, &started),
    );
    try std.testing.expect(started.isSet());
}
