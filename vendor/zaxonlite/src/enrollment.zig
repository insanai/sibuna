//! Minimal static-membership enrollment for production mTLS identities.
//!
//! An already authenticated operator asks one configured issuer node to
//! create a short-lived token. Only a SHA-256-derived record is persisted on
//! the issuer; the opaque token bundle also carries the issuer endpoint and
//! cluster CA certificate. The joining process creates its private key and
//! CSR locally. The issuer verifies the CSR and target membership, atomically
//! renames the token record to `used` and syncs that directory, then signs the
//! certificate. A crash after consumption can lose the response but cannot
//! issue the same token twice; the operator creates a replacement token.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

extern "c" fn renameatx_np(
    from_fd: c_int,
    from: [*:0]const u8,
    to_fd: c_int,
    to: [*:0]const u8,
    flags: c_uint,
) c_int;

const tls = @import("tls.zig");
const wire = @import("wire.zig");
const client = @import("client.zig");
const deadlines = @import("net_deadline.zig");
const durability = @import("durability.zig");
const configuration = @import("configuration.zig");

pub const token_bytes = 32;
pub const default_ttl_seconds: u64 = 10 * 60;
pub const maximum_ttl_seconds: u64 = 24 * 60 * 60;
pub const certificate_validity_seconds: u64 = 365 * 24 * 60 * 60;
pub const maximum_ca_bytes: usize = 64 * 1024;
pub const maximum_endpoint_bytes: usize = 512;
pub const maximum_bundle_bytes: usize = 128 * 1024;
pub const store_directory = "enrollment-tokens";

const record_magic = "ZXER";
const record_version: u16 = 1;
const record_size = 4 + 2 + 4 + 4 + 16 + 8 + 32;
const bundle_magic = "ZXET";
const bundle_version: u16 = 1;
const bundle_fixed_size = 4 + 2 + 4 + 4 + 16 + 8 + 2 + 4 + token_bytes;

pub const Error = error{
    InvalidToken,
    TokenUsed,
    TokenExpired,
    TokenIdentityMismatch,
    InvalidBundle,
    InvalidEndpoint,
    EnrollmentRefused,
    IdentityDestinationExists,
};

pub const IssuedToken = struct {
    secret: [token_bytes]u8,
    expires_unix_seconds: u64,
};

const Record = struct {
    node_id: u32,
    issuer_node_id: u32,
    database_id: u128,
    expires_unix_seconds: u64,
    secret_hash: [32]u8,

    fn encode(self: Record, buffer: *[record_size]u8) []const u8 {
        @memcpy(buffer[0..4], record_magic);
        std.mem.writeInt(u16, buffer[4..6], record_version, .little);
        std.mem.writeInt(u32, buffer[6..10], self.node_id, .little);
        std.mem.writeInt(u32, buffer[10..14], self.issuer_node_id, .little);
        std.mem.writeInt(u128, buffer[14..30], self.database_id, .little);
        std.mem.writeInt(u64, buffer[30..38], self.expires_unix_seconds, .little);
        @memcpy(buffer[38..70], &self.secret_hash);
        return buffer;
    }

    fn decode(bytes: []const u8) Error!Record {
        if (bytes.len != record_size or !std.mem.eql(u8, bytes[0..4], record_magic) or
            std.mem.readInt(u16, bytes[4..6], .little) != record_version)
        {
            return error.InvalidToken;
        }
        const result = Record{
            .node_id = std.mem.readInt(u32, bytes[6..10], .little),
            .issuer_node_id = std.mem.readInt(u32, bytes[10..14], .little),
            .database_id = std.mem.readInt(u128, bytes[14..30], .little),
            .expires_unix_seconds = std.mem.readInt(u64, bytes[30..38], .little),
            .secret_hash = bytes[38..70].*,
        };
        if (result.node_id == 0 or result.issuer_node_id == 0 or
            result.database_id == 0 or result.expires_unix_seconds == 0)
        {
            return error.InvalidToken;
        }
        return result;
    }
};

pub const Bundle = struct {
    node_id: u32,
    issuer_node_id: u32,
    database_id: u128,
    expires_unix_seconds: u64,
    secret: [token_bytes]u8,
    endpoint: []const u8,
    ca_pem: []const u8,

    pub fn encodeAlloc(
        self: Bundle,
        gpa: std.mem.Allocator,
    ) (Error || std.mem.Allocator.Error)![]u8 {
        if (self.node_id == 0 or self.issuer_node_id == 0 or
            self.database_id == 0 or self.expires_unix_seconds == 0 or
            self.endpoint.len == 0 or self.endpoint.len > maximum_endpoint_bytes or
            self.ca_pem.len == 0 or self.ca_pem.len > maximum_ca_bytes)
        {
            return error.InvalidBundle;
        }
        const total = bundle_fixed_size + self.endpoint.len + self.ca_pem.len;
        if (total > maximum_bundle_bytes) return error.InvalidBundle;
        const bytes = try gpa.alloc(u8, total);
        errdefer gpa.free(bytes);
        @memcpy(bytes[0..4], bundle_magic);
        std.mem.writeInt(u16, bytes[4..6], bundle_version, .little);
        std.mem.writeInt(u32, bytes[6..10], self.node_id, .little);
        std.mem.writeInt(u32, bytes[10..14], self.issuer_node_id, .little);
        std.mem.writeInt(u128, bytes[14..30], self.database_id, .little);
        std.mem.writeInt(u64, bytes[30..38], self.expires_unix_seconds, .little);
        std.mem.writeInt(u16, bytes[38..40], @intCast(self.endpoint.len), .little);
        std.mem.writeInt(u32, bytes[40..44], @intCast(self.ca_pem.len), .little);
        @memcpy(bytes[44..76], &self.secret);
        @memcpy(bytes[76..][0..self.endpoint.len], self.endpoint);
        @memcpy(bytes[76 + self.endpoint.len ..], self.ca_pem);
        return bytes;
    }

    pub fn decode(bytes: []const u8) Error!Bundle {
        if (bytes.len < bundle_fixed_size or bytes.len > maximum_bundle_bytes or
            !std.mem.eql(u8, bytes[0..4], bundle_magic) or
            std.mem.readInt(u16, bytes[4..6], .little) != bundle_version)
        {
            return error.InvalidBundle;
        }
        const endpoint_len = std.mem.readInt(u16, bytes[38..40], .little);
        const ca_len = std.mem.readInt(u32, bytes[40..44], .little);
        if (endpoint_len == 0 or endpoint_len > maximum_endpoint_bytes or
            ca_len == 0 or ca_len > maximum_ca_bytes or
            bytes.len != bundle_fixed_size + endpoint_len + ca_len)
        {
            return error.InvalidBundle;
        }
        const result = Bundle{
            .node_id = std.mem.readInt(u32, bytes[6..10], .little),
            .issuer_node_id = std.mem.readInt(u32, bytes[10..14], .little),
            .database_id = std.mem.readInt(u128, bytes[14..30], .little),
            .expires_unix_seconds = std.mem.readInt(u64, bytes[30..38], .little),
            .secret = bytes[44..76].*,
            .endpoint = bytes[76 .. 76 + endpoint_len],
            .ca_pem = bytes[76 + endpoint_len ..],
        };
        if (result.node_id == 0 or result.issuer_node_id == 0 or
            result.database_id == 0 or result.expires_unix_seconds == 0)
        {
            return error.InvalidBundle;
        }
        return result;
    }
};

pub fn nowUnixSeconds(io: Io) u64 {
    const seconds = std.Io.Clock.Timestamp.now(io, .real).raw.toSeconds();
    return if (seconds <= 0) 0 else @intCast(seconds);
}

pub fn issueToken(
    io: Io,
    data_directory: []const u8,
    node_id: u32,
    issuer_node_id: u32,
    database_id: u128,
    ttl_seconds: u64,
) !IssuedToken {
    return issueTokenAt(
        io,
        data_directory,
        node_id,
        issuer_node_id,
        database_id,
        nowUnixSeconds(io),
        ttl_seconds,
    );
}

/// Opens the token store owner-only, creating it if needed. Iterating so
/// the handle is a real descriptor: `fchmod` and `fsync` reject the
/// `O_PATH` handles Linux gets from non-iterating opens.
fn openTokenStore(io: Io, root: Io.Dir) !Io.Dir {
    _ = try root.createDirPathStatus(
        io,
        store_directory,
        @fromBackingInt(@intCast(0o700)),
    );
    var directory = try root.openDir(io, store_directory, .{ .iterate = true });
    errdefer directory.close(io);
    // Windows protects the store through its inherited ACL; Zig 0.16 does
    // not implement setting POSIX directory permissions there.
    if (builtin.os.tag != .windows) {
        try directory.setPermissions(io, @fromBackingInt(@intCast(0o700)));
    }
    return directory;
}

pub fn issueTokenAt(
    io: Io,
    data_directory: []const u8,
    node_id: u32,
    issuer_node_id: u32,
    database_id: u128,
    now: u64,
    ttl_seconds: u64,
) !IssuedToken {
    if (node_id == 0 or issuer_node_id == 0 or database_id == 0 or now == 0 or
        ttl_seconds == 0 or ttl_seconds > maximum_ttl_seconds or
        now > std.math.maxInt(u64) - ttl_seconds)
    {
        return error.InvalidToken;
    }
    var root = try Io.Dir.cwd().openDir(io, data_directory, .{});
    defer root.close(io);
    var directory = try openTokenStore(io, root);
    defer directory.close(io);

    var secret: [token_bytes]u8 = undefined;
    io.random(&secret);
    const digest = hashSecret(secret);
    var pending_name_buffer: [72]u8 = undefined;
    const pending_name = tokenName(&pending_name_buffer, digest, ".pending");
    var random_suffix: [8]u8 = undefined;
    io.random(&random_suffix);
    const suffix_hex = std.fmt.bytesToHex(random_suffix, .lower);
    var temporary_name_buffer: [96]u8 = undefined;
    const temporary_name = std.fmt.bufPrint(
        &temporary_name_buffer,
        ".issue-{s}.tmp",
        .{&suffix_hex},
    ) catch unreachable;
    const record = Record{
        .node_id = node_id,
        .issuer_node_id = issuer_node_id,
        .database_id = database_id,
        .expires_unix_seconds = now + ttl_seconds,
        .secret_hash = digest,
    };
    var record_buffer: [record_size]u8 = undefined;
    var temporary_exists = true;
    errdefer if (temporary_exists) directory.deleteFile(io, temporary_name) catch {};
    {
        var file = try directory.createFile(io, temporary_name, .{
            .exclusive = true,
            .permissions = @fromBackingInt(@intCast(0o600)),
        });
        defer file.close(io);
        try file.writeStreamingAll(io, record.encode(&record_buffer));
        try durability.syncFile(io, file);
    }
    directory.renamePreserve(temporary_name, directory, pending_name, io) catch |err| switch (err) {
        error.PathAlreadyExists => return error.InvalidToken,
        else => return err,
    };
    temporary_exists = false;
    try durability.syncPathnameTransition(io, directory, pending_name);
    return .{ .secret = secret, .expires_unix_seconds = now + ttl_seconds };
}

/// Atomically consumes a token before certificate signing. On return success,
/// retrying the same token always reports `TokenUsed`, including after a crash.
pub fn consumeToken(
    gpa: std.mem.Allocator,
    io: Io,
    data_directory: []const u8,
    secret: [token_bytes]u8,
    node_id: u32,
    issuer_node_id: u32,
    database_id: u128,
) !void {
    return consumeTokenAt(
        gpa,
        io,
        data_directory,
        secret,
        node_id,
        issuer_node_id,
        database_id,
        nowUnixSeconds(io),
    );
}

pub fn consumeTokenAt(
    gpa: std.mem.Allocator,
    io: Io,
    data_directory: []const u8,
    secret: [token_bytes]u8,
    node_id: u32,
    issuer_node_id: u32,
    database_id: u128,
    now: u64,
) !void {
    const digest = hashSecret(secret);
    var pending_name_buffer: [72]u8 = undefined;
    const pending_name = tokenName(&pending_name_buffer, digest, ".pending");
    var used_name_buffer: [72]u8 = undefined;
    const used_name = tokenName(&used_name_buffer, digest, ".used");
    var root = try Io.Dir.cwd().openDir(io, data_directory, .{});
    defer root.close(io);
    var directory = root.openDir(io, store_directory, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.InvalidToken,
        else => return err,
    };
    defer directory.close(io);
    const bytes = directory.readFileAlloc(
        io,
        pending_name,
        gpa,
        .limited(record_size + 1),
    ) catch |err| switch (err) {
        error.FileNotFound => {
            if (directory.access(io, used_name, .{})) |_| {
                return error.TokenUsed;
            } else |_| {
                return error.InvalidToken;
            }
        },
        else => return err,
    };
    defer gpa.free(bytes);
    const record = try Record.decode(bytes);
    if (!std.crypto.timing_safe.eql([32]u8, digest, record.secret_hash)) {
        return error.InvalidToken;
    }
    if (record.node_id != node_id or record.issuer_node_id != issuer_node_id or
        record.database_id != database_id)
    {
        return error.TokenIdentityMismatch;
    }
    if (now == 0 or now >= record.expires_unix_seconds) return error.TokenExpired;
    directory.renamePreserve(pending_name, directory, used_name, io) catch |err| switch (err) {
        error.FileNotFound, error.PathAlreadyExists => return error.TokenUsed,
        else => return err,
    };
    // A token that is not durably marked used can be replayed after a
    // crash, so this transition takes its barrier immediately.
    try durability.syncPathnameTransition(io, directory, used_name);
}

pub const EnrolledIdentity = struct {
    credentials: tls.GeneratedCredentials,
    certificate_pem: []u8,
    /// Decided configuration and registry digest at issuance; a joining
    /// replacement records them in its data directory's join descriptor.
    configuration_id: u64 = 0,
    registry_digest: [32]u8 = @as([32]u8, @splat(0)),

    pub fn deinit(self: *EnrolledIdentity, gpa: std.mem.Allocator) void {
        self.credentials.deinit(gpa);
        gpa.free(self.certificate_pem);
        self.* = undefined;
    }
};

/// Performs the single request allowed on a certificate-less TLS connection.
pub fn requestCertificate(
    gpa: std.mem.Allocator,
    io: Io,
    bundle: Bundle,
) !EnrolledIdentity {
    if (nowUnixSeconds(io) >= bundle.expires_unix_seconds) {
        return error.TokenExpired;
    }
    const endpoint = client.Endpoint.parse(bundle.endpoint) catch
        return error.InvalidEndpoint;
    if (endpoint.unix_path != null) return error.InvalidEndpoint;
    var credentials = try tls.generateNodeCredentials(gpa, bundle.node_id);
    errdefer credentials.deinit(gpa);
    var context = try tls.Context.initEnrollmentClient(bundle.ca_pem);
    defer context.deinit();
    const address = try std.Io.net.IpAddress.parse(endpoint.host, endpoint.port);
    var stream = try deadlines.connectIp(io, address, null);
    defer stream.close(io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var write_buffer: [64 * 1024]u8 = undefined;
    var tls_stream = try tls.Stream.connect(
        &context,
        stream,
        &read_buffer,
        &write_buffer,
    );
    defer tls_stream.deinit();
    var expected_name_buffer: [tls.max_common_name]u8 = undefined;
    const expected_name = tls.nodeCommonName(&expected_name_buffer, bundle.issuer_node_id);
    if (!std.mem.eql(u8, expected_name, tls_stream.peerCommonName())) {
        return error.TlsPeerUnverified;
    }

    const exchanged = try performEnrollmentExchange(gpa, &tls_stream, bundle, credentials.csr_pem);
    try tls.validateIssuedIdentity(
        exchanged.certificate_pem,
        credentials.private_key_pem,
        bundle.node_id,
        bundle.ca_pem,
    );
    return .{
        .credentials = credentials,
        .certificate_pem = exchanged.certificate_pem,
        .configuration_id = exchanged.configuration_id,
        .registry_digest = exchanged.registry_digest,
    };
}

const ExchangeResult = struct {
    certificate_pem: []u8,
    configuration_id: u64,
    registry_digest: [32]u8,
};

fn performEnrollmentExchange(
    gpa: std.mem.Allocator,
    tls_stream: *tls.Stream,
    bundle: Bundle,
    csr_pem: []const u8,
) !ExchangeResult {
    var hello_buffer: [wire.Hello.encoded_size]u8 = undefined;
    const hello = wire.Hello{
        .version = wire.protocol_version,
        .kind = .enrollment,
        .node_id = bundle.node_id,
        .database_id = bundle.database_id,
        .configuration_id = 0,
    };
    try wire.writeFrame(&tls_stream.writer, .hello, hello.encode(&hello_buffer));
    var request_buffer: [wire.EnrollmentRequest.max_encoded_size]u8 = undefined;
    const request = wire.EnrollmentRequest{
        .secret = bundle.secret,
        .node_id = bundle.node_id,
        .database_id = bundle.database_id,
        .csr = csr_pem,
    };
    try wire.writeFrame(
        &tls_stream.writer,
        .enrollment_request,
        try request.encode(&request_buffer),
    );
    try tls_stream.writer.flush();
    const header = try wire.readFrameHeader(&tls_stream.reader);
    if (header.kind != .enrollment_response or
        header.body_len > wire.EnrollmentResponse.max_encoded_size)
    {
        return error.EnrollmentRefused;
    }
    const body = try wire.readFrameBody(gpa, &tls_stream.reader, header);
    defer gpa.free(body);
    const response = try wire.EnrollmentResponse.decode(body);
    if (response.status != .ok) return error.EnrollmentRefused;
    // The response binding must name exactly the identity this bundle
    // authorized; a mismatch means a confused or hostile issuer.
    if (response.node_id != bundle.node_id or
        response.database_id != bundle.database_id)
    {
        return error.EnrollmentRefused;
    }
    return .{
        .certificate_pem = try gpa.dupe(u8, response.certificate),
        .configuration_id = response.configuration_id,
        .registry_digest = response.registry_digest,
    };
}

/// Installs all three PEM files as one directory rename. A crash exposes either
/// no identity directory or a complete, synced identity directory.
pub fn installIdentity(
    io: Io,
    destination: []const u8,
    identity: *const EnrolledIdentity,
    ca_pem: []const u8,
) !void {
    const parent_path = std.fs.path.dirname(destination) orelse ".";
    const final_name = std.fs.path.basename(destination);
    if (final_name.len == 0 or std.mem.eql(u8, final_name, ".") or
        std.mem.eql(u8, final_name, ".."))
    {
        return error.InvalidEndpoint;
    }
    var parent = if (std.fs.path.isAbsolute(parent_path))
        try Io.Dir.openDirAbsolute(io, parent_path, .{})
    else
        try Io.Dir.cwd().openDir(io, parent_path, .{});
    defer parent.close(io);
    if (parent.access(io, final_name, .{})) |_| {
        return error.IdentityDestinationExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    var nonce_bytes: [8]u8 = undefined;
    io.random(&nonce_bytes);
    const nonce = std.fmt.bytesToHex(nonce_bytes, .lower);
    var temporary_name_buffer: [std.Io.Dir.max_name_bytes]u8 = undefined;
    const temporary_name = std.fmt.bufPrint(
        &temporary_name_buffer,
        ".{s}.enroll-{s}",
        .{ final_name, &nonce },
    ) catch return error.NameTooLong;
    try parent.createDir(io, temporary_name, @fromBackingInt(@intCast(0o700)));
    var temporary_exists = true;
    errdefer if (temporary_exists) parent.deleteTree(io, temporary_name) catch {};
    var directory = try parent.openDir(io, temporary_name, .{});
    defer directory.close(io);
    try writeSyncedFile(io, directory, "node.key", identity.credentials.private_key_pem, 0o600);
    try writeSyncedFile(io, directory, "node.crt", identity.certificate_pem, 0o644);
    try writeSyncedFile(io, directory, "ca.crt", ca_pem, 0o644);
    try durability.syncDirectory(directory);
    try publishIdentityDirectory(parent, temporary_name, final_name, io);
    temporary_exists = false;
    try durability.syncDirectory(parent);
    // A renamed directory carries no handle of its own. Flushing a file at
    // its published path is what commits the entry where the volume log,
    // rather than the parent directory, records it.
    var published = try parent.openDir(io, final_name, .{ .iterate = true });
    defer published.close(io);
    try durability.syncPathnameTransition(io, published, "node.crt");
}

pub fn writeBundleFile(io: Io, path: []const u8, bytes: []const u8) !void {
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const name = std.fs.path.basename(path);
    if (name.len == 0) return error.InvalidBundle;
    var parent = if (std.fs.path.isAbsolute(parent_path))
        try Io.Dir.openDirAbsolute(io, parent_path, .{})
    else
        try Io.Dir.cwd().openDir(io, parent_path, .{});
    defer parent.close(io);
    if (parent.access(io, name, .{})) |_| {
        return error.IdentityDestinationExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    var nonce_bytes: [8]u8 = undefined;
    io.random(&nonce_bytes);
    const nonce = std.fmt.bytesToHex(nonce_bytes, .lower);
    var temporary_buffer: [std.Io.Dir.max_name_bytes]u8 = undefined;
    const temporary = std.fmt.bufPrint(
        &temporary_buffer,
        ".{s}.issue-{s}",
        .{ name, &nonce },
    ) catch return error.NameTooLong;
    var temporary_exists = true;
    errdefer if (temporary_exists) parent.deleteFile(io, temporary) catch {};
    {
        var file = try parent.createFile(io, temporary, .{
            .exclusive = true,
            .permissions = @fromBackingInt(@intCast(0o600)),
        });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try durability.syncFile(io, file);
    }
    parent.renamePreserve(temporary, parent, name, io) catch |err| switch (err) {
        error.PathAlreadyExists => return error.IdentityDestinationExists,
        else => return err,
    };
    temporary_exists = false;
    try durability.syncPathnameTransition(io, parent, name);
}

pub fn readBundleFile(
    gpa: std.mem.Allocator,
    io: Io,
    path: []const u8,
) ![]u8 {
    try configuration.validatePrivateFile(io, path);
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(maximum_bundle_bytes));
}

pub fn removeBundleFile(io: Io, path: []const u8) !void {
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const name = std.fs.path.basename(path);
    var parent = if (std.fs.path.isAbsolute(parent_path))
        try Io.Dir.openDirAbsolute(io, parent_path, .{})
    else
        try Io.Dir.cwd().openDir(io, parent_path, .{});
    defer parent.close(io);
    try parent.deleteFile(io, name);
    // Removals are best-effort: a bundle that reappears after a crash is
    // cleaned up again, and no protocol decision rests on its absence.
    try durability.syncDirectory(parent);
}

fn hashSecret(secret: [token_bytes]u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("zaxonlite.enrollment-token.v1");
    hasher.update(&secret);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn tokenName(buffer: *[72]u8, digest: [32]u8, suffix: []const u8) []const u8 {
    const hex = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ &hex, suffix }) catch unreachable;
}

fn writeSyncedFile(
    io: Io,
    directory: Io.Dir,
    name: []const u8,
    bytes: []const u8,
    mode: u16,
) !void {
    var file = try directory.createFile(io, name, .{
        .exclusive = true,
        .permissions = @fromBackingInt(@intCast(mode)),
    });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try durability.syncFile(io, file);
}

/// Publishes a fully synced identity directory without replacing an existing
/// path. Zig's non-Linux POSIX fallback uses hard links for no-replace rename,
/// which cannot publish a directory, so macOS uses its native atomic
/// RENAME_EXCL operation directly.
fn publishIdentityDirectory(
    parent: Io.Dir,
    temporary_name: []const u8,
    final_name: []const u8,
    io: Io,
) !void {
    if (builtin.os.tag != .macos) {
        parent.renamePreserve(temporary_name, parent, final_name, io) catch |err| switch (err) {
            error.PathAlreadyExists => return error.IdentityDestinationExists,
            else => return err,
        };
        return;
    }

    var temporary_buffer: [Io.Dir.max_name_bytes + 1]u8 = undefined;
    var final_buffer: [Io.Dir.max_name_bytes + 1]u8 = undefined;
    const temporary_z = std.mem.printSentinel(&temporary_buffer, "{s}", .{temporary_name}, 0) catch
        return error.NameTooLong;
    const final_z = std.mem.printSentinel(&final_buffer, "{s}", .{final_name}, 0) catch
        return error.NameTooLong;
    if (renameatx_np(
        parent.handle,
        temporary_z.ptr,
        parent.handle,
        final_z.ptr,
        0x00000004,
    ) == 0) return;
    return switch (std.posix.errno(-1)) {
        .EXIST => error.IdentityDestinationExists,
        .ACCES => error.AccessDenied,
        .PERM => error.PermissionDenied,
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .ISDIR => error.IsDir,
        .NOTEMPTY => error.DirNotEmpty,
        .ROFS => error.ReadOnlyFileSystem,
        .NOSPC => error.NoSpaceLeft,
        else => error.Unexpected,
    };
}

const testing = std.testing;

const ConsumeRace = struct {
    root: []const u8,
    secret: [token_bytes]u8,
    outcome: Outcome = .pending,

    const Outcome = enum { pending, consumed, used, unexpected };

    fn run(self: *ConsumeRace) void {
        consumeTokenAt(
            std.heap.page_allocator,
            testing.io,
            self.root,
            self.secret,
            7,
            1,
            99,
            3001,
        ) catch |err| {
            self.outcome = if (err == error.TokenUsed) .used else .unexpected;
            return;
        };
        self.outcome = .consumed;
    }
};

test "token is identity-bound, expiring, and consumed exactly once" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(testing.io, &root_buffer);
    const root = root_buffer[0..root_len];
    const issued = try issueTokenAt(testing.io, root, 3, 1, 99, 1000, 60);
    try testing.expectError(
        error.TokenIdentityMismatch,
        consumeTokenAt(
            testing.allocator,
            testing.io,
            root,
            issued.secret,
            4,
            1,
            99,
            1001,
        ),
    );
    try testing.expectError(
        error.TokenIdentityMismatch,
        consumeTokenAt(
            testing.allocator,
            testing.io,
            root,
            issued.secret,
            3,
            1,
            100,
            1001,
        ),
    );
    try consumeTokenAt(
        testing.allocator,
        testing.io,
        root,
        issued.secret,
        3,
        1,
        99,
        1059,
    );
    try testing.expectError(
        error.TokenUsed,
        consumeTokenAt(
            testing.allocator,
            testing.io,
            root,
            issued.secret,
            3,
            1,
            99,
            1059,
        ),
    );

    const expired = try issueTokenAt(testing.io, root, 4, 1, 99, 2000, 10);
    try testing.expectError(
        error.TokenExpired,
        consumeTokenAt(
            testing.allocator,
            testing.io,
            root,
            expired.secret,
            4,
            1,
            99,
            2010,
        ),
    );
}

test "opaque bundle round trips and rejects truncation" {
    const bundle = Bundle{
        .node_id = 3,
        .issuer_node_id = 1,
        .database_id = 99,
        .expires_unix_seconds = 1234,
        .secret = @as([token_bytes]u8, @splat(0x5a)),
        .endpoint = "127.0.0.1:9001",
        .ca_pem = "-----BEGIN CERTIFICATE-----\nca\n",
    };
    const bytes = try bundle.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    const decoded = try Bundle.decode(bytes);
    try testing.expectEqual(bundle.node_id, decoded.node_id);
    try testing.expectEqual(bundle.issuer_node_id, decoded.issuer_node_id);
    try testing.expectEqual(bundle.database_id, decoded.database_id);
    try testing.expectEqual(bundle.secret, decoded.secret);
    try testing.expectEqualStrings(bundle.endpoint, decoded.endpoint);
    try testing.expectEqualStrings(bundle.ca_pem, decoded.ca_pem);
    try testing.expectError(error.InvalidBundle, Bundle.decode(bytes[0 .. bytes.len - 1]));
}

test "concurrent token redemption has one winner" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(testing.io, &root_buffer);
    const root = root_buffer[0..root_len];
    const issued = try issueTokenAt(testing.io, root, 7, 1, 99, 3000, 60);
    var first = ConsumeRace{ .root = root, .secret = issued.secret };
    var second = ConsumeRace{ .root = root, .secret = issued.secret };
    const first_thread = try std.Thread.spawn(.{}, ConsumeRace.run, .{&first});
    const second_thread = try std.Thread.spawn(.{}, ConsumeRace.run, .{&second});
    first_thread.join();
    second_thread.join();
    const first_won = first.outcome == .consumed and second.outcome == .used;
    const second_won = second.outcome == .consumed and first.outcome == .used;
    try testing.expect(first_won or second_won);
}
