//! Mutual TLS 1.3 transport built on the system OpenSSL 3 library.
//!
//! This is the optional second transport authentication mode, beside the
//! shared-secret PSK handshake in `transport_auth.zig`. Where the PSK
//! proves possession of one cluster-wide secret, mTLS gives every node a
//! per-node certificate: connections verify the peer's chain against the
//! cluster CA, require a certificate in both directions, and bind a peer
//! connection's certificate common name to the node id it claims in its
//! hello. TLS also provides the confidentiality the PSK mode lacks.
//!
//! Interop shape: a small set of hand-declared OpenSSL externs (no header
//! translation), one `Context` per process per direction, and a `Stream`
//! that exposes the same `std.Io.Reader`/`std.Io.Writer` interfaces the
//! framing layer already consumes, so wire.zig and transport_auth.zig
//! run unchanged above it. Handshakes and I/O use the blocking socket;
//! shutting the socket down unblocks them, which is how the server's
//! existing watchdog and shutdown paths cancel TLS connections too.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

// ----------------------------------------------------------------------
// OpenSSL 3 externs (libssl / libcrypto)
// ----------------------------------------------------------------------

const SSL_CTX = opaque {};
const SSL = opaque {};
const SSL_METHOD = opaque {};
const X509 = opaque {};
const X509_NAME = opaque {};
const X509_REQ = opaque {};
const X509_STORE = opaque {};
const X509_EXTENSION = opaque {};
const EVP_PKEY = opaque {};
const EVP_MD = opaque {};
const EVP_CIPHER = opaque {};
const BIO = opaque {};
const BIO_METHOD = opaque {};
const ASN1_INTEGER = opaque {};

const SSL_FILETYPE_PEM: c_int = 1;
const SSL_VERIFY_PEER: c_int = 0x01;
const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 0x02;
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
const TLS1_3_VERSION: c_long = 0x0304;
const X509_V_OK: c_long = 0;
const NID_commonName: c_int = 13;
const NID_key_usage: c_int = 83;
const NID_basic_constraints: c_int = 87;
const NID_ext_key_usage: c_int = 126;
const MBSTRING_ASC: c_int = 0x1001;
const SSL_ERROR_ZERO_RETURN: c_int = 6;

extern "c" fn TLS_server_method() *const SSL_METHOD;
extern "c" fn TLS_client_method() *const SSL_METHOD;
extern "c" fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
extern "c" fn SSL_CTX_free(ctx: *SSL_CTX) void;
extern "c" fn SSL_CTX_use_certificate_chain_file(
    ctx: *SSL_CTX,
    file: [*:0]const u8,
) c_int;
extern "c" fn SSL_CTX_use_PrivateKey_file(
    ctx: *SSL_CTX,
    file: [*:0]const u8,
    file_type: c_int,
) c_int;
extern "c" fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) c_int;
extern "c" fn SSL_CTX_load_verify_locations(
    ctx: *SSL_CTX,
    ca_file: ?[*:0]const u8,
    ca_path: ?[*:0]const u8,
) c_int;
extern "c" fn SSL_CTX_set_verify(
    ctx: *SSL_CTX,
    mode: c_int,
    callback: ?*const anyopaque,
) void;
extern "c" fn SSL_CTX_get_cert_store(ctx: *const SSL_CTX) ?*X509_STORE;
extern "c" fn SSL_CTX_ctrl(
    ctx: *SSL_CTX,
    cmd: c_int,
    larg: c_long,
    parg: ?*anyopaque,
) c_long;
extern "c" fn SSL_new(ctx: *SSL_CTX) ?*SSL;
extern "c" fn SSL_free(ssl: *SSL) void;
extern "c" fn SSL_set_fd(ssl: *SSL, fd: c_int) c_int;
extern "c" fn SSL_accept(ssl: *SSL) c_int;
extern "c" fn SSL_connect(ssl: *SSL) c_int;
extern "c" fn SSL_read(ssl: *SSL, buf: *anyopaque, num: c_int) c_int;
extern "c" fn SSL_write(ssl: *SSL, buf: *const anyopaque, num: c_int) c_int;
extern "c" fn SSL_shutdown(ssl: *SSL) c_int;
extern "c" fn SSL_get_error(ssl: *const SSL, ret: c_int) c_int;
extern "c" fn SSL_get_verify_result(ssl: *const SSL) c_long;
extern "c" fn SSL_get1_peer_certificate(ssl: *const SSL) ?*X509;
extern "c" fn X509_free(x: *X509) void;
extern "c" fn X509_get_subject_name(x: *const X509) ?*X509_NAME;
extern "c" fn X509_get_pubkey(x: *const X509) ?*EVP_PKEY;
extern "c" fn X509_verify(x: *X509, key: *EVP_PKEY) c_int;
extern "c" fn X509_NAME_get_text_by_NID(
    name: *X509_NAME,
    nid: c_int,
    buf: [*]u8,
    len: c_int,
) c_int;
extern "c" fn X509_STORE_add_cert(store: *X509_STORE, cert: *X509) c_int;
extern "c" fn X509_REQ_new() ?*X509_REQ;
extern "c" fn X509_REQ_free(request: *X509_REQ) void;
extern "c" fn X509_REQ_set_version(request: *X509_REQ, version: c_long) c_int;
extern "c" fn X509_REQ_set_subject_name(request: *X509_REQ, name: *X509_NAME) c_int;
extern "c" fn X509_REQ_get_subject_name(request: *X509_REQ) ?*X509_NAME;
extern "c" fn X509_REQ_set_pubkey(request: *X509_REQ, key: *EVP_PKEY) c_int;
extern "c" fn X509_REQ_get_pubkey(request: *X509_REQ) ?*EVP_PKEY;
extern "c" fn X509_REQ_sign(request: *X509_REQ, key: *EVP_PKEY, md: ?*const EVP_MD) c_int;
extern "c" fn X509_REQ_verify(request: *X509_REQ, key: *EVP_PKEY) c_int;
extern "c" fn X509_NAME_new() ?*X509_NAME;
extern "c" fn X509_NAME_free(name: *X509_NAME) void;
extern "c" fn X509_NAME_add_entry_by_txt(
    name: *X509_NAME,
    field: [*:0]const u8,
    value_type: c_int,
    bytes: [*]const u8,
    len: c_int,
    location: c_int,
    set: c_int,
) c_int;
extern "c" fn EVP_PKEY_Q_keygen(
    libctx: ?*anyopaque,
    propq: ?[*:0]const u8,
    key_type: [*:0]const u8,
    ...,
) ?*EVP_PKEY;
extern "c" fn EVP_PKEY_free(key: *EVP_PKEY) void;
extern "c" fn EVP_PKEY_is_a(key: *const EVP_PKEY, name: [*:0]const u8) c_int;
extern "c" fn EVP_sha256() *const EVP_MD;
extern "c" fn BIO_s_mem() *const BIO_METHOD;
extern "c" fn BIO_new(method: *const BIO_METHOD) ?*BIO;
extern "c" fn BIO_new_mem_buf(buffer: *const anyopaque, len: c_int) ?*BIO;
extern "c" fn BIO_new_file(path: [*:0]const u8, mode: [*:0]const u8) ?*BIO;
extern "c" fn BIO_free(bio: *BIO) c_int;
extern "c" fn BIO_ctrl_pending(bio: *BIO) usize;
extern "c" fn BIO_read(bio: *BIO, buffer: *anyopaque, len: c_int) c_int;
extern "c" fn PEM_write_bio_PrivateKey(
    bio: *BIO,
    key: *const EVP_PKEY,
    cipher: ?*const EVP_CIPHER,
    password: ?[*]const u8,
    password_len: c_int,
    callback: ?*const anyopaque,
    userdata: ?*anyopaque,
) c_int;
extern "c" fn PEM_write_bio_X509_REQ(bio: *BIO, request: *X509_REQ) c_int;
extern "c" fn PEM_write_bio_X509(bio: *BIO, certificate: *X509) c_int;
extern "c" fn PEM_read_bio_X509_REQ(
    bio: *BIO,
    request: ?**X509_REQ,
    callback: ?*const anyopaque,
    userdata: ?*anyopaque,
) ?*X509_REQ;
extern "c" fn PEM_read_bio_X509(
    bio: *BIO,
    certificate: ?**X509,
    callback: ?*const anyopaque,
    userdata: ?*anyopaque,
) ?*X509;
extern "c" fn PEM_read_bio_PrivateKey(
    bio: *BIO,
    key: ?**EVP_PKEY,
    callback: ?*const anyopaque,
    userdata: ?*anyopaque,
) ?*EVP_PKEY;
extern "c" fn X509_new() ?*X509;
extern "c" fn X509_set_version(certificate: *X509, version: c_long) c_int;
extern "c" fn X509_set_serialNumber(certificate: *X509, serial: *ASN1_INTEGER) c_int;
extern "c" fn ASN1_INTEGER_new() ?*ASN1_INTEGER;
extern "c" fn ASN1_INTEGER_free(value: *ASN1_INTEGER) void;
extern "c" fn ASN1_INTEGER_set_uint64(value: *ASN1_INTEGER, number: u64) c_int;
extern "c" fn X509_getm_notBefore(certificate: *const X509) ?*anyopaque;
extern "c" fn X509_getm_notAfter(certificate: *const X509) ?*anyopaque;
extern "c" fn X509_gmtime_adj(time: *anyopaque, seconds: c_long) ?*anyopaque;
extern "c" fn X509_set_issuer_name(certificate: *X509, name: *X509_NAME) c_int;
extern "c" fn X509_set_subject_name(certificate: *X509, name: *X509_NAME) c_int;
extern "c" fn X509_set_pubkey(certificate: *X509, key: *EVP_PKEY) c_int;
extern "c" fn X509_check_private_key(certificate: *const X509, key: *const EVP_PKEY) c_int;
extern "c" fn X509_sign(certificate: *X509, key: *EVP_PKEY, md: ?*const EVP_MD) c_int;
extern "c" fn X509V3_EXT_conf_nid(
    conf: ?*anyopaque,
    context: ?*anyopaque,
    nid: c_int,
    value: [*:0]const u8,
) ?*X509_EXTENSION;
extern "c" fn X509_add_ext(certificate: *X509, extension: *X509_EXTENSION, location: c_int) c_int;
extern "c" fn X509_EXTENSION_free(extension: *X509_EXTENSION) void;
extern "c" fn ERR_clear_error() void;

// ----------------------------------------------------------------------
// Configuration and identity
// ----------------------------------------------------------------------

pub const Error = error{
    TlsInit,
    TlsCredentials,
    TlsHandshakeFailed,
    TlsPeerUnverified,
    CertificateRequestFailed,
    CertificateIssueFailed,
    InvalidCertificateRequest,
    InvalidCertificate,
    NameTooLong,
};

/// PEM file paths for one node's transport identity. All three are
/// required together: the node certificate, its private key, and the
/// cluster CA every peer certificate must chain to.
pub const Config = struct {
    cert_path: []const u8,
    key_path: []const u8,
    ca_path: []const u8,
};

/// Longest certificate common name this module reads; longer names fail
/// verification rather than truncating an identity comparison.
pub const max_common_name = 64;

/// Renders the certificate common name a configured node must present:
/// `zaxon-node-<id>`. Enrollment (P1.1) issues certificates with exactly
/// this name; the transport refuses a peer whose certificate and hello
/// disagree.
pub fn nodeCommonName(buffer: *[max_common_name]u8, node_id: u32) []const u8 {
    return std.fmt.bufPrint(buffer, "zaxon-node-{d}", .{node_id}) catch
        unreachable;
}

/// Parses the only certificate-name shape accepted for a storage endpoint.
/// Client principals may use other CA-issued names, but cannot impersonate a
/// server merely because they chain to the same small cluster CA.
pub fn parseNodeCommonName(name: []const u8) ?u32 {
    const prefix = "zaxon-node-";
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    const suffix = name[prefix.len..];
    if (suffix.len == 0) return null;
    const id = std.fmt.parseInt(u32, suffix, 10) catch return null;
    return if (id == 0) null else id;
}

/// Upper bound for one administrator principal name.
pub const max_admin_name = 32;

/// Administrator principals use a distinct name shape, `zaxon-admin-<name>`,
/// issued by the same cluster CA. The namespaces never overlap: a node
/// certificate can never authorize a membership operation, and an admin
/// certificate can never authenticate as a storage node.
pub fn adminCommonName(buffer: *[max_common_name]u8, name: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer, "zaxon-admin-{s}", .{name}) catch
        unreachable;
}

/// Parses an administrator certificate name: `zaxon-admin-<name>` with a
/// nonempty lowercase `[a-z0-9-]` name of at most 32 bytes.
pub fn parseAdminCommonName(name: []const u8) ?[]const u8 {
    const prefix = "zaxon-admin-";
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    const suffix = name[prefix.len..];
    if (suffix.len == 0 or suffix.len > max_admin_name) return null;
    for (suffix) |byte| {
        switch (byte) {
            'a'...'z', '0'...'9', '-' => {},
            else => return null,
        }
    }
    return suffix;
}

fn pathZ(buffer: *[std.Io.Dir.max_path_bytes]u8, path: []const u8) Error![:0]const u8 {
    return std.mem.printSentinel(buffer, "{s}", .{path}, 0) catch
        return error.NameTooLong;
}

// ----------------------------------------------------------------------
// Context: one per process per direction
// ----------------------------------------------------------------------

pub const Context = struct {
    handle: *SSL_CTX,

    pub fn initServer(config: Config) Error!Context {
        return initCommon(TLS_server_method(), config, true);
    }

    /// Enrollment issuers accept a TLS connection without a client
    /// certificate so the caller can present its one-time token and CSR.
    /// Application framing still rejects every non-enrollment hello without
    /// a verified peer certificate.
    pub fn initEnrollmentServer(config: Config) Error!Context {
        return initCommon(TLS_server_method(), config, false);
    }

    pub fn initClient(config: Config) Error!Context {
        return initCommon(TLS_client_method(), config, true);
    }

    /// Creates a server-authenticated TLS client from the CA PEM carried in
    /// the enrollment bundle. No client certificate exists yet.
    pub fn initEnrollmentClient(ca_pem: []const u8) Error!Context {
        const ctx = try initBare(TLS_client_method());
        errdefer SSL_CTX_free(ctx);
        const bio = BIO_new_mem_buf(ca_pem.ptr, @intCast(ca_pem.len)) orelse
            return error.TlsCredentials;
        defer _ = BIO_free(bio);
        const ca = PEM_read_bio_X509(bio, null, null, null) orelse
            return error.TlsCredentials;
        defer X509_free(ca);
        const store = SSL_CTX_get_cert_store(ctx) orelse return error.TlsInit;
        if (X509_STORE_add_cert(store, ca) != 1) return error.TlsCredentials;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, null);
        return .{ .handle = ctx };
    }

    /// Both directions verify the peer chain against the cluster CA and
    /// require a certificate from the peer — that is the mutual part —
    /// and refuse anything below TLS 1.3.
    fn initBare(method: *const SSL_METHOD) Error!*SSL_CTX {
        const ctx = SSL_CTX_new(method) orelse return error.TlsInit;
        errdefer SSL_CTX_free(ctx);
        if (SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_SET_MIN_PROTO_VERSION,
            TLS1_3_VERSION,
            null,
        ) != 1) {
            return error.TlsInit;
        }
        return ctx;
    }

    fn initCommon(
        method: *const SSL_METHOD,
        config: Config,
        require_peer_certificate: bool,
    ) Error!Context {
        const ctx = try initBare(method);
        errdefer SSL_CTX_free(ctx);

        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        if (SSL_CTX_use_certificate_chain_file(
            ctx,
            (try pathZ(&path_buffer, config.cert_path)).ptr,
        ) != 1) {
            return error.TlsCredentials;
        }
        if (SSL_CTX_use_PrivateKey_file(
            ctx,
            (try pathZ(&path_buffer, config.key_path)).ptr,
            SSL_FILETYPE_PEM,
        ) != 1) {
            return error.TlsCredentials;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) return error.TlsCredentials;
        if (SSL_CTX_load_verify_locations(
            ctx,
            (try pathZ(&path_buffer, config.ca_path)).ptr,
            null,
        ) != 1) {
            return error.TlsCredentials;
        }
        SSL_CTX_set_verify(
            ctx,
            SSL_VERIFY_PEER | if (require_peer_certificate)
                SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            else
                0,
            null,
        );
        return .{ .handle = ctx };
    }

    pub fn deinit(self: *Context) void {
        SSL_CTX_free(self.handle);
        self.* = undefined;
    }
};

// ----------------------------------------------------------------------
// Stream: one TLS connection over an accepted or dialed socket
// ----------------------------------------------------------------------

pub const Stream = struct {
    ssl: *SSL,
    /// Certificate common name of the verified peer; the transport binds
    /// this to the peer's claimed hello identity.
    common_name_buffer: [max_common_name]u8,
    common_name_len: usize,
    reader: Io.Reader,
    writer: Io.Writer,

    /// Responder half: runs the TLS handshake over the accepted socket.
    /// `read_buffer`/`write_buffer` back the exposed interfaces and must
    /// outlive the stream. The socket stays owned by the caller; closing
    /// or shutting it down unblocks any in-flight TLS call.
    pub fn accept(
        context: *const Context,
        socket: std.Io.net.Stream,
        read_buffer: []u8,
        write_buffer: []u8,
    ) Error!Stream {
        return handshake(context, socket, read_buffer, write_buffer, SSL_accept, true);
    }

    /// Enrollment-enabled responder variant. A verified common name is
    /// recorded when supplied, but a missing client certificate is allowed
    /// until the application validates an enrollment hello and token.
    pub fn acceptOptionalPeer(
        context: *const Context,
        socket: std.Io.net.Stream,
        read_buffer: []u8,
        write_buffer: []u8,
    ) Error!Stream {
        return handshake(context, socket, read_buffer, write_buffer, SSL_accept, false);
    }

    /// Initiator half; see `accept`.
    pub fn connect(
        context: *const Context,
        socket: std.Io.net.Stream,
        read_buffer: []u8,
        write_buffer: []u8,
    ) Error!Stream {
        return handshake(context, socket, read_buffer, write_buffer, SSL_connect, true);
    }

    fn handshake(
        context: *const Context,
        socket: std.Io.net.Stream,
        read_buffer: []u8,
        write_buffer: []u8,
        step: *const fn (ssl: *SSL) callconv(.c) c_int,
        require_peer_certificate: bool,
    ) Error!Stream {
        disableSigpipe(socket.socket.handle);
        ERR_clear_error();
        const ssl = SSL_new(context.handle) orelse return error.TlsInit;
        errdefer SSL_free(ssl);
        if (SSL_set_fd(ssl, socketDescriptor(socket.socket.handle)) != 1) {
            return error.TlsInit;
        }
        if (step(ssl) != 1) return error.TlsHandshakeFailed;
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            return error.TlsPeerUnverified;
        }

        var self = Stream{
            .ssl = ssl,
            .common_name_buffer = undefined,
            .common_name_len = 0,
            .reader = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = read_buffer,
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .vtable = &.{ .drain = drainImpl },
                .buffer = write_buffer,
            },
        };
        try self.readPeerCommonName(require_peer_certificate);
        return self;
    }

    /// OpenSSL's socket BIO API still accepts `int` on Windows even though
    /// WinSock spells SOCKET as a pointer-sized handle. OpenSSL documents the
    /// narrowing conversion as safe for current Windows socket-table indices.
    fn socketDescriptor(handle: std.Io.net.Socket.Handle) c_int {
        return if (builtin.os.tag == .windows)
            @intCast(@intFromPtr(handle))
        else
            @intCast(handle);
    }

    /// SIGPIPE would kill the process when OpenSSL writes to a peer that
    /// already closed; connection errors must surface as write failures.
    fn disableSigpipe(handle: anytype) void {
        if (@hasDecl(std.posix.SO, "NOSIGPIPE")) {
            const one: c_int = 1;
            std.posix.setsockopt(
                handle,
                std.posix.SOL.SOCKET,
                std.posix.SO.NOSIGPIPE,
                std.mem.asBytes(&one),
            ) catch {};
        }
    }

    fn readPeerCommonName(self: *Stream, required: bool) Error!void {
        // Verification already required a certificate; a missing one or
        // an over-long name is a refused identity, not a truncated one.
        const certificate = SSL_get1_peer_certificate(self.ssl) orelse {
            if (required) return error.TlsPeerUnverified;
            return;
        };
        defer X509_free(certificate);
        const subject = X509_get_subject_name(certificate) orelse
            return error.TlsPeerUnverified;
        const written = X509_NAME_get_text_by_NID(
            subject,
            NID_commonName,
            &self.common_name_buffer,
            @intCast(self.common_name_buffer.len),
        );
        if (written <= 0 or written >= self.common_name_buffer.len) {
            return error.TlsPeerUnverified;
        }
        self.common_name_len = @intCast(written);
    }

    /// The verified peer certificate's common name.
    pub fn peerCommonName(self: *const Stream) []const u8 {
        return self.common_name_buffer[0..self.common_name_len];
    }

    pub fn hasPeerCertificate(self: *const Stream) bool {
        return self.common_name_len != 0;
    }

    /// Sends a best-effort close_notify and releases the TLS state. The
    /// underlying socket remains the caller's to close.
    pub fn deinit(self: *Stream) void {
        _ = SSL_shutdown(self.ssl);
        SSL_free(self.ssl);
        self.* = undefined;
    }

    fn readSsl(self: *Stream, destination: []u8) Io.Reader.StreamError!usize {
        ERR_clear_error();
        const len: c_int = @intCast(@min(
            destination.len,
            std.math.maxInt(c_int),
        ));
        const n = SSL_read(self.ssl, destination.ptr, len);
        if (n > 0) return @intCast(n);
        if (SSL_get_error(self.ssl, n) == SSL_ERROR_ZERO_RETURN) {
            return error.EndOfStream;
        }
        return error.ReadFailed;
    }

    /// Blocking-mode SSL_write completes the whole buffer or fails, so
    /// one call per slice suffices (chunked to the C int limit).
    fn writeSsl(self: *Stream, source: []const u8) Io.Writer.Error!usize {
        var offset: usize = 0;
        while (offset < source.len) {
            ERR_clear_error();
            const len: c_int = @intCast(@min(
                source.len - offset,
                std.math.maxInt(c_int),
            ));
            const n = SSL_write(self.ssl, source.ptr + offset, len);
            if (n <= 0) return error.WriteFailed;
            offset += @intCast(n);
        }
        return source.len;
    }

    fn streamImpl(
        io_reader: *Io.Reader,
        io_writer: *Io.Writer,
        limit: Io.Limit,
    ) Io.Reader.StreamError!usize {
        const self: *Stream = @alignCast(@fieldParentPtr("reader", io_reader));
        const destination = limit.slice(try io_writer.writableSliceGreedy(1));
        const n = try self.readSsl(destination);
        io_writer.advance(n);
        return n;
    }

    fn drainImpl(
        io_writer: *Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) Io.Writer.Error!usize {
        const self: *Stream = @alignCast(@fieldParentPtr("writer", io_writer));
        var written: usize = 0;
        written += try self.writeSsl(io_writer.buffered());
        for (data, 0..) |slice, index| {
            const repeat = if (index == data.len - 1) splat else 1;
            for (0..repeat) |_| written += try self.writeSsl(slice);
        }
        return io_writer.consume(written);
    }
};

// ----------------------------------------------------------------------
// Enrollment credentials and certificate issuance
// ----------------------------------------------------------------------

pub const GeneratedCredentials = struct {
    private_key_pem: []u8,
    csr_pem: []u8,

    pub fn deinit(self: *GeneratedCredentials, gpa: std.mem.Allocator) void {
        @memset(self.private_key_pem, 0);
        gpa.free(self.private_key_pem);
        gpa.free(self.csr_pem);
        self.* = undefined;
    }
};

/// Generates one P-256 private key locally and a signed CSR whose only
/// identity claim is the configured node common name. The private key never
/// crosses the enrollment connection.
pub fn generateNodeCredentials(
    gpa: std.mem.Allocator,
    node_id: u32,
) (Error || std.mem.Allocator.Error)!GeneratedCredentials {
    ERR_clear_error();
    const key = EVP_PKEY_Q_keygen(null, null, "EC", "P-256") orelse
        return error.CertificateRequestFailed;
    defer EVP_PKEY_free(key);
    const request = X509_REQ_new() orelse return error.CertificateRequestFailed;
    defer X509_REQ_free(request);
    const subject = X509_NAME_new() orelse return error.CertificateRequestFailed;
    defer X509_NAME_free(subject);

    var name_buffer: [max_common_name]u8 = undefined;
    const common_name = nodeCommonName(&name_buffer, node_id);
    if (X509_NAME_add_entry_by_txt(
        subject,
        "CN",
        MBSTRING_ASC,
        common_name.ptr,
        @intCast(common_name.len),
        -1,
        0,
    ) != 1 or
        X509_REQ_set_version(request, 0) != 1 or
        X509_REQ_set_subject_name(request, subject) != 1 or
        X509_REQ_set_pubkey(request, key) != 1 or
        X509_REQ_sign(request, key, EVP_sha256()) <= 0)
    {
        return error.CertificateRequestFailed;
    }

    const key_bio = BIO_new(BIO_s_mem()) orelse return error.CertificateRequestFailed;
    defer _ = BIO_free(key_bio);
    if (PEM_write_bio_PrivateKey(key_bio, key, null, null, 0, null, null) != 1) {
        return error.CertificateRequestFailed;
    }
    const csr_bio = BIO_new(BIO_s_mem()) orelse return error.CertificateRequestFailed;
    defer _ = BIO_free(csr_bio);
    if (PEM_write_bio_X509_REQ(csr_bio, request) != 1) {
        return error.CertificateRequestFailed;
    }
    const private_key_pem = try bioAlloc(gpa, key_bio, 32 * 1024);
    errdefer {
        @memset(private_key_pem, 0);
        gpa.free(private_key_pem);
    }
    return .{
        .private_key_pem = private_key_pem,
        .csr_pem = try bioAlloc(gpa, csr_bio, 32 * 1024),
    };
}

/// Checks the CSR signature and exact configured node identity before a token
/// is consumed. The issued certificate does not copy arbitrary CSR extensions.
pub fn validateNodeCsr(csr_pem: []const u8, node_id: u32) Error!void {
    const bio = BIO_new_mem_buf(csr_pem.ptr, @intCast(csr_pem.len)) orelse
        return error.InvalidCertificateRequest;
    defer _ = BIO_free(bio);
    const request = PEM_read_bio_X509_REQ(bio, null, null, null) orelse
        return error.InvalidCertificateRequest;
    defer X509_REQ_free(request);
    const public_key = X509_REQ_get_pubkey(request) orelse
        return error.InvalidCertificateRequest;
    defer EVP_PKEY_free(public_key);
    if (X509_REQ_verify(request, public_key) != 1) {
        return error.InvalidCertificateRequest;
    }
    const subject = X509_REQ_get_subject_name(request) orelse
        return error.InvalidCertificateRequest;
    try requireNodeName(subject, node_id, error.InvalidCertificateRequest);
}

/// Validates that an enrollment issuer key is a private key matching the
/// configured cluster CA certificate. Called at server startup, before the
/// optional-client-certificate TLS mode is enabled.
pub fn validateIssuer(ca_cert_path: []const u8, ca_key_path: []const u8) Error!void {
    var cert_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var key_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cert_bio = BIO_new_file(
        (try pathZ(&cert_path_buffer, ca_cert_path)).ptr,
        "r",
    ) orelse return error.TlsCredentials;
    defer _ = BIO_free(cert_bio);
    const ca = PEM_read_bio_X509(cert_bio, null, null, null) orelse
        return error.TlsCredentials;
    defer X509_free(ca);
    const key_bio = BIO_new_file(
        (try pathZ(&key_path_buffer, ca_key_path)).ptr,
        "r",
    ) orelse return error.TlsCredentials;
    defer _ = BIO_free(key_bio);
    const key = PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse
        return error.TlsCredentials;
    defer EVP_PKEY_free(key);
    if (X509_check_private_key(ca, key) != 1) return error.TlsCredentials;
}

/// Signs a validated CSR with the configured cluster CA. The certificate is
/// constrained to TLS client/server authentication and carries no CSR-provided
/// extensions. `serial` must come from the host's secure random source.
pub fn issueNodeCertificate(
    gpa: std.mem.Allocator,
    csr_pem: []const u8,
    node_id: u32,
    ca_cert_path: []const u8,
    ca_key_path: []const u8,
    serial: u64,
    validity_seconds: u64,
) (Error || std.mem.Allocator.Error)![]u8 {
    try validateNodeCsr(csr_pem, node_id);
    if (validity_seconds == 0 or validity_seconds > 10 * 365 * 24 * 60 * 60) {
        return error.CertificateIssueFailed;
    }

    const request_bio = BIO_new_mem_buf(csr_pem.ptr, @intCast(csr_pem.len)) orelse
        return error.CertificateIssueFailed;
    defer _ = BIO_free(request_bio);
    const request = PEM_read_bio_X509_REQ(request_bio, null, null, null) orelse
        return error.CertificateIssueFailed;
    defer X509_REQ_free(request);
    const public_key = X509_REQ_get_pubkey(request) orelse
        return error.CertificateIssueFailed;
    defer EVP_PKEY_free(public_key);

    var cert_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var key_path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const ca_bio = BIO_new_file(
        (try pathZ(&cert_path_buffer, ca_cert_path)).ptr,
        "r",
    ) orelse return error.CertificateIssueFailed;
    defer _ = BIO_free(ca_bio);
    const ca = PEM_read_bio_X509(ca_bio, null, null, null) orelse
        return error.CertificateIssueFailed;
    defer X509_free(ca);
    const key_bio = BIO_new_file(
        (try pathZ(&key_path_buffer, ca_key_path)).ptr,
        "r",
    ) orelse return error.CertificateIssueFailed;
    defer _ = BIO_free(key_bio);
    const ca_key = PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse
        return error.CertificateIssueFailed;
    defer EVP_PKEY_free(ca_key);
    if (X509_check_private_key(ca, ca_key) != 1) {
        return error.CertificateIssueFailed;
    }

    const certificate = X509_new() orelse return error.CertificateIssueFailed;
    defer X509_free(certificate);
    const serial_number = ASN1_INTEGER_new() orelse
        return error.CertificateIssueFailed;
    defer ASN1_INTEGER_free(serial_number);
    const subject = X509_REQ_get_subject_name(request) orelse
        return error.CertificateIssueFailed;
    const issuer = X509_get_subject_name(ca) orelse
        return error.CertificateIssueFailed;
    const before = X509_getm_notBefore(certificate) orelse
        return error.CertificateIssueFailed;
    const after = X509_getm_notAfter(certificate) orelse
        return error.CertificateIssueFailed;
    if (X509_set_version(certificate, 2) != 1 or
        ASN1_INTEGER_set_uint64(serial_number, if (serial == 0) 1 else serial) != 1 or
        X509_set_serialNumber(certificate, serial_number) != 1 or
        X509_gmtime_adj(before, -60) == null or
        X509_gmtime_adj(after, @intCast(validity_seconds)) == null or
        X509_set_issuer_name(certificate, issuer) != 1 or
        X509_set_subject_name(certificate, subject) != 1 or
        X509_set_pubkey(certificate, public_key) != 1)
    {
        return error.CertificateIssueFailed;
    }
    try addCertificateExtension(certificate, NID_basic_constraints, "critical,CA:FALSE");
    try addCertificateExtension(certificate, NID_key_usage, "critical,digitalSignature");
    try addCertificateExtension(certificate, NID_ext_key_usage, "serverAuth,clientAuth");
    const digest: ?*const EVP_MD = if (EVP_PKEY_is_a(ca_key, "ED25519") == 1 or
        EVP_PKEY_is_a(ca_key, "ED448") == 1)
        null
    else
        EVP_sha256();
    if (X509_sign(certificate, ca_key, digest) <= 0) {
        return error.CertificateIssueFailed;
    }

    const output = BIO_new(BIO_s_mem()) orelse return error.CertificateIssueFailed;
    defer _ = BIO_free(output);
    if (PEM_write_bio_X509(output, certificate) != 1) {
        return error.CertificateIssueFailed;
    }
    return bioAlloc(gpa, output, 64 * 1024);
}

/// Defends against a malformed or substituted enrollment response before the
/// new identity is installed on disk.
pub fn validateIssuedIdentity(
    certificate_pem: []const u8,
    private_key_pem: []const u8,
    node_id: u32,
    ca_pem: []const u8,
) Error!void {
    const cert_bio = BIO_new_mem_buf(certificate_pem.ptr, @intCast(certificate_pem.len)) orelse
        return error.InvalidCertificate;
    defer _ = BIO_free(cert_bio);
    const certificate = PEM_read_bio_X509(cert_bio, null, null, null) orelse
        return error.InvalidCertificate;
    defer X509_free(certificate);
    const key_bio = BIO_new_mem_buf(private_key_pem.ptr, @intCast(private_key_pem.len)) orelse
        return error.InvalidCertificate;
    defer _ = BIO_free(key_bio);
    const key = PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse
        return error.InvalidCertificate;
    defer EVP_PKEY_free(key);
    if (X509_check_private_key(certificate, key) != 1) {
        return error.InvalidCertificate;
    }
    const subject = X509_get_subject_name(certificate) orelse
        return error.InvalidCertificate;
    try requireNodeName(subject, node_id, error.InvalidCertificate);
    const ca_bio = BIO_new_mem_buf(ca_pem.ptr, @intCast(ca_pem.len)) orelse
        return error.InvalidCertificate;
    defer _ = BIO_free(ca_bio);
    const ca = PEM_read_bio_X509(ca_bio, null, null, null) orelse
        return error.InvalidCertificate;
    defer X509_free(ca);
    const ca_public_key = X509_get_pubkey(ca) orelse
        return error.InvalidCertificate;
    defer EVP_PKEY_free(ca_public_key);
    if (X509_verify(certificate, ca_public_key) != 1) {
        return error.InvalidCertificate;
    }
}

fn requireNodeName(name: *X509_NAME, node_id: u32, failure: Error) Error!void {
    var actual_buffer: [max_common_name]u8 = undefined;
    const count = X509_NAME_get_text_by_NID(
        name,
        NID_commonName,
        &actual_buffer,
        @intCast(actual_buffer.len),
    );
    if (count <= 0 or count >= actual_buffer.len) return failure;
    var expected_buffer: [max_common_name]u8 = undefined;
    const expected = nodeCommonName(&expected_buffer, node_id);
    if (!std.mem.eql(u8, expected, actual_buffer[0..@intCast(count)])) return failure;
}

fn addCertificateExtension(
    certificate: *X509,
    nid: c_int,
    value: [*:0]const u8,
) Error!void {
    const extension = X509V3_EXT_conf_nid(null, null, nid, value) orelse
        return error.CertificateIssueFailed;
    defer X509_EXTENSION_free(extension);
    if (X509_add_ext(certificate, extension, -1) != 1) {
        return error.CertificateIssueFailed;
    }
}

fn bioAlloc(
    gpa: std.mem.Allocator,
    bio: *BIO,
    maximum: usize,
) std.mem.Allocator.Error![]u8 {
    const length = BIO_ctrl_pending(bio);
    if (length == 0 or length > maximum) return error.OutOfMemory;
    const bytes = try gpa.alloc(u8, length);
    errdefer gpa.free(bytes);
    const count = BIO_read(bio, bytes.ptr, @intCast(bytes.len));
    if (count != bytes.len) return error.OutOfMemory;
    return bytes;
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const testing = std.testing;

test "node common name is deterministic and bounded" {
    var buffer: [max_common_name]u8 = undefined;
    try testing.expectEqualStrings("zaxon-node-3", nodeCommonName(&buffer, 3));
    try testing.expectEqualStrings(
        "zaxon-node-4294967295",
        nodeCommonName(&buffer, std.math.maxInt(u32)),
    );
}

test "node common name parser rejects client principals" {
    try testing.expectEqual(@as(?u32, 17), parseNodeCommonName("zaxon-node-17"));
    try testing.expectEqual(@as(?u32, null), parseNodeCommonName("zaxon-client"));
    try testing.expectEqual(@as(?u32, null), parseNodeCommonName("zaxon-node-0"));
    try testing.expectEqual(@as(?u32, null), parseNodeCommonName("zaxon-node-x"));
}

test "admin common name parser accepts only the admin namespace" {
    try testing.expectEqualStrings("ops-1", parseAdminCommonName("zaxon-admin-ops-1").?);
    try testing.expectEqual(@as(?[]const u8, null), parseAdminCommonName("zaxon-node-3"));
    try testing.expectEqual(@as(?[]const u8, null), parseAdminCommonName("zaxon-admin-"));
    try testing.expectEqual(@as(?[]const u8, null), parseAdminCommonName("zaxon-admin-Ops"));
    try testing.expectEqual(
        @as(?[]const u8, null),
        parseAdminCommonName("zaxon-admin-" ++ &@as([33]u8, @splat(97))),
    );
    // The namespaces never overlap.
    try testing.expectEqual(@as(?u32, null), parseNodeCommonName("zaxon-admin-ops"));

    var buffer: [max_common_name]u8 = undefined;
    try testing.expectEqualStrings("zaxon-admin-ops", adminCommonName(&buffer, "ops"));
}

test "enrollment key stays local and CSR binds the requested node" {
    var generated = try generateNodeCredentials(testing.allocator, 23);
    defer generated.deinit(testing.allocator);
    try testing.expect(std.mem.startsWith(
        u8,
        generated.private_key_pem,
        "-----BEGIN PRIVATE KEY-----",
    ));
    try testing.expect(std.mem.startsWith(
        u8,
        generated.csr_pem,
        "-----BEGIN CERTIFICATE REQUEST-----",
    ));
    try validateNodeCsr(generated.csr_pem, 23);
    try testing.expectError(
        error.InvalidCertificateRequest,
        validateNodeCsr(generated.csr_pem, 24),
    );
    try testing.expectError(
        error.InvalidCertificateRequest,
        validateNodeCsr("not a PEM certificate request", 23),
    );
}

test "context refuses missing credential files" {
    try testing.expectError(error.TlsCredentials, Context.initServer(.{
        .cert_path = ".zig-cache/definitely-missing-cert.pem",
        .key_path = ".zig-cache/definitely-missing-key.pem",
        .ca_path = ".zig-cache/definitely-missing-ca.pem",
    }));
}
