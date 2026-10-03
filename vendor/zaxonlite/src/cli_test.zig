//! The zaxon CLI contract test.
//!
//! Drives the real binary end to end and asserts the documented contract:
//! exit codes, JSON output shape, session retry semantics, the interactive
//! shell in script mode, directory locking, and offline client-mode
//! failure. Runs against a scratch directory and cleans up after itself.
//!
//! Usage: cli-test <path-to-zaxon>

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

var zaxon_path: []const u8 = undefined;
var scratch_root: []const u8 = undefined;
var failures: usize = 0;

const RunResult = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: *RunResult, gpa: std.mem.Allocator) void {
        gpa.free(self.stdout);
        gpa.free(self.stderr);
    }
};

fn runCli(
    gpa: std.mem.Allocator,
    io: Io,
    arguments: []const []const u8,
    stdin_text: ?[]const u8,
) !RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, zaxon_path);
    try argv.appendSlice(gpa, arguments);

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = if (stdin_text != null) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    if (stdin_text) |text| {
        const stdin = child.stdin.?;
        var write_buffer: [4096]u8 = undefined;
        var writer = stdin.writerStreaming(io, &write_buffer);
        writer.interface.writeAll(text) catch {};
        writer.interface.flush() catch {};
        stdin.close(io);
        child.stdin = null;
    }

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.readerStreaming(io, &stdout_buffer);
    const stdout = try stdout_reader.interface.allocRemaining(gpa, .limited(1 << 22));
    errdefer gpa.free(stdout);
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.readerStreaming(io, &stderr_buffer);
    const stderr = try stderr_reader.interface.allocRemaining(gpa, .limited(1 << 22));
    errdefer gpa.free(stderr);

    const term = try child.wait(io);
    const code: u8 = switch (term) {
        .exited => |value| value,
        else => 255,
    };
    return .{ .code = code, .stdout = stdout, .stderr = stderr };
}

fn check(
    condition: bool,
    name: []const u8,
    result: *const RunResult,
) void {
    if (condition) {
        std.debug.print("ok   {s}\n", .{name});
    } else {
        failures += 1;
        std.debug.print(
            "FAIL {s}\n  code={d}\n  stdout: {s}\n  stderr: {s}\n",
            .{ name, result.code, result.stdout, result.stderr },
        );
    }
}

fn expect(
    gpa: std.mem.Allocator,
    io: Io,
    name: []const u8,
    arguments: []const []const u8,
    stdin_text: ?[]const u8,
    expected_code: u8,
    stdout_contains: ?[]const u8,
    stderr_contains: ?[]const u8,
) !void {
    var result = try runCli(gpa, io, arguments, stdin_text);
    defer result.deinit(gpa);
    var ok = result.code == expected_code;
    if (stdout_contains) |needle| {
        ok = ok and std.mem.indexOf(u8, result.stdout, needle) != null;
    }
    if (stderr_contains) |needle| {
        ok = ok and std.mem.indexOf(u8, result.stderr, needle) != null;
    }
    check(ok, name, &result);
}

fn runProgram(io: Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.ProgramFailed;
}

/// Creates `<dir>/<name>.key` and `<dir>/<name>.crt` with the given
/// common name; self-signed when `signer` is null, otherwise signed by
/// the previously generated `<dir>/<signer>.{key,crt}`.
fn generateTlsIdentity(
    gpa: std.mem.Allocator,
    io: Io,
    dir: []const u8,
    name: []const u8,
    signer: ?[]const u8,
    common_name: []const u8,
) !void {
    const key = try std.fmt.allocPrint(gpa, "{s}/{s}.key", .{ dir, name });
    defer gpa.free(key);
    const crt = try std.fmt.allocPrint(gpa, "{s}/{s}.crt", .{ dir, name });
    defer gpa.free(crt);
    const subject = try std.fmt.allocPrint(gpa, "/CN={s}", .{common_name});
    defer gpa.free(subject);
    try runProgram(io, &.{
        "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
        "-out",    key,
    });
    const signing = signer orelse {
        try runProgram(io, &.{
            "openssl", "req", "-x509", "-new", "-key",  key,
            "-out",    crt,   "-days", "2",    "-subj", subject,
        });
        return;
    };
    const csr = try std.fmt.allocPrint(gpa, "{s}/{s}.csr", .{ dir, name });
    defer gpa.free(csr);
    const signer_key = try std.fmt.allocPrint(gpa, "{s}/{s}.key", .{ dir, signing });
    defer gpa.free(signer_key);
    const signer_crt = try std.fmt.allocPrint(gpa, "{s}/{s}.crt", .{ dir, signing });
    defer gpa.free(signer_crt);
    try runProgram(io, &.{
        "openssl", "req", "-new", "-key", key, "-out", csr, "-subj", subject,
    });
    try runProgram(io, &.{
        "openssl", "x509",     "-req",   "-in",      csr,
        "-CA",     signer_crt, "-CAkey", signer_key, "-CAcreateserial",
        "-out",    crt,        "-days",  "2",
    });
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    zaxon_path = iterator.next() orelse {
        std.debug.print("usage: cli-test <path-to-zaxon>\n", .{});
        return 2;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    const root = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/zx-cli-{x}", .{nonce});
    defer gpa.free(root);
    scratch_root = root;
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    const data = try std.fmt.allocPrint(gpa, "{s}/node", .{root});
    defer gpa.free(data);
    const backup_path = try std.fmt.allocPrint(gpa, "{s}/backup.db", .{root});
    defer gpa.free(backup_path);
    const config_path = try std.fmt.allocPrint(gpa, "{s}/config.json", .{root});
    defer gpa.free(config_path);
    const config_json = try std.fmt.allocPrint(
        gpa,
        "{{\"data\":\"{s}\"}}",
        .{data},
    );
    defer gpa.free(config_json);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = config_path,
        .data = config_json,
    });

    // --- usage and version -------------------------------------------
    try expect(gpa, io, "no arguments prints usage, exit 2", &.{}, null, 2, "Usage:", null);
    try expect(gpa, io, "version exits 0", &.{"version"}, null, 0, "zaxon ", null);
    try expect(gpa, io, "help exits 0", &.{"help"}, null, 0, "Commands:", null);
    try expect(
        gpa,
        io,
        "unknown option exits 2",
        &.{ "status", "--data", data, "--bogus" },
        null,
        2,
        null,
        "-- INVALID OPTIONS --",
    );
    try expect(
        gpa,
        io,
        "exec without sql exits 2",
        &.{ "exec", "--data", data },
        null,
        2,
        null,
        "exec needs --sql",
    );

    // --- embedded write/read path ------------------------------------
    try expect(
        gpa,
        io,
        "create table",
        &.{ "exec", "--data", data, "--sql", "create table t(a integer primary key, b text)" },
        null,
        0,
        "0 row(s) changed",
        null,
    );
    try expect(
        gpa,
        io,
        "config file supplies data directory",
        &.{ "status", "--config", config_path, "--json" },
        null,
        0,
        "\"node_id\":1",
        null,
    );
    try expect(
        gpa,
        io,
        "CLI overrides config file",
        &.{ "status", "--config", config_path, "--data", data, "--json" },
        null,
        0,
        "\"node_id\":1",
        null,
    );
    try expect(
        gpa,
        io,
        "insert rows",
        &.{ "exec", "--data", data, "--sql", "insert into t(b) values ('x'),('y')" },
        null,
        0,
        "2 row(s) changed",
        null,
    );
    try expect(
        gpa,
        io,
        "query json shape",
        &.{ "query", "--data", data, "--sql", "select * from t order by a", "--json" },
        null,
        0,
        "{\"columns\":[\"a\",\"b\"],\"rows\":[[\"1\",\"x\"],[\"2\",\"y\"]]}",
        null,
    );
    try expect(
        gpa,
        io,
        "write statement via query exits 1",
        &.{ "query", "--data", data, "--sql", "insert into t(b) values ('nope')" },
        null,
        1,
        null,
        "not read-only",
    );
    try expect(
        gpa,
        io,
        "sql error exits 1 with message",
        &.{ "exec", "--data", data, "--sql", "insert into missing values (1)" },
        null,
        1,
        null,
        "no such table",
    );

    // --- sessions ------------------------------------------------------
    try expect(
        gpa,
        io,
        "open session",
        &.{ "session", "--data", data },
        null,
        0,
        "session 1",
        null,
    );
    try expect(
        gpa,
        io,
        "idempotent exec",
        &.{
            "exec",      "--data", data,
            "--session", "1",      "--sequence",
            "1",         "--sql",  "insert into t(b) values ('z')",
        },
        null,
        0,
        "1 row(s) changed",
        null,
    );
    try expect(
        gpa,
        io,
        "duplicate sequence replays recorded result",
        &.{
            "exec",      "--data", data,
            "--session", "1",      "--sequence",
            "1",         "--sql",  "insert into t(b) values ('z')",
        },
        null,
        0,
        "replayed",
        null,
    );
    try expect(
        gpa,
        io,
        "sequence gap exits 1",
        &.{
            "exec",      "--data", data,
            "--session", "1",      "--sequence",
            "9",         "--sql",  "insert into t(b) values ('gap')",
        },
        null,
        1,
        null,
        "SequenceGap",
    );
    try expect(
        gpa,
        io,
        "unknown session exits 1",
        &.{
            "exec",      "--data", data,
            "--session", "77",     "--sequence",
            "1",         "--sql",  "insert into t(b) values ('s')",
        },
        null,
        1,
        null,
        "UnknownSession",
    );

    // --- status, anchor, backup, integrity -----------------------------
    try expect(
        gpa,
        io,
        "status json parses",
        &.{ "status", "--data", data, "--json" },
        null,
        0,
        "\"role\":\"leader\"",
        null,
    );
    try expect(
        gpa,
        io,
        "anchor publishes a durable state anchor",
        &.{ "anchor", "--data", data },
        null,
        0,
        "state anchor published",
        null,
    );
    try expect(
        gpa,
        io,
        "backup writes a file",
        &.{ "backup", "--data", data, "--to", backup_path },
        null,
        0,
        "backup written",
        null,
    );
    {
        Io.Dir.cwd().access(io, backup_path, .{}) catch {
            failures += 1;
            std.debug.print("FAIL backup file exists\n", .{});
        };
    }
    try expect(
        gpa,
        io,
        "integrity-check passes",
        &.{ "integrity-check", "--data", data },
        null,
        0,
        "sqlite: pass",
        null,
    );
    try expect(
        gpa,
        io,
        "recover rebuilds and verifies",
        &.{ "recover", "--data", data },
        null,
        0,
        "recovery rebuild complete",
        null,
    );
    try expect(
        gpa,
        io,
        "members reports static membership",
        &.{ "members", "--data", data, "--json" },
        null,
        0,
        "\"membership\":\"static\"",
        null,
    );
    try expect(
        gpa,
        io,
        "expire-sessions runs",
        &.{ "expire-sessions", "--data", data, "--retain", "1000" },
        null,
        0,
        "session(s) expired",
        null,
    );

    // --- interactive shell in script mode ------------------------------
    try expect(
        gpa,
        io,
        "shell executes scripted statements",
        &.{ "sql", "--data", data },
        "insert into t(b) values ('shell');\nselect count(*) from t;\n.quit\n",
        0,
        "count(*)",
        null,
    );
    // The non-TTY fallback is a contract (ZDS 0005): the legacy unaligned
    // table shape, byte for byte, so piped automation never changes.
    try expect(
        gpa,
        io,
        "piped shell keeps the legacy table format",
        &.{ "sql", "--data", data },
        "select 1 as a, 'x' as b;\n.quit\n",
        0,
        "a | b\n--+--\n1 | x\n",
        null,
    );
    try expect(
        gpa,
        io,
        "piped shell keeps legacy dot commands",
        &.{ "sql", "--data", data },
        ".tables\n.quit\n",
        0,
        "name\n----\nt\n",
        null,
    );
    try expect(
        gpa,
        io,
        "piped shell rejects unknown dot commands",
        &.{ "sql", "--data", data },
        ".bogus\n.quit\n",
        0,
        null,
        "-- UNKNOWN SHELL COMMAND --",
    );
    try expect(
        gpa,
        io,
        "shell flags are accepted outside a TTY",
        &.{ "sql", "--data", data, "--no-color", "--no-history" },
        "select count(*) from t;\n.quit\n",
        0,
        "count(*)",
        null,
    );
    {
        // The piped fallback must never create a history file.
        const history_file = try std.fmt.allocPrint(
            gpa,
            "{s}/.zaxon_history",
            .{data},
        );
        defer gpa.free(history_file);
        if (Io.Dir.cwd().access(io, history_file, .{})) |_| {
            failures += 1;
            std.debug.print("FAIL piped shell wrote a history file\n", .{});
        } else |_| {
            std.debug.print("ok   piped shell writes no history file\n", .{});
        }
    }

    // --- locking --------------------------------------------------------
    {
        const node = try zaxonlite.Node.open(gpa, io, .{ .directory = data });
        defer node.close();
        try expect(
            gpa,
            io,
            "locked directory exits 4",
            &.{ "status", "--data", data },
            null,
            4,
            null,
            "-- NODE DIRECTORY LOCKED --",
        );
    }

    // --- unix-domain socket service --------------------------------------
    {
        const unix_data = try std.fmt.allocPrint(gpa, "{s}/unix-node", .{root});
        defer gpa.free(unix_data);
        const socket_path = try std.fmt.allocPrint(gpa, "{s}/zaxon.sock", .{root});
        defer gpa.free(socket_path);
        const unix_endpoint = try std.fmt.allocPrint(gpa, "unix:{s}", .{socket_path});
        defer gpa.free(unix_endpoint);

        try expect(
            gpa,
            io,
            "unix listener refuses peers",
            &.{
                "serve",       "--data", unix_data,
                "--node",      "1",      "--listen",
                unix_endpoint, "--peer", "2@127.0.0.1:9902",
            },
            null,
            2,
            null,
            "single-node",
        );

        var serve_child = try std.process.spawn(io, .{
            .argv = &.{
                zaxon_path, "serve",
                "--data",   unix_data,
                "--node",   "1",
                "--listen", unix_endpoint,
            },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        var socket_ready = false;
        var waited: usize = 0;
        while (waited < 200) : (waited += 1) {
            if (Io.Dir.cwd().access(io, socket_path, .{})) |_| {
                socket_ready = true;
                break;
            } else |_| {}
            io.sleep(.fromMilliseconds(25), .awake) catch {};
        }
        if (!socket_ready) {
            failures += 1;
            std.debug.print("FAIL unix socket never appeared\n", .{});
        }

        // Owner-only permissions are applied before serving.
        if (Io.Dir.cwd().statFile(io, socket_path, .{})) |stat| {
            const mode = @backingInt(stat.permissions) & 0o777;
            if (mode != 0o600) {
                failures += 1;
                std.debug.print("FAIL unix socket mode {o} != 600\n", .{mode});
            } else {
                std.debug.print("ok   unix socket is owner-only\n", .{});
            }
        } else |err| {
            failures += 1;
            std.debug.print(
                "FAIL unix socket stat: {s}\n",
                .{@errorName(err)},
            );
        }

        try expect(
            gpa,
            io,
            "status over unix socket",
            &.{ "status", "--connect", unix_endpoint, "--json" },
            null,
            0,
            "\"node_id\":1",
            null,
        );
        try expect(
            gpa,
            io,
            "exec over unix socket",
            &.{
                "exec",  "--connect",                             unix_endpoint,
                "--sql", "create table u(a integer primary key)",
            },
            null,
            0,
            "0 row(s) changed",
            null,
        );

        // A second server must refuse the live socket path instead of
        // silently taking it over.
        const second_data = try std.fmt.allocPrint(gpa, "{s}/unix-node2", .{root});
        defer gpa.free(second_data);
        try expect(
            gpa,
            io,
            "existing socket path is refused",
            &.{
                "serve",       "--data", second_data,
                "--node",      "1",      "--listen",
                unix_endpoint,
            },
            null,
            4,
            null,
            "UNIX SOCKET LISTEN FAILED",
        );

        try expect(
            gpa,
            io,
            "stop over unix socket",
            &.{ "stop", "--connect", unix_endpoint },
            null,
            0,
            null,
            null,
        );
        _ = try serve_child.wait(io);

        // Orderly shutdown removes the socket path.
        if (Io.Dir.cwd().access(io, socket_path, .{})) |_| {
            failures += 1;
            std.debug.print("FAIL unix socket not removed on shutdown\n", .{});
        } else |_| {
            std.debug.print("ok   unix socket removed on shutdown\n", .{});
        }
    }

    // --- loopback-only development PSK service --------------------------
    {
        const psk_data = try std.fmt.allocPrint(gpa, "{s}/psk-node", .{root});
        defer gpa.free(psk_data);
        const psk_file = try std.fmt.allocPrint(gpa, "{s}/demo.psk", .{root});
        defer gpa.free(psk_file);
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = psk_file,
            .data = "cli-test-development-psk-32-bytes",
            .flags = .{ .permissions = @fromBackingInt(@intCast(0o600)) },
        });
        const psk_port: u16 = @intCast(12000 + nonce % 5000);
        const psk_listen = try std.fmt.allocPrint(
            gpa,
            "127.0.0.1:{d}",
            .{psk_port},
        );
        defer gpa.free(psk_listen);
        const public_listen = try std.fmt.allocPrint(
            gpa,
            "0.0.0.0:{d}",
            .{psk_port},
        );
        defer gpa.free(public_listen);

        try expect(
            gpa,
            io,
            "development PSK requires an auth provider",
            &.{
                "serve",    "--data",    psk_data,
                "--node",   "1",         "--listen",
                psk_listen, "--dev-psk",
            },
            null,
            2,
            null,
            "--dev-psk requires --auth-file",
        );
        try expect(
            gpa,
            io,
            "development PSK refuses a non-loopback listener",
            &.{
                "serve",       "--data",      psk_data,
                "--node",      "1",           "--listen",
                public_listen, "--auth-file", psk_file,
                "--dev-psk",
            },
            null,
            2,
            null,
            "loopback",
        );

        var serve_child = try std.process.spawn(io, .{
            .argv = &.{
                zaxon_path,    "serve",
                "--data",      psk_data,
                "--node",      "1",
                "--listen",    psk_listen,
                "--auth-file", psk_file,
                "--dev-psk",
            },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .pipe,
        });
        var psk_ready = false;
        for (0..80) |_| {
            var result = try runCli(
                gpa,
                io,
                &.{
                    "status",      "--connect", psk_listen,
                    "--auth-file", psk_file,    "--json",
                },
                null,
            );
            if (result.code == 0) psk_ready = true;
            result.deinit(gpa);
            if (psk_ready) break;
            io.sleep(.fromMilliseconds(25), .awake) catch {};
        }
        if (!psk_ready) {
            failures += 1;
            std.debug.print("FAIL development PSK server never became ready\n", .{});
        }
        try expect(
            gpa,
            io,
            "exec over development PSK",
            &.{
                "exec",                                      "--connect", psk_listen,
                "--auth-file",                               psk_file,    "--sql",
                "create table psk_t(a integer primary key)",
            },
            null,
            0,
            "0 row(s) changed",
            null,
        );
        // Leader announcements are intentionally debounced for three
        // 25 ms protocol ticks. Fast hosts can complete the exec and stop
        // commands before that operator-facing readiness log is emitted.
        io.sleep(.fromMilliseconds(100), .awake) catch {};
        try expect(
            gpa,
            io,
            "stop development PSK server",
            &.{
                "stop",        "--connect", psk_listen,
                "--auth-file", psk_file,
            },
            null,
            0,
            null,
            null,
        );
        var log_buffer: [4096]u8 = undefined;
        var log_reader = serve_child.stderr.?.readerStreaming(io, &log_buffer);
        const serve_log = try log_reader.interface.allocRemaining(
            gpa,
            .limited(64 * 1024),
        );
        defer gpa.free(serve_log);
        _ = try serve_child.wait(io);
        if (std.mem.indexOf(u8, serve_log, "development PSK (loopback only)") == null or
            std.mem.indexOf(u8, serve_log, "writes are ready") == null)
        {
            failures += 1;
            std.debug.print("FAIL serve startup/leader log missing: {s}\n", .{serve_log});
        } else {
            std.debug.print("ok   serve logs transport and leader readiness\n", .{});
        }
    }

    // --- mutual TLS service ----------------------------------------------
    {
        const tls_root = try std.fmt.allocPrint(gpa, "{s}/tls", .{root});
        defer gpa.free(tls_root);
        try Io.Dir.cwd().createDirPath(io, tls_root);
        try generateTlsIdentity(gpa, io, tls_root, "ca", null, "zaxon-test-ca");
        try generateTlsIdentity(gpa, io, tls_root, "n1", "ca", "zaxon-node-1");
        try generateTlsIdentity(gpa, io, tls_root, "r2", "ca", "zaxon-node-2");
        try generateTlsIdentity(gpa, io, tls_root, "r3", "ca", "zaxon-node-3");
        try generateTlsIdentity(gpa, io, tls_root, "client", "ca", "zaxon-client");
        // A second CA whose certificates the cluster must refuse.
        try generateTlsIdentity(gpa, io, tls_root, "ca2", null, "other-ca");
        try generateTlsIdentity(gpa, io, tls_root, "rogue", "ca2", "zaxon-node-1");

        const tls_data = try std.fmt.allocPrint(gpa, "{s}/tls-node", .{root});
        defer gpa.free(tls_data);
        const port: u16 = @intCast(20000 + nonce % 20000);
        const listen = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{port});
        defer gpa.free(listen);
        const ca = try std.fmt.allocPrint(gpa, "{s}/ca.crt", .{tls_root});
        defer gpa.free(ca);
        const ca_key = try std.fmt.allocPrint(gpa, "{s}/ca.key", .{tls_root});
        defer gpa.free(ca_key);
        const n1_cert = try std.fmt.allocPrint(gpa, "{s}/n1.crt", .{tls_root});
        defer gpa.free(n1_cert);
        const n1_key = try std.fmt.allocPrint(gpa, "{s}/n1.key", .{tls_root});
        defer gpa.free(n1_key);
        const client_cert = try std.fmt.allocPrint(gpa, "{s}/client.crt", .{tls_root});
        defer gpa.free(client_cert);
        const client_key = try std.fmt.allocPrint(gpa, "{s}/client.key", .{tls_root});
        defer gpa.free(client_key);
        const rogue_cert = try std.fmt.allocPrint(gpa, "{s}/rogue.crt", .{tls_root});
        defer gpa.free(rogue_cert);
        const rogue_key = try std.fmt.allocPrint(gpa, "{s}/rogue.key", .{tls_root});
        defer gpa.free(rogue_key);
        const ca2 = try std.fmt.allocPrint(gpa, "{s}/ca2.crt", .{tls_root});
        defer gpa.free(ca2);
        const token_path = try std.fmt.allocPrint(gpa, "{s}/node2.token", .{tls_root});
        defer gpa.free(token_path);
        const replay_token_path = try std.fmt.allocPrint(
            gpa,
            "{s}/node2-replay.token",
            .{tls_root},
        );
        defer gpa.free(replay_token_path);
        const enrolled_dir = try std.fmt.allocPrint(gpa, "{s}/node2-identity", .{tls_root});
        defer gpa.free(enrolled_dir);
        const replay_dir = try std.fmt.allocPrint(gpa, "{s}/node2-replay", .{tls_root});
        defer gpa.free(replay_dir);
        const revocation_path = try std.fmt.allocPrint(
            gpa,
            "{s}/revoked-nodes",
            .{tls_root},
        );
        defer gpa.free(revocation_path);
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = revocation_path,
            .data = "# initially empty\n",
        });
        const node2_address = try std.fmt.allocPrint(
            gpa,
            "2@127.0.0.1:{d}/standby",
            .{port + 1},
        );
        defer gpa.free(node2_address);

        try expect(
            gpa,
            io,
            "partial tls flags exit 2",
            &.{ "status", "--connect", listen, "--tls-ca", ca },
            null,
            2,
            null,
            "given together",
        );
        try expect(
            gpa,
            io,
            "loopback TCP refuses plaintext production mode",
            &.{
                "serve",  "--data", tls_data,
                "--node", "1",      "--listen",
                listen,
            },
            null,
            4,
            null,
            "MUTUAL TLS REQUIRED",
        );

        var serve_child = try std.process.spawn(io, .{
            .argv = &.{
                zaxon_path,            "serve",
                "--data",              tls_data,
                "--node",              "1",
                "--listen",            listen,
                "--peer",              node2_address,
                "--tls-cert",          n1_cert,
                "--tls-key",           n1_key,
                "--tls-ca",            ca,
                "--enrollment-ca-key", ca_key,
                "--revocation-file",   revocation_path,
            },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        io.sleep(.fromMilliseconds(300), .awake) catch {};

        try expect(
            gpa,
            io,
            "status over mutual TLS",
            &.{
                "status",     "--connect", listen,
                "--tls-cert", client_cert, "--tls-key",
                client_key,   "--tls-ca",  ca,
                "--json",
            },
            null,
            0,
            "\"node_id\":1",
            null,
        );

        try expect(
            gpa,
            io,
            "mTLS operator issues one-time enrollment token",
            &.{
                "enroll-token", "--connect",     listen,
                "--node",       "2",             "--to",
                token_path,     "--ttl-seconds", "60",
                "--tls-cert",   client_cert,     "--tls-key",
                client_key,     "--tls-ca",      ca,
            },
            null,
            0,
            "enrollment token bundle written to",
            null,
        );
        const token_copy = try Io.Dir.cwd().readFileAlloc(
            io,
            token_path,
            gpa,
            .limited(128 * 1024 + 1),
        );
        defer gpa.free(token_copy);
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = replay_token_path,
            .data = token_copy,
            .flags = .{ .permissions = @fromBackingInt(@intCast(0o600)) },
        });
        try expect(
            gpa,
            io,
            "joining node generates CSR and installs identity",
            &.{
                "enroll",         "--token-file", token_path,
                "--identity-dir", enrolled_dir,
            },
            null,
            0,
            "node 2 enrolled",
            null,
        );
        const node2_cert = try std.fmt.allocPrint(gpa, "{s}/node.crt", .{enrolled_dir});
        defer gpa.free(node2_cert);
        const node2_key = try std.fmt.allocPrint(gpa, "{s}/node.key", .{enrolled_dir});
        defer gpa.free(node2_key);
        const node2_ca = try std.fmt.allocPrint(gpa, "{s}/ca.crt", .{enrolled_dir});
        defer gpa.free(node2_ca);
        const identity_stat = try Io.Dir.cwd().statFile(io, enrolled_dir, .{
            .follow_symlinks = false,
        });
        const key_stat = try Io.Dir.cwd().statFile(io, node2_key, .{
            .follow_symlinks = false,
        });
        if (@backingInt(identity_stat.permissions) & 0o077 != 0 or
            @backingInt(key_stat.permissions) & 0o077 != 0)
        {
            std.debug.print("FAIL enrolled identity permissions are not owner-only\n", .{});
            failures += 1;
        } else {
            std.debug.print("ok   enrolled identity directory and key are owner-only\n", .{});
        }
        try expect(
            gpa,
            io,
            "enrolled identity authenticates over mTLS",
            &.{
                "status",     "--connect", listen,
                "--tls-cert", node2_cert,  "--tls-key",
                node2_key,    "--tls-ca",  node2_ca,
                "--json",
            },
            null,
            0,
            "\"node_id\":1",
            null,
        );
        try expect(
            gpa,
            io,
            "consumed enrollment token cannot be replayed",
            &.{
                "enroll",         "--token-file", replay_token_path,
                "--identity-dir", replay_dir,
            },
            null,
            4,
            null,
            "ENROLLMENT REFUSED",
        );
        try expect(
            gpa,
            io,
            "exec over mutual TLS",
            &.{
                "exec",       "--connect",                                 listen,
                "--tls-cert", client_cert,                                 "--tls-key",
                client_key,   "--tls-ca",                                  ca,
                "--sql",      "create table tls_t(a integer primary key)",
            },
            null,
            0,
            "0 row(s) changed",
            null,
        );
        // A plaintext client cannot speak to a TLS listener.
        try expect(
            gpa,
            io,
            "plaintext client fails against TLS server",
            &.{ "status", "--connect", listen, "--json" },
            null,
            4,
            null,
            "-- NO REACHABLE LEADER --",
        );
        // A certificate from a foreign CA is refused even with the right name.
        try expect(
            gpa,
            io,
            "foreign-CA certificate is refused",
            &.{
                "status",     "--connect", listen,
                "--tls-cert", rogue_cert,  "--tls-key",
                rogue_key,    "--tls-ca",  ca,
                "--json",
            },
            null,
            4,
            null,
            "-- NO REACHABLE LEADER --",
        );
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = revocation_path,
            .data = "2\n",
        });
        // The server reloads the revocation file every 40 ticks; under CI
        // load that cadence can exceed any fixed sleep. Poll until the
        // denylist takes effect, then assert the exact contract once.
        const revoked_argv = [_][]const u8{
            "status",     "--connect", listen,
            "--tls-cert", node2_cert,  "--tls-key",
            node2_key,    "--tls-ca",  node2_ca,
            "--json",
        };
        var revocation_attempts: usize = 0;
        while (revocation_attempts < 40) : (revocation_attempts += 1) {
            var probe = try runCli(gpa, io, &revoked_argv, null);
            const refused = probe.code == 4;
            probe.deinit(gpa);
            if (refused) break;
            io.sleep(.fromMilliseconds(250), .awake) catch {};
        }
        try expect(
            gpa,
            io,
            "revoked node credential is refused as a client",
            &revoked_argv,
            null,
            4,
            null,
            "-- NO REACHABLE LEADER --",
        );

        try expect(
            gpa,
            io,
            "stop over mutual TLS",
            &.{
                "stop",       "--connect", listen,
                "--tls-cert", client_cert, "--tls-key",
                client_key,   "--tls-ca",  ca,
            },
            null,
            0,
            null,
            null,
        );
        _ = try serve_child.wait(io);

        // Regression for the quickstart: one mTLS seed may redirect a
        // leader-only command to a different configured node. The new
        // connection is accepted only when its certificate CN matches the
        // advertised node ID.
        var redirect_data: [3][]u8 = undefined;
        var redirect_listen: [3][]u8 = undefined;
        defer for (redirect_data) |path| gpa.free(path);
        defer for (redirect_listen) |endpoint| gpa.free(endpoint);
        var redirect_children = @as([3]?std.process.Child, @splat(null));
        defer for (&redirect_children) |*child| {
            if (child.*) |*running| {
                running.kill(io);
                child.* = null;
            }
        };
        for (0..3) |index| {
            const id = index + 1;
            redirect_data[index] = try std.fmt.allocPrint(
                gpa,
                "{s}/redirect-n{d}",
                .{ tls_root, id },
            );
            redirect_listen[index] = try std.fmt.allocPrint(
                gpa,
                "127.0.0.1:{d}",
                .{port + 10 + @as(u16, @intCast(index))},
            );

            var argv: std.ArrayList([]const u8) = .empty;
            defer argv.deinit(gpa);
            var scratch: std.ArrayList([]u8) = .empty;
            defer {
                for (scratch.items) |item| gpa.free(item);
                scratch.deinit(gpa);
            }
            const id_text = try std.fmt.allocPrint(gpa, "{d}", .{id});
            try scratch.append(gpa, id_text);
            try argv.appendSlice(gpa, &.{
                zaxon_path,
                "serve",
                "--data",
                redirect_data[index],
                "--node",
                id_text,
                "--listen",
                redirect_listen[index],
            });
            for (0..3) |peer_index| {
                if (peer_index == index) continue;
                const peer = try std.fmt.allocPrint(
                    gpa,
                    "{d}@127.0.0.1:{d}",
                    .{
                        peer_index + 1,
                        port + 10 + @as(u16, @intCast(peer_index)),
                    },
                );
                try scratch.append(gpa, peer);
                try argv.appendSlice(gpa, &.{ "--peer", peer });
            }
            const identity_name = switch (index) {
                0 => "n1",
                1 => "r2",
                else => "r3",
            };
            const redirect_cert = try std.fmt.allocPrint(
                gpa,
                "{s}/{s}.crt",
                .{ tls_root, identity_name },
            );
            try scratch.append(gpa, redirect_cert);
            const redirect_key = try std.fmt.allocPrint(
                gpa,
                "{s}/{s}.key",
                .{ tls_root, identity_name },
            );
            try scratch.append(gpa, redirect_key);
            try argv.appendSlice(gpa, &.{
                "--tls-cert", redirect_cert,
                "--tls-key",  redirect_key,
                "--tls-ca",   ca,
                "--sync",     "os",
            });
            redirect_children[index] = try std.process.spawn(io, .{
                .argv = argv.items,
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            });
        }

        const redirect_seeds = try std.fmt.allocPrint(
            gpa,
            "{s},{s},{s}",
            .{ redirect_listen[0], redirect_listen[1], redirect_listen[2] },
        );
        defer gpa.free(redirect_seeds);
        var leader_id: u32 = 0;
        for (0..120) |_| {
            var result = try runCli(
                gpa,
                io,
                &.{
                    "leader",     "--connect", redirect_seeds,
                    "--tls-cert", client_cert, "--tls-key",
                    client_key,   "--tls-ca",  ca,
                    "--json",
                },
                null,
            );
            defer result.deinit(gpa);
            if (result.code == 0) {
                const parsed = std.json.parseFromSlice(
                    std.json.Value,
                    gpa,
                    result.stdout,
                    .{},
                ) catch null;
                if (parsed) |value| {
                    defer value.deinit();
                    switch (value.value) {
                        .object => |object| if (object.get("leader")) |leader| {
                            switch (leader) {
                                .object => |leader_object| {
                                    if (leader_object.get("id")) |id_value| {
                                        if (id_value == .integer and
                                            id_value.integer > 0 and
                                            id_value.integer <= 3)
                                        {
                                            leader_id = @intCast(id_value.integer);
                                        }
                                    }
                                },
                                else => {},
                            }
                        },
                        else => {},
                    }
                }
            }
            if (leader_id != 0) break;
            io.sleep(.fromMilliseconds(25), .awake) catch {};
        }
        if (leader_id == 0) {
            failures += 1;
            std.debug.print("FAIL mTLS redirect cluster never elected a leader\n", .{});
        } else {
            const follower_index: usize = if (leader_id == 1) 1 else 0;
            try expect(
                gpa,
                io,
                "mTLS single seed follows authenticated leader redirect",
                &.{
                    "exec",
                    "--connect",
                    redirect_listen[follower_index],
                    "--sql",
                    "create table redirected(a integer primary key)",
                    "--tls-cert",
                    client_cert,
                    "--tls-key",
                    client_key,
                    "--tls-ca",
                    ca,
                },
                null,
                0,
                "0 row(s) changed",
                null,
            );
        }
        for (0..3) |index| {
            var stopped = try runCli(
                gpa,
                io,
                &.{
                    "stop",       "--connect", redirect_listen[index],
                    "--tls-cert", client_cert, "--tls-key",
                    client_key,   "--tls-ca",  ca,
                },
                null,
            );
            stopped.deinit(gpa);
        }
        for (&redirect_children) |*child| {
            if (child.*) |*running| {
                _ = running.wait(io) catch {};
                child.* = null;
            }
        }
    }

    // --- offline client mode ---------------------------------------------
    try expect(
        gpa,
        io,
        "client mode with no server exits 4",
        &.{ "status", "--connect", "127.0.0.1:9", "--json" },
        null,
        4,
        null,
        "-- NO REACHABLE LEADER --",
    );

    // --- membership and replacement command contract ----------------------
    try expect(
        gpa,
        io,
        "membership requires the status subcommand",
        &.{ "membership", "--connect", "127.0.0.1:9" },
        null,
        2,
        null,
        "membership needs a subcommand",
    );
    try expect(
        gpa,
        io,
        "membership status with no server exits 4",
        &.{ "membership", "status", "--connect", "127.0.0.1:9" },
        null,
        4,
        null,
        "-- NO REACHABLE LEADER --",
    );
    try expect(
        gpa,
        io,
        "replace-voter validates its arguments",
        &.{ "replace-voter", "--connect", "127.0.0.1:9" },
        null,
        2,
        null,
        "replace-voter needs --operation",
    );
    try expect(
        gpa,
        io,
        "replace-voter validates the new node spec",
        &.{
            "replace-voter", "--connect",  "127.0.0.1:9",
            "--operation",   "1",          "--expected-config",
            "1",             "--old-node", "3",
            "--new-node",    "not-a-spec",
        },
        null,
        2,
        null,
        "--new-node must be <id>@<host>:<port>",
    );

    if (failures == 0) {
        std.debug.print("cli contract test: all checks passed\n", .{});
        return 0;
    }
    std.debug.print("cli contract test: {d} failure(s)\n", .{failures});
    return 1;
}
