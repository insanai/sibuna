//! zaxon: the zaxonlite command line.
//!
//! Two modes share one command surface:
//! * embedded (`--data <dir>`): the command opens the node in-process,
//!   exactly as an embedding application would;
//! * client (`--connect host:port[,host:port...]`): the command speaks the
//!   RPC protocol to running `zaxon serve` processes, following leader
//!   redirects.
//!
//! `zaxon serve` hosts one role-aware node behind a TCP endpoint, alone or in
//! a runtime-sized cluster registry.

const std = @import("std");
const zaxonlite = @import("zaxonlite");
const cli_shell = @import("cli/shell.zig");
const cli_render = @import("cli/render.zig");
const cli_term = @import("zaxon_cli_ui").term;

/// The terminal layer's panic handler restores the operator's terminal
/// before the default panic runs; a no-op unless the rich shell is active.
pub const panic = cli_term.Panic;

const Node = zaxonlite.Node;
const server = zaxonlite.server;
const client = zaxonlite.client;
const gateway = zaxonlite.gateway;
const configuration = zaxonlite.configuration;
const diagnostic = zaxonlite.diagnostic;
const tls = zaxonlite.tls;
const enrollment = zaxonlite.enrollment;
const Role = zaxonlite.Role;

const exit_ok: u8 = 0;
const exit_sql: u8 = 1;
const exit_usage: u8 = 2;
const exit_integrity: u8 = 3;
const exit_unavailable: u8 = 4;

const usage_text =
    \\zaxon — embedded replicated SQLite (zaxonlite)
    \\
    \\Usage:
    \\  zaxon <command> --data <dir> [options]          embedded mode
    \\  zaxon <command> --connect host:port[,...]       client mode
    \\  zaxon serve --data <dir> --node <id> --listen <endpoint>
    \\        [--role <role>] [--peer <id>@host:port[/role] ...]
    \\        [--cluster-id <text>]
    \\        [--auth-file <path>] [--dev-psk] [--enable-failpoints]
    \\
    \\Commands:
    \\  sql               Interactive SQL shell (embedded or client mode).
    \\  exec              Execute SQL; --session/--sequence for idempotent retry.
    \\  query             Read query. --level any|leader|linearizable.
    \\  session           Open a client session and print its ID.
    \\  status            Show node status. --json for automation.
    \\  members           Show cluster membership and node roles.
    \\  membership status Show the decided registry, phase, and quorum health.
    \\  replace-voter     Replace one data voter (admin certificate required):
    \\                    --operation <u64> --expected-config <id>
    \\                    --old-node <id> --new-node <id>@<host>:<port>
    \\  leader            Show the current leader (client mode).
    \\  wait              Wait for --applied <slot> and/or --leader (client mode).
    \\  anchor            Publish a durable state anchor for fast recovery.
    \\  backup            Stream a consistent logical backup. --to <path>.
    \\  integrity-check   Verify SQLite image, descriptor chain, and payloads.
    \\  recover           Rebuild from authoritative state and verify it.
    \\  expire-sessions   Delete idle sessions; --retain <n> newest activity.
    \\  enroll-token      Create a short-lived token bundle for --node (client mode).
    \\  enroll            Redeem --token-file into an atomic --identity-dir.
    \\  serve             Host this node behind a TCP endpoint.
    \\  stop              Ask a served node to shut down (client mode).
    \\  version           Print the zaxonlite version.
    \\
    \\Options:
    \\  --config <path>     JSON config; or ZAXON_CONFIG.
    \\  --data <dir>        Node data directory (created when missing).
    \\  --connect <list>    Comma-separated endpoints (host:port or unix:<path>).
    \\  --sql <text>        SQL for exec/query.
    \\  --session <id>      Session ID for exec.
    \\  --sequence <n>      Monotonic per-session sequence for exec.
    \\  --level <level>     Read level for query (default linearizable).
    \\  --freshness-ms <n>  Maximum age for a local learner read.
    \\  --to <path>         Backup or enrollment-token destination path.
    \\  --retain <n>        Activity window for expire-sessions.
    \\  --applied <slot>    Slot to wait for (wait).
    \\  --leader            Also wait for a known leader (wait).
    \\  --timeout-ms <n>    Wait deadline in milliseconds.
    \\  --node <id>         This node's ID (serve) or enrollment target.
    \\  --listen <endpoint> host:port, or unix:<path> for owner-only local
    \\                      service over a Unix-domain socket (serve).
    \\  --role <role>       data-voter|witness|standby|read-replica|gateway.
    \\  --peer <spec>       id@host:port[/role] (repeat; serve).
    \\  --admin <name>      authorize one zaxon-admin principal (repeat; serve).
    \\  --cluster-id <text> Extra entropy for the derived database identity.
    \\  --auth-file <path>  PSK provider; or ZAXON_AUTH_FILE. Never a literal key.
    \\  --dev-psk           Loopback-only PSK transport for local development.
    \\  --tls-cert <path>   Node certificate PEM (mutual TLS; needs all three).
    \\  --tls-key <path>    Node private key PEM.
    \\  --tls-ca <path>     Cluster CA PEM that peer certificates chain to.
    \\  --enrollment-ca-key <path>
    \\                      CA private key PEM; enables token/CSR issuance on serve.
    \\  --token-file <path> Opaque owner-only enrollment bundle (enroll).
    \\  --identity-dir <dir> New directory receiving node.key/node.crt/ca.crt.
    \\  --ttl-seconds <n>   Enrollment token lifetime (default 600, maximum 86400).
    \\  --revocation-file <path>
    \\                      Reloaded node-ID denylist (serve).
    \\  --sync <mode>       full (default; F_FULLFSYNC on macOS, survives power
    \\                      loss) or os (plain fsync; faster, development only).
    \\  --mmap-size <bytes> SQLite-managed mapped-I/O limit (serve). Default 0
    \\                      (disabled); maximum 1073741824 (1 GiB). A mapped
    \\                      I/O fault can terminate the process; opting in
    \\                      accepts that operational risk.
    \\  --retention-slots <n>  Keep the most recent n slots of journal
    \\                      history below the chosen trim (default 0).
    \\  --journal-cap-bytes <n>  Refuse writes once journal plus payload
    \\                      bytes reach n, rather than delete unproven
    \\                      history (default 64 GiB; 0 disables).
    \\  --enable-failpoints Honor failpoint RPCs (test controllers only).
    \\  --segment-records <n>  Test-only journal segment size (64..16384);
    \\                      requires --enable-failpoints.
    \\  --test-storage-delay-ms <n>  Test-only delay before every journal
    \\                      barrier; requires --enable-failpoints.
    \\  --test-vote-delay-ms <n>  Test-only hold on outgoing phase-two
    \\                      votes; requires --enable-failpoints.
    \\  --test-anchor-interval-ms <n>  Test-only anchor cadence;
    \\                      requires --enable-failpoints.
    \\  --json              Machine-readable output on stdout.
    \\  --no-color          Plain shell output even on a color terminal.
    \\  --no-history        Never write the interactive shell history file.
    \\
    \\Exit codes: 0 ok, 1 SQL/session error, 2 usage, 3 integrity failure,
    \\4 node unavailable (locked, corrupt, or no leader).
    \\
;

const Options = struct {
    command: []const u8,
    config: ?[]const u8 = null,
    data: ?[]const u8 = null,
    connect: ?[]const u8 = null,
    sql: ?[:0]const u8 = null,
    session: ?u64 = null,
    sequence: ?u64 = null,
    level: ?[]const u8 = null,
    freshness_ms: ?u64 = null,
    to: ?[]const u8 = null,
    retain: ?u64 = null,
    applied: ?u64 = null,
    wait_leader: bool = false,
    timeout_ms: ?u64 = null,
    node_id: ?u32 = null,
    role: Role = .data_voter,
    role_set: bool = false,
    listen: ?[]const u8 = null,
    peers: std.ArrayList([]const u8) = .empty,
    admins: std.ArrayList([]const u8) = .empty,
    cluster_id: ?[]const u8 = null,
    auth_file: ?[]const u8 = null,
    tls_cert: ?[]const u8 = null,
    tls_key: ?[]const u8 = null,
    tls_ca: ?[]const u8 = null,
    enrollment_ca_key: ?[]const u8 = null,
    token_file: ?[]const u8 = null,
    identity_dir: ?[]const u8 = null,
    ttl_seconds: ?u64 = null,
    operation: ?u64 = null,
    expected_config: ?u64 = null,
    old_node: ?u32 = null,
    new_node: ?[]const u8 = null,
    revocation_file: ?[]const u8 = null,
    sync: ?[]const u8 = null,
    mmap_size: ?u64 = null,
    retention_slots: ?u64 = null,
    journal_cap_bytes: ?u64 = null,
    segment_records: ?usize = null,
    test_storage_delay_ms: ?u64 = null,
    test_vote_delay_ms: ?u64 = null,
    test_anchor_interval_ms: ?u64 = null,
    enable_failpoints: bool = false,
    dev_psk: bool = false,
    insecure_test_tcp: bool = false,
    json: bool = false,
    no_color: bool = false,
    no_history: bool = false,
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    const code = run(
        gpa,
        io,
        init.minimal.args,
        init.environ_map,
        out,
        err_out,
    ) catch |err| blk: {
        diagnostic.write(
            err_out,
            "command failed",
            @errorName(err),
            "Preserve the error and node logs before retrying.",
        ) catch {};
        break :blk exit_unavailable;
    };
    out.flush() catch {};
    err_out.flush() catch {};
    return code;
}

fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: std.process.Args,
    environ: *std.process.Environ.Map,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    // Windows hands the process one command-line string that has to be
    // split and re-encoded, so only the allocating initializer is portable.
    var iterator = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer iterator.deinit();
    _ = iterator.next();

    var command = iterator.next() orelse {
        try out.writeAll(usage_text);
        return exit_usage;
    };
    // The only two-word command: `zaxon membership status`.
    if (std.mem.eql(u8, command, "membership")) {
        const subcommand = iterator.next() orelse "";
        if (!std.mem.eql(u8, subcommand, "status")) {
            return usageError(err_out, "membership needs a subcommand: status");
        }
        command = "membership";
    }
    var options = Options{ .command = command };
    defer options.peers.deinit(gpa);
    defer options.admins.deinit(gpa);
    if (try parseOptions(gpa, &iterator, &options, err_out, out)) |code| return code;

    if (std.mem.eql(u8, command, "version")) {
        try out.print("zaxon {s}\n", .{zaxonlite.version});
        return exit_ok;
    }
    if (std.mem.eql(u8, command, "help")) {
        try out.writeAll(usage_text);
        return exit_ok;
    }
    const config_path = options.config orelse environ.get("ZAXON_CONFIG");
    var loaded_config: ?configuration.Loaded = if (config_path) |path|
        configuration.loadFile(gpa, io, path) catch |err| {
            try diagnostic.write(
                err_out,
                "configuration unreadable",
                @errorName(err),
                "Check the provider path, permissions, and JSON fields.",
            );
            return exit_usage;
        }
    else
        null;
    defer if (loaded_config) |*loaded| loaded.deinit();
    const file_config = if (loaded_config) |*loaded| loaded.value() else null;
    applyConfiguration(gpa, environ, file_config, &options, err_out) catch
        return exit_usage;
    if (options.sync) |sync_text| {
        const mode = std.meta.stringToEnum(
            zaxonlite.durability.SyncMode,
            sync_text,
        ) orelse return usageError(err_out, "--sync must be os or full");
        zaxonlite.durability.setSyncMode(mode);
    }
    if (std.mem.eql(u8, command, "enroll")) {
        return enrollCommand(gpa, io, &options, out, err_out);
    }
    var secret: ?configuration.Secret = if (options.auth_file) |path|
        configuration.loadSecret(gpa, io, path) catch |err| {
            try diagnostic.write(
                err_out,
                "authentication provider unreadable",
                @errorName(err),
                "Use a readable provider file containing at least 32 bytes.",
            );
            return exit_usage;
        }
    else
        null;
    defer if (secret) |*value| value.deinit(gpa);
    const secret_bytes: ?[]const u8 = if (secret) |*value| value.bytes else null;
    const tls_config = resolveTlsConfig(
        options.tls_cert,
        options.tls_key,
        options.tls_ca,
        err_out,
    ) catch |err| switch (err) {
        error.UsageError => return exit_usage,
        else => return err,
    };
    if (std.mem.eql(u8, command, "serve")) {
        return serveCommand(gpa, io, &options, secret_bytes, tls_config, err_out);
    }
    return dispatchRemoteOrLocal(
        gpa,
        io,
        environ,
        &options,
        command,
        secret_bytes,
        tls_config,
        out,
        err_out,
    );
}

fn resolveTlsConfig(
    cert: ?[]const u8,
    key: ?[]const u8,
    ca: ?[]const u8,
    err_out: *std.Io.Writer,
) !?tls.Config {
    const any = cert != null or key != null or ca != null;
    if (!any) return null;
    if (cert == null or key == null or ca == null) {
        _ = try usageError(err_out, "--tls-cert, --tls-key, and --tls-ca must be given together");
        return error.UsageError;
    }
    return .{ .cert_path = cert.?, .key_path = key.?, .ca_path = ca.? };
}

fn dispatchRemoteOrLocal(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: *std.process.Environ.Map,
    options: *Options,
    command: []const u8,
    secret_bytes: ?[]const u8,
    tls_config: ?tls.Config,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    if (options.connect != null) {
        var tls_context: ?tls.Context = null;
        defer if (tls_context) |*context| context.deinit();
        if (tls_config) |config| {
            configuration.validatePrivateFile(io, config.key_path) catch |err| {
                try diagnostic.write(
                    err_out,
                    "unsafe TLS private key",
                    @errorName(err),
                    "Use a regular, non-symlink key file with mode 0600.",
                );
                return exit_usage;
            };
            tls_context = tls.Context.initClient(config) catch |err| {
                try diagnostic.write(
                    err_out,
                    "tls identity failed",
                    @errorName(err),
                    "Check that --tls-cert, --tls-key, and --tls-ca name readable PEM files.",
                );
                return exit_usage;
            };
        }
        const transport = client.Transport{
            .secret = secret_bytes,
            .tls = if (tls_context) |*context| context else null,
        };
        return remote(gpa, io, environ, options, transport, out, err_out);
    }

    const data = options.data orelse
        return usageError(err_out, "--data <dir> or --connect is required");
    const node = Node.open(gpa, io, .{ .directory = data }) catch |err| switch (err) {
        error.NodeLocked => {
            try diagnostic.write(
                err_out,
                "node directory locked",
                "Another process owns this data directory.",
                "Stop that process or choose a different --data directory.",
            );
            return exit_unavailable;
        },
        else => {
            try diagnostic.write(
                err_out,
                "node open failed",
                @errorName(err),
                "Inspect identity, journal, payload, and filesystem diagnostics.",
            );
            return exit_unavailable;
        },
    };
    defer node.close();

    return executeLocalNodeCommand(gpa, io, environ, options, node, data, command, out, err_out);
}

fn executeLocalNodeCommand(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: *std.process.Environ.Map,
    options: *const Options,
    node: *zaxonlite.Node,
    data: []const u8,
    command: []const u8,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    if (std.mem.eql(u8, command, "sql")) {
        const history_path = try std.fmt.allocPrint(gpa, "{s}/.zaxon_history", .{data});
        defer gpa.free(history_path);
        return cli_shell.run(gpa, io, environ, .{ .embedded = node }, .{
            .no_color = options.no_color,
            .no_history = options.no_history,
            .history_path = history_path,
        }, out, err_out);
    }
    if (std.mem.eql(u8, command, "exec")) {
        const sql = options.sql orelse return usageError(err_out, "exec needs --sql");
        if ((options.session == null) != (options.sequence == null)) {
            return usageError(err_out, "--session and --sequence go together");
        }
        return cli_render.execEmbedded(
            node,
            sql,
            options.session,
            options.sequence,
            options.json,
            out,
            err_out,
        );
    }
    if (std.mem.eql(u8, command, "query")) {
        const sql = options.sql orelse return usageError(err_out, "query needs --sql");
        return cli_render.queryEmbedded(gpa, node, sql, options.json, out, err_out);
    }
    if (std.mem.eql(u8, command, "session")) {
        const session = try node.openSession();
        if (options.json) {
            try out.print("{{\"session_id\":{d}}}\n", .{session});
        } else {
            try out.print("session {d}\n", .{session});
        }
        return exit_ok;
    }
    if (std.mem.eql(u8, command, "status")) {
        try cli_render.printStatus(node, options.json, out);
        return exit_ok;
    }
    if (std.mem.eql(u8, command, "members")) {
        const status = node.status();
        if (options.json) try out.writeAll("{\"membership\":\"static\",\"members\":[");
        for (node.memberIds(), 0..) |member, index| {
            if (options.json) {
                if (index > 0) try out.writeAll(",");
                try out.print("{d}", .{member});
            } else {
                const suffix = if (member == status.node_id) " (self)" else "";
                try out.print("node {d}{s}\n", .{ member, suffix });
            }
        }
        if (options.json) try out.writeAll("]}\n");
        return exit_ok;
    }
    if (std.mem.eql(u8, command, "anchor") or
        std.mem.eql(u8, command, "backup") or
        std.mem.eql(u8, command, "integrity-check") or
        std.mem.eql(u8, command, "recover") or
        std.mem.eql(u8, command, "expire-sessions"))
    {
        return executeLocalMaintenanceCommand(options, node, command, out, err_out);
    }

    try diagnostic.write(
        err_out,
        "unknown command",
        command,
        "Run 'zaxon help' to list the supported commands.",
    );
    try out.writeAll(usage_text);
    return exit_usage;
}

fn executeLocalMaintenanceCommand(
    options: *const Options,
    node: *zaxonlite.Node,
    command: []const u8,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    if (std.mem.eql(u8, command, "anchor")) {
        try node.createStateAnchor();
        const status = node.status();
        if (options.json) {
            try out.print(
                "{{\"durable_state_slot\":{d}}}\n",
                .{status.durable_state_slot},
            );
        } else {
            try out.print(
                "state anchor published at slot {d}\n",
                .{status.durable_state_slot},
            );
        }
        return exit_ok;
    }
    if (std.mem.eql(u8, command, "backup")) {
        const destination = options.to orelse return usageError(err_out, "backup needs --to");
        node.backup(destination) catch |err| switch (err) {
            error.SqliteError => {
                try diagnostic.write(
                    err_out,
                    "backup failed",
                    node.lastSqliteMessage(),
                    "Choose a new path and verify its parent directory.",
                );
                return exit_sql;
            },
            else => return err,
        };
        try out.print("backup written to {s}\n", .{destination});
        return exit_ok;
    }
    if (std.mem.eql(u8, command, "integrity-check") or std.mem.eql(u8, command, "recover")) {
        const report = try node.integrityCheck();
        if (options.json) {
            try out.print(
                "{{\"sqlite_ok\":{},\"chain_ok\":{},\"payloads_ok\":{}}}\n",
                .{ report.sqlite_ok, report.chain_ok, report.payloads_ok },
            );
        } else {
            const pass = passFail(report.sqlite_ok);
            const chain_pass = passFail(report.chain_ok);
            const payload_pass = passFail(report.payloads_ok);
            try out.print(
                "sqlite: {s}\nchain: {s}\npayloads: {s}\n",
                .{ pass, chain_pass, payload_pass },
            );
            if (std.mem.eql(u8, command, "recover")) {
                try out.writeAll("recovery rebuild complete\n");
            }
        }
        return if (report.ok()) exit_ok else exit_integrity;
    }
    if (std.mem.eql(u8, command, "expire-sessions")) {
        const retain = options.retain orelse
            return usageError(err_out, "expire-sessions needs --retain");
        const result = try node.expireSessions(retain);
        try out.print("{d} session(s) expired\n", .{result.changes});
        return exit_ok;
    }
    return exit_usage;
}

/// Applies the public precedence contract: explicit CLI values are already in
/// `options`; environment values then override file values.
fn applyConfiguration(
    gpa: std.mem.Allocator,
    environ: *std.process.Environ.Map,
    file: ?*const configuration.File,
    options: *Options,
    err_out: *std.Io.Writer,
) !void {
    applyNetworkConfig(environ, file, options);
    try applySecurityConfig(environ, file, options, err_out);
    try applyPeersConfig(gpa, environ, file, options);
}

fn applyNetworkConfig(
    environ: *std.process.Environ.Map,
    file: ?*const configuration.File,
    options: *Options,
) void {
    if (options.data == null) {
        options.data = environ.get("ZAXON_DATA") orelse if (file) |v| v.data else null;
    }
    if (options.connect == null) {
        options.connect = environ.get("ZAXON_CONNECT") orelse
            if (file) |v| v.connect else null;
    }
    if (options.listen == null) {
        options.listen = environ.get("ZAXON_LISTEN") orelse if (file) |v| v.listen else null;
    }
    if (options.cluster_id == null) {
        options.cluster_id = environ.get("ZAXON_CLUSTER_ID") orelse
            if (file) |v| v.cluster_id else null;
    }
    if (options.sync == null) {
        options.sync = environ.get("ZAXON_SYNC") orelse if (file) |v| v.sync else null;
    }
}

fn applySecurityConfig(
    environ: *std.process.Environ.Map,
    file: ?*const configuration.File,
    options: *Options,
    err_out: *std.Io.Writer,
) !void {
    if (options.auth_file == null) {
        options.auth_file = environ.get("ZAXON_AUTH_FILE") orelse
            if (file) |v| v.auth_file else null;
    }
    if (options.tls_cert == null) {
        options.tls_cert = environ.get("ZAXON_TLS_CERT") orelse if (file) |v| v.tls_cert else null;
    }
    if (options.tls_key == null) {
        options.tls_key = environ.get("ZAXON_TLS_KEY") orelse if (file) |v| v.tls_key else null;
    }
    if (options.tls_ca == null) {
        options.tls_ca = environ.get("ZAXON_TLS_CA") orelse if (file) |v| v.tls_ca else null;
    }
    if (options.enrollment_ca_key == null) {
        options.enrollment_ca_key = environ.get("ZAXON_ENROLLMENT_CA_KEY") orelse
            if (file) |v| v.enrollment_ca_key else null;
    }
    if (options.revocation_file == null) {
        options.revocation_file = environ.get("ZAXON_REVOCATION_FILE") orelse
            if (file) |v| v.revocation_file else null;
    }
    if (options.node_id == null) {
        if (environ.get("ZAXON_NODE")) |text| {
            options.node_id = std.fmt.parseInt(u32, text, 10) catch {
                _ = try usageError(err_out, "ZAXON_NODE must be an integer");
                return error.InvalidEnvironment;
            };
        } else if (file) |v| {
            options.node_id = v.node;
        }
    }
    if (!options.role_set) {
        const role_text = environ.get("ZAXON_ROLE") orelse if (file) |v| v.role else null;
        if (role_text) |text| {
            options.role = Role.parse(text) catch {
                _ = try usageError(err_out, "ZAXON_ROLE/config role is unknown");
                return error.InvalidEnvironment;
            };
            options.role_set = true;
        }
    }
}

fn applyPeersConfig(
    gpa: std.mem.Allocator,
    environ: *std.process.Environ.Map,
    file: ?*const configuration.File,
    options: *Options,
) !void {
    if (options.peers.items.len == 0) {
        if (environ.get("ZAXON_PEER")) |text| {
            var iterator = std.mem.splitScalar(u8, text, ',');
            while (iterator.next()) |item| {
                const trimmed = std.mem.trim(u8, item, " \t\r\n");
                if (trimmed.len > 0) try options.peers.append(gpa, trimmed);
            }
        } else if (file) |value| {
            for (value.peers) |item| try options.peers.append(gpa, item);
        }
    }
    if (options.admins.items.len == 0) {
        if (file) |value| {
            for (value.admins) |item| try options.admins.append(gpa, item);
        }
    }
}

fn usageError(err_out: *std.Io.Writer, message: []const u8) !u8 {
    try diagnostic.write(
        err_out,
        "invalid command",
        message,
        "Run 'zaxon help' to see commands and required options.",
    );
    return exit_usage;
}

fn passFail(ok: bool) []const u8 {
    return if (ok) "pass" else "FAIL";
}

// ----------------------------------------------------------------------
// serve
// ----------------------------------------------------------------------

fn serveCommand(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: *Options,
    auth_secret: ?[]const u8,
    tls_config: ?tls.Config,
    err_out: *std.Io.Writer,
) !u8 {
    if (tls_config) |config| {
        configuration.validatePrivateFile(io, config.key_path) catch |err| {
            try diagnostic.write(
                err_out,
                "unsafe TLS private key",
                @errorName(err),
                "Use a regular, non-symlink key file with mode 0600.",
            );
            return exit_usage;
        };
    }
    const data = options.data orelse
        return usageError(err_out, "serve needs --data");
    const node_id = options.node_id orelse
        return usageError(err_out, "serve needs --node");
    const listen_text = options.listen orelse
        return usageError(err_out, "serve needs --listen");
    const listen = client.Endpoint.parse(listen_text) catch
        return usageError(err_out, "--listen must be host:port or unix:<path>");
    if (listen.unix_path != null) {
        if (options.role == .gateway) {
            return usageError(err_out, "gateway mode listens on TCP");
        }
        if (options.peers.items.len > 0) {
            return usageError(
                err_out,
                "unix socket service is single-node; peers need host:port",
            );
        }
    }

    var members: std.ArrayList(server.PeerAddress) = .empty;
    defer members.deinit(gpa);
    buildPeerMembers(gpa, options, node_id, listen, &members, err_out) catch |err| switch (err) {
        error.UsageError => return exit_usage,
        else => return err,
    };

    const database_id: ?u128 = if (members.items.len > 1)
        server.deriveDatabaseId(members.items, options.cluster_id)
    else
        null;

    if (options.role == .gateway) {
        if (options.dev_psk) {
            return usageError(err_out, "gateway mode does not terminate --dev-psk");
        }
        if (tls_config != null) {
            return usageError(
                err_out,
                "gateway mode passes TLS through; put --tls-* on clients " ++
                    "and storage nodes, not the gateway",
            );
        }
        if (options.enrollment_ca_key != null) {
            return usageError(
                err_out,
                "gateway mode cannot issue enrollment certificates",
            );
        }
        var backends: std.ArrayList(client.Endpoint) = .empty;
        defer backends.deinit(gpa);
        for (members.items) |member| {
            const capabilities = member.role.capabilities();
            if (member.id == node_id or
                (!capabilities.serves_reads and !capabilities.serves_writes))
            {
                continue;
            }
            try backends.append(gpa, .{ .host = member.host, .port = member.port });
        }
        return gateway.serve(gpa, io, .{
            .listen_host = listen.host,
            .listen_port = listen.port,
            .backends = backends.items,
        }, err_out);
    }

    if (options.segment_records) |records| {
        // Test-only journal geometry: segment-scale scenarios (rotation,
        // reclamation, beyond-retention transfer) shrink segments instead
        // of writing millions of rows. Never raised above the production
        // capacity the on-disk index is sized for.
        if (!options.enable_failpoints) {
            return usageError(
                err_out,
                "--segment-records is test-only; it requires --enable-failpoints",
            );
        }
        if (records < 64 or records > zaxonlite.segment.capacity_records) {
            return usageError(err_out, "--segment-records must be 64..16384");
        }
        zaxonlite.segment.rotation_records = records;
    }
    if ((options.test_storage_delay_ms != null or
        options.test_vote_delay_ms != null or
        options.test_anchor_interval_ms != null) and
        !options.enable_failpoints)
    {
        // Deterministic takeover scenarios stretch one node's barrier or
        // hold its votes so an inherited slot stays undecided for a known
        // window.
        return usageError(
            err_out,
            "test delay and anchor interval flags are test-only; " ++
                "they require --enable-failpoints",
        );
    }
    if (options.test_anchor_interval_ms) |milliseconds| {
        if (milliseconds == 0) {
            return usageError(err_out, "--test-anchor-interval-ms must be positive");
        }
        zaxonlite.Node.anchor_interval_ns =
            @as(i96, milliseconds) * std.time.ns_per_ms;
    }

    return server.serve(gpa, io, .{
        .directory = data,
        .node_id = node_id,
        .listen_host = listen.host,
        .listen_port = listen.port,
        .listen_unix = listen.unix_path,
        .members = members.items,
        .database_id = database_id,
        .auth_secret = auth_secret,
        .allow_psk_only_loopback = options.dev_psk,
        .tls = tls_config,
        .enrollment_ca_key = options.enrollment_ca_key,
        .revocation_file = options.revocation_file,
        .admin_principals = options.admins.items,
        .enable_failpoints = options.enable_failpoints,
        .allow_insecure_test_tcp = options.insecure_test_tcp,
        .test_faults = .{
            .storage_delay_ms = options.test_storage_delay_ms orelse 0,
            .vote_delay_ms = options.test_vote_delay_ms orelse 0,
        },
        .mmap_size = options.mmap_size orelse 0,
        .retention_slots = options.retention_slots orelse 0,
        .journal_cap_bytes = options.journal_cap_bytes orelse
            64 * 1024 * 1024 * 1024,
    }, err_out);
}

fn buildPeerMembers(
    gpa: std.mem.Allocator,
    options: *const Options,
    node_id: u32,
    listen: client.Endpoint,
    members: *std.ArrayList(server.PeerAddress),
    err_out: *std.Io.Writer,
) !void {
    try members.append(gpa, .{
        .id = node_id,
        .host = listen.host,
        .port = listen.port,
        .role = options.role,
    });
    for (options.peers.items) |peer_text| {
        const at = std.mem.indexOfScalar(u8, peer_text, '@') orelse {
            _ = try usageError(err_out, "--peer must be id@host:port");
            return error.UsageError;
        };
        const id = std.fmt.parseInt(u32, peer_text[0..at], 10) catch {
            _ = try usageError(err_out, "--peer must be id@host:port");
            return error.UsageError;
        };
        if (id == node_id) continue;
        const address_and_role = peer_text[at + 1 ..];
        const slash = std.mem.lastIndexOfScalar(u8, address_and_role, '/');
        const address = if (slash) |index| address_and_role[0..index] else address_and_role;
        const role = if (slash) |index|
            Role.parse(address_and_role[index + 1 ..]) catch {
                _ = try usageError(err_out, "--peer has an unknown role");
                return error.UsageError;
            }
        else
            Role.data_voter;
        const endpoint = client.Endpoint.parse(address) catch {
            _ = try usageError(err_out, "--peer must be id@host:port[/role]");
            return error.UsageError;
        };
        try members.append(gpa, .{
            .id = id,
            .host = endpoint.host,
            .port = endpoint.port,
            .role = role,
        });
    }
}

// ----------------------------------------------------------------------
// Client mode
// ----------------------------------------------------------------------

fn parseEndpoints(
    gpa: std.mem.Allocator,
    text: []const u8,
) !std.ArrayList(client.Endpoint) {
    var list: std.ArrayList(client.Endpoint) = .empty;
    errdefer list.deinit(gpa);
    var parts = std.mem.tokenizeScalar(u8, text, ',');
    while (parts.next()) |part| {
        try list.append(gpa, try client.Endpoint.parse(part));
    }
    if (list.items.len == 0) return error.InvalidEndpoint;
    return list;
}

fn remote(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: *std.process.Environ.Map,
    options: *Options,
    transport: client.Transport,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    var endpoints = parseEndpoints(gpa, options.connect.?) catch
        return usageError(
            err_out,
            "--connect entries must be host:port or unix:<path>",
        );
    defer endpoints.deinit(gpa);

    const command = options.command;
    if (std.mem.eql(u8, command, "sql")) {
        var cluster = client.ClusterConnection.init(
            gpa,
            io,
            endpoints.items,
            transport,
        );
        defer cluster.deinit();
        return cli_shell.run(gpa, io, environ, .{ .remote = &cluster }, .{
            .no_color = options.no_color,
            .no_history = options.no_history,
            .history_path = environ.get("ZAXON_HISTORY"),
        }, out, err_out);
    }
    if (std.mem.eql(u8, command, "backup")) {
        return remoteBackup(gpa, io, options, endpoints.items, transport, out, err_out);
    }

    var request: std.Io.Writer.Allocating = .init(gpa);
    defer request.deinit();
    const require_leader = buildRemoteRequestBody(
        command,
        options,
        &request.writer,
        err_out,
    ) catch |err| switch (err) {
        error.UsageError => return exit_usage,
        else => return err,
    };

    var cluster = client.ClusterConnection.init(
        gpa,
        io,
        endpoints.items,
        transport,
    );
    defer cluster.deinit();
    var result = cluster.call(request.written(), require_leader) catch {
        try cli_render.noLeaderDiagnostic(err_out, cluster.refused_leader_hint);
        return exit_unavailable;
    };
    defer {
        if (std.mem.eql(u8, command, "enroll-token")) @memset(result.body, 0);
        result.deinit(gpa);
    }
    if (std.mem.eql(u8, command, "enroll-token")) {
        return saveEnrollmentBundle(
            gpa,
            io,
            options,
            result,
            out,
            err_out,
        );
    }
    return cli_render.renderRemote(
        gpa,
        options.command,
        options.json,
        result.body,
        out,
        err_out,
    );
}

fn remoteBackup(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: *Options,
    endpoint_list: []const client.Endpoint,
    transport: client.Transport,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const destination = options.to orelse return usageError(err_out, "backup needs --to");
    var probe_cluster = client.ClusterConnection.init(gpa, io, endpoint_list, transport);
    defer probe_cluster.deinit();
    var probe = probe_cluster.call("{\"op\":\"query\",\"sql\":\"select 1\"}", true) catch {
        try cli_render.noLeaderDiagnostic(err_out, probe_cluster.refused_leader_hint);
        return exit_unavailable;
    };
    defer probe.deinit(gpa);
    const connection = client.Connection.openWithTransport(
        gpa,
        io,
        probe.endpoint,
        transport,
    ) catch {
        try diagnostic.write(
            err_out,
            "backup interrupted",
            "The selected leader became unavailable.",
            "Retry against the endpoint list; the destination was not installed.",
        );
        return exit_unavailable;
    };
    defer connection.close();
    connection.backupTo(destination) catch |err| {
        try diagnostic.write(
            err_out,
            "remote backup failed",
            @errorName(err),
            "Check the destination, cluster health, and transport logs.",
        );
        return exit_unavailable;
    };
    if (options.json) {
        try out.writeAll("{\"ok\":true}\n");
    } else {
        try out.print("backup written to {s}\n", .{destination});
    }
    return exit_ok;
}

fn buildRemoteRequestBody(
    command: []const u8,
    options: *const Options,
    writer: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !bool {
    if (std.mem.eql(u8, command, "exec")) {
        const sql = options.sql orelse {
            _ = try usageError(err_out, "exec needs --sql");
            return error.UsageError;
        };
        if ((options.session == null) != (options.sequence == null)) {
            _ = try usageError(err_out, "--session and --sequence go together");
            return error.UsageError;
        }
        try writer.writeAll("{\"op\":\"exec\",\"sql\":");
        try cli_render.writeJsonString(writer, sql);
        if (options.session) |session| {
            try writer.print(",\"session\":{d},\"sequence\":{d}", .{ session, options.sequence.? });
        }
        try writer.writeAll("}");
        return true;
    }
    if (std.mem.eql(u8, command, "query")) {
        const sql = options.sql orelse {
            _ = try usageError(err_out, "query needs --sql");
            return error.UsageError;
        };
        const level = options.level orelse "linearizable";
        const require_leader = !std.mem.eql(u8, level, "any");
        try writer.writeAll("{\"op\":\"query\",\"sql\":");
        try cli_render.writeJsonString(writer, sql);
        try writer.print(",\"level\":\"{s}\"", .{level});
        if (options.freshness_ms) |freshness| {
            try writer.print(",\"freshness_ms\":{d}", .{freshness});
        }
        try writer.writeAll("}");
        return require_leader;
    }
    if (std.mem.eql(u8, command, "status")) {
        try writer.writeAll("{\"op\":\"status\"}");
        return false;
    }
    if (std.mem.eql(u8, command, "members")) {
        try writer.writeAll("{\"op\":\"members\"}");
        return false;
    }
    if (std.mem.eql(u8, command, "leader")) {
        try writer.writeAll("{\"op\":\"leader\"}");
        return false;
    }
    if (std.mem.eql(u8, command, "session")) {
        try writer.writeAll("{\"op\":\"session\"}");
        return true;
    }
    if (std.mem.eql(u8, command, "wait")) {
        try writer.print(
            "{{\"op\":\"wait\",\"applied\":{d},\"leader\":{},\"timeout_ms\":{d}}}",
            .{ options.applied orelse 0, options.wait_leader, options.timeout_ms orelse 10_000 },
        );
        return false;
    }
    if (std.mem.eql(u8, command, "anchor")) {
        try writer.writeAll("{\"op\":\"anchor\"}");
        return true;
    }
    if (std.mem.eql(u8, command, "integrity-check")) {
        try writer.writeAll("{\"op\":\"integrity\"}");
        return false;
    }
    if (std.mem.eql(u8, command, "expire-sessions")) {
        const retain = options.retain orelse {
            _ = try usageError(err_out, "expire-sessions needs --retain");
            return error.UsageError;
        };
        try writer.print("{{\"op\":\"expire-sessions\",\"retain\":{d}}}", .{retain});
        return true;
    }
    if (std.mem.eql(u8, command, "enroll-token")) {
        return buildRemoteEnrollTokenBody(options, writer, err_out);
    }
    if (std.mem.eql(u8, command, "membership")) {
        try writer.writeAll("{\"op\":\"membership\"}");
        return false;
    }
    if (std.mem.eql(u8, command, "replace-voter")) {
        return buildRemoteReplaceVoterBody(options, writer, err_out);
    }
    if (std.mem.eql(u8, command, "stop")) {
        try writer.writeAll("{\"op\":\"stop\"}");
        return false;
    }

    try diagnostic.write(
        err_out,
        "unsupported client command",
        command,
        "Use --data for this operation or select a remote-capable command.",
    );
    return error.UsageError;
}

fn buildRemoteReplaceVoterBody(
    options: *const Options,
    writer: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !bool {
    const operation = options.operation orelse {
        _ = try usageError(err_out, "replace-voter needs --operation");
        return error.UsageError;
    };
    const expected_config = options.expected_config orelse {
        _ = try usageError(err_out, "replace-voter needs --expected-config");
        return error.UsageError;
    };
    const old_node = options.old_node orelse {
        _ = try usageError(err_out, "replace-voter needs --old-node");
        return error.UsageError;
    };
    const new_node_spec = options.new_node orelse {
        _ = try usageError(err_out, "replace-voter needs --new-node <id>@<host>:<port>");
        return error.UsageError;
    };
    const at = std.mem.indexOfScalar(u8, new_node_spec, '@') orelse {
        _ = try usageError(err_out, "--new-node must be <id>@<host>:<port>");
        return error.UsageError;
    };
    const new_node = std.fmt.parseInt(u32, new_node_spec[0..at], 10) catch {
        _ = try usageError(err_out, "--new-node must be <id>@<host>:<port>");
        return error.UsageError;
    };
    const endpoint = new_node_spec[at + 1 ..];
    if (endpoint.len == 0 or new_node == 0) {
        _ = try usageError(err_out, "--new-node must be <id>@<host>:<port>");
        return error.UsageError;
    }
    try writer.print(
        "{{\"op\":\"replace-voter\",\"operation\":{d},\"expected_config\":{d}," ++
            "\"old_node\":{d},\"new_node\":{d},\"endpoint\":",
        .{ operation, expected_config, old_node, new_node },
    );
    try cli_render.writeJsonString(writer, endpoint);
    try writer.writeAll("}");
    return true;
}

fn buildRemoteEnrollTokenBody(
    options: *const Options,
    writer: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !bool {
    const node_id = options.node_id orelse {
        _ = try usageError(err_out, "enroll-token needs --node");
        return error.UsageError;
    };
    const ttl_seconds = options.ttl_seconds orelse enrollment.default_ttl_seconds;
    if (ttl_seconds == 0 or ttl_seconds > enrollment.maximum_ttl_seconds) {
        _ = try usageError(err_out, "--ttl-seconds must be between 1 and 86400");
        return error.UsageError;
    }
    if (options.to == null) {
        _ = try usageError(err_out, "enroll-token needs --to");
        return error.UsageError;
    }
    if (options.tls_ca == null) {
        _ = try usageError(err_out, "enroll-token requires --tls-ca");
        return error.UsageError;
    }
    try writer.print(
        "{{\"op\":\"issue-enrollment-token\",\"node_id\":{d},\"ttl_seconds\":{d}}}",
        .{ node_id, ttl_seconds },
    );
    return false;
}

fn saveEnrollmentBundle(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: *const Options,
    result: client.CallResult,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const ca_pem = std.Io.Dir.cwd().readFileAlloc(
        io,
        options.tls_ca.?,
        gpa,
        .limited(enrollment.maximum_ca_bytes + 1),
    ) catch |err| {
        try diagnostic.write(
            err_out,
            "cluster CA unreadable",
            @errorName(err),
            "Keep the CA certificate used by the authenticated issuer available.",
        );
        return exit_usage;
    };
    defer gpa.free(ca_pem);

    const endpoint = try std.fmt.allocPrint(
        gpa,
        "{s}:{d}",
        .{ result.endpoint.host, result.endpoint.port },
    );
    defer gpa.free(endpoint);

    const bundle = parseEnrollmentBundle(
        gpa,
        result,
        ca_pem,
        endpoint,
        err_out,
    ) catch |err| switch (err) {
        error.Unavailable => return exit_unavailable,
        else => return err,
    };

    const encoded = bundle.encodeAlloc(gpa) catch |err| {
        try diagnostic.write(
            err_out,
            "invalid enrollment response",
            @errorName(err),
            "Preserve the issuer log and retry with a new token.",
        );
        return exit_unavailable;
    };
    defer {
        @memset(encoded, 0);
        gpa.free(encoded);
    }
    enrollment.writeBundleFile(io, options.to.?, encoded) catch |err| {
        try diagnostic.write(
            err_out,
            "token bundle not written",
            @errorName(err),
            "Choose a new path whose parent exists; existing files are never overwritten.",
        );
        return exit_unavailable;
    };
    if (options.json) {
        try out.print(
            "{{\"ok\":true,\"path\":\"{s}\",\"node_id\":{d},\"expires_unix_seconds\":{d}}}\n",
            .{ options.to.?, bundle.node_id, bundle.expires_unix_seconds },
        );
    } else {
        try out.print(
            "enrollment token bundle written to {s} (node {d})\n",
            .{ options.to.?, bundle.node_id },
        );
    }
    return exit_ok;
}

fn parseEnrollmentBundle(
    gpa: std.mem.Allocator,
    result: client.CallResult,
    ca_pem: []const u8,
    endpoint: []const u8,
    err_out: *std.Io.Writer,
) !enrollment.Bundle {
    const Response = struct {
        ok: bool = false,
        node_id: u32 = 0,
        issuer_node_id: u32 = 0,
        database_id: []const u8 = "",
        expires_unix_seconds: u64 = 0,
        token: []const u8 = "",
        @"error": ?[]const u8 = null,
        message: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(Response, gpa, result.body, .{
        .ignore_unknown_fields = true,
    }) catch {
        try cli_render.malformedResponseDiagnostic(err_out);
        return error.Unavailable;
    };
    defer parsed.deinit();
    const response = parsed.value;
    if (!response.ok) {
        try diagnostic.write(
            err_out,
            response.@"error" orelse "enrollment_unavailable",
            response.message orelse "token issuance failed",
            "Connect with an existing mTLS identity to a configured issuer node.",
        );
        return error.Unavailable;
    }
    if (response.node_id == 0 or response.issuer_node_id == 0 or
        response.database_id.len != 32 or response.token.len != 64 or
        response.expires_unix_seconds == 0 or result.endpoint.unix_path != null)
    {
        try cli_render.malformedResponseDiagnostic(err_out);
        return error.Unavailable;
    }
    var secret: [enrollment.token_bytes]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret, response.token) catch {
        try cli_render.malformedResponseDiagnostic(err_out);
        return error.Unavailable;
    };
    const database_id = std.fmt.parseInt(u128, response.database_id, 16) catch {
        try cli_render.malformedResponseDiagnostic(err_out);
        return error.Unavailable;
    };
    return .{
        .node_id = response.node_id,
        .issuer_node_id = response.issuer_node_id,
        .database_id = database_id,
        .expires_unix_seconds = response.expires_unix_seconds,
        .secret = secret,
        .endpoint = endpoint,
        .ca_pem = ca_pem,
    };
}

fn enrollCommand(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: *const Options,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const token_path = options.token_file orelse
        return usageError(err_out, "enroll needs --token-file");
    const identity_dir = options.identity_dir orelse
        return usageError(err_out, "enroll needs --identity-dir");
    const bundle_bytes = enrollment.readBundleFile(gpa, io, token_path) catch |err| {
        try diagnostic.write(
            err_out,
            "enrollment token unreadable",
            @errorName(err),
            "Use the owner-only opaque bundle produced by enroll-token.",
        );
        return exit_usage;
    };
    defer {
        @memset(bundle_bytes, 0);
        gpa.free(bundle_bytes);
    }
    const bundle = enrollment.Bundle.decode(bundle_bytes) catch |err| {
        try diagnostic.write(
            err_out,
            "enrollment token invalid",
            @errorName(err),
            "Request a new enrollment token from a configured issuer.",
        );
        return exit_usage;
    };
    var identity = enrollment.requestCertificate(gpa, io, bundle) catch |err| {
        try diagnostic.write(
            err_out,
            "enrollment refused",
            @errorName(err),
            "Check expiry, target node ID, issuer reachability, and request a new token.",
        );
        return exit_unavailable;
    };
    defer identity.deinit(gpa);
    enrollment.installIdentity(io, identity_dir, &identity, bundle.ca_pem) catch |err| {
        try diagnostic.write(
            err_out,
            "identity installation failed",
            @errorName(err),
            "Token consumed. Preserve error, remove no existing identity, and request new token.",
        );
        return exit_unavailable;
    };
    enrollment.removeBundleFile(io, token_path) catch {};
    // A joining replacement records the decided database identity and
    // registry digest beside its future durable state, so its first start
    // adopts the cluster's identity instead of deriving one from flags.
    if (options.data) |data| {
        zaxonlite.node.writeJoinDescriptor(io, data, .{
            .database_id = bundle.database_id,
            .configuration_id = identity.configuration_id,
            .registry_digest = identity.registry_digest,
        }) catch |err| {
            try diagnostic.write(
                err_out,
                "join descriptor write failed",
                @errorName(err),
                "Check the --data directory before starting the node.",
            );
            return exit_unavailable;
        };
    }
    if (options.json) {
        try out.print(
            "{{\"ok\":true,\"node_id\":{d},\"identity_dir\":\"{s}\"}}\n",
            .{ bundle.node_id, identity_dir },
        );
    } else {
        try out.print(
            "node {d} enrolled; identity installed in {s}\n",
            .{ bundle.node_id, identity_dir },
        );
    }
    return exit_ok;
}

fn optError(err_out: *std.Io.Writer, msg: []const u8) !?u8 {
    try diagnostic.write(err_out, "invalid options", msg, "Run 'zaxon help' to list options.");
    return exit_usage;
}

fn parseOptions(
    gpa: std.mem.Allocator,
    iterator: *std.process.Args.Iterator,
    options: *Options,
    err_out: *std.Io.Writer,
    out: *std.Io.Writer,
) !?u8 {
    while (iterator.next()) |arg| {
        if (try parseOptionFlag(gpa, iterator, options, arg, err_out, out)) |code| {
            return code;
        }
    }
    return null;
}

fn parseOptionFlag(
    gpa: std.mem.Allocator,
    iterator: *std.process.Args.Iterator,
    options: *Options,
    arg: []const u8,
    err_out: *std.Io.Writer,
    out: *std.Io.Writer,
) !?u8 {
    if (std.mem.eql(u8, arg, "--config")) {
        options.config = iterator.next() orelse
            return optError(err_out, "--config needs a value");
    } else if (std.mem.eql(u8, arg, "--data")) {
        options.data = iterator.next() orelse
            return optError(err_out, "--data needs a value");
    } else if (std.mem.eql(u8, arg, "--connect")) {
        options.connect = iterator.next() orelse
            return optError(err_out, "--connect needs a value");
    } else if (std.mem.eql(u8, arg, "--sql")) {
        options.sql = iterator.next() orelse
            return optError(err_out, "--sql needs a value");
    } else if (std.mem.eql(u8, arg, "--session")) {
        const text = iterator.next() orelse
            return optError(err_out, "--session needs a value");
        options.session = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--session must be an integer");
    } else if (std.mem.eql(u8, arg, "--sequence")) {
        const text = iterator.next() orelse
            return optError(err_out, "--sequence needs a value");
        options.sequence = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--sequence must be an integer");
    } else if (std.mem.eql(u8, arg, "--level")) {
        options.level = iterator.next() orelse
            return optError(err_out, "--level needs a value");
    } else if (std.mem.eql(u8, arg, "--freshness-ms")) {
        const text = iterator.next() orelse
            return optError(err_out, "--freshness-ms needs a value");
        options.freshness_ms = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--freshness-ms must be an integer");
    } else if (std.mem.eql(u8, arg, "--to")) {
        options.to = iterator.next() orelse
            return optError(err_out, "--to needs a value");
    } else if (std.mem.eql(u8, arg, "--retain")) {
        const text = iterator.next() orelse
            return optError(err_out, "--retain needs a value");
        options.retain = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--retain must be an integer");
    } else if (std.mem.eql(u8, arg, "--applied")) {
        const text = iterator.next() orelse
            return optError(err_out, "--applied needs a value");
        options.applied = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--applied must be an integer");
    } else if (std.mem.eql(u8, arg, "--leader")) {
        options.wait_leader = true;
    } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
        const text = iterator.next() orelse
            return optError(err_out, "--timeout-ms needs a value");
        options.timeout_ms = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--timeout-ms must be an integer");
    } else if (std.mem.eql(u8, arg, "--node")) {
        const text = iterator.next() orelse
            return optError(err_out, "--node needs a value");
        options.node_id = std.fmt.parseInt(u32, text, 10) catch
            return optError(err_out, "--node must be an integer");
    } else if (std.mem.eql(u8, arg, "--listen")) {
        options.listen = iterator.next() orelse
            return optError(err_out, "--listen needs a value");
    } else if (std.mem.eql(u8, arg, "--role")) {
        const text = iterator.next() orelse
            return optError(err_out, "--role needs a value");
        options.role = Role.parse(text) catch
            return optError(err_out, "--role is not a known node role");
        options.role_set = true;
    } else if (std.mem.eql(u8, arg, "--peer")) {
        const text = iterator.next() orelse
            return optError(err_out, "--peer needs a value");
        try options.peers.append(gpa, text);
    } else if (std.mem.eql(u8, arg, "--admin")) {
        const text = iterator.next() orelse
            return optError(err_out, "--admin needs a value");
        try options.admins.append(gpa, text);
    } else if (std.mem.eql(u8, arg, "--cluster-id")) {
        options.cluster_id = iterator.next() orelse
            return optError(err_out, "--cluster-id needs a value");
    } else if (std.mem.eql(u8, arg, "--auth-file")) {
        options.auth_file = iterator.next() orelse
            return optError(err_out, "--auth-file needs a value");
    } else if (std.mem.eql(u8, arg, "--tls-cert")) {
        options.tls_cert = iterator.next() orelse
            return optError(err_out, "--tls-cert needs a value");
    } else if (std.mem.eql(u8, arg, "--tls-key")) {
        options.tls_key = iterator.next() orelse
            return optError(err_out, "--tls-key needs a value");
    } else if (std.mem.eql(u8, arg, "--tls-ca")) {
        options.tls_ca = iterator.next() orelse
            return optError(err_out, "--tls-ca needs a value");
    } else if (std.mem.eql(u8, arg, "--enrollment-ca-key")) {
        options.enrollment_ca_key = iterator.next() orelse
            return optError(err_out, "--enrollment-ca-key needs a value");
    } else if (std.mem.eql(u8, arg, "--token-file")) {
        options.token_file = iterator.next() orelse
            return optError(err_out, "--token-file needs a value");
    } else if (std.mem.eql(u8, arg, "--identity-dir")) {
        options.identity_dir = iterator.next() orelse
            return optError(err_out, "--identity-dir needs a value");
    } else if (std.mem.eql(u8, arg, "--ttl-seconds")) {
        const text = iterator.next() orelse
            return optError(err_out, "--ttl-seconds needs a value");
        options.ttl_seconds = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--ttl-seconds must be an integer");
    } else if (std.mem.eql(u8, arg, "--operation")) {
        const text = iterator.next() orelse
            return optError(err_out, "--operation needs a value");
        options.operation = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--operation must be an integer");
    } else if (std.mem.eql(u8, arg, "--expected-config")) {
        const text = iterator.next() orelse
            return optError(err_out, "--expected-config needs a value");
        options.expected_config = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--expected-config must be an integer");
    } else if (std.mem.eql(u8, arg, "--old-node")) {
        const text = iterator.next() orelse
            return optError(err_out, "--old-node needs a value");
        options.old_node = std.fmt.parseInt(u32, text, 10) catch
            return optError(err_out, "--old-node must be an integer");
    } else if (std.mem.eql(u8, arg, "--new-node")) {
        options.new_node = iterator.next() orelse
            return optError(err_out, "--new-node needs a value");
    } else if (std.mem.eql(u8, arg, "--revocation-file")) {
        options.revocation_file = iterator.next() orelse
            return optError(err_out, "--revocation-file needs a value");
    } else if (std.mem.eql(u8, arg, "--sync")) {
        options.sync = iterator.next() orelse return optError(err_out, "--sync needs a value");
    } else if (std.mem.eql(u8, arg, "--mmap-size")) {
        const text = iterator.next() orelse
            return optError(err_out, "--mmap-size needs a value");
        options.mmap_size = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--mmap-size must be an integer byte count");
    } else if (std.mem.eql(u8, arg, "--retention-slots")) {
        const text = iterator.next() orelse
            return optError(err_out, "--retention-slots needs a value");
        options.retention_slots = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--retention-slots must be an integer");
    } else if (std.mem.eql(u8, arg, "--journal-cap-bytes")) {
        const text = iterator.next() orelse
            return optError(err_out, "--journal-cap-bytes needs a value");
        options.journal_cap_bytes = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--journal-cap-bytes must be an integer");
    } else if (std.mem.eql(u8, arg, "--segment-records")) {
        const text = iterator.next() orelse
            return optError(err_out, "--segment-records needs a value");
        options.segment_records = std.fmt.parseInt(usize, text, 10) catch
            return optError(err_out, "--segment-records must be an integer");
    } else if (std.mem.eql(u8, arg, "--test-storage-delay-ms")) {
        const text = iterator.next() orelse
            return optError(err_out, "--test-storage-delay-ms needs a value");
        options.test_storage_delay_ms = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--test-storage-delay-ms must be an integer");
    } else if (std.mem.eql(u8, arg, "--test-vote-delay-ms")) {
        const text = iterator.next() orelse
            return optError(err_out, "--test-vote-delay-ms needs a value");
        options.test_vote_delay_ms = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--test-vote-delay-ms must be an integer");
    } else if (std.mem.eql(u8, arg, "--test-anchor-interval-ms")) {
        const text = iterator.next() orelse
            return optError(err_out, "--test-anchor-interval-ms needs a value");
        options.test_anchor_interval_ms = std.fmt.parseInt(u64, text, 10) catch
            return optError(err_out, "--test-anchor-interval-ms must be an integer");
    } else if (std.mem.eql(u8, arg, "--enable-failpoints")) {
        options.enable_failpoints = true;
    } else if (std.mem.eql(u8, arg, "--dev-psk")) {
        options.dev_psk = true;
    } else if (std.mem.eql(u8, arg, "--insecure-test-tcp")) {
        options.insecure_test_tcp = true;
    } else if (std.mem.eql(u8, arg, "--json")) {
        options.json = true;
    } else if (std.mem.eql(u8, arg, "--no-color")) {
        options.no_color = true;
    } else if (std.mem.eql(u8, arg, "--no-history")) {
        options.no_history = true;
    } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
        try out.writeAll(usage_text);
        return exit_ok;
    } else {
        return optError(err_out, "unknown option");
    }
    return null;
}
