//! Shared CLI result rendering (ZDS 0005, M1).
//!
//! One renderer serves the one-shot commands and both shells, replacing the
//! duplicated table writers that previously lived in `main.zig`. The plain
//! writers here are the byte-exact legacy formats used by scripts and the
//! CLI contract test; the rich formats live in `zaxon_cli_ui`.

const std = @import("std");
const zaxonlite = @import("zaxonlite");
const ui = @import("zaxon_cli_ui");

const client = zaxonlite.client;
const diagnostic = zaxonlite.diagnostic;

pub const exit_ok: u8 = 0;
pub const exit_sql: u8 = 1;
pub const exit_usage: u8 = 2;
pub const exit_integrity: u8 = 3;
pub const exit_unavailable: u8 = 4;

/// The neutral result view and its plain writers now live in the shared
/// `zaxon_cli_ui` module; re-exported here so callers keep one import.
pub const View = ui.view.View;
pub const writePlainTable = ui.view.writePlainTable;
pub const writeJsonResult = ui.view.writeJsonResult;
pub const writeJsonString = ui.view.writeJsonString;

pub fn viewOf(result: *const zaxonlite.QueryResult) View {
    return .{ .columns = result.columns, .rows = result.rows };
}

pub fn printStatus(node: *zaxonlite.Node, json: bool, out: *std.Io.Writer) !void {
    const status = node.status();
    if (json) return printStatusJson(status, out);
    return printStatusPlain(status, out);
}

fn printStatusJson(status: zaxonlite.node.Status, out: *std.Io.Writer) !void {
    const chain_hex = std.fmt.bytesToHex(status.chain, .lower);
    const history_hex = std.fmt.bytesToHex(status.history, .lower);
    try out.print(
        "{{\"node_id\":{d},\"database_id\":\"{x:0>32}\"," ++
            "\"configuration_id\":{d},\"role\":\"{s}\"," ++
            "\"node_type\":\"{s}\",\"leader\":{?d}," ++
            "\"decided_slot\":{d},\"applied_slot\":{d}," ++
            "\"durable_state_slot\":{d},\"memory_floor\":{d}," ++
            "\"trim_decision_slot\":{d},\"chosen_trim_slot\":{d}," ++
            "\"trim_ignored\":{d},\"retained_first_slot\":{d}," ++
            "\"journal_records\":{d},\"journal_segment_count\":{d}," ++
            "\"journal_bytes\":{d}," ++
            "\"chain\":\"{s}\",\"history\":\"{s}\",\"page_size\":{d}," ++
            "\"fts5_enabled\":{},\"sqlite_vec_version\":\"{s}\"," ++
            "\"search_feature_version\":{d},\"simd_backend\":\"{s}\"," ++
            "\"mmap_size\":{d},\"candidate_hard_limit\":{d}}}\n",
        .{
            status.node_id,                status.database_id,
            status.configuration_id,       status.role,
            status.node_type,              status.leader,
            status.decided_slot,           status.applied_slot,
            status.durable_state_slot,     status.memory_floor,
            status.trim_decision_slot,     status.chosen_trim_slot,
            status.trim_ignored,           status.retained_first_slot,
            status.journal_records,        status.journal_segment_count,
            status.journal_bytes,          &chain_hex,
            &history_hex,                  status.page_size,
            status.fts5_enabled,           status.sqlite_vec_version,
            status.search_feature_version, status.simd_backend,
            status.mmap_size,              status.candidate_hard_limit,
        },
    );
}

fn printStatusPlain(status: zaxonlite.node.Status, out: *std.Io.Writer) !void {
    const chain_hex = std.fmt.bytesToHex(status.chain, .lower);
    try out.print(
        \\node id:          {d}
        \\database id:      {x:0>32}
        \\configuration id: {d}
        \\role:             {s}
        \\node type:        {s}
        \\decided slot:     {d}
        \\applied slot:     {d}
        \\durable slot:     {d}
        \\memory floor:     {d}
        \\trim decision:    {d}
        \\trimmed through:  {d}
        \\trims ignored:    {d}
        \\retained first:   {d}
        \\journal records:  {d}
        \\journal segments: {d}
        \\journal bytes:    {d}
        \\chain:            {s}
        \\page size:        {d}
        \\fts5:             {s}
        \\sqlite-vec:       {s}
        \\search feature:   {d}
        \\simd backend:     {s}
        \\mmap size:        {d}
        \\candidate limit:  {d}
        \\
    , .{
        status.node_id,
        status.database_id,
        status.configuration_id,
        status.role,
        status.node_type,
        status.decided_slot,
        status.applied_slot,
        status.durable_state_slot,
        status.memory_floor,
        status.trim_decision_slot,
        status.chosen_trim_slot,
        status.trim_ignored,
        status.retained_first_slot,
        status.journal_records,
        status.journal_segment_count,
        status.journal_bytes,
        &chain_hex,
        status.page_size,
        if (status.fts5_enabled) "enabled" else "missing",
        status.sqlite_vec_version,
        status.search_feature_version,
        status.simd_backend,
        status.mmap_size,
        status.candidate_hard_limit,
    });
}

const remote_hints = [_]struct { code: []const u8, hint: []const u8 }{
    .{
        .code = "not_leader",
        .hint = "Retry the advertised leader or restore a voter quorum.",
    },
    .{
        .code = "retry",
        .hint = "Retry the same request shortly; the leader is still catching up or changed.",
    },
    .{
        .code = "timeout",
        .hint = "Retry; a queued timeout never executed, otherwise use an idempotent session.",
    },
    .{
        .code = "ambiguous",
        .hint = "Retry through an idempotent session so an applied write is not repeated.",
    },
    .{
        .code = "unavailable",
        .hint = "Retry another member and read this node's log for the failure.",
    },
    .{
        .code = "stale",
        .hint = "Wait for learner catch-up, relax freshness, or query the leader.",
    },
    .{
        .code = "sql",
        .hint = "Correct the SQL statement; use exec for statements that write.",
    },
    .{
        .code = "session",
        .hint = "Retry only the latest sequence in the same unexpired session.",
    },
    .{
        .code = "stale_configuration",
        .hint = "Read membership status and retry with its configuration ID.",
    },
    .{
        .code = "unknown_voter",
        .hint = "Read membership status and choose one listed data voter.",
    },
    .{
        .code = "node_id_not_fresh",
        .hint = "Choose a node ID above highest_allocated_node_id.",
    },
    .{
        .code = "node_id_exhausted",
        .hint = "No further voter replacement is safe for this database.",
    },
    .{
        .code = "operation_id_exhausted",
        .hint = "No further voter replacement is safe for this database.",
    },
    .{
        .code = "configuration_id_exhausted",
        .hint = "No further voter replacement is safe for this database.",
    },
    .{
        .code = "invalid_endpoint",
        .hint = "Use a printable host:port endpoint within the documented length bound.",
    },
    .{
        .code = "endpoint_in_use",
        .hint = "Choose an endpoint that is not assigned to a current node.",
    },
    .{
        .code = "too_few_voters",
        .hint = "Restore at least three healthy voters before replacing one.",
    },
    .{
        .code = "operation_conflict",
        .hint = "Reuse the exact original arguments or submit a newer operation ID.",
    },
    .{
        .code = "operation_pending",
        .hint = "Query membership status and wait for the pending operation to finish.",
    },
    .{
        .code = "operation_history_expired",
        .hint = "Read membership status, then submit a new operation ID.",
    },
    .{
        .code = "corrupt_pending_operation",
        .hint = "Stop the node and restore its membership metadata from a verified backup.",
    },
    .{
        .code = "replacement_busy",
        .hint = "Wait for the current write to finish, then retry the same operation.",
    },
    .{
        .code = "storage_failed",
        .hint = "Repair durable storage and restart the node before retrying.",
    },
    .{
        .code = "local_node_failed",
        .hint = "Replace or repair this local member; inspect its first-failure diagnostic.",
    },
    .{
        .code = "no_registry",
        .hint = "Run voter replacement only on a registry-backed network cluster.",
    },
    .{
        .code = "role_cannot_write",
        .hint = "Retry the data-voter leader advertised by node status.",
    },
};

pub fn remoteHint(code: []const u8) []const u8 {
    for (remote_hints) |entry| {
        if (std.mem.eql(u8, entry.code, code)) return entry.hint;
    }
    return "Inspect node status and retry only when the reported condition is resolved.";
}

test "replacement errors have specific operator hints" {
    const codes = [_][]const u8{
        "retry",
        "timeout",
        "ambiguous",
        "unavailable",
        "local_node_failed",
        "stale_configuration",
        "node_id_not_fresh",
        "operation_conflict",
        "operation_pending",
        "corrupt_pending_operation",
    };
    const fallback = remoteHint("unknown");
    for (codes) |code| {
        try std.testing.expect(!std.mem.eql(u8, remoteHint(code), fallback));
    }
}

pub fn noLeaderDiagnostic(
    err_out: *std.Io.Writer,
    refused: ?client.RefusedLeaderHint,
) !void {
    if (refused) |hint| {
        var message_buffer: [320]u8 = undefined;
        var hint_buffer: [320]u8 = undefined;
        const message = std.fmt.bufPrint(
            &message_buffer,
            "The cluster advertised leader node {d} at {s}:{d}, but " ++
                "without mTLS the client cannot verify a redirect " ++
                "target's identity and only contacts --connect endpoints.",
            .{ hint.node_id, hint.host(), hint.port },
        ) catch unreachable;
        const advice = std.fmt.bufPrint(
            &hint_buffer,
            "Add {s}:{d} to --connect (list every member), or use mTLS " ++
                "so redirects are followed with identity pinning.",
            .{ hint.host(), hint.port },
        ) catch unreachable;
        return diagnostic.write(
            err_out,
            "leader redirect refused",
            message,
            advice,
        );
    }
    try diagnostic.write(
        err_out,
        "no reachable leader",
        "No seed endpoint or authenticated leader redirect could complete " ++
            "this leader-only request.",
        "Restore a voter quorum and verify credentials. With --dev-psk, " ++
            "include every cluster member in --connect.",
    );
}

pub fn malformedResponseDiagnostic(err_out: *std.Io.Writer) !void {
    try diagnostic.write(
        err_out,
        "malformed response",
        "The peer returned a body outside the Zaxonlite JSON contract.",
        "Check protocol versions and preserve the peer log for diagnosis.",
    );
}

/// Prints a remote response body for `command`. `json` passes the raw
/// response through; otherwise a human summary is rendered per command.
pub fn renderRemote(
    gpa: std.mem.Allocator,
    command: []const u8,
    json: bool,
    body: []const u8,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, body, .{}) catch {
        try malformedResponseDiagnostic(err_out);
        return exit_unavailable;
    };
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |*obj| obj,
        else => {
            try malformedResponseDiagnostic(err_out);
            return exit_unavailable;
        },
    };

    const ok = blk: {
        const value = object.get("ok") orelse break :blk false;
        break :blk value == .bool and value.bool;
    };
    if (!ok) return renderRemoteError(command, json, body, object, out, err_out);

    if (json) {
        try out.print("{s}\n", .{body});
        return exit_ok;
    }
    return renderRemoteSuccess(command, body, object, out);
}

fn renderRemoteError(
    command: []const u8,
    json: bool,
    body: []const u8,
    object: *const std.json.ObjectMap,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const code = blk: {
        const value = object.get("error") orelse break :blk "unknown";
        break :blk if (value == .string) value.string else "unknown";
    };
    const message = blk: {
        const value = object.get("message") orelse break :blk "";
        break :blk if (value == .string) value.string else "";
    };
    if (std.mem.eql(u8, command, "integrity-check") and object.get("sqlite_ok") != null) {
        if (json) {
            try out.print("{s}\n", .{body});
        } else {
            try out.writeAll("integrity: FAIL\n");
        }
        return exit_integrity;
    }
    if (json) {
        try out.print("{s}\n", .{body});
    } else {
        try diagnostic.write(err_out, code, message, remoteHint(code));
    }
    if (std.mem.eql(u8, code, "sql") or std.mem.eql(u8, code, "session")) return exit_sql;
    if (std.mem.eql(u8, code, "bad_request")) return exit_usage;
    return exit_unavailable;
}

fn renderRemoteSuccess(
    command: []const u8,
    body: []const u8,
    object: *const std.json.ObjectMap,
    out: *std.Io.Writer,
) !u8 {
    if (std.mem.eql(u8, command, "exec")) {
        const changes = jsonInt(object.get("changes")) orelse 0;
        const replayed = blk: {
            const value = object.get("replayed") orelse break :blk false;
            break :blk value == .bool and value.bool;
        };
        if (replayed) {
            try out.print("replayed: {d} row(s) changed (recorded result)\n", .{changes});
        } else {
            try out.print("{d} row(s) changed\n", .{changes});
        }
    } else if (std.mem.eql(u8, command, "query")) {
        try renderRemoteTable(object, out);
    } else if (std.mem.eql(u8, command, "session")) {
        try out.print("session {d}\n", .{jsonInt(object.get("session_id")) orelse 0});
    } else if (std.mem.eql(u8, command, "leader")) {
        try renderRemoteLeader(object, out);
    } else if (std.mem.eql(u8, command, "wait")) {
        try out.print("applied {d}, leader {?d}\n", .{
            jsonInt(object.get("applied_slot")) orelse 0,
            jsonInt(object.get("leader")),
        });
    } else if (std.mem.eql(u8, command, "integrity-check")) {
        try out.writeAll("integrity: pass\n");
    } else if (std.mem.eql(u8, command, "expire-sessions")) {
        try out.print("{d} session(s) expired\n", .{jsonInt(object.get("expired")) orelse 0});
    } else if (std.mem.eql(u8, command, "replace-voter")) {
        const phase = jsonString(object.get("phase")) orelse "unknown";
        try out.print(
            "operation {d}: {s}\n",
            .{ jsonInt(object.get("operation")) orelse 0, phase },
        );
        if (std.mem.eql(u8, phase, "proposed")) {
            try out.writeAll(
                "the stop sign is in Paxos; query `zaxon membership status` " ++
                    "by operation id. A timeout does not mean failure.\n",
            );
        }
    } else if (std.mem.eql(u8, command, "membership")) {
        try renderRemoteMembership(object, out);
    } else {
        try out.print("{s}\n", .{body});
    }
    return exit_ok;
}

fn renderRemoteMembership(object: *const std.json.ObjectMap, out: *std.Io.Writer) !void {
    try out.print(
        "configuration {d} ({s}); quorum_available={}; installation={s}\n",
        .{
            jsonInt(object.get("configuration_id")) orelse 0,
            jsonString(object.get("phase")) orelse "unknown",
            blk: {
                const value = object.get("quorum_available") orelse
                    break :blk false;
                break :blk value == .bool and value.bool;
            },
            jsonString(object.get("installation_state")) orelse "unknown",
        },
    );
    if (jsonString(object.get("registry_digest"))) |digest| {
        try out.print("registry digest {s}\n", .{digest});
    }
    if (jsonInt(object.get("operation_id"))) |operation_id| {
        try out.print("pending operation {d}\n", .{operation_id});
    }
    if (jsonString(object.get("installation_error"))) |message| {
        try out.print("installation error {s}\n", .{message});
    }
    if (object.get("nodes")) |nodes| {
        if (nodes == .array) for (nodes.array.items) |item| {
            if (item != .object) continue;
            try out.print("node {d} {s} {s}\n", .{
                jsonInt(item.object.get("id")) orelse 0,
                jsonString(item.object.get("role")) orelse "?",
                jsonString(item.object.get("endpoint")) orelse "?",
            });
        };
    }
}

fn renderRemoteLeader(object: *const std.json.ObjectMap, out: *std.Io.Writer) !void {
    if (object.get("leader")) |leader| switch (leader) {
        .object => |leader_object| {
            const id = jsonInt(leader_object.get("id")) orelse 0;
            if (leader_object.get("host")) |host| {
                if (host == .string) {
                    try out.print("leader: node {d} at {s}:{d}\n", .{
                        id,
                        host.string,
                        jsonInt(leader_object.get("port")) orelse 0,
                    });
                    return;
                }
            }
            try out.print("leader: node {d}\n", .{id});
        },
        else => try out.writeAll("leader: none\n"),
    };
}

pub fn jsonString(value: ?std.json.Value) ?[]const u8 {
    const wrapped = value orelse return null;
    return switch (wrapped) {
        .string => |text| text,
        else => null,
    };
}

pub fn jsonInt(value: ?std.json.Value) ?i64 {
    const v = value orelse return null;
    return switch (v) {
        .integer => |n| n,
        else => null,
    };
}

pub fn renderRemoteTable(
    object: *const std.json.ObjectMap,
    out: *std.Io.Writer,
) !void {
    const columns = object.get("columns") orelse return;
    const rows = object.get("rows") orelse return;
    if (columns != .array or rows != .array) return;
    for (columns.array.items, 0..) |column, index| {
        if (index > 0) try out.writeAll(" | ");
        if (column == .string) try out.writeAll(column.string);
    }
    try out.writeAll("\n");
    for (columns.array.items, 0..) |column, index| {
        if (index > 0) try out.writeAll("-+-");
        const len = if (column == .string) column.string.len else 4;
        for (0..len) |_| try out.writeAll("-");
    }
    try out.writeAll("\n");
    for (rows.array.items) |row| {
        if (row != .array) continue;
        for (row.array.items, 0..) |cell, index| {
            if (index > 0) try out.writeAll(" | ");
            switch (cell) {
                .string => |text| try out.writeAll(text),
                .null => try out.writeAll("NULL"),
                .integer => |n| try out.print("{d}", .{n}),
                .float => |f| try out.print("{d}", .{f}),
                else => try out.writeAll("?"),
            }
        }
        try out.writeAll("\n");
    }
}

/// Runs one embedded write and prints its outcome: the shared body of the
/// `exec` command and the plain shell.
pub fn execEmbedded(
    node: *zaxonlite.Node,
    sql: [:0]const u8,
    session: ?u64,
    sequence: ?u64,
    json: bool,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const result = blk: {
        if (session) |value| {
            break :blk node.execIdempotent(value, sequence.?, sql);
        }
        break :blk node.exec(sql);
    } catch |err| switch (err) {
        error.SqliteError, error.SqliteBusy => {
            try diagnostic.write(
                err_out,
                "sql error",
                node.lastSqliteMessage(),
                "Correct the statement and retry it as a new request.",
            );
            return exit_sql;
        },
        error.UnknownSession, error.SequenceGap, error.ResultExpired => {
            try diagnostic.write(
                err_out,
                "session error",
                @errorName(err),
                "Use the same live session and its next monotonic sequence.",
            );
            return exit_sql;
        },
        else => return err,
    };
    if (json) {
        try out.print(
            "{{\"changes\":{d},\"slot\":{d},\"replayed\":{}}}\n",
            .{ result.changes, result.slot, result.replayed },
        );
    } else if (result.replayed) {
        try out.print("replayed: {d} row(s) changed (recorded result)\n", .{result.changes});
    } else {
        try out.print("{d} row(s) changed\n", .{result.changes});
    }
    return exit_ok;
}

/// Runs one embedded read and prints the legacy table or JSON shape: the
/// shared body of the `query` command and the plain shell.
pub fn queryEmbedded(
    gpa: std.mem.Allocator,
    node: *zaxonlite.Node,
    sql: []const u8,
    json: bool,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    var result = node.query(gpa, sql) catch |err| switch (err) {
        error.SqliteError, error.SqliteBusy, error.WriteInReadQuery => {
            const message = if (err == error.WriteInReadQuery)
                "statement is not read-only; use exec"
            else
                node.lastSqliteMessage();
            try diagnostic.write(
                err_out,
                "query error",
                message,
                "Use query only for read-only SQL; use exec for writes.",
            );
            return exit_sql;
        },
        else => return err,
    };
    defer result.deinit();

    if (json) {
        try writeJsonResult(viewOf(&result), out);
    } else {
        try writePlainTable(viewOf(&result), out);
    }
    return exit_ok;
}

/// Builds a borrowed `View` from a remote query response object. Integer and
/// float cells are formatted into the arena; string and null cells borrow
/// from the parsed JSON, so the parsed value must outlive the view.
pub fn remoteView(
    arena: std.mem.Allocator,
    object: *const std.json.ObjectMap,
) !?View {
    const columns_value = object.get("columns") orelse return null;
    const rows_value = object.get("rows") orelse return null;
    if (columns_value != .array or rows_value != .array) return null;

    const columns = try arena.alloc([]const u8, columns_value.array.items.len);
    for (columns_value.array.items, 0..) |column, index| {
        columns[index] = if (column == .string) column.string else "?";
    }
    const rows = try arena.alloc([]const ?[]const u8, rows_value.array.items.len);
    var row_count: usize = 0;
    for (rows_value.array.items) |row_value| {
        if (row_value != .array) continue;
        const row = try arena.alloc(?[]const u8, row_value.array.items.len);
        for (row_value.array.items, 0..) |cell, index| {
            row[index] = switch (cell) {
                .string => |text| text,
                .null => null,
                .integer => |n| try std.fmt.allocPrint(arena, "{d}", .{n}),
                .float => |f| try std.fmt.allocPrint(arena, "{d}", .{f}),
                else => "?",
            };
        }
        rows[row_count] = row;
        row_count += 1;
    }
    return .{ .columns = columns, .rows = rows[0..row_count] };
}
