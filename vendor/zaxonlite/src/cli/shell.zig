//! The interactive `zaxon sql` shell (ZDS 0005).
//!
//! One REPL, two execution backends (`embedded.Embedded`'s node or
//! `client.ClusterConnection`), and two input paths:
//!
//! * the rich path — raw-mode line editing, history with `ctrl+r` search,
//!   SQL highlighting, aligned tables, and a pager — taken only when stdin
//!   and stdout are both TTYs and TERM is capable;
//! * the plain path — the historical `takeDelimiter('\n')` loop, kept
//!   byte-identical so pipes, scripts, and the CLI contract test observe
//!   no change.
//!
//! Raw mode is active only while editing or waiting for an interruptible
//! remote request; results and diagnostics always print in cooked mode.

const std = @import("std");
const zaxonlite = @import("zaxonlite");
const ui = @import("zaxon_cli_ui");
const render = @import("render.zig");

const term_mod = ui.term;
const editor_mod = ui.editor;
const history_mod = ui.history;
const highlight = ui.highlight;
const table = ui.table;

const client = zaxonlite.client;
const diagnostic = zaxonlite.diagnostic;
const Node = zaxonlite.Node;
pub const exit_ok = render.exit_ok;

/// The execution seam: both variants already exist and produce the same
/// `columns`/`rows` result shape.
pub const Backend = union(enum) {
    embedded: *Node,
    remote: *client.ClusterConnection,
};

pub const Config = struct {
    no_color: bool = false,
    no_history: bool = false,
    /// Resolved by main: `<data>/.zaxon_history` in embedded mode,
    /// `$ZAXON_HISTORY` in client mode, null to disable persistence.
    history_path: ?[]const u8 = null,
};

/// Runs the shell, choosing the rich or plain path from the terminal.
pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: *std.process.Environ.Map,
    backend: Backend,
    config: Config,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const detection = term_mod.detect(io, environ, config.no_color);
    if (detection.interactive) {
        if (term_mod.Term.init(gpa, io, detection.caps)) |terminal_value| {
            var terminal = terminal_value;
            defer terminal.deinit();
            try terminal.installResizeHandler();
            return runRich(gpa, io, backend, config, &terminal, out, err_out);
        } else |_| {
            // No controlling terminal after all: fall through to plain.
        }
    }
    return switch (backend) {
        .embedded => |node| plainEmbedded(gpa, io, node, out, err_out),
        .remote => |cluster| plainRemote(gpa, io, cluster, out, err_out),
    };
}

/// Statement routing shared by every path: reads go to `query`, everything
/// else is a replicated write.
pub fn isReadStatement(sql: []const u8) bool {
    var tokenizer = highlight.Tokenizer.init(sql);
    while (tokenizer.next()) |span| {
        switch (span.kind) {
            .text, .comment => continue,
            .keyword, .identifier => {
                const first = span.bytes(sql);
                if (std.ascii.eqlIgnoreCase(first, "with")) {
                    return withStatementIsRead(sql, &tokenizer);
                }
                return std.ascii.eqlIgnoreCase(first, "select") or
                    std.ascii.eqlIgnoreCase(first, "values") or
                    std.ascii.eqlIgnoreCase(first, "explain");
            },
            else => return false,
        }
    }
    return false;
}

/// Finds the top-level statement after one or more CTE bodies. Tracking
/// parentheses is sufficient here because the tokenizer has already hidden
/// quoted text and comments from the structural scan.
fn withStatementIsRead(sql: []const u8, tokenizer: *highlight.Tokenizer) bool {
    var depth: usize = 0;
    var completed_group = false;
    while (tokenizer.next()) |span| {
        switch (span.kind) {
            .text, .comment, .string => continue,
            .operator => switch (sql[span.start]) {
                '(' => depth += 1,
                ')' => if (depth > 0) {
                    depth -= 1;
                    if (depth == 0) completed_group = true;
                },
                ',' => if (depth == 0) {
                    completed_group = false;
                },
                else => {},
            },
            .keyword, .identifier => {
                if (depth != 0 or !completed_group) continue;
                const word = span.bytes(sql);
                if (std.ascii.eqlIgnoreCase(word, "select") or
                    std.ascii.eqlIgnoreCase(word, "values")) return true;
                if (std.ascii.eqlIgnoreCase(word, "insert") or
                    std.ascii.eqlIgnoreCase(word, "update") or
                    std.ascii.eqlIgnoreCase(word, "delete") or
                    std.ascii.eqlIgnoreCase(word, "replace")) return false;
            },
            else => {},
        }
    }
    return false;
}

// ----------------------------------------------------------------------
// Plain path: the historical loops, byte for byte.
// ----------------------------------------------------------------------

fn plainEmbedded(
    gpa: std.mem.Allocator,
    io: std.Io,
    node: *Node,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    try out.print(
        "zaxonlite {s} — one durable node, journal-replicated SQLite\n" ++
            "SQL statements end my line; dot commands: .status .tables .quit\n",
        .{zaxonlite.version},
    );
    var stdin_buffer: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, &stdin_buffer);
    const in = &stdin_reader.interface;

    while (true) {
        try out.writeAll("zaxon> ");
        try out.flush();
        const raw_line = in.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                try diagnostic.write(
                    err_out,
                    "input line too long",
                    "The shell statement exceeds its bounded input buffer.",
                    "Split the statement or run a smaller --sql request.",
                );
                try err_out.flush();
                continue;
            },
            else => return err,
        };
        const line_bytes = raw_line orelse break;
        const line = std.mem.trim(u8, line_bytes, " \t\r");
        if (line.len == 0) continue;

        if (line[0] == '.') {
            if (std.mem.eql(u8, line, ".quit") or std.mem.eql(u8, line, ".exit")) break;
            if (std.mem.eql(u8, line, ".status")) {
                try render.printStatus(node, false, out);
                continue;
            }
            if (std.mem.eql(u8, line, ".tables")) {
                _ = try render.queryEmbedded(gpa, node, tables_sql, false, out, err_out);
                continue;
            }
            try diagnostic.write(
                err_out,
                "unknown shell command",
                line,
                "Use .status, .tables, or .quit, or enter SQL.",
            );
            try err_out.flush();
            continue;
        }

        if (isReadStatement(line)) {
            _ = try render.queryEmbedded(gpa, node, line, false, out, err_out);
        } else {
            const sql = try gpa.dupeSentinel(u8, line, 0);
            defer gpa.free(sql);
            _ = try render.execEmbedded(node, sql, null, null, false, out, err_out);
        }
        try err_out.flush();
    }
    return exit_ok;
}

fn plainRemote(
    gpa: std.mem.Allocator,
    io: std.Io,
    cluster: *client.ClusterConnection,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    try out.print(
        "zaxonlite {s} — connected shell\n" ++
            "SQL statements end my line; dot commands: .status .quit\n",
        .{zaxonlite.version},
    );
    var stdin_buffer: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, &stdin_buffer);
    const in = &stdin_reader.interface;

    while (true) {
        try out.writeAll("zaxon> ");
        try out.flush();
        const raw_line = in.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                try diagnostic.write(
                    err_out,
                    "input line too long",
                    "The shell statement exceeds its bounded input buffer.",
                    "Split the statement or run a smaller --sql request.",
                );
                try err_out.flush();
                continue;
            },
            else => return err,
        };
        const line_bytes = raw_line orelse break;
        const line = std.mem.trim(u8, line_bytes, " \t\r");
        if (line.len == 0) continue;
        if (!try plainRemoteLoopStep(gpa, cluster, line, out, err_out)) break;
    }
    return exit_ok;
}

fn plainRemoteLoopStep(
    gpa: std.mem.Allocator,
    cluster: *client.ClusterConnection,
    line: []const u8,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !bool {
    var request: std.Io.Writer.Allocating = .init(gpa);
    defer request.deinit();
    var command: []const u8 = "query";
    var as_json = false;
    if (line[0] == '.') {
        if (std.mem.eql(u8, line, ".quit") or std.mem.eql(u8, line, ".exit")) return false;
        if (std.mem.eql(u8, line, ".status")) {
            try request.writer.writeAll("{\"op\":\"status\"}");
            command = "status";
            as_json = true;
        } else {
            try diagnostic.write(
                err_out,
                "unknown shell command",
                line,
                "Use .status or .quit, or enter a SQL statement.",
            );
            try err_out.flush();
            return true;
        }
    } else if (isReadStatement(line)) {
        try request.writer.writeAll("{\"op\":\"query\",\"sql\":");
        try render.writeJsonString(&request.writer, line);
        try request.writer.writeAll(",\"level\":\"linearizable\"}");
    } else {
        command = "exec";
        try request.writer.writeAll("{\"op\":\"exec\",\"sql\":");
        try render.writeJsonString(&request.writer, line);
        try request.writer.writeAll("}");
    }

    var result = cluster.call(request.written(), true) catch {
        try render.noLeaderDiagnostic(err_out, cluster.refused_leader_hint);
        try err_out.flush();
        return true;
    };
    defer result.deinit(gpa);
    _ = try render.renderRemote(gpa, command, as_json, result.body, out, err_out);
    try out.flush();
    try err_out.flush();
    return true;
}

// ----------------------------------------------------------------------
// Rich path
// ----------------------------------------------------------------------

/// Everything the rich loop and the dot commands need, threaded explicitly
/// so the shell never reaches for globals.
pub const Shell = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    backend: Backend,
    terminal: *term_mod.Term,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
    history: history_mod.History,
    /// The shared line reader; points at this shell's terminal and history.
    reader: *ui.LineReader,
    statement: std.ArrayList(u8) = .empty,
    mode: table.Mode = .auto,
    timer: bool = false,
    history_enabled: bool,
    history_configured: bool,
    history_path: ?[]const u8,
    quit: bool = false,

    /// The explicit failure surface of the shell and every dot command.
    /// Backend and SQL failures are rendered as diagnostics and never
    /// escape as errors.
    pub const Error = error{
        OutOfMemory,
        WriteFailed,
        ReadFailed,
        EndOfStream,
        TtyUnavailable,
        ConcurrencyUnavailable,
    };
};

fn runRich(
    gpa: std.mem.Allocator,
    io: std.Io,
    backend: Backend,
    config: Config,
    terminal: *term_mod.Term,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    var reader = ui.LineReader{
        .gpa = gpa,
        .terminal = terminal,
        .history = undefined,
    };
    var shell = Shell{
        .gpa = gpa,
        .io = io,
        .backend = backend,
        .terminal = terminal,
        .out = out,
        .err_out = err_out,
        .history = history_mod.History.init(gpa),
        .reader = &reader,
        .history_enabled = !config.no_history and config.history_path != null,
        .history_configured = !config.no_history and config.history_path != null,
        .history_path = config.history_path,
    };
    // The history lives in the shell (dot commands replace it wholesale);
    // the field address is stable for the reader once the shell exists.
    reader.history = &shell.history;
    defer shell.history.deinit();
    defer shell.statement.deinit(gpa);

    try terminal.suspendRaw();
    if (shell.history_enabled) {
        shell.history.load(io, shell.history_path.?) catch |err| {
            try historyIoDiagnostic(&shell, "history load failed", err);
        };
    }

    try out.print(
        "zaxonlite {s} — interactive shell\n" ++
            "Statements end with ';'. Type .help for commands and keys.\n",
        .{zaxonlite.version},
    );
    try out.flush();

    while (!shell.quit) {
        switch (try shell.reader.readLine(prompt(&shell))) {
            .submitted => try processRichLine(&shell),
            // The reader already cleared its editor and left history
            // navigation; the accumulated statement is ours to drop.
            .canceled => shell.statement.clearRetainingCapacity(),
            .eof => break,
        }
    }

    if (shell.history_enabled) {
        shell.history.save(io, shell.history_path.?) catch |err| {
            try historyIoDiagnostic(&shell, "history save failed", err);
        };
    }
    return exit_ok;
}

fn processRichLine(shell: *Shell) Shell.Error!void {
    const line = std.mem.trim(u8, shell.reader.text(), " \t\r");
    if (line.len == 0 and shell.statement.items.len == 0) return;

    if (shell.statement.items.len == 0 and line.len > 0 and line[0] == '.') {
        try runDot(shell, line);
        try shell.out.flush();
        try shell.err_out.flush();
        return;
    }

    const edited = shell.reader.text();
    if (shell.statement.items.len + edited.len > editor_mod.capacity) {
        try statementTooLongDiagnostic(shell);
        shell.statement.clearRetainingCapacity();
        shell.history.resetNav();
        return;
    }
    try shell.statement.appendSlice(shell.gpa, edited);
    if (!highlight.statementComplete(shell.statement.items)) {
        if (shell.statement.items.len == editor_mod.capacity) {
            try statementTooLongDiagnostic(shell);
            shell.statement.clearRetainingCapacity();
            shell.history.resetNav();
            return;
        }
        try shell.statement.append(shell.gpa, '\n');
        return;
    }
    const statement = std.mem.trim(u8, shell.statement.items, " \t\r\n");
    if (statement.len > 0) {
        try shell.history.append(shell.statement.items);
        try executeStatement(shell, statement);
    }
    shell.history.resetNav();
    shell.statement.clearRetainingCapacity();
    try shell.out.flush();
    try shell.err_out.flush();
}

fn statementTooLongDiagnostic(shell: *Shell) Shell.Error!void {
    diagnostic.write(
        shell.err_out,
        "input statement too long",
        "The accumulated statement exceeds the 64 KiB shell limit.",
        "Split the statement or run a smaller --sql request.",
    ) catch return error.WriteFailed;
}

fn historyIoDiagnostic(
    shell: *Shell,
    title: []const u8,
    err: anyerror,
) Shell.Error!void {
    diagnostic.write(
        shell.err_out,
        title,
        @errorName(err),
        "Check the history path and its owner-only file permissions.",
    ) catch return error.WriteFailed;
    shell.err_out.flush() catch return error.WriteFailed;
}

fn prompt(shell: *const Shell) []const u8 {
    return if (shell.statement.items.len == 0) "zaxon> " else "  ...> ";
}

// ----------------------------------------------------------------------
// Statement execution and result rendering
// ----------------------------------------------------------------------

fn executeStatement(shell: *Shell, statement: []const u8) Shell.Error!void {
    const start = std.Io.Timestamp.now(shell.io, .awake);
    switch (shell.backend) {
        .embedded => |node| try executeEmbedded(shell, node, statement),
        .remote => |cluster| try executeRemote(shell, cluster, statement),
    }
    if (shell.timer) {
        const elapsed = start.durationTo(std.Io.Timestamp.now(shell.io, .awake));
        const ms = @as(f64, @floatFromInt(@max(elapsed.nanoseconds, 0))) /
            1_000_000.0;
        shell.out.print("Time: {d:.1} ms\n", .{ms}) catch
            return error.WriteFailed;
    }
}

fn executeEmbedded(
    shell: *Shell,
    node: *Node,
    statement: []const u8,
) Shell.Error!void {
    if (isReadStatement(statement)) {
        var result = node.query(shell.gpa, statement) catch |err| {
            try renderEmbeddedError(shell, node, err);
            return;
        };
        defer result.deinit();
        try renderView(shell, render.viewOf(&result));
        return;
    }
    const sql = shell.gpa.dupeSentinel(u8, statement, 0) catch return error.OutOfMemory;
    defer shell.gpa.free(sql);
    const result = node.exec(sql) catch |err| {
        try renderEmbeddedError(shell, node, err);
        return;
    };
    if (result.replayed) {
        shell.out.print(
            "replayed: {d} row(s) changed (recorded result)\n",
            .{result.changes},
        ) catch return error.WriteFailed;
    } else {
        shell.out.print("{d} row(s) changed\n", .{result.changes}) catch
            return error.WriteFailed;
    }
}

fn renderEmbeddedError(shell: *Shell, node: *Node, err: anyerror) Shell.Error!void {
    const write_error = switch (err) {
        error.SqliteError, error.SqliteBusy => diagnostic.write(
            shell.err_out,
            "sql error",
            node.lastSqliteMessage(),
            "Correct the statement and retry it as a new request.",
        ),
        error.WriteInReadQuery => diagnostic.write(
            shell.err_out,
            "query error",
            "statement is not read-only; use exec",
            "Use query only for read-only SQL; use exec for writes.",
        ),
        else => diagnostic.write(
            shell.err_out,
            "statement failed",
            @errorName(err),
            "Inspect node status; the shell session stays open.",
        ),
    };
    write_error catch return error.WriteFailed;
}

fn executeRemote(
    shell: *Shell,
    cluster: *client.ClusterConnection,
    statement: []const u8,
) Shell.Error!void {
    var request: std.Io.Writer.Allocating = .init(shell.gpa);
    defer request.deinit();
    const read = isReadStatement(statement);
    if (read) {
        request.writer.writeAll("{\"op\":\"query\",\"sql\":") catch
            return error.OutOfMemory;
        render.writeJsonString(&request.writer, statement) catch
            return error.OutOfMemory;
        request.writer.writeAll(",\"level\":\"linearizable\"}") catch
            return error.OutOfMemory;
    } else {
        request.writer.writeAll("{\"op\":\"exec\",\"sql\":") catch
            return error.OutOfMemory;
        render.writeJsonString(&request.writer, statement) catch
            return error.OutOfMemory;
        request.writer.writeAll("}") catch return error.OutOfMemory;
    }

    var result = (try waitForRemote(shell, cluster, request.written())) orelse
        return;
    defer result.deinit(shell.gpa);
    try renderRemoteBody(shell, if (read) "query" else "exec", result.body);
}

const RemoteOutcome = union(enum) {
    success: client.CallResult,
    failure: anyerror,
};

const InterruptOutcome = union(enum) {
    interrupted,
    unavailable: anyerror,
};

const RemoteWaitOutcome = union(enum) {
    remote: RemoteOutcome,
    interrupt: InterruptOutcome,
};

fn callRemote(
    cluster: *client.ClusterConnection,
    request: []const u8,
    started: *std.Io.Event,
) RemoteOutcome {
    const result = cluster.callInterruptible(request, true, started) catch |err|
        return .{ .failure = err };
    return .{ .success = result };
}

fn waitForInterrupt(terminal: *term_mod.Term) InterruptOutcome {
    terminal.waitForInterrupt() catch |err|
        return .{ .unavailable = err };
    return .interrupted;
}

fn waitForRemote(
    shell: *Shell,
    cluster: *client.ClusterConnection,
    request: []const u8,
) Shell.Error!?client.CallResult {
    var outcomes: [2]RemoteWaitOutcome = undefined;
    var select = std.Io.Select(RemoteWaitOutcome).init(shell.io, &outcomes);
    var remote_started: std.Io.Event = .unset;
    var select_active = true;
    defer if (select_active) drainRemoteWait(&select, shell.gpa);

    try shell.terminal.resumeRaw();
    var raw_active = true;
    defer if (raw_active) shell.terminal.suspendRaw() catch {};

    select.concurrent(.remote, callRemote, .{ cluster, request, &remote_started }) catch
        return error.ConcurrencyUnavailable;
    remote_started.wait(shell.io) catch return error.ReadFailed;
    select.concurrent(.interrupt, waitForInterrupt, .{shell.terminal}) catch
        return error.ConcurrencyUnavailable;

    while (true) {
        const outcome = select.await() catch return error.ReadFailed;
        switch (outcome) {
            .remote => |remote| {
                drainRemoteWait(&select, shell.gpa);
                select_active = false;
                try shell.terminal.suspendRaw();
                raw_active = false;
                return switch (remote) {
                    .success => |result| result,
                    .failure => {
                        render.noLeaderDiagnostic(
                            shell.err_out,
                            cluster.refused_leader_hint,
                        ) catch return error.WriteFailed;
                        return null;
                    },
                };
            },
            .interrupt => |interrupt| switch (interrupt) {
                .unavailable => continue,
                .interrupted => {
                    cluster.cancelCurrent();
                    drainRemoteWait(&select, shell.gpa);
                    select_active = false;
                    try shell.terminal.suspendRaw();
                    raw_active = false;
                    diagnostic.write(
                        shell.err_out,
                        "canceled locally",
                        "The remote statement may still apply server-side.",
                        "Check its effects before retrying, especially for writes.",
                    ) catch return error.WriteFailed;
                    return null;
                },
            },
        }
    }
}

fn drainRemoteWait(
    select: *std.Io.Select(RemoteWaitOutcome),
    gpa: std.mem.Allocator,
) void {
    while (select.cancel()) |outcome| switch (outcome) {
        .remote => |remote| switch (remote) {
            .success => |value| {
                var result = value;
                result.deinit(gpa);
            },
            .failure => {},
        },
        .interrupt => {},
    };
}

/// Renders a remote response body richly: query results go through the
/// aligned renderer, everything else keeps the legacy summaries.
fn renderRemoteBody(
    shell: *Shell,
    command: []const u8,
    body: []const u8,
) Shell.Error!void {
    if (!std.mem.eql(u8, command, "query")) {
        _ = render.renderRemote(
            shell.gpa,
            command,
            false,
            body,
            shell.out,
            shell.err_out,
        ) catch return error.WriteFailed;
        return;
    }
    const parsed = std.json.parseFromSlice(std.json.Value, shell.gpa, body, .{}) catch {
        render.malformedResponseDiagnostic(shell.err_out) catch
            return error.WriteFailed;
        return;
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        render.malformedResponseDiagnostic(shell.err_out) catch
            return error.WriteFailed;
        return;
    }
    const object = &parsed.value.object;
    const ok = if (object.get("ok")) |value| value == .bool and value.bool else false;
    if (!ok) {
        _ = render.renderRemote(
            shell.gpa,
            command,
            false,
            body,
            shell.out,
            shell.err_out,
        ) catch return error.WriteFailed;
        return;
    }
    var arena = std.heap.ArenaAllocator.init(shell.gpa);
    defer arena.deinit();
    const view = render.remoteView(arena.allocator(), object) catch
        return error.OutOfMemory;
    if (view) |value| {
        try renderView(shell, value);
    } else {
        render.malformedResponseDiagnostic(shell.err_out) catch
            return error.WriteFailed;
    }
}

/// Renders a result view in the current display mode, paging results that
/// would overflow the screen. The pager renders colorless so its width
/// math sees no escape sequences.
fn renderView(shell: *Shell, view: table.View) Shell.Error!void {
    const height = shell.terminal.height();
    const width = shell.terminal.width();
    const estimated: usize = switch (shell.mode) {
        .expanded => view.rows.len * (view.columns.len + 1),
        .auto => if (table.shouldExpand(view, width))
            view.rows.len * (view.columns.len + 1)
        else
            view.rows.len + 4,
        else => view.rows.len + 4,
    };
    const paged = shell.mode != .json and shell.mode != .csv and
        estimated + 1 > height;

    var buffer: std.Io.Writer.Allocating = .init(shell.gpa);
    defer buffer.deinit();
    const rows = table.write(view, .{
        .mode = shell.mode,
        .caps = .{
            .color = shell.terminal.caps.color and !paged,
            .unicode = shell.terminal.caps.unicode,
        },
        .terminal_width = width,
    }, &buffer.writer) catch |err| switch (err) {
        error.TooManyColumns => {
            diagnostic.write(
                shell.err_out,
                "result has too many columns",
                "Table mode supports SQLite's compiled 2,000-column limit.",
                "Use .mode expanded, json, or csv for a malformed remote result.",
            ) catch return error.WriteFailed;
            return;
        },
        else => return error.OutOfMemory,
    };

    if (paged) {
        try ui.pager.page(shell.gpa, shell.terminal, buffer.written());
    } else {
        shell.out.writeAll(buffer.written()) catch return error.WriteFailed;
    }
    if (shell.mode != .json and shell.mode != .csv) {
        shell.out.print("({d} row{s})\n", .{
            rows,
            if (rows == 1) "" else "s",
        }) catch return error.WriteFailed;
    }
}

// ----------------------------------------------------------------------
// Dot commands: a comptime registry (ZDS 0005, M5)
// ----------------------------------------------------------------------

const DotCommand = struct {
    name: []const u8,
    usage: []const u8,
    help: []const u8,
    run: *const fn (shell: *Shell, args: []const u8) Shell.Error!void,
};

/// Declared once; dispatch and `.help` derive from this table, so a
/// command cannot exist without documentation and a handler with the
/// wrong signature is a compile error.
const dot_commands = [_]DotCommand{
    .{ .name = "help", .usage = "", .help = "List commands and key bindings.", .run = runHelp },
    .{ .name = "tables", .usage = "", .help = "List user tables.", .run = runTables },
    .{ .name = "schema", .usage = "[name]", .help = "Print CREATE statements.", .run = runSchema },
    .{ .name = "status", .usage = "", .help = "Show node or cluster status.", .run = runStatus },
    .{ .name = "members", .usage = "", .help = "Show cluster membership.", .run = runMembers },
    .{
        .name = "mode",
        .usage = "table|expanded|auto|json|csv",
        .help = "Select the result display mode.",
        .run = runMode,
    },
    .{
        .name = "timer",
        .usage = "on|off",
        .help = "Toggle elapsed-time display.",
        .run = runTimer,
    },
    .{
        .name = "history",
        .usage = "[off|clear]",
        .help = "Show, disable, or clear history.",
        .run = runHistory,
    },
    .{ .name = "quit", .usage = "", .help = "Leave the shell (also ctrl+d).", .run = runQuit },
    .{ .name = "exit", .usage = "", .help = "Leave the shell.", .run = runQuit },
};

comptime {
    for (dot_commands) |command| {
        if (command.name.len == 0 or command.help.len == 0) {
            @compileError("every dot command must carry a name and help text");
        }
    }
}

const dot_map = blk: {
    var entries: [dot_commands.len]struct { []const u8, usize } = undefined;
    for (dot_commands, 0..) |command, index| {
        entries[index] = .{ command.name, index };
    }
    const map = std.StaticStringMap(usize).initComptime(entries);
    break :blk map;
};

fn runDot(shell: *Shell, line: []const u8) Shell.Error!void {
    const body = line[1..];
    const space = std.mem.indexOfAny(u8, body, " \t");
    const name = if (space) |index| body[0..index] else body;
    const args = if (space) |index|
        std.mem.trim(u8, body[index..], " \t")
    else
        "";
    const index = dot_map.get(name) orelse {
        diagnostic.write(
            shell.err_out,
            "unknown shell command",
            line,
            "Type .help to list commands, or enter a SQL statement.",
        ) catch return error.WriteFailed;
        return;
    };
    try dot_commands[index].run(shell, args);
}

fn runHelp(shell: *Shell, args: []const u8) Shell.Error!void {
    _ = args;
    const out = shell.out;
    out.writeAll("Commands:\n") catch return error.WriteFailed;
    // Generated from the registry: adding a command updates this listing.
    inline for (dot_commands) |command| {
        const left = "." ++ command.name ++
            (if (command.usage.len > 0) " " ++ command.usage else "");
        out.print("  {s:<34} {s}\n", .{ left, command.help }) catch
            return error.WriteFailed;
    }
    out.writeAll(
        \\
        \\Keys:
        \\  ctrl+a / ctrl+e    start / end of line
        \\  alt+b / alt+f      word left / right
        \\  ctrl+w             delete the previous word
        \\  ctrl+u / ctrl+k    delete to start / end of line
        \\  ctrl+y             restore the most recently deleted text
        \\  ctrl+l             clear and repaint the screen
        \\  up / down          walk history
        \\  ctrl+r             reverse incremental history search
        \\  ctrl+c             cancel input or abandon a remote wait
        \\  ctrl+d             leave the shell (empty line)
        \\
        \\A statement runs when it ends with ';'. A leading space keeps a
        \\statement out of history.
        \\
    ) catch return error.WriteFailed;
}

const tables_sql =
    "select name from sqlite_master where type = 'table' " ++
    "and name not like '\\_\\_zaxon\\_%' escape '\\' order by name";

fn runTables(shell: *Shell, args: []const u8) Shell.Error!void {
    _ = args;
    try runReadQuery(shell, tables_sql);
}

fn runSchema(shell: *Shell, args: []const u8) Shell.Error!void {
    if (args.len == 0) {
        try runSchemaQuery(
            shell,
            "select sql from sqlite_master where sql is not null " ++
                "and name not like '\\_\\_zaxon\\_%' escape '\\' order by name",
        );
        return;
    }
    var sql: std.Io.Writer.Allocating = .init(shell.gpa);
    defer sql.deinit();
    sql.writer.writeAll(
        "select sql from sqlite_master where sql is not null and name = '",
    ) catch return error.OutOfMemory;
    for (args) |byte| {
        if (byte == '\'') {
            sql.writer.writeAll("''") catch return error.OutOfMemory;
        } else {
            sql.writer.writeAll(&.{byte}) catch return error.OutOfMemory;
        }
    }
    sql.writer.writeAll("'") catch return error.OutOfMemory;
    try runSchemaQuery(shell, sql.written());
}

fn runStatus(shell: *Shell, args: []const u8) Shell.Error!void {
    _ = args;
    switch (shell.backend) {
        .embedded => |node| render.printStatus(node, false, shell.out) catch
            return error.WriteFailed,
        .remote => |cluster| {
            var result = cluster.call("{\"op\":\"status\"}", false) catch {
                render.noLeaderDiagnostic(
                    shell.err_out,
                    cluster.refused_leader_hint,
                ) catch return error.WriteFailed;
                return;
            };
            defer result.deinit(shell.gpa);
            shell.out.print("{s}\n", .{result.body}) catch
                return error.WriteFailed;
        },
    }
}

fn runMembers(shell: *Shell, args: []const u8) Shell.Error!void {
    _ = args;
    switch (shell.backend) {
        .embedded => |node| {
            const status = node.status();
            for (node.memberIds()) |member| {
                shell.out.print("node {d}{s}\n", .{
                    member,
                    if (member == status.node_id) " (self)" else "",
                }) catch return error.WriteFailed;
            }
        },
        .remote => |cluster| {
            var result = cluster.call("{\"op\":\"members\"}", false) catch {
                render.noLeaderDiagnostic(
                    shell.err_out,
                    cluster.refused_leader_hint,
                ) catch return error.WriteFailed;
                return;
            };
            defer result.deinit(shell.gpa);
            shell.out.print("{s}\n", .{result.body}) catch
                return error.WriteFailed;
        },
    }
}

fn runMode(shell: *Shell, args: []const u8) Shell.Error!void {
    if (args.len == 0) {
        shell.out.print("display mode: {t}\n", .{shell.mode}) catch
            return error.WriteFailed;
        return;
    }
    const mode = table.Mode.parse(args) orelse {
        diagnostic.write(
            shell.err_out,
            "unknown display mode",
            args,
            "Use .mode table, expanded, auto, json, or csv.",
        ) catch return error.WriteFailed;
        return;
    };
    shell.mode = mode;
    shell.out.print("display mode: {t}\n", .{shell.mode}) catch
        return error.WriteFailed;
}

fn runTimer(shell: *Shell, args: []const u8) Shell.Error!void {
    if (std.mem.eql(u8, args, "on")) {
        shell.timer = true;
    } else if (std.mem.eql(u8, args, "off")) {
        shell.timer = false;
    } else if (args.len == 0) {
        shell.timer = !shell.timer;
    } else {
        diagnostic.write(
            shell.err_out,
            "invalid timer setting",
            args,
            "Use .timer on or .timer off.",
        ) catch return error.WriteFailed;
        return;
    }
    shell.out.print(
        "timer: {s}\n",
        .{if (shell.timer) "on" else "off"},
    ) catch return error.WriteFailed;
}

fn runHistory(shell: *Shell, args: []const u8) Shell.Error!void {
    if (std.mem.eql(u8, args, "off")) {
        shell.history_enabled = false;
        shell.out.writeAll("history persistence: off\n") catch
            return error.WriteFailed;
        return;
    }
    if (std.mem.eql(u8, args, "clear")) {
        shell.history.deinit();
        shell.history = history_mod.History.init(shell.gpa);
        if (shell.history_configured) {
            shell.history.save(shell.io, shell.history_path.?) catch |err| {
                try historyIoDiagnostic(shell, "history clear failed", err);
                return;
            };
        }
        shell.out.writeAll("history cleared\n") catch return error.WriteFailed;
        return;
    }
    if (args.len != 0) {
        diagnostic.write(
            shell.err_out,
            "invalid history command",
            args,
            "Use .history, .history off, or .history clear.",
        ) catch return error.WriteFailed;
        return;
    }
    const total = shell.history.count();
    const shown = @min(total, 20);
    var index = total - shown;
    while (index < total) : (index += 1) {
        shell.out.print("{d:>5}  ", .{index + 1}) catch return error.WriteFailed;
        table.writeSanitized(shell.out, shell.history.entry(index)) catch
            return error.WriteFailed;
        shell.out.writeAll("\n") catch return error.WriteFailed;
    }
}

fn runQuit(shell: *Shell, args: []const u8) Shell.Error!void {
    _ = args;
    shell.quit = true;
}

/// A read-only query issued by a dot command, rendered in the current
/// display mode against either backend.
fn runReadQuery(shell: *Shell, sql: []const u8) Shell.Error!void {
    switch (shell.backend) {
        .embedded => |node| {
            var result = node.query(shell.gpa, sql) catch |err| {
                try renderEmbeddedError(shell, node, err);
                return;
            };
            defer result.deinit();
            try renderView(shell, render.viewOf(&result));
        },
        .remote => |cluster| try executeRemote(shell, cluster, sql),
    }
}

/// `.schema` prints statement text, one per line, rather than a table.
fn runSchemaQuery(shell: *Shell, sql: []const u8) Shell.Error!void {
    switch (shell.backend) {
        .embedded => |node| {
            var result = node.query(shell.gpa, sql) catch |err| {
                try renderEmbeddedError(shell, node, err);
                return;
            };
            defer result.deinit();
            try writeSchemaRows(shell, render.viewOf(&result));
        },
        .remote => |cluster| {
            var request: std.Io.Writer.Allocating = .init(shell.gpa);
            defer request.deinit();
            request.writer.writeAll("{\"op\":\"query\",\"sql\":") catch
                return error.OutOfMemory;
            render.writeJsonString(&request.writer, sql) catch
                return error.OutOfMemory;
            request.writer.writeAll(",\"level\":\"linearizable\"}") catch
                return error.OutOfMemory;
            var result = cluster.call(request.written(), true) catch {
                render.noLeaderDiagnostic(
                    shell.err_out,
                    cluster.refused_leader_hint,
                ) catch return error.WriteFailed;
                return;
            };
            defer result.deinit(shell.gpa);
            const parsed = std.json.parseFromSlice(
                std.json.Value,
                shell.gpa,
                result.body,
                .{},
            ) catch {
                render.malformedResponseDiagnostic(shell.err_out) catch
                    return error.WriteFailed;
                return;
            };
            defer parsed.deinit();
            if (parsed.value != .object) return;
            var arena = std.heap.ArenaAllocator.init(shell.gpa);
            defer arena.deinit();
            const view = render.remoteView(
                arena.allocator(),
                &parsed.value.object,
            ) catch return error.OutOfMemory;
            if (view) |value| try writeSchemaRows(shell, value);
        },
    }
}

fn writeSchemaRows(shell: *Shell, view: table.View) Shell.Error!void {
    for (view.rows) |row| {
        for (row) |cell| {
            const text = cell orelse continue;
            table.writeSanitized(shell.out, text) catch return error.WriteFailed;
            shell.out.writeAll(";\n") catch return error.WriteFailed;
        }
    }
}

test "statement routing skips comments and classifies CTE bodies" {
    const testing = std.testing;
    try testing.expect(isReadStatement("-- comment\nselect 1"));
    try testing.expect(isReadStatement("/* comment */ values (1)"));
    try testing.expect(isReadStatement(
        "with a as (select 1), b(x) as (values (2)) select * from b",
    ));
    try testing.expect(!isReadStatement(
        "with a as (select 1) insert into t select * from a",
    ));
    try testing.expect(!isReadStatement(
        "with recursive a(x) as (values(1) union all select x+1 from a) " ++
            "update t set x = (select max(x) from a)",
    ));
}

test "dot-command registry is complete and maps every declaration" {
    const testing = std.testing;
    inline for (dot_commands, 0..) |command, index| {
        try testing.expect(command.name.len > 0);
        try testing.expect(command.help.len > 0);
        try testing.expectEqual(index, dot_map.get(command.name).?);
    }
}
