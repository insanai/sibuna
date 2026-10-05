//! Running protection changes use the same authenticated API as the console.
//! Preparation and selection are separate commands with explicit review revisions.
const std = @import("std");
const p = @import("console").protocol;
const arguments = @import("crs_management_args.zig");
const sessions = @import("console_session.zig");
const client = @import("console_client.zig");
const reply = @import("crs_management_reply.zig");
const Writer = std.Io.Writer;
const Error = sessions.Error || error{
    InvalidConfiguration,
    PreparationFailed,
    ManagedTaskFailed,
};
const Budget = @import("console_deadline.zig").Budget;

pub fn execute(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) u8 {
    const args = arguments.parse(argv) catch |err| {
        std.debug.print("CRSCLI001: invalid management command ({t}). " ++
            "Hint: use --origin, --username, --password-file and an explicit --revision " ++
            "for changes. Select requires the reviewed candidate --id.\n", .{err});
        return 1;
    };
    var bytes: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writer(io, &bytes);
    run(allocator, io, args, &writer.interface) catch |err| {
        std.debug.print("CRSCLIMANAGE: management command failed ({t}). " ++
            "Hint: query status before retrying an unknown outcome. Use administrator " ++
            "credentials in private files and review the candidate before selection.\n", .{err});
        return 1;
    };
    writer.interface.flush() catch {
        std.debug.print("CRSCLIWRITE: report delivery failed. " ++
            "Query status before retrying.\n", .{});
        return 1;
    };
    return 0;
}

fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: arguments.Args,
    writer: *Writer,
) Error!void {
    var session = try client.Session.init(allocator, io, args.origin);
    defer session.deinit();
    defer sessions.close(&session);
    if (try sessions.login(&session, args.credentials) != .admin) return error.Forbidden;
    const snapshot = try allocator.create(p.crs_api.Status);
    defer allocator.destroy(snapshot);
    const budget: Budget = .{
        .started = std.Io.Clock.awake.now(io).nanoseconds,
        .seconds = args.timeout,
    };
    switch (args.operation) {
        .@"test", .review => return @import("crs_task_client.zig").run(
            &session,
            args,
            budget,
            writer,
        ),
        .status => try reply.status(&session, snapshot),
        .select, .discard => {
            try edit(&session, args);
            try reply.status(&session, snapshot);
        },
        else => {
            try reply.status(&session, snapshot);
            if (snapshot.revision != args.revision.?) return error.Conflict;
            const id = args.id orelse snapshot.next_id;
            try prepare(&session, args, snapshot, id);
            awaitCandidate(&session, snapshot, id, budget) catch |err| {
                if (reply.find(snapshot, id)) |failed|
                    @import("crs_diagnostic.zig").report(failed.diagnostic);
                return err;
            };
            const candidate = reply.find(snapshot, id) orelse return error.InvalidResponse;
            var revision: [20]u8 = undefined;
            try std.json.Stringify.value(.{
                .protection = "unchanged",
                .candidate = candidate,
                .selection_requires_revision = std.fmt.bufPrint(
                    &revision,
                    "{d}",
                    .{args.revision.?},
                ) catch unreachable,
            }, .{}, writer);
            return writer.writeByte('\n');
        },
    }
    // Desired state and boot-fenced receipts stay distinct in this typed report.
    try std.json.Stringify.value(snapshot.*, .{}, writer);
    try writer.writeByte('\n');
}

fn awaitCandidate(
    session: *client.Session,
    snapshot: *p.crs_api.Status,
    id: p.crs_management.Id,
    budget: Budget,
) Error!void {
    while (true) {
        try reply.statusWithin(session, snapshot, try budget.remaining(session.io));
        if (reply.find(snapshot, id)) |candidate| switch (candidate.state) {
            .verified => return,
            .preparing => {},
            else => return error.PreparationFailed,
        };
        try budget.wait(session.io);
    }
}

fn edit(session: *client.Session, args: arguments.Args) Error!void {
    var bytes: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    var writer: Writer = .fixed(&bytes);
    var revision: [20]u8 = undefined;
    try std.json.Stringify.value(.{
        .id = args.id.?.slice(),
        .expected_revision = std.fmt.bufPrint(&revision, "{d}", .{args.revision.?}) catch
            unreachable,
    }, .{}, &writer);
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    const selecting = args.operation == .select;
    const result = try session.request(
        if (selecting) .crs_select else .crs_discard,
        bytes[0..writer.end],
        &response,
    );
    try sessions.requireOk(result.status);
    if (selecting) {
        var committed: struct {
            committed: bool,
            revision: u64,
            application: p.Bytes(16),
        } = undefined;
        try reply.read(
            session.allocator,
            @TypeOf(committed),
            &committed,
            response[0..result.length],
        );
        if (!committed.committed or committed.revision != args.revision.? + 1 or
            !std.mem.eql(u8, committed.application.slice(), "unconfirmed"))
            return error.InvalidResponse;
    } else {
        var discarded: struct { discarded: bool } = undefined;
        try reply.read(
            session.allocator,
            @TypeOf(discarded),
            &discarded,
            response[0..result.length],
        );
        if (!discarded.discarded) return error.InvalidResponse;
    }
}

fn prepare(
    session: *client.Session,
    args: arguments.Args,
    snapshot: *const p.crs_api.Status,
    id: p.crs_management.Id,
) Error!void {
    const source = @import("crs_candidate.zig").readConfiguration(
        session.allocator,
        session.io,
        args.configuration,
    ) catch return error.InvalidConfiguration;
    defer session.allocator.free(source.buffer);
    defer std.crypto.secureZero(u8, source.buffer);
    const bytes = try session.allocator.alloc(u8, p.crs_api.body_bytes);
    defer session.allocator.free(bytes);
    defer std.crypto.secureZero(u8, bytes);
    var writer: Writer = .fixed(bytes);
    var revision: [20]u8 = undefined;
    var version_buffer: [17]u8 = undefined;
    const version = if (args.version) |value|
        value.write(&version_buffer) catch return error.InvalidConfiguration
    else
        null;
    const settings = try @import("crs_management_settings.zig").read(session, args, snapshot);
    try std.json.Stringify.value(.{
        .id = id.slice(),
        .kind = @tagName(args.operation),
        .expected_revision = std.fmt.bufPrint(&revision, "{d}", .{args.revision.?}) catch
            unreachable,
        .version = version,
        .settings = settings,
        .configuration = if (args.configuration != null) source.value else @as(?[]const u8, null),
    }, .{}, &writer);
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    const result = try session.request(.crs_prepare, bytes[0..writer.end], &response);
    try sessions.requireOk(result.status);
    var accepted: struct { accepted: bool, id: p.crs_management.Id } = undefined;
    try reply.read(session.allocator, @TypeOf(accepted), &accepted, response[0..result.length]);
    if (!accepted.accepted or !std.mem.eql(u8, accepted.id.slice(), id.slice()))
        return error.InvalidResponse;
}

test {
    _ = arguments;
    _ = reply;
}
