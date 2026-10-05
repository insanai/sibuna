//! Native reviews and samples share submission, deadlines and polling. The
//! issuing session stays alive through polling and is closed by the composing CLI.
const std = @import("std");
const p = @import("console").protocol;
const sample = p.crs_tests.sample;
const client = @import("console_client.zig");
const sessions = @import("console_session.zig");
const reply = @import("crs_management_reply.zig");
const Args = @import("crs_management_args.zig").Args;
const Budget = @import("console_deadline.zig").Budget;
pub const Error = sessions.Error || error{ InvalidConfiguration, ManagedTaskFailed };

pub fn run(
    session: *client.Session,
    args: Args,
    budget: Budget,
    writer: *std.Io.Writer,
) Error!void {
    const kind: p.crs_tasks.Kind = if (args.operation == .review) .review else .sample;
    const id = if (kind == .review)
        try review(session, args, budget)
    else
        try submit(session, args, budget);
    const output = try session.allocator.create(p.crs_tests.Status);
    defer session.allocator.destroy(output);
    var bytes: [64]u8 = undefined;
    var query: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(.{ .id = id.slice() }, .{}, &query);
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    const endpoint: client.Endpoint = if (kind == .review) .crs_review_read else .crs_test_read;
    while (true) {
        const timeout = @min(20 * std.time.ns_per_s, try budget.remaining(session.io));
        const body_query = query.buffered();
        const received = try session.requestWithin(endpoint, body_query, &response, timeout);
        try sessions.requireOk(received.status);
        const body = response[0..received.length];
        try reply.read(session.allocator, p.crs_tests.Status, output, body);
        output.validate() catch return error.InvalidResponse;
        if (output.kind != kind or !std.mem.eql(u8, output.id.slice(), id.slice()))
            return error.InvalidResponse;
        if (output.state == .failed) {
            @import("crs_diagnostic.zig").report(output.diagnostic);
            if (output.failure) |cause| std.debug.print("CRSTASKFAILED: {s}. " ++
                "Hint: refresh the source and saved revision before retrying.\n", .{
                cause.slice(),
            });
            return error.ManagedTaskFailed;
        }
        if (output.state == .complete) break;
        try budget.wait(session.io);
    }
    try std.json.Stringify.value(.{
        .private_test = kind == .sample,
        .rule_review = kind == .review,
        .active_protection = "unchanged",
        .origin_contacted = false,
        .result = output.*,
    }, .{}, writer);
    try writer.writeByte('\n');
}

fn submit(session: *client.Session, args: Args, budget: Budget) Error!p.crs_management.Id {
    const source = @import("crs_candidate.zig").readFile(
        session.allocator,
        session.io,
        args.sample_file.?,
        sample.sample_json_bytes,
    ) catch return error.InvalidConfiguration;
    defer session.allocator.free(source.buffer);
    defer std.crypto.secureZero(u8, source.buffer);
    const memory = try session.allocator.alloc(u8, sample.parser_bytes);
    defer session.allocator.free(memory);
    defer std.crypto.secureZero(u8, memory);
    var arena: std.heap.FixedBufferAllocator = .init(memory);
    const parsed = sample.decode(arena.allocator(), source.value) catch
        return error.InvalidConfiguration;
    defer parsed.deinit();
    const bytes = try session.allocator.alloc(u8, sample.sample_json_bytes);
    defer session.allocator.free(bytes);
    defer std.crypto.secureZero(u8, bytes);
    var writer: std.Io.Writer = .fixed(bytes);
    var revision: [20]u8 = undefined;
    const expected_revision = std.fmt.bufPrint(&revision, "{d}", .{args.revision.?}) catch
        unreachable;
    try std.json.Stringify.value(.{
        .source = args.id.?.slice(),
        .expected_revision = expected_revision,
        .mode = args.mode,
        .sample = parsed.value,
    }, .{}, &writer);
    return accepted(session, .crs_test, writer.buffered(), budget);
}

fn accepted(
    session: *client.Session,
    endpoint: client.Endpoint,
    body: []u8,
    budget: Budget,
) Error!p.crs_management.Id {
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    const timeout = @min(20 * std.time.ns_per_s, try budget.remaining(session.io));
    const received = try session.requestWithin(endpoint, body, &response, timeout);
    try sessions.requireOk(received.status);
    var acknowledgement: struct { accepted: bool, id: p.crs_management.Id } = undefined;
    const bytes = response[0..received.length];
    try reply.read(session.allocator, @TypeOf(acknowledgement), &acknowledgement, bytes);
    if (!acknowledgement.accepted or !p.crs_management.validId(acknowledgement.id))
        return error.InvalidResponse;
    return acknowledgement.id;
}

fn review(session: *client.Session, args: Args, budget: Budget) Error!p.crs_management.Id {
    var bytes: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    var writer: std.Io.Writer = .fixed(&bytes);
    var revision: [20]u8 = undefined;
    try std.json.Stringify.value(.{
        .source = args.id.?.slice(),
        .expected_revision = std.fmt.bufPrint(&revision, "{d}", .{args.revision.?}) catch
            unreachable,
    }, .{}, &writer);
    return accepted(session, .crs_review, writer.buffered(), budget);
}
