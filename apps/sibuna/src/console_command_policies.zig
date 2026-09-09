//! Managed policy set transfer. Export walks the catalog and prints every document as one
//! JSON array; import stages the array's documents in chunks under one digest and commits
//! them against the revision observed at the start, so a concurrent edit is refused.
const std = @import("std");
const p = @import("console").protocol;
const client = @import("console_client.zig");
const command = @import("console_command.zig");
const arguments = @import("console_command_args.zig");
const Error = command.Error;
const max_file = 640 * 1024;

pub fn run(session: *client.Session, args: arguments.Args, writer: *std.Io.Writer) Error!void {
    if (args.kind == .policies_export) return exportSet(session, writer);
    return importSet(session, args, writer);
}

fn call(
    session: *client.Session,
    endpoint: client.Endpoint,
    payload: *[2048]u8,
    body: []const u8,
    output: *[client.max_response + 1]u8,
) Error![]const u8 {
    @memcpy(payload[0..body.len], body);
    const reply = try session.request(endpoint, payload[0..body.len], output);
    try command.requireOk(reply.status);
    return output[0..reply.length];
}

fn exportSet(session: *client.Session, writer: *std.Io.Writer) Error!void {
    var payload: [2048]u8 = undefined;
    var output: [client.max_response + 1]u8 = undefined;
    var document_output: [client.max_response + 1]u8 = undefined;
    var after: p.Bytes(128) = .{};
    var written: usize = 0;
    try writer.writeByte('[');
    while (true) {
        var request: [256]u8 = undefined;
        const body = std.fmt.bufPrint(&request, "{{\"kind\":\"catalog\",\"after\":\"{s}\"}}", .{
            after.slice(),
        }) catch return error.InvalidResponse;
        const page = try call(session, .policies_read, &payload, body, &output);
        var memory: [16384]u8 = undefined;
        var arena = std.heap.FixedBufferAllocator.init(&memory);
        const parsed = std.json.parseFromSliceLeaky(struct {
            rows: []const struct { id: []const u8 },
            next: ?[]const u8 = null,
        }, arena.allocator(), page, .{ .ignore_unknown_fields = true }) catch
            return error.InvalidResponse;
        for (parsed.rows) |row| {
            var read: [256]u8 = undefined;
            const read_body = std.fmt.bufPrint(
                &read,
                "{{\"kind\":\"document\",\"id\":\"{s}\"}}",
                .{row.id},
            ) catch return error.InvalidResponse;
            const reply = try call(session, .policies_read, &payload, read_body, &document_output);
            var document_memory: [16384]u8 = undefined;
            var document_arena = std.heap.FixedBufferAllocator.init(&document_memory);
            const document = std.json.parseFromSliceLeaky(
                struct { document: []const u8 },
                document_arena.allocator(),
                reply,
                .{ .ignore_unknown_fields = true },
            ) catch return error.InvalidResponse;
            if (written != 0) try writer.writeByte(',');
            try writer.writeAll(document.document);
            written += 1;
        }
        const next = parsed.next orelse break;
        if (next.len == 0 or next.len > 128) return error.InvalidResponse;
        after = p.Bytes(128).init(next) catch return error.InvalidResponse;
    }
    try writer.writeAll("]\n");
}

fn importSet(session: *client.Session, args: arguments.Args, writer: *std.Io.Writer) Error!void {
    const text = try readFile(session, args.file);
    defer session.allocator.free(text);
    const memory = session.allocator.alloc(u8, 2 * max_file) catch return error.OutOfMemory;
    defer session.allocator.free(memory);
    var arena = std.heap.FixedBufferAllocator.init(memory);
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), text, .{}) catch
        return error.InvalidResponse;
    if (root != .array or root.array.items.len == 0 or root.array.items.len > 128)
        return error.InvalidResponse;
    var payload: [2048]u8 = undefined;
    var output: [client.max_response + 1]u8 = undefined;
    const page = try call(session, .policies_query, &payload, "{}", &output);
    var page_memory: [8192]u8 = undefined;
    var page_arena = std.heap.FixedBufferAllocator.init(&page_memory);
    const committed = std.json.parseFromSliceLeaky(
        struct { committed: []const u8 },
        page_arena.allocator(),
        page,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidResponse;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var documents: [128][]const u8 = undefined;
    for (root.array.items, 0..) |item, index| {
        if (item != .object) return error.InvalidResponse;
        var document: std.Io.Writer.Allocating = .init(arena.allocator());
        std.json.Stringify.value(item, .{}, &document.writer) catch return error.InvalidResponse;
        const bytes = document.written();
        if (bytes.len > 1536) return error.InvalidResponse;
        if (index != 0) hash.update("\n");
        hash.update(bytes);
        documents[index] = bytes;
    }
    const digest = std.fmt.bytesToHex(hash.finalResult(), .lower);
    for (documents[0..root.array.items.len], 0..) |document, ordinal| {
        var chunk: std.Io.Writer.Allocating = .init(arena.allocator());
        std.json.Stringify.value(.{
            .digest = @as([]const u8, &digest),
            .ordinal = ordinal,
            .document = document,
        }, .{}, &chunk.writer) catch return error.InvalidResponse;
        if (chunk.written().len > payload.len) return error.InvalidResponse;
        _ = try call(session, .policies_import_chunk, &payload, chunk.written(), &output);
    }
    var commit: [256]u8 = undefined;
    const commit_body = std.fmt.bufPrint(
        &commit,
        "{{\"digest\":\"{s}\",\"count\":{d},\"expected_revision\":\"{s}\"}}",
        .{ digest, root.array.items.len, committed.committed },
    ) catch return error.InvalidResponse;
    const reply = try call(session, .policies_import_commit, &payload, commit_body, &output);
    try writer.writeAll(reply);
    try writer.writeByte('\n');
}

fn readFile(session: *client.Session, path: []const u8) Error![]u8 {
    const file = std.Io.Dir.cwd().openFile(session.io, path, .{}) catch
        return error.CredentialFile;
    defer file.close(session.io);
    const buffer = session.allocator.alloc(u8, max_file + 1) catch return error.OutOfMemory;
    errdefer session.allocator.free(buffer);
    var reader = file.reader(session.io, buffer[0..0]);
    const length = reader.interface.readSliceShort(buffer) catch return error.CredentialFile;
    if (length > max_file) return error.InvalidResponse;
    return session.allocator.realloc(buffer, length) catch buffer[0..length];
}
