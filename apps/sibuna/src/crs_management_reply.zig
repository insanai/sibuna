//! Native and Wasm clients decode the same owned contract. No raw response or
//! private error text is printed by the CLI, even if a peer adds unknown fields.
const std = @import("std");
const p = @import("console").protocol;
const client = @import("console_client.zig");
const sessions = @import("console_session.zig");
pub const Error = sessions.Error;

// A full four-candidate/nine-member view fits the 16 KiB wire bound, but its JSON
// object maps need more storage than the encoded bytes. Share the UI's bounded
// 512 KiB parser allowance; keep it off native I/O worker stacks and erase it.
pub fn read(
    allocator: std.mem.Allocator,
    comptime T: type,
    output: *T,
    bytes: []const u8,
) Error!void {
    if (bytes.len > client.max_response) return error.ResponseTooLarge;
    const arena = try allocator.alloc(u8, 512 * 1024);
    defer allocator.free(arena);
    defer std.crypto.secureZero(u8, arena);
    var fixed = std.heap.FixedBufferAllocator.init(arena);
    const parsed = std.json.parseFromSlice(std.json.Value, fixed.allocator(), bytes, .{}) catch
        return error.InvalidResponse;
    defer parsed.deinit();
    p.json_value.into(output, parsed.value, fixed.allocator()) catch return error.InvalidResponse;
}

pub fn status(session: *client.Session, output: *p.crs_api.Status) Error!void {
    return statusWithin(session, output, 20 * std.time.ns_per_s);
}

pub fn statusWithin(
    session: *client.Session,
    output: *p.crs_api.Status,
    remaining_ns: u64,
) Error!void {
    var empty: [0]u8 = .{};
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    const timeout = @min(remaining_ns, 20 * std.time.ns_per_s);
    const reply = try session.requestWithin(.crs_status, &empty, &response, timeout);
    try sessions.requireOk(reply.status);
    try read(session.allocator, p.crs_api.Status, output, response[0..reply.length]);
    try output.validate();
}

pub fn find(snapshot: *const p.crs_api.Status, id: p.crs_management.Id) ?p.crs_api.Candidate {
    for (snapshot.candidates[0..snapshot.count]) |row| {
        const candidate = row.?;
        if (std.mem.eql(u8, candidate.id.slice(), id.slice())) return candidate;
    }
    return null;
}

test "native CRS replies preserve full revisions and omit unexpected peer fields" {
    const t = std.testing;
    var output: struct { committed: bool, revision: u64, application: p.Bytes(16) } = undefined;
    const valid = "{\"committed\":true,\"revision\":\"9007199254740993\"," ++
        "\"application\":\"unconfirmed\",\"private_trace\":\"not printed\"}";
    try read(t.allocator, @TypeOf(output), &output, valid);
    try t.expectEqual(@as(u64, 9007199254740993), output.revision);
    try t.expectEqualStrings("unconfirmed", output.application.slice());
    const invalid = "{\"committed\":true,\"revision\":\"+1\"," ++
        "\"application\":\"unconfirmed\"}";
    try t.expectError(error.InvalidResponse, read(t.allocator, @TypeOf(output), &output, invalid));
}

test "native CRS replies decode a full candidate and member view within the wire bound" {
    const t = std.testing;
    const id = try p.crs_management.Id.init("11111111111111111111111111111111");
    const candidate: p.crs_api.Candidate = .{
        .id = id,
        .kind = .rollback,
        .state = .selected,
        .expected_revision = 9007199254740992,
        .created_at = 9007199254740992,
        .expires = 9007199254740992,
        .verified_at = 9007199254740992,
        .completed_at = 9007199254740992,
        .reason = .none,
        .artifact = .{
            .revision = 9007199254740993,
            .previous_revision = 9007199254740992,
            .release = try p.Bytes(17).init("65535.65535.65535"),
            .source_digest = try p.Bytes(64).init(&@as([64]u8, @splat('1'))),
            .operator_digest = try p.Bytes(64).init(&@as([64]u8, @splat('2'))),
            .conditions = 701,
            .compiled_peak = 9007199254740993,
            .settings = .{},
        },
    };
    var previous = candidate;
    previous.artifact.?.revision -= 1;
    var snapshot: p.crs_api.Status = .{
        .available = true,
        .next_id = id,
        .revision = candidate.artifact.?.revision,
        .selected_at = candidate.created_at,
        .current = candidate,
        .previous = previous,
        .candidates = @splat(candidate),
        .count = p.crs_management.candidate_capacity,
        .nodes = @splat(.{
            .node = 1,
            .boot = id,
            .revision = 9007199254740993,
            .applied = true,
            .observed_at = 9007199254740993,
        }),
        .node_count = p.nodes.max_members,
        .local = .{},
        .job = id,
        .stage = .verified,
        .reason = .none,
    };
    try snapshot.validate();
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, snapshot, .{});
    defer t.allocator.free(bytes);
    try t.expect(bytes.len <= client.max_response);
    var decoded: p.crs_api.Status = undefined;
    try read(t.allocator, p.crs_api.Status, &decoded, bytes);
    try decoded.validate();
    try t.expectEqualDeep(snapshot, decoded);
}
