//! Publisher imports run in the daemon; this client observes the committed generation.
//! Polling has one monotonic budget, including HTTP waits. Session closure does not imply
//! that a timed-out import rolled back: activation may have committed before response loss.
const std = @import("std");
const p = @import("console").protocol;
const geoip = @import("console").geoip;
const client = @import("console_client.zig");
const command = @import("console_command.zig");
const arguments = @import("console_command_args.zig");
const Error = command.Error;
const Status = enum { idle, downloading, validating, storing, applied, failed };
const Metadata = struct {
    revision: u64,
    digest: p.Bytes(64),
    provider: p.Bytes(p.geo.max_provider),
    version: p.Bytes(p.geo.max_version),
    status: Status,
    progress: u32,
};
const Wire = struct {
    revision: u64,
    digest: []const u8,
    provider: []const u8,
    source_version: []const u8,
    source_digests: []const u8,
    ranges: u32,
    loaded_at: u64,
    status: Status,
    processed_ranges: u32,
    source: []const u8,
    license: []const u8,
    attribution: []const u8,
};
const Budget = struct {
    end: i96,

    fn remaining(self: Budget, io: std.Io) Error!u64 {
        const duration = self.end - std.Io.Clock.awake.now(io).nanoseconds;
        if (duration <= 0) return error.Deadline;
        return @intCast(@min(duration, 20 * std.time.ns_per_s));
    }
};

pub fn run(session: *client.Session, args: arguments.Args, writer: *std.Io.Writer) Error!void {
    var buffer: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const budget: Budget = .{
        .end = std.Io.Clock.awake.now(session.io).nanoseconds +
            @as(i96, args.timeout) * std.time.ns_per_s,
    };
    const length = try query(session, &buffer, budget);
    const before = try parse(buffer[0..length]);
    if (args.kind == .geo_status or try alreadyActive(before, args)) {
        try writer.writeAll(buffer[0..length]);
        return writer.writeByte('\n');
    }
    if (before.revision == std.math.maxInt(i64) or busy(before.status)) return error.Conflict;
    try submit(session, args, before.revision, &buffer, budget);
    var last_status: ?Status = null;
    var last_progress: u32 = 0;
    while (true) {
        const received = try query(session, &buffer, budget);
        const current = try parse(buffer[0..received]);
        if (current.revision != before.revision) {
            if (current.revision != before.revision + 1 or !try alreadyActive(current, args))
                return error.Conflict;
            try writer.writeAll(buffer[0..received]);
            return writer.writeByte('\n');
        }
        if (current.status == .failed) return error.ImportFailed;
        if (last_status != current.status or last_progress != current.progress) {
            std.debug.print("GeoIP {t}: {d} ranges\n", .{ current.status, current.progress });
            last_status = current.status;
            last_progress = current.progress;
        }
        const delay = @min(try budget.remaining(session.io), 2 * std.time.ns_per_s);
        std.Io.sleep(session.io, .fromNanoseconds(delay), .awake) catch return error.Canceled;
    }
}

fn alreadyActive(metadata: Metadata, args: arguments.Args) Error!bool {
    if (metadata.revision == 0 or !std.mem.eql(u8, metadata.version.slice(), args.version) or
        !std.mem.eql(u8, metadata.provider.slice(), args.provider)) return false;
    if (args.checksum.len != 0 and
        !std.ascii.eqlIgnoreCase(metadata.digest.slice(), args.checksum)) return error.Conflict;
    return true;
}

fn busy(status: Status) bool {
    return status == .downloading or status == .validating or status == .storing;
}

fn query(
    session: *client.Session,
    output: *[client.max_response + 1]u8,
    budget: Budget,
) Error!usize {
    var empty: [0]u8 = .{};
    const reply = try session.requestWithin(
        .geo_status,
        &empty,
        output,
        try budget.remaining(session.io),
    );
    try command.requireOk(reply.status);
    return reply.length;
}

fn submit(
    session: *client.Session,
    args: arguments.Args,
    revision: u64,
    output: *[client.max_response + 1]u8,
    budget: Budget,
) Error!void {
    var payload: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &payload);
    var body: std.Io.Writer = .fixed(&payload);
    var revision_buffer: [20]u8 = undefined;
    const expected = std.fmt.bufPrint(&revision_buffer, "{d}", .{revision}) catch unreachable;
    try std.json.Stringify.value(.{
        .provider = args.provider,
        .source_version = args.version,
        .expected_revision = expected,
        .checksum = args.checksum,
    }, .{}, &body);
    const reply = try session.requestWithin(
        .geo_update,
        body.buffer[0..body.end],
        output,
        try budget.remaining(session.io),
    );
    try command.requireOk(reply.status);
    var scratch: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    const accepted = std.json.parseFromSlice(
        struct { accepted: bool },
        fixed.allocator(),
        output[0..reply.length],
        .{},
    ) catch return error.InvalidResponse;
    defer accepted.deinit();
    if (!accepted.value.accepted) return error.InvalidResponse;
}

fn parse(bytes: []const u8) Error!Metadata {
    var scratch: [16 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    const parsed = std.json.parseFromSlice(Wire, fixed.allocator(), bytes, .{}) catch
        return error.InvalidResponse;
    defer parsed.deinit();
    const wire = parsed.value;
    if (wire.revision > std.math.maxInt(i64) or wire.ranges > 1024 * 1024 or
        wire.processed_ranges > 1024 * 1024) return error.InvalidResponse;
    const provider = geoip.Provider.parse(wire.provider) orelse return error.InvalidResponse;
    // An embedded build snapshot reports revision 0 with a populated generation.
    const embedded = wire.revision == 0 and std.mem.eql(u8, wire.source, "embedded snapshot");
    if ((!embedded and !std.mem.eql(u8, wire.source, provider.title())) or
        !std.mem.eql(u8, wire.license, provider.license()) or
        !std.mem.eql(u8, wire.attribution, provider.attribution() orelse "") or
        !p.geo.validSourceDigests(wire.source_digests)) return error.InvalidResponse;
    if (wire.revision == 0 and !embedded) {
        if (wire.digest.len != 0 or wire.source_version.len != 0 or
            wire.ranges != 0 or wire.loaded_at != 0) return error.InvalidResponse;
    } else {
        if (wire.digest.len != 64 or !provider.versionValid(wire.source_version) or
            wire.ranges == 0 or (wire.loaded_at == 0) != embedded) return error.InvalidResponse;
        for (wire.digest) |byte| if (!std.ascii.isHex(byte)) return error.InvalidResponse;
    }
    return .{
        .revision = wire.revision,
        .digest = p.Bytes(64).init(wire.digest) catch return error.InvalidResponse,
        .provider = p.Bytes(p.geo.max_provider).init(wire.provider) catch
            return error.InvalidResponse,
        .version = p.Bytes(p.geo.max_version).init(wire.source_version) catch
            return error.InvalidResponse,
        .status = wire.status,
        .progress = wire.processed_ranges,
    };
}
