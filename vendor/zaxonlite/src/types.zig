//! The single concrete ReplicatedLog instantiation shared by every
//! zaxonlite module, plus wire encodings for its entry and write types.

const std = @import("std");
const paxos = @import("paxos");
const command = @import("command.zig");

pub const Command = command.Command;

/// Compile-time bounds for the replicated command log. `window_slots` is the
/// consensus window: a backpressure bound on how far chosen history can run
/// ahead of the trimmed floor. The ZDS 0011 certified chosen trim path
/// advances that floor during normal service (before ZDS 0011 the window was
/// a hard epoch capacity the host had to checkpoint before reaching).
pub const log_options = paxos.ReplicatedLogOptions{
    // This is a voter bound, not a total-node bound. Non-voting learners and
    // gateways live in the runtime product registry and do not consume these
    // slots. Nine voters tolerate four failures; larger deployments add an
    // arbitrary number of replicas or shard into independent voter groups.
    .max_members = 9,
    // 2048 keeps a 100-operation warmup plus a normal 1000-operation run
    // inside one epoch. At 256,
    // four checkpoint/re-election pauses dominated sustained write latency
    // even though the steady-state commit path was faster. The bound remains
    // deliberately small compared with an unbounded database log.
    .window_slots = 2048,
    .max_batch = 16,
    // A batch's chain base is read from applied state, so a new leader
    // must deliver everything it inherited before it proposes again.
    .gate_proposals_on_inherited_prefix = true,
    // 512 holds zx2 stop metadata: checkpoint name, manifest digest,
    // next-registry digest, and the bounded replacement seed.
    .max_metadata_bytes = 512,
};

pub const Log = paxos.ReplicatedLog(Command, log_options);

pub const Entry = Log.Entry;
pub const StopSign = Log.StopSign;
pub const Write = Log.Write;

/// Maximum canonical encoded size of one `Entry`.
pub const max_entry_size = blk: {
    const stop_size = 8 + 2 + log_options.max_members * @sizeOf(paxos.NodeId) +
        2 + log_options.max_metadata_bytes;
    break :blk 1 + @max(command.encoded_size, stop_size);
};

pub const ballot_size = 8 + 4 + 4;

/// Maximum canonical encoded size of one `Write` payload. The slot is a
/// 64-bit global instance number (ZDS 0011).
pub const max_write_size = 1 + ballot_size + 8 + max_entry_size;

pub const DecodeError = command.DecodeError || error{
    InvalidEntryTag,
    InvalidWriteTag,
    TruncatedRecord,
    InvalidStopSign,
};

pub fn encodeBallot(ballot: paxos.Ballot, writer: *Cursor) void {
    writer.int(u64, ballot.round);
    writer.int(u32, ballot.priority);
    writer.int(u32, ballot.node);
}

pub fn decodeBallot(reader: *ReadCursor) DecodeError!paxos.Ballot {
    return .{
        .round = try reader.int(u64),
        .priority = try reader.int(u32),
        .node = try reader.int(u32),
    };
}

pub fn encodeEntry(entry: Entry, writer: *Cursor) void {
    switch (entry) {
        .command => |cmd| {
            writer.byte(0);
            var buffer: [command.encoded_size]u8 = undefined;
            command.encode(cmd, &buffer);
            writer.bytes(&buffer);
        },
        .stop => |stop| {
            writer.byte(1);
            writer.int(u64, stop.configuration_id);
            const members = stop.membersSlice();
            writer.int(u16, @intCast(members.len));
            for (members) |member| writer.int(u32, member);
            const metadata = stop.metadataSlice();
            writer.int(u16, @intCast(metadata.len));
            writer.bytes(metadata);
        },
    }
}

pub fn decodeEntry(reader: *ReadCursor) DecodeError!Entry {
    const tag = try reader.byte();
    switch (tag) {
        0 => {
            const raw = try reader.take(command.encoded_size);
            return .{ .command = try command.decode(raw) };
        },
        1 => {
            const configuration_id = try reader.int(u64);
            const member_count = try reader.int(u16);
            if (member_count == 0 or member_count > log_options.max_members) {
                return error.InvalidStopSign;
            }
            var members: [log_options.max_members]paxos.NodeId = undefined;
            for (members[0..member_count]) |*member| {
                member.* = try reader.int(u32);
            }
            const metadata_count = try reader.int(u16);
            if (metadata_count > log_options.max_metadata_bytes) {
                return error.InvalidStopSign;
            }
            const metadata = try reader.take(metadata_count);

            // The library validates the configuration ID and the member
            // list, including zero and duplicate IDs a raw copy would let
            // through.
            const stop = StopSign.create(
                configuration_id,
                members[0..member_count],
                metadata,
            ) catch return error.InvalidStopSign;
            return .{ .stop = stop };
        },
        else => return error.InvalidEntryTag,
    }
}

pub fn encodeWrite(write: Write, writer: *Cursor) void {
    switch (write) {
        .promise => |ballot| {
            writer.byte(0);
            encodeBallot(ballot, writer);
        },
        .accept => |accept| {
            writer.byte(1);
            encodeBallot(accept.ballot, writer);
            writer.int(u64, accept.slot);
            encodeEntry(accept.value, writer);
        },
        .commit => |commit| {
            writer.byte(2);
            writer.int(u64, commit.slot);
            encodeEntry(commit.value, writer);
        },
        .trim_anchor => |anchor| {
            writer.byte(3);
            writer.int(u64, anchor.trim_id);
            writer.int(u64, anchor.chosen_trim_slot);
            writer.bytes(&anchor.history_hash);
        },
    }
}

pub fn decodeWrite(buffer: []const u8) DecodeError!Write {
    var reader = ReadCursor{ .buffer = buffer };
    const tag = try reader.byte();
    const write: Write = switch (tag) {
        0 => .{ .promise = try decodeBallot(&reader) },
        1 => .{ .accept = .{
            .ballot = try decodeBallot(&reader),
            .slot = try reader.int(u64),
            .value = try decodeEntry(&reader),
        } },
        2 => .{ .commit = .{
            .slot = try reader.int(u64),
            .value = try decodeEntry(&reader),
        } },
        3 => blk: {
            var anchor = Log.TrimAnchor{
                .trim_id = try reader.int(u64),
                .chosen_trim_slot = try reader.int(u64),
            };
            const hash = try reader.take(32);
            @memcpy(&anchor.history_hash, hash);
            break :blk .{ .trim_anchor = anchor };
        },
        else => return error.InvalidWriteTag,
    };
    if (reader.offset != buffer.len) return error.TruncatedRecord;
    return write;
}

pub const Cursor = struct {
    buffer: []u8,
    offset: usize = 0,

    pub fn byte(self: *Cursor, value: u8) void {
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    pub fn int(self: *Cursor, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.buffer[self.offset..][0..@sizeOf(T)], value, .little);
        self.offset += @sizeOf(T);
    }

    pub fn bytes(self: *Cursor, value: []const u8) void {
        @memcpy(self.buffer[self.offset..][0..value.len], value);
        self.offset += value.len;
    }
};

pub const ReadCursor = struct {
    buffer: []const u8,
    offset: usize = 0,

    pub fn byte(self: *ReadCursor) DecodeError!u8 {
        if (self.offset + 1 > self.buffer.len) return error.TruncatedRecord;
        const value = self.buffer[self.offset];
        self.offset += 1;
        return value;
    }

    pub fn int(self: *ReadCursor, comptime T: type) DecodeError!T {
        if (self.offset + @sizeOf(T) > self.buffer.len) return error.TruncatedRecord;
        const value = std.mem.readInt(
            T,
            self.buffer[self.offset..][0..@sizeOf(T)],
            .little,
        );
        self.offset += @sizeOf(T);
        return value;
    }

    pub fn take(self: *ReadCursor, count: usize) DecodeError![]const u8 {
        if (self.offset + count > self.buffer.len) return error.TruncatedRecord;
        const slice = self.buffer[self.offset..][0..count];
        self.offset += count;
        return slice;
    }
};

test "write records round trip" {
    const ballot = paxos.Ballot{ .round = 9, .priority = 2, .node = 1 };
    const noop_cmd = Command.noop;
    const stop = try StopSign.create(7, &.{ 1, 2, 3 }, "manifest");

    const cases = [_]Write{
        .{ .promise = ballot },
        .{ .accept = .{ .ballot = ballot, .slot = 3, .value = .{ .command = noop_cmd } } },
        .{ .commit = .{ .slot = 3, .value = .{ .stop = stop } } },
    };
    for (cases) |case| {
        var buffer: [max_write_size]u8 = undefined;
        var cursor = Cursor{ .buffer = &buffer };
        encodeWrite(case, &cursor);
        const decoded = try decodeWrite(buffer[0..cursor.offset]);
        try std.testing.expectEqualDeep(case, decoded);
    }
}

test "stop sign decoder rejects duplicate and zero member ids" {
    const cases = [_][]const paxos.NodeId{
        &.{ 1, 2, 2 },
        &.{ 1, 0, 3 },
    };
    for (cases) |bad_members| {
        var buffer: [max_entry_size]u8 = undefined;
        var cursor = Cursor{ .buffer = &buffer };
        cursor.byte(1);
        cursor.int(u64, 7);
        cursor.int(u16, @intCast(bad_members.len));
        for (bad_members) |member| cursor.int(u32, member);
        cursor.int(u16, 0);
        var reader = ReadCursor{ .buffer = buffer[0..cursor.offset] };
        try std.testing.expectError(error.InvalidStopSign, decodeEntry(&reader));
    }
}
