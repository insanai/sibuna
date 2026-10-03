//! The fixed-size replicated command descriptor and its canonical codec.
//!
//! Paxos never carries transaction bytes directly. A `transaction_batch`
//! descriptor names an immutable payload by content hash; the payload store
//! owns the bytes. Chain hashes are cumulative replicated-history identities
//! computed in O(1) per descriptor, not hashes of the SQLite file.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const HashBytes = [32]u8;

/// Maximum external payload carried by one wire frame (hash plus bytes must
/// fit below the protocol's 64 MiB frame-body bound).
/// Leaves room below the 64 MiB frame bound for the content hash (32),
/// authenticated sequence (8), HMAC-SHA256 tag (32), and strict `<` bound.
pub const max_payload_bytes: usize = 64 * 1024 * 1024 - 73;

pub const TransactionBatch = struct {
    database_id: u128,
    batch_id: u128,
    base_data_slot: u64,
    base_chain_hash: HashBytes,
    result_chain_hash: HashBytes,
    payload_hash: HashBytes,
    payload_bytes: u64,
    transaction_count: u32,
    frame_count: u32,
};

pub const ReadBarrier = struct {
    nonce: u128,
};

/// A chosen log-trim decision (ZDS 0011): every slot at or below
/// `through_slot` is chosen under `history_hash`, and nodes may release
/// journal history through it subject to their local delete rules. The
/// command's chosen global log slot is its identity; it is deliberately not
/// repeated inside the command body.
pub const TrimRecord = struct {
    through_slot: u64,
    history_hash: HashBytes,
    configuration_id: u64,
    /// The trim policy that produced the anchor. Zero is the only v1
    /// policy: the minimum durable-state frontier of every data replica.
    policy: u8,
};

/// A chosen state-transfer lease (ZDS 0011): while active, every node caps
/// physical deletion at `base_slot` so the receiver's replay suffix
/// survives even if the original sender fails.
pub const TransferLease = struct {
    lease_id: u64,
    receiver_id: u32,
    base_slot: u64,
    base_history_hash: HashBytes,
    configuration_id: u64,
    expires_after_leader_ticks: u32,
};

/// Releases a transfer lease after the receiver durably installed the
/// image and caught up, or after the leader expired it.
pub const LeaseComplete = struct {
    lease_id: u64,
};

pub const Command = union(enum) {
    noop,
    transaction_batch: TransactionBatch,
    read_barrier: ReadBarrier,
    trim: TrimRecord,
    transfer_lease: TransferLease,
    lease_complete: LeaseComplete,
};

/// Canonical little-endian encoding, fixed maximum size. The first byte is
/// the tag; unused trailing bytes are zero. `transaction_batch` remains the
/// largest variant, so the trim and lease records change nothing here.
pub const encoded_size = 1 + @sizeOf(u128) * 2 + @sizeOf(u64) * 2 + 32 * 3 + @sizeOf(u32) * 2;

pub const DecodeError = error{
    InvalidTag,
    InvalidPolicy,
    TruncatedCommand,
    NonCanonicalPadding,
};

pub fn encode(cmd: Command, out: *[encoded_size]u8) void {
    @memset(out, 0);
    var writer = FixedWriter{ .buffer = out };
    switch (cmd) {
        .noop => writer.byte(0),
        .transaction_batch => |batch| {
            writer.byte(1);
            writer.int(u128, batch.database_id);
            writer.int(u128, batch.batch_id);
            writer.int(u64, batch.base_data_slot);
            writer.bytes(&batch.base_chain_hash);
            writer.bytes(&batch.result_chain_hash);
            writer.bytes(&batch.payload_hash);
            writer.int(u64, batch.payload_bytes);
            writer.int(u32, batch.transaction_count);
            writer.int(u32, batch.frame_count);
        },
        .read_barrier => |barrier| {
            writer.byte(2);
            writer.int(u128, barrier.nonce);
        },
        .trim => |trim| {
            writer.byte(3);
            writer.int(u64, trim.through_slot);
            writer.bytes(&trim.history_hash);
            writer.int(u64, trim.configuration_id);
            writer.byte(trim.policy);
        },
        .transfer_lease => |lease| {
            writer.byte(4);
            writer.int(u64, lease.lease_id);
            writer.int(u32, lease.receiver_id);
            writer.int(u64, lease.base_slot);
            writer.bytes(&lease.base_history_hash);
            writer.int(u64, lease.configuration_id);
            writer.int(u32, lease.expires_after_leader_ticks);
        },
        .lease_complete => |complete| {
            writer.byte(5);
            writer.int(u64, complete.lease_id);
        },
    }
}

pub fn decode(buffer: []const u8) DecodeError!Command {
    if (buffer.len != encoded_size) return error.TruncatedCommand;
    var reader = FixedReader{ .buffer = buffer };
    const tag = reader.byte();
    const cmd: Command = switch (tag) {
        0 => .noop,
        1 => .{ .transaction_batch = .{
            .database_id = reader.int(u128),
            .batch_id = reader.int(u128),
            .base_data_slot = reader.int(u64),
            .base_chain_hash = reader.hash(),
            .result_chain_hash = reader.hash(),
            .payload_hash = reader.hash(),
            .payload_bytes = reader.int(u64),
            .transaction_count = reader.int(u32),
            .frame_count = reader.int(u32),
        } },
        2 => .{ .read_barrier = .{ .nonce = reader.int(u128) } },
        3 => blk: {
            const trim = TrimRecord{
                .through_slot = reader.int(u64),
                .history_hash = reader.hash(),
                .configuration_id = reader.int(u64),
                .policy = reader.byte(),
            };
            if (trim.policy != 0) return error.InvalidPolicy;
            break :blk .{ .trim = trim };
        },
        4 => .{ .transfer_lease = .{
            .lease_id = reader.int(u64),
            .receiver_id = reader.int(u32),
            .base_slot = reader.int(u64),
            .base_history_hash = reader.hash(),
            .configuration_id = reader.int(u64),
            .expires_after_leader_ticks = reader.int(u32),
        } },
        5 => .{ .lease_complete = .{ .lease_id = reader.int(u64) } },
        else => return error.InvalidTag,
    };
    for (buffer[reader.offset..]) |trailing| {
        if (trailing != 0) return error.NonCanonicalPadding;
    }
    return cmd;
}

/// The genesis chain identity for a fresh database.
pub fn genesisChain(database_id: u128) HashBytes {
    var hasher = Sha256.init(.{});
    hasher.update("zaxonlite.chain.genesis.v1");
    hasher.update(&encodeInt(u128, database_id));
    var digest: HashBytes = undefined;
    hasher.final(&digest);
    return digest;
}

/// One O(1) cumulative chain step over a domain-separated, length-implicit
/// fixed-width canonical encoding:
/// C_i = H(C_{i-1}, database_id, batch_id, base_data_slot, payload_hash,
///         payload_bytes, transaction_count, frame_count).
pub fn chainStep(
    base_chain_hash: HashBytes,
    batch: TransactionBatch,
) HashBytes {
    var hasher = Sha256.init(.{});
    hasher.update("zaxonlite.chain.step.v1");
    hasher.update(&base_chain_hash);
    hasher.update(&encodeInt(u128, batch.database_id));
    hasher.update(&encodeInt(u128, batch.batch_id));
    hasher.update(&encodeInt(u64, batch.base_data_slot));
    hasher.update(&batch.payload_hash);
    hasher.update(&encodeInt(u64, batch.payload_bytes));
    hasher.update(&encodeInt(u32, batch.transaction_count));
    hasher.update(&encodeInt(u32, batch.frame_count));
    var digest: HashBytes = undefined;
    hasher.final(&digest);
    return digest;
}

/// Validates that a descriptor's result chain hash matches its own fields.
pub fn chainValid(batch: TransactionBatch) bool {
    const expected = chainStep(batch.base_chain_hash, batch);
    return std.mem.eql(u8, &expected, &batch.result_chain_hash);
}

fn encodeInt(comptime T: type, value: T) [@sizeOf(T)]u8 {
    var out: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &out, value, .little);
    return out;
}

const FixedWriter = struct {
    buffer: *[encoded_size]u8,
    offset: usize = 0,

    fn byte(self: *FixedWriter, value: u8) void {
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    fn int(self: *FixedWriter, comptime T: type, value: T) void {
        std.mem.writeInt(
            T,
            self.buffer[self.offset..][0..@sizeOf(T)],
            value,
            .little,
        );
        self.offset += @sizeOf(T);
    }

    fn bytes(self: *FixedWriter, value: []const u8) void {
        @memcpy(self.buffer[self.offset..][0..value.len], value);
        self.offset += value.len;
    }
};

const FixedReader = struct {
    buffer: []const u8,
    offset: usize = 0,

    fn byte(self: *FixedReader) u8 {
        const value = self.buffer[self.offset];
        self.offset += 1;
        return value;
    }

    fn int(self: *FixedReader, comptime T: type) T {
        const value = std.mem.readInt(
            T,
            self.buffer[self.offset..][0..@sizeOf(T)],
            .little,
        );
        self.offset += @sizeOf(T);
        return value;
    }

    fn hash(self: *FixedReader) HashBytes {
        var value: HashBytes = undefined;
        @memcpy(&value, self.buffer[self.offset..][0..32]);
        self.offset += 32;
        return value;
    }
};

fn sampleBatch() TransactionBatch {
    var batch = TransactionBatch{
        .database_id = 0xdead_beef_0123_4567_89ab_cdef_0011_2233,
        .batch_id = 42,
        .base_data_slot = 7,
        .base_chain_hash = @as([32]u8, @splat(1)),
        .result_chain_hash = undefined,
        .payload_hash = @as([32]u8, @splat(3)),
        .payload_bytes = 4096,
        .transaction_count = 2,
        .frame_count = 5,
    };
    batch.result_chain_hash = chainStep(batch.base_chain_hash, batch);
    return batch;
}

test "command round trips through the canonical codec" {
    const cases = [_]Command{
        .noop,
        .{ .transaction_batch = sampleBatch() },
        .{ .read_barrier = .{ .nonce = 0x1234_5678_9abc_def0 } },
        .{ .trim = .{
            .through_slot = 90_000,
            .history_hash = @as([32]u8, @splat(5)),
            .configuration_id = 3,
            .policy = 0,
        } },
        .{ .transfer_lease = .{
            .lease_id = 11,
            .receiver_id = 4,
            .base_slot = 88_000,
            .base_history_hash = @as([32]u8, @splat(6)),
            .configuration_id = 3,
            .expires_after_leader_ticks = 600,
        } },
        .{ .lease_complete = .{ .lease_id = 11 } },
    };
    for (cases) |case| {
        var encoded: [encoded_size]u8 = undefined;
        encode(case, &encoded);
        const decoded = try decode(&encoded);
        try std.testing.expectEqualDeep(case, decoded);
    }
}

test "decode rejects an unknown trim policy" {
    var encoded: [encoded_size]u8 = undefined;
    encode(.{ .trim = .{
        .through_slot = 10,
        .history_hash = @as([32]u8, @splat(0)),
        .configuration_id = 1,
        .policy = 0,
    } }, &encoded);
    // The policy byte sits after tag, the trim slot, the hash, and the
    // configuration ID.
    encoded[1 + 8 + 32 + 8] = 1;
    try std.testing.expectError(error.InvalidPolicy, decode(&encoded));
}

test "decode rejects malformed descriptors" {
    var encoded: [encoded_size]u8 = undefined;
    encode(.noop, &encoded);

    encoded[0] = 9;
    try std.testing.expectError(error.InvalidTag, decode(&encoded));

    encoded[0] = 0;
    encoded[encoded_size - 1] = 1;
    try std.testing.expectError(error.NonCanonicalPadding, decode(&encoded));

    try std.testing.expectError(
        error.TruncatedCommand,
        decode(encoded[0 .. encoded_size - 1]),
    );
}

test "chain step is deterministic and order sensitive" {
    const batch = sampleBatch();
    try std.testing.expect(chainValid(batch));

    var reordered = batch;
    reordered.batch_id = 43;
    reordered.result_chain_hash = chainStep(reordered.base_chain_hash, reordered);
    try std.testing.expect(
        !std.mem.eql(u8, &batch.result_chain_hash, &reordered.result_chain_hash),
    );

    var tampered = batch;
    tampered.payload_hash = @as([32]u8, @splat(4));
    try std.testing.expect(!chainValid(tampered));

    const genesis_a = genesisChain(1);
    const genesis_b = genesisChain(2);
    try std.testing.expect(!std.mem.eql(u8, &genesis_a, &genesis_b));
}
