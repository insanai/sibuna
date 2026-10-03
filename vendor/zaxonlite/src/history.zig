//! The global ordered-history anchor (ZDS 0011).
//!
//! Every chosen log entry advances one cumulative SHA-256 chain:
//!
//!     H_0 = SHA256(0x00 || LE16(version) || LE128(database_id))
//!     L_s = SHA256(0x01 || leaf_bytes(s))
//!     H_s = SHA256(0x02 || H_{s-1} || L_s)
//!
//! Unlike `command.chainStep`, which validates transaction-batch causality
//! and deliberately ignores noops, stops, and retention records, this chain
//! commits to the complete chosen order: every entry kind, its global slot,
//! and its configuration. Transaction leaves fold the batch chain's
//! `result_chain_hash` in, so the history anchor subsumes the data chain
//! rather than competing with it. Anchors `(s, H_s)` bind applied-state
//! records, trim records, and state-transfer manifests to one exact prefix.
//!
//! The one-byte domains and fixed-width leaf encoding remove concatenation
//! ambiguity, following the same discipline as `command.chainStep` and the
//! leaf/node separation in RFC 6962/9162. The chain is an integrity
//! commitment for crash-fault recovery, not a Byzantine proof.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

const command = @import("command.zig");
const types = @import("types.zig");

pub const HashBytes = command.HashBytes;

/// Leaf format version committed by the genesis hash.
pub const leaf_version: u16 = 1;

const domain_genesis: u8 = 0x00;
const domain_leaf: u8 = 0x01;
const domain_step: u8 = 0x02;

/// The entry kind bound into each leaf. Values are durable format bytes.
pub const LeafKind = enum(u8) {
    noop = 0,
    transaction_batch = 1,
    read_barrier = 2,
    trim = 3,
    transfer_lease = 4,
    lease_complete = 5,
    stop = 6,

    /// The leaf kind for a chosen log entry.
    pub fn of(entry: types.Entry) LeafKind {
        return switch (entry) {
            .command => |cmd| switch (cmd) {
                .noop => .noop,
                .transaction_batch => .transaction_batch,
                .read_barrier => .read_barrier,
                .trim => .trim,
                .transfer_lease => .transfer_lease,
                .lease_complete => .lease_complete,
            },
            .stop => .stop,
        };
    }
};

/// H_0: the genesis anchor for a fresh database at slot zero.
pub fn genesis(database_id: u128) HashBytes {
    var hasher = Sha256.init(.{});
    hasher.update(&[_]u8{domain_genesis});
    hasher.update(&encodeInt(u16, leaf_version));
    hasher.update(&encodeInt(u128, database_id));
    var digest: HashBytes = undefined;
    hasher.final(&digest);
    return digest;
}

/// L_s: the leaf hash for one chosen entry at one global slot. The leaf is
/// a fixed-width canonical encoding: version, database ID, configuration
/// ID, global slot, kind, the zero-padded canonical entry bytes, then the
/// payload digest and batch chain hash (zero for entries without them).
pub fn leafHash(
    database_id: u128,
    configuration_id: u64,
    global_slot: u64,
    entry: types.Entry,
) HashBytes {
    var hasher = Sha256.init(.{});
    hasher.update(&[_]u8{domain_leaf});
    hasher.update(&encodeInt(u16, leaf_version));
    hasher.update(&encodeInt(u128, database_id));
    hasher.update(&encodeInt(u64, configuration_id));
    hasher.update(&encodeInt(u64, global_slot));
    hasher.update(&[_]u8{@backingInt(LeafKind.of(entry))});

    var entry_bytes = @as([types.max_entry_size]u8, @splat(0));
    var cursor = types.Cursor{ .buffer = &entry_bytes };
    types.encodeEntry(entry, &cursor);
    hasher.update(&entry_bytes);

    const zero = @as([32]u8, @splat(0));
    switch (entry) {
        .command => |cmd| switch (cmd) {
            .transaction_batch => |batch| {
                hasher.update(&batch.payload_hash);
                hasher.update(&batch.result_chain_hash);
            },
            else => {
                hasher.update(&zero);
                hasher.update(&zero);
            },
        },
        .stop => {
            hasher.update(&zero);
            hasher.update(&zero);
        },
    }

    var digest: HashBytes = undefined;
    hasher.final(&digest);
    return digest;
}

/// H_s from H_{s-1} and L_s.
pub fn step(previous: HashBytes, leaf: HashBytes) HashBytes {
    var hasher = Sha256.init(.{});
    hasher.update(&[_]u8{domain_step});
    hasher.update(&previous);
    hasher.update(&leaf);
    var digest: HashBytes = undefined;
    hasher.final(&digest);
    return digest;
}

/// Convenience: advances the anchor over one chosen entry.
pub fn advance(
    previous: HashBytes,
    database_id: u128,
    configuration_id: u64,
    global_slot: u64,
    entry: types.Entry,
) HashBytes {
    return step(previous, leafHash(database_id, configuration_id, global_slot, entry));
}

fn encodeInt(comptime T: type, value: T) [@sizeOf(T)]u8 {
    var out: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &out, value, .little);
    return out;
}

const testing = std.testing;

fn sampleBatchEntry() types.Entry {
    var batch = command.TransactionBatch{
        .database_id = 7,
        .batch_id = 42,
        .base_data_slot = 3,
        .base_chain_hash = @as([32]u8, @splat(1)),
        .result_chain_hash = undefined,
        .payload_hash = @as([32]u8, @splat(2)),
        .payload_bytes = 4096,
        .transaction_count = 1,
        .frame_count = 2,
    };
    batch.result_chain_hash = command.chainStep(batch.base_chain_hash, batch);
    return .{ .command = .{ .transaction_batch = batch } };
}

test "the anchor binds slot, configuration, database, and entry identity" {
    const entry = sampleBatchEntry();
    const base = leafHash(7, 1, 10, entry);
    try testing.expectEqualSlices(u8, &base, &leafHash(7, 1, 10, entry));
    try testing.expect(!std.mem.eql(u8, &base, &leafHash(7, 1, 11, entry)));
    try testing.expect(!std.mem.eql(u8, &base, &leafHash(7, 2, 10, entry)));
    try testing.expect(!std.mem.eql(u8, &base, &leafHash(8, 1, 10, entry)));
    try testing.expect(!std.mem.eql(
        u8,
        &base,
        &leafHash(7, 1, 10, .{ .command = .noop }),
    ));
    try testing.expect(!std.mem.eql(u8, &genesis(1), &genesis(2)));
}

test "the chain is order sensitive and folds the batch chain in" {
    const noop_entry = types.Entry{ .command = .noop };
    const batch_entry = sampleBatchEntry();

    const forward = advance(
        advance(genesis(7), 7, 1, 1, noop_entry),
        7,
        1,
        2,
        batch_entry,
    );
    const reversed = advance(
        advance(genesis(7), 7, 1, 1, batch_entry),
        7,
        1,
        2,
        noop_entry,
    );
    try testing.expect(!std.mem.eql(u8, &forward, &reversed));

    // Two batches that differ only in their cumulative data-chain identity
    // produce different history anchors: the global chain subsumes it.
    var altered = batch_entry;
    altered.command.transaction_batch.result_chain_hash = @as([32]u8, @splat(9));
    try testing.expect(!std.mem.eql(
        u8,
        &leafHash(7, 1, 2, batch_entry),
        &leafHash(7, 1, 2, altered),
    ));
}

test "the encoding is pinned by a stable vector" {
    // Guards the durable leaf format: any accidental change to the field
    // order, widths, padding, or domains breaks this vector.
    const anchor = advance(genesis(1), 1, 1, 1, .{ .command = .noop });
    var hex_buffer: [64]u8 = undefined;
    const hex = std.fmt.bufPrint(
        &hex_buffer,
        "{x}",
        .{&anchor},
    ) catch unreachable;
    try testing.expectEqualStrings(
        "f1a79233c0eafe530206b61fe6a9a456feba7972b0b7ec6f3ff68da89499472b",
        hex,
    );
}
