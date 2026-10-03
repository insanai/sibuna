//! Seeded property fuzzing for zaxonlite.
//!
//! Three layers, all deterministic per seed:
//! 1. decoder robustness: random and mutated-valid bytes through every
//!    wire/journal/command/payload parser must never crash, and every
//!    valid encoding must round trip;
//! 2. journal-file robustness: random write streams with randomly injected
//!    tail damage must reopen (with the damaged suffix truncated) or be
//!    rejected as corrupt — never crash or mis-parse;
//! 3. end-to-end node property: random SQL against a real node with random
//!    restarts, anchors, torn tails, and image deletions must keep the
//!    integrity report clean and converge to identical logical content
//!    after every rebuild.
//!
//! Usage: fuzz [iterations] [seed]

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const paxos = @import("paxos");

const wire = zaxonlite.wire;
const types = zaxonlite.types;
const command = zaxonlite.command;
const wal = zaxonlite.wal;
const Node = zaxonlite.Node;

pub fn main(init: std.process.Init) !u8 {
    // Logic and process-crash coverage need no power-loss flush latency.
    zaxonlite.durability.setSyncMode(.os);
    const gpa = init.gpa;
    const io = init.io;

    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iterator.deinit();
    _ = iterator.next();
    const iterations = blk: {
        const text = iterator.next() orelse break :blk @as(usize, 300);
        break :blk std.fmt.parseInt(usize, text, 10) catch 300;
    };
    const seed = blk: {
        const text = iterator.next() orelse {
            var bytes: [8]u8 = undefined;
            io.random(&bytes);
            break :blk std.mem.readInt(u64, &bytes, .little);
        };
        break :blk std.fmt.parseInt(u64, text, 10) catch 0;
    };
    std.debug.print("fuzz: {d} iterations, seed {d}\n", .{ iterations, seed });

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    try fuzzDecoders(gpa, random, iterations);
    std.debug.print("fuzz: decoders ok\n", .{});
    try fuzzJournal(gpa, io, random, @max(iterations / 10, 10));
    std.debug.print("fuzz: journal ok\n", .{});
    try fuzzNode(gpa, io, random, @max(iterations / 3, 30), seed);
    std.debug.print("fuzz: node property ok\n", .{});
    std.debug.print("fuzz: PASS (seed {d})\n", .{seed});
    return 0;
}

// ----------------------------------------------------------------------
// Layer 1: decoders
// ----------------------------------------------------------------------

fn fuzzDecoders(
    gpa: std.mem.Allocator,
    random: std.Random,
    iterations: usize,
) !void {
    var buffer: [4096]u8 = undefined;
    for (0..iterations) |_| {
        // Pure random bytes of random length through every parser.
        const len = random.intRangeAtMost(usize, 0, buffer.len);
        random.bytes(buffer[0..len]);
        _ = wire.Hello.decode(buffer[0..len]) catch {};
        _ = wire.decodeEnvelope(buffer[0..len]) catch {};
        _ = wire.FenceRequest.decode(buffer[0..len]) catch {};
        _ = wire.FenceAck.decode(buffer[0..len]) catch {};
        _ = wire.SnapshotBegin.decode(buffer[0..len]) catch {};
        _ = types.decodeWrite(buffer[0..len]) catch {};
        _ = wal.PayloadView.parse(buffer[0..len]) catch {};
        if (len == command.encoded_size) {
            _ = command.decode(buffer[0..len]) catch {};
        }

        // Valid envelope, round-tripped, then mutated.
        const envelope = randomEnvelope(random);
        var envelope_buffer: [wire.max_envelope_size]u8 = undefined;
        const encoded = wire.encodeEnvelope(envelope, &envelope_buffer);
        const decoded = try wire.decodeEnvelope(encoded);
        if (!std.meta.eql(envelope, decoded)) return error.RoundTripMismatch;

        const copy = try gpa.dupe(u8, encoded);
        defer gpa.free(copy);
        const flips = random.intRangeAtMost(usize, 1, 4);
        for (0..flips) |_| {
            copy[random.intRangeLessThan(usize, 0, copy.len)] ^=
                @as(u8, 1) << random.intRangeAtMost(u3, 0, 7);
        }
        // Must decode to something or fail cleanly; never crash.
        _ = wire.decodeEnvelope(copy) catch {};
    }
}

fn randomEnvelope(random: std.Random) types.Log.Envelope {
    const ballot = paxos.Ballot{
        .round = random.intRangeAtMost(u64, 0, 1000),
        .priority = random.intRangeAtMost(u32, 0, 9),
        .node = random.intRangeAtMost(u32, 1, 3),
    };
    var batch = command.TransactionBatch{
        .database_id = random.int(u128),
        .batch_id = random.int(u128),
        .base_data_slot = random.intRangeAtMost(u64, 0, 255),
        .base_chain_hash = undefined,
        .result_chain_hash = undefined,
        .payload_hash = undefined,
        .payload_bytes = random.intRangeAtMost(u64, 1, 1 << 30),
        .transaction_count = random.intRangeAtMost(u32, 1, 16),
        .frame_count = random.intRangeAtMost(u32, 1, 512),
    };
    random.bytes(&batch.base_chain_hash);
    random.bytes(&batch.result_chain_hash);
    random.bytes(&batch.payload_hash);
    const entry = types.Entry{ .command = .{ .transaction_batch = batch } };
    const slot = random.intRangeAtMost(u32, 1, 255);

    const message: types.Log.Message = switch (random.intRangeAtMost(u8, 0, 8)) {
        0 => .{ .prepare = .{ .ballot = ballot, .first = slot } },
        1 => .{ .promise = .{
            .ballot = ballot,
            .slot = slot,
            .accepted = .{ .ballot = ballot, .value = entry },
        } },
        2 => .{ .promise_range = .{
            .ballot = ballot,
            .anchor = .{
                .trim_id = 1,
                .chosen_trim_slot = slot,
                .history_hash = batch.payload_hash,
            },
            .chosen_through = slot,
            .first = slot,
            .last = slot + 7,
            .accepted_count = 3,
            .more = random.boolean(),
        } },
        3 => .{ .accept = .{ .ballot = ballot, .slot = slot, .value = entry } },
        4 => .{ .accepted = .{ .ballot = ballot, .slot = slot, .decided_through = slot } },
        5 => .{ .commit = .{ .slot = slot, .value = entry } },
        6 => .{ .learn = .{ .from_slot = slot, .count = 32 } },
        7 => .{ .nack = .{
            .rejected = ballot,
            .promised = ballot,
            .decided_through = slot,
        } },
        else => .{ .heartbeat = .{ .ballot = ballot, .decided_through = slot } },
    };
    return .{
        .from = random.intRangeAtMost(u32, 1, 3),
        .to = random.intRangeAtMost(u32, 1, 3),
        .message = message,
    };
}

// ----------------------------------------------------------------------
// Layer 2: journal files
// ----------------------------------------------------------------------

fn fuzzJournal(
    gpa: std.mem.Allocator,
    io: Io,
    random: std.Random,
    iterations: usize,
) !void {
    const journal_mod = zaxonlite.journal;
    for (0..iterations) |iteration| {
        var tmp_path_buffer: [64]u8 = undefined;
        const tmp_path = std.fmt.bufPrint(
            &tmp_path_buffer,
            ".zig-cache/tmp/zx-fuzz-journal-{d}",
            .{iteration},
        ) catch unreachable;
        Io.Dir.cwd().deleteTree(io, tmp_path) catch {};
        var dir = try Io.Dir.cwd().createDirPathOpen(io, tmp_path, .{});
        defer {
            dir.close(io);
            Io.Dir.cwd().deleteTree(io, tmp_path) catch {};
        }

        // A protocol-valid stream of random writes: ballots never regress
        // and accepts precede commits at each slot.
        var journal = try journal_mod.Journal.create(io, gpa, dir, 1);
        const write_count = random.intRangeAtMost(usize, 1, 24);
        var slot: u32 = 1;
        var round: u64 = 1;
        for (0..write_count) |_| {
            round += random.intRangeAtMost(u64, 0, 2);
            const ballot = paxos.Ballot{ .round = round, .node = 1 };
            const write: types.Write = switch (random.intRangeAtMost(u8, 0, 2)) {
                0 => .{ .promise = ballot },
                1 => .{ .accept = .{
                    .ballot = ballot,
                    .slot = slot,
                    .value = .{ .command = .noop },
                } },
                else => blk: {
                    const value: types.Write = .{ .commit = .{
                        .slot = slot,
                        .value = .{ .command = .noop },
                    } };
                    slot = @min(slot + 1, 255);
                    break :blk value;
                },
            };
            try journal.appendWrites(&.{write});
        }
        try journal.sync();
        const end = journal.active.end_offset;

        // Random damage: garbage appended, or bytes flipped near the tail.
        const damage = random.intRangeAtMost(u8, 0, 2);
        if (damage == 1) {
            var garbage: [64]u8 = undefined;
            const garbage_len = random.intRangeAtMost(usize, 1, garbage.len);
            random.bytes(garbage[0..garbage_len]);
            try journal.active.file.writePositionalAll(io, garbage[0..garbage_len], end);
        } else if (damage == 2 and end > 0) {
            var byte: [1]u8 = undefined;
            const offset = random.intRangeLessThan(u64, 0, end);
            _ = try journal.active.file.readPositionalAll(io, &byte, offset);
            byte[0] ^= @as(u8, 1) << random.intRangeAtMost(u3, 0, 7);
            try journal.active.file.writePositionalAll(io, &byte, offset);
        }
        journal.close();

        // Reopen: success (with valid prefix) or clean corruption error.
        const durable = try gpa.create(types.Log.DurableState);
        defer gpa.destroy(durable);
        durable.* = .{};
        var info: journal_mod.ReplayInfo = undefined;
        if (journal_mod.Journal.open(io, gpa, dir, 1, durable, &info)) |opened| {
            var reopened = opened;
            reopened.close();
            if (damage == 0 and info.record_count != write_count) {
                return error.LostValidRecords;
            }
        } else |err| switch (err) {
            error.CorruptJournal,
            error.CorruptSegment,
            error.UnsupportedSegmentVersion,
            error.CorruptManifest,
            error.SequenceGap,
            => {
                if (damage == 0) return error.RejectedValidJournal;
            },
            else => return err,
        }
    }
}

// ----------------------------------------------------------------------
// Layer 3: end-to-end node property
// ----------------------------------------------------------------------

fn fuzzNode(
    gpa: std.mem.Allocator,
    io: Io,
    random: std.Random,
    operations: usize,
    seed: u64,
) !void {
    var tmp_path_buffer: [64]u8 = undefined;
    const tmp_path = std.fmt.bufPrint(
        &tmp_path_buffer,
        ".zig-cache/tmp/zx-fuzz-node-{x}",
        .{seed},
    ) catch unreachable;
    Io.Dir.cwd().deleteTree(io, tmp_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, tmp_path) catch {};

    var node = try Node.open(gpa, io, .{ .directory = tmp_path });
    var open = true;
    defer if (open) node.close();

    _ = try node.exec(
        "create table f(id integer primary key, k integer, v blob)",
    );
    var expected_rows: i64 = 0;
    var sql_buffer: [256]u8 = undefined;

    for (0..operations) |_| {
        switch (random.intRangeAtMost(u8, 0, 9)) {
            // Insert a batch of random rows (nondeterministic SQL included).
            0, 1, 2, 3 => {
                const rows = random.intRangeAtMost(u32, 1, 8);
                var sql_writer = std.Io.Writer.fixed(&sql_buffer);
                sql_writer.writeAll("insert into f(k, v) values ") catch unreachable;
                for (0..rows) |row| {
                    if (row > 0) sql_writer.writeAll(",") catch unreachable;
                    sql_writer.print(
                        "({d}, randomblob({d}))",
                        .{ random.int(u16), random.intRangeAtMost(u32, 1, 512) },
                    ) catch unreachable;
                }
                sql_writer.writeAll("\x00") catch unreachable;
                const written = sql_writer.buffered();
                const sql: [:0]const u8 = @ptrCast(written[0 .. written.len - 1]);
                _ = try node.exec(sql);
                expected_rows += rows;
            },
            // Update random rows.
            4 => {
                const sql = std.mem.printSentinel(
                    &sql_buffer,
                    "update f set k = k + 1, v = randomblob(32) " ++
                        "where id % {d} = 0",
                    .{random.intRangeAtMost(u32, 2, 9)},
                    0,
                ) catch unreachable;
                _ = try node.exec(sql);
            },
            // Delete a few rows.
            5 => {
                const result = try node.exec(
                    "delete from f where id in " ++
                        "(select id from f order by id desc limit 2)",
                );
                expected_rows -= result.changes;
            },
            // Failed SQL must replicate nothing.
            6 => {
                _ = node.exec("insert into missing_table values (1)") catch {};
            },
            // Publish a durable state anchor.
            7 => try node.createStateAnchor(),
            // Restart, sometimes with injected tail garbage or a deleted
            // materialized image.
            8, 9 => {
                const injure = random.intRangeAtMost(u8, 0, 2);
                node.close();
                open = false;
                if (injure == 1) {
                    // Torn tail: garbage after the valid journal prefix.
                    try appendJournalGarbage(io, tmp_path, random);
                } else if (injure == 2) {
                    var db_buffer: [96]u8 = undefined;
                    const db_path = std.fmt.bufPrint(
                        &db_buffer,
                        "{s}/current.db",
                        .{tmp_path},
                    ) catch unreachable;
                    Io.Dir.cwd().deleteFile(io, db_path) catch {};
                }
                node = try Node.open(gpa, io, .{ .directory = tmp_path });
                open = true;
            },
            else => unreachable,
        }
    }

    // Final oracle: integrity report clean, row count matches the model.
    const report = try node.integrityCheck();
    if (!report.ok()) return error.IntegrityFailed;
    var result = try node.query(gpa, "select count(*) from f");
    defer result.deinit();
    const count = try std.fmt.parseInt(i64, result.rows[0][0].?, 10);
    if (count != expected_rows) {
        std.debug.print(
            "row count mismatch: expected {d}, got {d}\n",
            .{ expected_rows, count },
        );
        return error.RowCountMismatch;
    }

    // Rebuild convergence: deleting the image must reproduce identical
    // logical content.
    const hash_before = try node.contentHash();
    node.close();
    open = false;
    {
        var db_buffer: [96]u8 = undefined;
        const db_path = std.fmt.bufPrint(
            &db_buffer,
            "{s}/current.db",
            .{tmp_path},
        ) catch unreachable;
        Io.Dir.cwd().deleteFile(io, db_path) catch {};
    }
    node = try Node.open(gpa, io, .{ .directory = tmp_path });
    open = true;
    const hash_after = try node.contentHash();
    if (!std.mem.eql(u8, &hash_before, &hash_after)) {
        return error.RebuildDiverged;
    }
}

fn appendJournalGarbage(io: Io, root: []const u8, random: std.Random) !void {
    var dir = try Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer dir.close(io);
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "paxos-")) continue;
        const file = try dir.openFile(io, entry.name, .{ .mode = .read_write });
        defer file.close(io);
        const size = try file.length(io);
        var garbage: [32]u8 = undefined;
        const garbage_len = random.intRangeAtMost(usize, 1, garbage.len);
        random.bytes(garbage[0..garbage_len]);
        try file.writePositionalAll(io, garbage[0..garbage_len], size);
        return;
    }
}
