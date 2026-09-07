//! Sibuna Challenge and Decay Store
//!
//! Provides a high-performance, sharded in-memory cache for tracking active
//! proof-of-work challenges with atomic double-spend prevention and zero heap churn.

const std = @import("std");

pub const StoreError = error{
    ChallengeNotFound,
    ChallengeExpired,
    DoubleSpendAttempt,
    FingerprintMismatch,
    StoreFull,
};

pub const ChallengeRecord = struct {
    id: [32]u8,
    id_len: u8,
    difficulty: u32,
    issued_at: u64,
    ttl_seconds: u32,
    bound_fingerprint: u64,
    spent: bool,
    occupied: bool,
};

pub const NUM_SHARDS = 16;
pub const SHARD_CAPACITY = 1024;

pub const SpinLock = struct {
    locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};

const Shard = struct {
    lock: SpinLock = .{},

    entries: [SHARD_CAPACITY]ChallengeRecord = [_]ChallengeRecord{.{
        .id = [_]u8{0} ** 32,
        .id_len = 0,
        .difficulty = 0,
        .issued_at = 0,
        .ttl_seconds = 0,
        .bound_fingerprint = 0,
        .spent = false,
        .occupied = false,
    }} ** SHARD_CAPACITY,

    fn findSlot(self: *Shard, id: []const u8, now: u64) ?usize {
        var free_idx: ?usize = null;
        var oldest_idx: usize = 0;
        var oldest_time: u64 = std.math.maxInt(u64);

        for (&self.entries, 0..) |*entry, idx| {
            if (!entry.occupied) {
                if (free_idx == null) free_idx = idx;
            } else if (entry.id_len == id.len and
                std.mem.eql(u8, entry.id[0..entry.id_len], id))
            {
                return idx;
            } else if (now > entry.issued_at + entry.ttl_seconds) {
                if (free_idx == null) free_idx = idx;
            } else if (entry.issued_at < oldest_time) {
                oldest_time = entry.issued_at;
                oldest_idx = idx;
            }
        }
        return free_idx orelse oldest_idx;
    }
};

pub const ChallengeStore = struct {
    shards: [NUM_SHARDS]Shard = [_]Shard{.{}} ** NUM_SHARDS,

    fn shardIndex(id: []const u8) usize {
        return @as(usize, @intCast(std.hash.Wyhash.hash(0xdead_beef, id) % NUM_SHARDS));
    }

    pub fn put(
        self: *ChallengeStore,
        id: []const u8,
        difficulty: u32,
        now: u64,
        ttl_seconds: u32,
        bound_fingerprint: u64,
    ) !void {
        if (id.len == 0 or id.len > 32) return error.StoreFull;
        const shard = &self.shards[shardIndex(id)];
        shard.lock.lock();
        defer shard.lock.unlock();

        const slot_idx = shard.findSlot(id, now) orelse return error.StoreFull;
        const entry = &shard.entries[slot_idx];

        @memcpy(entry.id[0..id.len], id);
        entry.id_len = @intCast(id.len);
        entry.difficulty = difficulty;
        entry.issued_at = now;
        entry.ttl_seconds = ttl_seconds;
        entry.bound_fingerprint = bound_fingerprint;
        entry.spent = false;
        entry.occupied = true;
    }

    pub fn getAndMarkSpent(
        self: *ChallengeStore,
        id: []const u8,
        now: u64,
        fingerprint: ?u64,
    ) StoreError!ChallengeRecord {
        if (id.len == 0 or id.len > 32) return error.ChallengeNotFound;
        const shard = &self.shards[shardIndex(id)];
        shard.lock.lock();
        defer shard.lock.unlock();

        for (&shard.entries) |*entry| {
            if (entry.occupied and entry.id_len == id.len and
                std.mem.eql(u8, entry.id[0..entry.id_len], id))
            {
                if (now > entry.issued_at + entry.ttl_seconds) {
                    entry.occupied = false;
                    return error.ChallengeExpired;
                }
                if (entry.spent) {
                    return error.DoubleSpendAttempt;
                }
                if (fingerprint) |fp| {
                    if (entry.bound_fingerprint != 0 and entry.bound_fingerprint != fp) {
                        return error.FingerprintMismatch;
                    }
                }
                entry.spent = true;
                return entry.*;
            }
        }
        return error.ChallengeNotFound;
    }
};

test "challenge store put, spend, double-spend prevention" {
    var store = ChallengeStore{};
    const now: u64 = 1_000_000;
    const cid = "test-challenge-uuid-1";

    try store.put(cid, 4, now, 600, 0x1234);

    // First spend: succeeds
    const rec = try store.getAndMarkSpent(cid, now + 10, 0x1234);
    try std.testing.expectEqual(@as(u32, 4), rec.difficulty);

    // Second spend: rejected as double-spend
    try std.testing.expectError(
        error.DoubleSpendAttempt,
        store.getAndMarkSpent(cid, now + 15, 0x1234),
    );

    // Expired challenge
    const exp_cid = "test-challenge-uuid-2";
    try store.put(exp_cid, 3, now, 10, 0x5678);
    try std.testing.expectError(
        error.ChallengeExpired,
        store.getAndMarkSpent(exp_cid, now + 20, 0x5678),
    );
}
