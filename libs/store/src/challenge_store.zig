//! Sibuna Spent-Challenge Set
//!
//! Challenges are stateless: the coordinator encodes issue time, difficulty,
//! algorithm, and client binding inside a MAC-authenticated identifier, so
//! issuing one costs the server no memory. The only state that must exist
//! is the set of identifiers that have already been *spent*, and every entry
//! in that set corresponds to a proof of work the client actually paid for.
//! An adversary therefore cannot fill this table without solving puzzles.
//!
//! Entries are the 16-byte challenge tag plus its expiry, kept in 16
//! lock-striped shards of Robin Hood open addressing (Celis, 1986): an
//! insert displaces any occupant closer to its home slot than the incoming
//! key, which keeps probe lengths tightly clustered around the mean.
//! Expired entries are dropped when displaced or overwritten in place when
//! that keeps the probe invariant, so no background sweeper is needed.

const std = @import("std");

pub const StoreError = error{
    ChallengeNotFound,
    ChallengeExpired,
    DoubleSpendAttempt,
    FingerprintMismatch,
    StoreFull,
};

pub const Tag = [16]u8;
pub const NUM_SHARDS = 16;
pub const SHARD_CAPACITY = 4096;
pub const MAX_PROBE = 64;

pub const Entry = struct {
    tag: Tag = [_]u8{0} ** 16,
    expires_at: u64 = 0,
    dist: u8 = 0,
    occupied: bool = false,

    fn expired(self: Entry, now: u64) bool {
        return now > self.expires_at;
    }
};

pub const SpinLock = struct {
    locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            while (self.locked.load(.monotonic)) std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};

const Shard = struct {
    lock: SpinLock align(64) = .{},
    entries: [SHARD_CAPACITY]Entry = [_]Entry{.{}} ** SHARD_CAPACITY,
    live: u32 = 0,

    fn home(tag: *const Tag) usize {
        return @intCast(std.mem.readInt(u64, tag[8..16], .little) % SHARD_CAPACITY);
    }

    /// Robin Hood lookup with early termination: once a slot's occupant is
    /// closer to its home than we are to ours, the key cannot be further.
    fn find(self: *Shard, tag: *const Tag) ?*Entry {
        var idx = home(tag);
        var dist: u8 = 0;
        while (dist < MAX_PROBE) : (dist += 1) {
            const e = &self.entries[idx];
            if (!e.occupied or e.dist < dist) return null;
            if (std.mem.eql(u8, &e.tag, tag)) return e;
            idx = (idx + 1) % SHARD_CAPACITY;
        }
        return null;
    }

    /// Simulate displacement before modifying live entries. A failed bounded
    /// insertion must not evict an already spent tag and permit its replay.
    fn canInsert(self: *const Shard, tag: *const Tag, now: u64) bool {
        var idx = home(tag);
        var dist: u8 = 0;
        var probes: usize = 0;
        while (dist < MAX_PROBE and probes < SHARD_CAPACITY) : (probes += 1) {
            const e = &self.entries[idx];
            if (!e.occupied or (e.expired(now) and dist >= e.dist)) return true;
            if (dist > e.dist) dist = e.dist;
            idx = (idx + 1) % SHARD_CAPACITY;
            dist += 1;
        }
        return false;
    }

    fn insert(self: *Shard, tag: *const Tag, expires_at: u64, now: u64) StoreError!void {
        if (!self.canInsert(tag, now)) return error.StoreFull;
        var carry = Entry{ .tag = tag.*, .expires_at = expires_at, .dist = 0, .occupied = true };
        var idx = home(tag);
        while (carry.dist < MAX_PROBE) {
            const e = &self.entries[idx];
            if (!e.occupied) {
                e.* = carry;
                self.live += 1;
                return;
            }
            // Overwriting an expired occupant is safe only when the new
            // distance is not smaller, so keys probing past this slot still
            // pass the early-termination test.
            if (e.expired(now) and carry.dist >= e.dist) {
                e.* = carry;
                return;
            }
            if (carry.dist > e.dist) {
                std.mem.swap(Entry, &carry, e);
                if (carry.expired(now)) return;
            }
            idx = (idx + 1) % SHARD_CAPACITY;
            carry.dist += 1;
        }
        return error.StoreFull;
    }
};

pub const ChallengeStore = struct {
    shards: [NUM_SHARDS]Shard = [_]Shard{.{}} ** NUM_SHARDS,

    fn shardFor(self: *ChallengeStore, tag: *const Tag) *Shard {
        return &self.shards[std.mem.readInt(u64, tag[0..8], .little) % NUM_SHARDS];
    }

    /// Records `tag` as spent until `expires_at`. Fails with
    /// `DoubleSpendAttempt` when it is already present and unexpired.
    pub fn markSpent(
        self: *ChallengeStore,
        tag: *const Tag,
        expires_at: u64,
        now: u64,
    ) StoreError!void {
        const shard = self.shardFor(tag);
        shard.lock.lock();
        defer shard.lock.unlock();
        if (shard.find(tag)) |existing| {
            if (!existing.expired(now)) return error.DoubleSpendAttempt;
            existing.expires_at = expires_at;
            return;
        }
        try shard.insert(tag, expires_at, now);
    }

    pub fn isSpent(self: *ChallengeStore, tag: *const Tag, now: u64) bool {
        const shard = self.shardFor(tag);
        shard.lock.lock();
        defer shard.lock.unlock();
        const e = shard.find(tag) orelse return false;
        return !e.expired(now);
    }
};

fn tagFrom(n: u64) Tag {
    var tag: Tag = undefined;
    std.mem.writeInt(u64, tag[0..8], std.hash.Wyhash.hash(1, std.mem.asBytes(&n)), .little);
    std.mem.writeInt(u64, tag[8..16], std.hash.Wyhash.hash(2, std.mem.asBytes(&n)), .little);
    return tag;
}

test "spent set rejects double spend and forgets expired tags" {
    var store = ChallengeStore{};
    const now: u64 = 1_000_000;
    const tag = tagFrom(1);
    try store.markSpent(&tag, now + 600, now);
    try std.testing.expect(store.isSpent(&tag, now + 10));
    try std.testing.expectError(
        error.DoubleSpendAttempt,
        store.markSpent(&tag, now + 600, now + 15),
    );
    try std.testing.expect(!store.isSpent(&tag, now + 601));
    // After expiry the same tag may be spent again (a fresh challenge with
    // an identical tag is astronomically unlikely, but the rule is defined).
    try store.markSpent(&tag, now + 1200, now + 601);
}

test "robin hood shards stay correct under load and reclaim expired slots" {
    const store = try std.testing.allocator.create(ChallengeStore);
    defer std.testing.allocator.destroy(store);
    store.* = .{};
    const now: u64 = 5000;
    const total: u64 = NUM_SHARDS * SHARD_CAPACITY / 2;
    var n: u64 = 0;
    while (n < total) : (n += 1) {
        const tag = tagFrom(n);
        try store.markSpent(&tag, now + 100, now);
    }
    n = 0;
    while (n < total) : (n += 1) {
        const tag = tagFrom(n);
        try std.testing.expect(store.isSpent(&tag, now + 50));
        try std.testing.expectError(
            error.DoubleSpendAttempt,
            store.markSpent(&tag, now + 100, now + 50),
        );
    }
    // Everything expires; the next generation reuses the same slots.
    n = total;
    while (n < 2 * total) : (n += 1) {
        const tag = tagFrom(n);
        try store.markSpent(&tag, now + 1000, now + 200);
    }
    n = total;
    while (n < 2 * total) : (n += 1) {
        const tag = tagFrom(n);
        try std.testing.expect(store.isSpent(&tag, now + 300));
    }
    try std.testing.expect(!store.isSpent(&tagFrom(3), now + 300));
}

test "failed insertion leaves all live spent tags reachable" {
    const shard = try std.testing.allocator.create(Shard);
    defer std.testing.allocator.destroy(shard);
    shard.* = .{};
    // A home-zero insertion displaces the home-one chain before hitting
    // the probe limit. Previously the last displaced live tag was lost.
    var tags: [MAX_PROBE + 1]Tag = undefined;
    for (&tags, 0..) |*tag, i| {
        tag.* = [_]u8{0} ** 16;
        std.mem.writeInt(u64, tag[0..8], i, .little);
        std.mem.writeInt(u64, tag[8..16], if (i == 0) 0 else 1, .little);
        try shard.insert(tag, 1000, 0);
    }
    var incoming = [_]u8{0} ** 16;
    incoming[0] = 255;
    try std.testing.expectError(error.StoreFull, shard.insert(&incoming, 1000, 0));
    for (&tags) |*tag| try std.testing.expect(shard.find(tag) != null);
    try std.testing.expect(shard.find(&incoming) == null);
}
