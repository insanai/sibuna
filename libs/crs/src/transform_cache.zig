//! Final transform outputs shared by rules within one phase. CRS families such as the XSS
//! rules repeat one six-decoder pipeline over the same value; computing it once per value
//! removes most of their cost without changing any rule's input.
//!
//! A pipeline is identified by its exact stage bytes; the hash only places entries.
//! A value is identified by its address and length. SID 0010's effect-lifetime lemma makes
//! acquired, TX and matched bytes immutable for a transaction, so that identity names fixed
//! bytes. Counted targets live in reused scratch and are never offered to the cache, and
//! the cache is cleared at every phase. Storage is bounded; a full cache stops caching.
const std = @import("std");

pub const capacity = 256;
const slots = 2 * capacity;

const Entry = struct {
    input: [*]const u8,
    length: usize,
    key: u64,
    stages: []const u8,
    output: []const u8,
};

pub const Cache = struct {
    entries: []Entry,
    bytes: []u8,
    /// Phase epoch in the high half, entry in the low half; other epochs read as empty.
    index: []u32,
    epoch: u16 = 1,
    used: usize = 0,
    byte_used: usize = 0,

    pub fn bytesFor(storage: usize) usize {
        return capacity * @sizeOf(Entry) + slots * @sizeOf(u32) + storage;
    }

    pub fn init(allocator: std.mem.Allocator, storage: usize) !Cache {
        const entries = try allocator.alloc(Entry, capacity);
        errdefer allocator.free(entries);
        const index = try allocator.alloc(u32, slots);
        errdefer allocator.free(index);
        @memset(index, 0);
        return .{ .entries = entries, .index = index, .bytes = try allocator.alloc(u8, storage) };
    }

    pub fn deinit(self: *Cache, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.index);
        allocator.free(self.entries);
        self.* = undefined;
    }

    /// Constant time; the index is wiped only when the epoch wraps.
    pub fn clear(self: *Cache) void {
        self.used = 0;
        self.byte_used = 0;
        self.epoch +%= 1;
        if (self.epoch == 0) {
            @memset(self.index, 0);
            self.epoch = 1;
        }
    }

    fn home(input: []const u8, key: u64) usize {
        const address: u64 = @intFromPtr(input.ptr);
        return @intCast(std.hash.int(address ^ key ^ (@as(u64, input.len) << 17)) % slots);
    }

    fn live(self: *const Cache, slot: u32) bool {
        return slot >> 16 == self.epoch;
    }

    /// `stages` must outlive the phase; generation programs do.
    pub fn find(self: *const Cache, input: []const u8, key: u64, stages: []const u8) ?[]const u8 {
        var position = home(input, key);
        while (self.live(self.index[position])) : (position = (position + 1) % slots) {
            const entry = self.entries[self.index[position] & 0xffff];
            if (entry.input == input.ptr and entry.length == input.len and entry.key == key and
                std.mem.eql(u8, entry.stages, stages)) return entry.output;
        }
        return null;
    }

    /// Copies the output so later transforms may reuse their scratch buffers.
    pub fn store(
        self: *Cache,
        input: []const u8,
        key: u64,
        stages: []const u8,
        output: []const u8,
    ) void {
        if (self.used == self.entries.len or output.len > self.bytes.len - self.byte_used)
            return;
        const copy = self.bytes[self.byte_used..][0..output.len];
        @memcpy(copy, output);
        self.byte_used += output.len;
        const entry: u32 = @intCast(self.used);
        self.entries[entry] = .{
            .input = input.ptr,
            .length = input.len,
            .key = key,
            .stages = stages,
            .output = copy,
        };
        self.used += 1;
        var position = home(input, key);
        while (self.live(self.index[position])) position = (position + 1) % slots;
        self.index[position] = @as(u32, self.epoch) << 16 | entry;
    }
};

test "cached outputs are owned copies matched by identity and pipeline" {
    const t = std.testing;
    var cache = try Cache.init(t.allocator, 16);
    defer cache.deinit(t.allocator);
    const value = "Hello";
    var scratch = "hello".*;
    cache.store(value, 7, "ab", &scratch);
    scratch[0] = 'X';
    try t.expectEqualStrings("hello", cache.find(value, 7, "ab").?);
    try t.expect(cache.find(value, 8, "ab") == null);
    try t.expect(cache.find(value, 7, "ac") == null);
    try t.expect(cache.find(value[0..4], 7, "ab") == null);
    cache.store(value, 9, "ab", "this output is too long");
    try t.expect(cache.find(value, 9, "ab") == null);
    cache.clear();
    try t.expect(cache.find(value, 7, "ab") == null);
    cache.epoch = std.math.maxInt(u16);
    cache.store(value, 7, "ab", "hello");
    cache.clear();
    try t.expect(cache.find(value, 7, "ab") == null);
    cache.store(value, 7, "ab", "hello");
    try t.expectEqualStrings("hello", cache.find(value, 7, "ab").?);
}
