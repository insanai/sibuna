const std = @import("std");

/// A fixed-capacity set whose storage is optimized for size and speed.
/// Uses a single register for small sets (<= 64 bits) and an array of u64 words for larger sets.
pub fn BitSet(comptime bit_count: usize) type {
    comptime {
        if (bit_count == 0) {
            @compileError("paxos BitSet bit_count must be greater than zero");
        }
    }
    if (bit_count <= 64) {
        const Bits = @Int(.unsigned, bit_count);
        return struct {
            const Self = @This();
            bits: Bits = 0,
            /// Adds `index`, returning true only on first insertion so
            /// callers can count distinct members without a second lookup.
            /// Asserts `index < bit_count` in safe builds.
            pub fn insert(self: *Self, index: usize) bool {
                std.debug.assert(index < bit_count);
                const mask = @as(Bits, 1) << @intCast(index);
                if (self.bits & mask != 0) return false;
                self.bits |= mask;
                return true;
            }
            /// Returns whether `index` is present.
            /// Asserts `index < bit_count` in safe builds.
            pub fn contains(self: Self, index: usize) bool {
                std.debug.assert(index < bit_count);
                return self.bits & (@as(Bits, 1) << @intCast(index)) != 0;
            }
            /// Returns the number of members currently in the set.
            pub fn count(self: Self) usize {
                return @intCast(@popCount(self.bits));
            }
        };
    } else {
        const word_size = 64;
        const word_count = (bit_count + word_size - 1) / word_size;
        const Word = u64;
        return struct {
            const Self = @This();
            words: [word_count]Word = @as([word_count]Word, @splat(0)),
            /// Adds `index`, returning true only on first insertion so
            /// callers can count distinct members without a second lookup.
            /// Asserts `index < bit_count` in safe builds.
            pub fn insert(self: *Self, index: usize) bool {
                std.debug.assert(index < bit_count);
                const word_idx = index / word_size;
                const mask = @as(Word, 1) << @intCast(index % word_size);
                if (self.words[word_idx] & mask != 0) return false;
                self.words[word_idx] |= mask;
                return true;
            }
            /// Returns whether `index` is present.
            /// Asserts `index < bit_count` in safe builds.
            pub fn contains(self: Self, index: usize) bool {
                std.debug.assert(index < bit_count);
                const mask = @as(Word, 1) << @intCast(index % word_size);
                return self.words[index / word_size] & mask != 0;
            }
            /// Returns the number of members currently in the set.
            pub fn count(self: Self) usize {
                var total: usize = 0;
                for (self.words) |word| total += @popCount(word);
                return total;
            }
        };
    }
}

test "bit set inserts once and counts members" {
    const Set = BitSet(7);
    var set = Set{};

    try std.testing.expect(set.insert(0));
    try std.testing.expect(set.insert(6));
    try std.testing.expect(!set.insert(0));
    try std.testing.expect(set.contains(6));
    try std.testing.expectEqual(@as(usize, 2), set.count());
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(Set));
}
