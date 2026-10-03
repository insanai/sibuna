//! A bounded non-voting learner for chosen Paxos values.
//!
//! `Learner` does not interpret promises or votes and cannot make a value
//! chosen. A trusted host feeds it values already established as chosen by the
//! active configuration. It buffers reordering, rejects conflicts, and releases
//! only a contiguous prefix to the application.

const std = @import("std");
const protocol = @import("protocol.zig");

/// Compile-time capacity of the bounded chosen-value window.
pub const Options = struct {
    /// Maximum chosen slots resident at once. Slots are global and never
    /// reset (ZDS 0011); a slot more than `max_entries` ahead of the
    /// released prefix is transient backpressure, not an error class the
    /// host can ignore.
    max_entries: usize = 256,
};

/// Outcome of recording one chosen value.
pub const LearnResult = enum {
    /// The identical value was already recorded for this slot; no change.
    duplicate,
    /// Recorded, but an undecided gap below it still blocks release.
    buffered,
    /// Recorded, and the contiguous released prefix advanced.
    advanced,
};

pub fn Learner(comptime Value: type, comptime options: Options) type {
    comptime {
        if (options.max_entries == 0) {
            @compileError("paxos Learner option max_entries must be greater than zero");
        }
    }

    return struct {
        const Self = @This();

        /// One released chosen value paired with its one-based slot.
        pub const Chosen = struct {
            slot: protocol.Slot,
            value: Value,
        };

        /// One slot-tagged window cell; slot zero means empty.
        pub const Cell = struct {
            slot: protocol.Slot = 0,
            value: Value = undefined,
        };

        configuration_id: u64,
        /// Sliding cell window over global slots: slot `s` lives in cell
        /// `(s - 1) % max_entries`, tag-checked. A released value stays
        /// readable until a later slot reuses its cell.
        learned: [options.max_entries]Cell =
            @as([options.max_entries]Cell, @splat(.{})),
        released_through: protocol.Slot = 0,

        /// Replaces `self` with an empty learner bound to one configuration;
        /// chosen values certified under any other configuration are rejected.
        pub fn init(self: *Self, configuration_id: u64) !void {
            if (configuration_id == 0) return error.InvalidConfigurationId;
            self.* = .{ .configuration_id = configuration_id };
            self.assertValid();
        }

        /// Records one host-certified chosen value for this configuration.
        /// Duplicates are idempotent; a different value for the same slot is
        /// evidence of corruption or a violated host certification contract.
        pub fn learnChosen(
            self: *Self,
            configuration_id: u64,
            slot: protocol.Slot,
            value: Value,
        ) !LearnResult {
            self.assertValid();
            if (configuration_id != self.configuration_id) {
                return error.ConfigurationMismatch;
            }
            if (slot == 0) return error.InvalidSlot;
            if (slot <= self.released_through) {
                // Still resident: the duplicate is still checkable.
                const cell = &self.learned[cellIndex(slot)];
                if (cell.slot == slot and !std.meta.eql(cell.value, value)) {
                    return error.ConflictingChosenValue;
                }
                return .duplicate;
            }
            if (slot > self.released_through + options.max_entries) {
                return error.WindowFull;
            }
            const cell = &self.learned[cellIndex(slot)];
            if (cell.slot == slot) {
                if (!std.meta.eql(cell.value, value)) {
                    return error.ConflictingChosenValue;
                }
                return .duplicate;
            }
            // Two distinct resident slots never share a cell, so anything
            // else in it is a released predecessor the host consumed.
            std.debug.assert(cell.slot <= self.released_through);
            cell.* = .{ .slot = slot, .value = value };
            const before = self.released_through;
            self.advanceReleasedPrefix();
            self.assertValid();
            return if (self.released_through > before) .advanced else .buffered;
        }

        /// Copies the contiguous chosen suffix beginning at `from_slot`.
        pub fn readChosen(
            self: *const Self,
            from_slot: protocol.Slot,
            output: []Chosen,
        ) ![]const Chosen {
            self.assertValid();
            if (from_slot == 0) return error.InvalidSlot;
            if (from_slot > self.released_through) return output[0..0];
            // A released slot whose cell was reused by a buffered later
            // slot has left the window; the host consumed it or must
            // recover it from its own journal.
            if (from_slot + options.max_entries <= self.released_through) {
                return error.Trimmed;
            }
            const count: usize = @intCast(self.released_through - from_slot + 1);
            if (output.len < count) return error.ReadBufferTooSmall;
            for (output[0..count], 0..) |*chosen, offset| {
                const slot = from_slot + @as(protocol.Slot, @intCast(offset));
                const cell = &self.learned[cellIndex(slot)];
                if (cell.slot != slot) return error.Trimmed;
                chosen.* = .{ .slot = slot, .value = cell.value };
            }
            return output[0..count];
        }

        /// Returns a released chosen value still resident in the window.
        /// Buffered values above the contiguous prefix stay hidden until
        /// the gap below them fills, so applications never observe
        /// out-of-order state.
        pub fn chosenAt(self: *const Self, slot: protocol.Slot) ?Value {
            if (slot == 0 or slot > self.released_through) return null;
            const cell = &self.learned[cellIndex(slot)];
            if (cell.slot != slot) return null;
            return cell.value;
        }

        fn advanceReleasedPrefix(self: *Self) void {
            while (true) {
                const next = self.released_through + 1;
                if (self.learned[cellIndex(next)].slot != next) return;
                self.released_through = next;
            }
        }

        fn assertValid(self: *const Self) void {
            if (!std.debug.runtime_safety) return;
            std.debug.assert(self.configuration_id > 0);
        }

        fn cellIndex(slot: protocol.Slot) usize {
            return @intCast((slot - 1) % options.max_entries);
        }
    };
}

test "learner releases only a contiguous chosen prefix" {
    const L = Learner(u64, .{ .max_entries = 4 });
    var learner: L = undefined;
    try learner.init(7);

    try std.testing.expectEqual(.buffered, try learner.learnChosen(7, 2, 22));
    try std.testing.expectEqual(@as(protocol.Slot, 0), learner.released_through);
    try std.testing.expectEqual(.advanced, try learner.learnChosen(7, 1, 11));
    try std.testing.expectEqual(@as(protocol.Slot, 2), learner.released_through);
    try std.testing.expectEqual(.duplicate, try learner.learnChosen(7, 2, 22));
    try std.testing.expectError(
        error.ConflictingChosenValue,
        learner.learnChosen(7, 2, 23),
    );
}

test "learner window wraps across global slots" {
    const L = Learner(u64, .{ .max_entries = 4 });
    var learner: L = undefined;
    try learner.init(7);

    // Fill and release well past the window capacity.
    for (1..11) |slot| {
        _ = try learner.learnChosen(7, @intCast(slot), @as(u64, slot) * 10);
    }
    try std.testing.expectEqual(@as(protocol.Slot, 10), learner.released_through);
    try std.testing.expectEqual(@as(?u64, 100), learner.chosenAt(10));
    // Slot 5's cell was reused by slot 9; the value left the window.
    try std.testing.expectEqual(@as(?u64, null), learner.chosenAt(5));
    var output: [4]L.Chosen = undefined;
    try std.testing.expectError(error.Trimmed, learner.readChosen(5, &output));

    // Backpressure, not corruption, beyond the resident window.
    try std.testing.expectError(
        error.WindowFull,
        learner.learnChosen(7, 15, 150),
    );
    // A gap stalls release; filling it resumes.
    _ = try learner.learnChosen(7, 12, 120);
    try std.testing.expectEqual(@as(protocol.Slot, 10), learner.released_through);
    try std.testing.expectEqual(.advanced, try learner.learnChosen(7, 11, 110));
    try std.testing.expectEqual(@as(protocol.Slot, 12), learner.released_through);
}

test "learner rejects messages from another configuration" {
    const L = Learner(u64, .{ .max_entries = 2 });
    var learner: L = undefined;
    try learner.init(9);
    try std.testing.expectError(
        error.ConfigurationMismatch,
        learner.learnChosen(8, 1, 1),
    );
}
