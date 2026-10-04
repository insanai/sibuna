//! Safe-index implementation of the pinned reference's byte path normalization.
// Compatibility algorithm adapted from ModSecurity 3.0.14 under Apache-2.0.
// Copyright (c) 2015-2021 Trustwave Holdings, Inc. See NOTICE and LICENSES/.
const std = @import("std");
const types = @import("transform_types.zig");

const State = struct {
    buffer: types.Buffer,
    win: bool,
    relative: bool,
    hit_root: bool = false,
    changed: bool = false,
    done: bool = false,
    position: usize = 0,
    written: usize = 0,

    fn byte(self: *State, index: usize) u8 {
        const value = self.buffer.input[index];
        if (self.win and value == '\\') {
            self.changed = true;
            return '/';
        }
        return value;
    }

    /// true skips the ordinary copy. Each removed byte was previously written;
    /// root saturation avoids the reference's temporary out-of-allocation pointer.
    fn segment(self: *State, value: u8) bool {
        const out = self.buffer.output;
        if (!self.done and value == '/') {
            self.changed = true;
        } else if (value == '.') {
            if (self.written > 0 and out[self.written - 1] == '.') {
                if (self.relative and (self.hit_root or self.written <= 2)) {
                    self.hit_root = true;
                    return false;
                }
                self.written -|= 3;
                while (self.written > 0 and out[self.written] != '/') self.written -= 1;
                if (self.written == 0) {
                    self.hit_root = true;
                    if (!self.relative and self.done) self.written = 1;
                }
                if (self.done) return true;
                self.position += 1;
                self.changed = true;
            } else if (self.written == 0 or out[self.written - 1] == '/') {
                self.changed = true;
                if (self.done) return true;
                if (self.written > 0) self.written -= 1;
                self.position += 1;
            }
        } else if (self.written > 0) {
            self.hit_root = false;
        }
        return false;
    }

    fn copy(self: *State) void {
        if (self.byte(self.position) == '/') {
            const start = self.position;
            while (self.position + 1 < self.buffer.input.len) {
                if (self.byte(self.position + 1) != '/') break;
                self.position += 1;
            }
            self.changed = self.changed or self.position != start;
            if (self.relative and self.written == 0) {
                self.position += 1;
                return;
            }
        }
        self.buffer.output[self.written] = self.byte(self.position);
        self.written += 1;
        self.position += 1;
    }
};

pub fn normalize(buffer: types.Buffer, win: bool) types.Write {
    if (buffer.input.len == 0) return .{ .length = 0, .changed = false };
    var state: State = .{
        .buffer = buffer,
        .win = win,
        .relative = buffer.input[0] != '/' and !(win and buffer.input[0] == '\\'),
    };
    const last = buffer.input[buffer.input.len - 1];
    const trailing = last == '/' or (win and last == '\\');
    while (!state.done and state.position < buffer.input.len) {
        std.debug.assert(state.written <= state.position);
        const value = state.byte(state.position);
        state.done = state.position + 1 == buffer.input.len;
        const boundary = state.done or state.byte(state.position + 1) == '/';
        if (boundary and state.segment(value)) continue;
        state.copy();
    }
    if (!trailing and state.written > 0 and buffer.output[state.written - 1] == '/') {
        state.written -= 1;
    }
    return .{ .length = state.written, .changed = state.changed };
}

test "root saturation relative traversal and binary path bytes remain bounded" {
    const cases = [_]struct {
        input: []const u8,
        output: []const u8,
        changed: bool,
        win: bool = false,
    }{
        .{ .input = "", .output = "", .changed = false },
        .{ .input = "/..", .output = "", .changed = false },
        .{ .input = "a/..", .output = "", .changed = false },
        .{ .input = "../../x", .output = "../../x", .changed = false },
        .{ .input = "/a//../b/", .output = "/b/", .changed = true },
        .{ .input = "a/./b\x00x", .output = "a/b\x00x", .changed = true },
        .{ .input = "\\a\\..\\b", .output = "/b", .changed = true, .win = true },
    };
    var output: [64]u8 = undefined;
    for (cases) |case| {
        const result = normalize(.{
            .input = case.input,
            .output = &output,
            .budget = undefined,
        }, case.win);
        try std.testing.expectEqualStrings(case.output, output[0..result.length]);
        try std.testing.expectEqual(case.changed, result.changed);
    }
}

test "hostile cursor sequences never cross input or output bounds" {
    var random = std.Random.DefaultPrng.init(0x50415448);
    const alphabet = "/.\\ab\x00";
    var input: [256]u8 = undefined;
    var output: [256]u8 = undefined;
    for (0..4096) |index| {
        const length = index % (input.len + 1);
        for (input[0..length]) |*byte| {
            const chosen = random.random().uintLessThan(usize, alphabet.len);
            byte.* = alphabet[chosen];
        }
        for ([_]bool{ false, true }) |win| {
            const result = normalize(.{
                .input = input[0..length],
                .output = output[0..length],
                .budget = undefined,
            }, win);
            try std.testing.expect(result.length <= length);
        }
    }
}
