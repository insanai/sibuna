//! Owned matcher storage allocated during startup or compilation, never during search.
//! Scratch lists can swap without changing ownership of the backing allocation.
const std = @import("std");
const types = @import("regex_types.zig");
const matcher = @import("regex_match.zig");

pub const Workspace = struct {
    allocator: std.mem.Allocator,
    threads: []matcher.Thread,
    scratch: matcher.Scratch,

    pub fn init(allocator: std.mem.Allocator, program: *const types.Program) !Workspace {
        const states = program.instructions.len;
        std.debug.assert(states > 0);
        return initStates(allocator, states);
    }

    /// One reserved workspace serves every immutable regex in a generation.
    pub fn initStates(allocator: std.mem.Allocator, states: usize) !Workspace {
        if (states == 0) return error.ScratchTooSmall;
        if (states > std.math.maxInt(usize) / (4 * @sizeOf(matcher.Thread))) {
            return error.ScratchTooSmall;
        }
        const threads = try allocator.alloc(matcher.Thread, states * 4);
        errdefer allocator.free(threads);
        const visited = try allocator.alloc(usize, states);
        return .{
            .allocator = allocator,
            .threads = threads,
            .scratch = .{
                .current = threads[0..states],
                .next = threads[states .. states * 2],
                .stack = threads[states * 2 ..],
                .visited = visited,
            },
        };
    }

    pub fn deinit(self: *Workspace) void {
        self.allocator.free(self.scratch.visited);
        self.allocator.free(self.threads);
        self.* = undefined;
    }
};
