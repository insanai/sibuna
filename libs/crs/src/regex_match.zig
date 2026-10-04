//! Ordered Pike simulation. No allocation, recursive backtracking or suffix restarts.
//! First arrival at a state wins; unsupported capture-dependent transitions are absent.
const std = @import("std");
const types = @import("regex_types.zig");
const work = @import("work.zig");

pub const Error = work.Error || error{ScratchTooSmall};
pub const Thread = struct { pc: u32, captures: [types.capture_slots]usize = @splat(types.unset) };
pub const Match = struct {
    captures: [types.capture_slots]usize,

    pub fn span(self: *const Match, group: usize) ?struct { start: usize, end: usize } {
        if (group > types.max_groups) return null;
        const start = self.captures[group * 2];
        const end = self.captures[group * 2 + 1];
        if (start == types.unset or end == types.unset) return null;
        std.debug.assert(start <= end);
        return .{ .start = start, .end = end };
    }
};

pub const Scratch = struct {
    current: []Thread,
    next: []Thread,
    stack: []Thread,
    visited: []usize,
    used: usize = 0,
    next_used: usize = 0,
    stack_used: usize = 0,

    pub fn requiredStates(program: *const types.Program) usize {
        return program.instructions.len;
    }

    fn validate(self: *const Scratch, states: usize) Error!void {
        if (self.current.len < states or self.next.len < states or
            self.visited.len < states or self.stack.len < states * 2) return error.ScratchTooSmall;
    }
};

const Context = struct {
    program: *const types.Program,
    input: []const u8,
    scratch: *Scratch,
    budget: *work.Budget,

    fn push(self: *Context, thread: Thread) Error!void {
        try self.budget.debit(1 + types.capture_slots);
        if (self.scratch.stack_used == self.scratch.stack.len) return error.ScratchTooSmall;
        self.scratch.stack[self.scratch.stack_used] = thread;
        self.scratch.stack_used += 1;
    }

    /// DFS follows the first split branch first. Marking on pop preserves its
    /// priority over a pending lower-priority path to the same instruction.
    fn closure(self: *Context, thread: Thread, position: usize) Error!void {
        const scratch = self.scratch;
        scratch.stack_used = 0;
        try self.push(thread);
        while (scratch.stack_used > 0) {
            scratch.stack_used -= 1;
            var active = scratch.stack[scratch.stack_used];
            try self.budget.debit(1 + types.capture_slots);
            if (scratch.visited[active.pc] == position) continue;
            scratch.visited[active.pc] = position;
            const instruction = self.program.instructions[active.pc];
            switch (instruction.op) {
                .split => {
                    active.pc = instruction.alternative;
                    try self.push(active);
                    active.pc = instruction.next;
                    try self.push(active);
                },
                .jump, .save => {
                    if (instruction.op == .save) active.captures[instruction.op.save] = position;
                    active.pc = instruction.next;
                    try self.push(active);
                },
                .assertion => |assertion| if (asserted(assertion, self.input, position)) {
                    active.pc = instruction.next;
                    try self.push(active);
                },
                .class, .accept => {
                    if (scratch.next_used == scratch.next.len) return error.ScratchTooSmall;
                    scratch.next[scratch.next_used] = active;
                    scratch.next_used += 1;
                },
            }
        }
    }
};

pub fn search(
    program: *const types.Program,
    input: []const u8,
    scratch: *Scratch,
    budget: *work.Budget,
) Error!?Match {
    try scratch.validate(program.instructions.len);
    try budget.debit(scratch.visited.len);
    @memset(scratch.visited, types.unset);
    scratch.used = 0;
    scratch.next_used = 0;
    var context: Context = .{
        .program = program,
        .input = input,
        .scratch = scratch,
        .budget = budget,
    };
    try context.closure(.{ .pc = program.start }, 0);
    var candidate: ?Match = null;
    var position: usize = 0;
    while (true) {
        std.mem.swap([]Thread, &scratch.current, &scratch.next);
        scratch.used = scratch.next_used;
        scratch.next_used = 0;
        for (scratch.current[0..scratch.used], 0..) |thread, index| {
            try budget.debit(1);
            if (program.instructions[thread.pc].op == .accept) {
                candidate = .{ .captures = thread.captures };
                scratch.used = index;
                break;
            }
        }
        if (position == input.len) return candidate;
        for (scratch.current[0..scratch.used]) |thread| {
            try budget.debit(1);
            const instruction = program.instructions[thread.pc];
            if (instruction.op.class.contains(input[position])) {
                var advanced = thread;
                advanced.pc = instruction.next;
                try context.closure(advanced, position + 1);
            }
        }
        position += 1;
        if (candidate != null and scratch.next_used == 0) return candidate;
        if (candidate == null) try context.closure(.{ .pc = program.start }, position);
    }
}

fn word(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

fn asserted(assertion: types.Assertion, input: []const u8, position: usize) bool {
    return switch (assertion.kind) {
        .absolute_start => position == 0,
        .absolute_end => position == input.len,
        .start => position == 0 or (assertion.multiline and input[position - 1] == '\n'),
        .end => position == input.len or (input[position] == '\n' and
            (assertion.multiline or position + 1 == input.len)),
        .final_end => position == input.len or
            (position + 1 == input.len and input[position] == '\n'),
        .word, .not_word => blk: {
            const previous = position > 0 and word(input[position - 1]);
            const next = position < input.len and word(input[position]);
            break :blk if (assertion.kind == .word) previous != next else previous == next;
        },
    };
}
