//! Ordered Pike simulation. No allocation, recursive backtracking or suffix restarts.
//! First arrival at a state wins; unsupported capture-dependent transitions are absent.
const std = @import("std");
const types = @import("regex_types.zig");
const work = @import("work.zig");
const dfa = @import("regex_dfa.zig");

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
    /// Present for reserved workspaces; Boolean matches use it before the NFA.
    dfa: ?dfa.Cache = null,

    pub fn requiredStates(program: *const types.Program) usize {
        return program.instructions.len;
    }

    fn validate(self: *const Scratch, states: usize) Error!void {
        if (self.current.len < states or self.next.len < states or
            self.visited.len < states or self.stack.len < states * 2) return error.ScratchTooSmall;
    }
};

/// A Boolean match needs no capture slots. Its state is a program counter, so each step
/// copies four bytes instead of a full capture thread.
const Pc = struct { pc: u32 };

/// Ordered Pike simulation state for either state shape. Control flow is shared, so a
/// Boolean match reaches the same decision as `search`. Work charges what a step copies.
fn Simulation(comptime State: type) type {
    return struct {
        program: *const types.Program,
        input: []const u8,
        current: []State,
        next: []State,
        stack: []State,
        visited: []usize,
        budget: *work.Budget,
        used: usize = 0,
        next_used: usize = 0,
        stack_used: usize = 0,
    };
}

fn simulation(
    comptime State: type,
    program: *const types.Program,
    input: []const u8,
    scratch: *Scratch,
    budget: *work.Budget,
) Simulation(State) {
    return .{
        .program = program,
        .input = input,
        .current = reinterpret(State, scratch.current),
        .next = reinterpret(State, scratch.next),
        .stack = reinterpret(State, scratch.stack),
        .visited = scratch.visited,
        .budget = budget,
    };
}

/// Reserved thread storage is reinterpreted, never resized: a state is no larger than a
/// thread, so every bound proven for threads holds for states.
/// One unit per state step plus one per capture slot it copies.
fn stepCost(comptime State: type) u64 {
    return 1 + if (@hasField(State, "captures")) types.capture_slots else 0;
}

fn reinterpret(comptime State: type, threads: []Thread) []State {
    if (State == Thread) return threads;
    comptime std.debug.assert(@sizeOf(State) <= @sizeOf(Thread));
    const states: []State = std.mem.bytesAsSlice(State, std.mem.sliceAsBytes(threads));
    return states[0..threads.len];
}

fn enter(comptime State: type, self: *Simulation(State), position: usize) Error!void {
    try self.budget.debit(1);
    if (!self.program.nullable and (position == self.input.len or
        !self.program.first.contains(self.input[position]))) return;
    try closure(State, self, .{ .pc = self.program.start }, position);
}

fn push(comptime State: type, self: *Simulation(State), state: State) Error!void {
    try self.budget.debit(stepCost(State));
    if (self.stack_used == self.stack.len) return error.ScratchTooSmall;
    self.stack[self.stack_used] = state;
    self.stack_used += 1;
}

/// DFS follows the first split branch first. Marking on pop preserves its priority over
/// a pending lower-priority path to the same instruction.
fn closure(
    comptime State: type,
    self: *Simulation(State),
    state: State,
    position: usize,
) Error!void {
    self.stack_used = 0;
    try push(State, self, state);
    while (self.stack_used > 0) {
        self.stack_used -= 1;
        var active = self.stack[self.stack_used];
        try self.budget.debit(stepCost(State));
        if (self.visited[active.pc] == position) continue;
        self.visited[active.pc] = position;
        const instruction = self.program.instructions[active.pc];
        switch (instruction.op) {
            .split => {
                active.pc = instruction.alternative;
                try push(State, self, active);
                active.pc = instruction.next;
                try push(State, self, active);
            },
            .jump, .save => {
                if (comptime @hasField(State, "captures")) {
                    if (instruction.op == .save) active.captures[instruction.op.save] = position;
                }
                active.pc = instruction.next;
                try push(State, self, active);
            },
            .assertion => |assertion| if (asserted(assertion, self.input, position)) {
                active.pc = instruction.next;
                try push(State, self, active);
            },
            .class, .accept => {
                if (self.next_used == self.next.len) return error.ScratchTooSmall;
                self.next[self.next_used] = active;
                self.next_used += 1;
            },
        }
    }
}

fn run(comptime State: type, self: *Simulation(State)) Error!?State {
    const states = self.program.instructions.len;
    // One transaction reserves the largest program's workspace. Reset and charge only
    // this program's states; unused capacity must not consume each rule's budget.
    try self.budget.debit(states);
    @memset(self.visited[0..states], types.unset);
    try enter(State, self, 0);
    var candidate: ?State = null;
    var position: usize = 0;
    while (true) {
        std.mem.swap([]State, &self.current, &self.next);
        self.used = self.next_used;
        self.next_used = 0;
        for (self.current[0..self.used], 0..) |state, index| {
            try self.budget.debit(1);
            if (self.program.instructions[state.pc].op == .accept) {
                candidate = state;
                self.used = index;
                break;
            }
        }
        if (position == self.input.len) return candidate;
        for (self.current[0..self.used]) |state| {
            try self.budget.debit(1);
            const instruction = self.program.instructions[state.pc];
            if (instruction.op.class.contains(self.input[position])) {
                var advanced = state;
                advanced.pc = instruction.next;
                try closure(State, self, advanced, position + 1);
            }
        }
        position += 1;
        if (candidate != null and self.next_used == 0) return candidate;
        if (candidate == null) try enter(State, self, position);
    }
}

pub fn search(
    program: *const types.Program,
    input: []const u8,
    scratch: *Scratch,
    budget: *work.Budget,
) Error!?Match {
    try scratch.validate(program.instructions.len);
    var state = simulation(Thread, program, input, scratch, budget);
    const accepted = try run(Thread, &state) orelse return null;
    return .{ .captures = accepted.captures };
}

/// Same decision as `search` when no capture is consumed, without copying capture slots.
pub fn matches(
    program: *const types.Program,
    input: []const u8,
    scratch: *Scratch,
    budget: *work.Budget,
) Error!bool {
    try scratch.validate(program.instructions.len);
    if (scratch.dfa) |*cache| {
        const buffers: dfa.Buffers = .{
            .stack = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(scratch.stack)),
            .kernel = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(scratch.current)),
            .visited = scratch.visited,
        };
        if (try dfa.matches(program, input, cache, buffers, budget)) |decision| return decision;
    }
    var state = simulation(Pc, program, input, scratch, budget);
    return try run(Pc, &state) != null;
}

fn word(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

fn asserted(assertion: types.Assertion, input: []const u8, position: usize) bool {
    return switch (assertion.kind) {
        .absolute_start => position == 0,
        .absolute_end => position == input.len,
        .start => position == 0 or (assertion.multiline and position < input.len and
            input[position - 1] == '\n'),
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
