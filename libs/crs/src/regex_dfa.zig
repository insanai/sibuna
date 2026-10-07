//! Lazy DFA for Boolean regex matching. CRS alternations reach thousands of NFA states,
//! and an ordered Pike simulation walks all of them for every input byte. A DFA state is
//! the set of states reached after a byte plus what the byte before tells the assertions;
//! each is built once per search and reused for every later byte that leads to it.
//!
//! The cache is bounded and reset when full. After `resets_allowed` resets the caller
//! falls back to the Pike simulation, so the worst case stays O(S N) as for the NFA.
const std = @import("std");
const types = @import("regex_types.zig");
const work = @import("work.zig");
const reserved = @import("reserved.zig");

pub const Error = work.Error || error{ScratchTooSmall};

/// DFA states cached per search, scaled with the largest program. Each owns one 256-entry
/// transition row; CRS command and XSS alternations visit hundreds of states on natural
/// text, so their cache reaches the full 1,024 while small programs reserve little.
pub fn stateCapacity(regex_states: usize) usize {
    return std.math.clamp(2 * regex_states, 16, 1024);
}
const resets_allowed = 4;
const unknown = std.math.maxInt(u32);
const accepted = unknown - 1;

/// What the previous byte contributes to assertions at the current position.
const Context = packed struct(u8) {
    begin: bool = false,
    newline: bool = false,
    word: bool = false,
    _: u5 = 0,
};

pub const Cache = struct {
    transitions: []u32,
    kernel_start: []u32,
    kernel_len: []u32,
    context: []Context,
    kernels: []u32,
    /// Search epoch in the high half, state in the low half; zero is empty.
    index: []u32,
    epoch: u16 = 1,
    states: u32 = 0,
    kernel_used: usize = 0,
    resets: u32 = 0,
    /// Closure marks persist across searches. Starting far above any input position keeps
    /// them distinct from the positions the Pike simulation writes into the same array.
    stamp: usize = 1 << (@bitSizeOf(usize) - 2),

    /// Kernel storage holds every cached state's set; a single set never exceeds the
    /// program's states, so at least four full sets always fit before a reset.
    pub fn kernelCapacity(regex_states: usize) usize {
        return 4 * regex_states + 16 * stateCapacity(regex_states);
    }

    pub fn bytes(regex_states: usize) usize {
        const states = stateCapacity(regex_states);
        return states * 256 * @sizeOf(u32) + states * (2 * @sizeOf(u32) + 1) +
            kernelCapacity(regex_states) * @sizeOf(u32) + 2 * states * @sizeOf(u32);
    }

    pub fn init(allocator: std.mem.Allocator, regex_states: usize) !Cache {
        const state_capacity = stateCapacity(regex_states);
        const transitions = try reserved.alloc(allocator, u32, state_capacity * 256);
        errdefer allocator.free(transitions);
        const kernel_start = try allocator.alloc(u32, state_capacity);
        errdefer allocator.free(kernel_start);
        const kernel_len = try allocator.alloc(u32, state_capacity);
        errdefer allocator.free(kernel_len);
        const context = try allocator.alloc(Context, state_capacity);
        errdefer allocator.free(context);
        const kernels = try reserved.alloc(allocator, u32, kernelCapacity(regex_states));
        errdefer allocator.free(kernels);
        return .{
            .transitions = transitions,
            .kernel_start = kernel_start,
            .kernel_len = kernel_len,
            .context = context,
            .kernels = kernels,
            .index = blk: {
                const index = try allocator.alloc(u32, 2 * state_capacity);
                @memset(index, 0);
                break :blk index;
            },
        };
    }

    pub fn deinit(self: *Cache, allocator: std.mem.Allocator) void {
        allocator.free(self.index);
        allocator.free(self.kernels);
        allocator.free(self.context);
        allocator.free(self.kernel_len);
        allocator.free(self.kernel_start);
        allocator.free(self.transitions);
        self.* = undefined;
    }

    /// Entries from an earlier epoch read as empty, so clearing is constant time. The
    /// index is wiped only when the epoch wraps.
    fn clear(self: *Cache) void {
        self.states = 0;
        self.kernel_used = 0;
        self.epoch +%= 1;
        if (self.epoch == 0) {
            @memset(self.index, 0);
            self.epoch = 1;
        }
    }

    fn live(self: *const Cache, entry: u32) bool {
        return entry >> 16 == self.epoch;
    }

    fn tagged(self: *const Cache, state: u32) u32 {
        return @as(u32, self.epoch) << 16 | state;
    }

    fn kernel(self: *const Cache, state: u32) []const u32 {
        return self.kernels[self.kernel_start[state]..][0..self.kernel_len[state]];
    }

    fn find(self: *const Cache, set: []const u32, context: Context) ?u32 {
        var position = hash(set, context) % self.index.len;
        while (self.live(self.index[position])) : (position = (position + 1) % self.index.len) {
            const state: u32 = self.index[position] & 0xffff;
            if (self.context[state] == context and std.mem.eql(u32, self.kernel(state), set))
                return state;
        }
        return null;
    }

    /// Returns null when the cache must be cleared first; the caller decides whether a
    /// further reset is allowed or the search falls back to the Pike simulation.
    fn insert(self: *Cache, set: []const u32, context: Context) ?u32 {
        if (self.states == self.kernel_start.len or set.len > self.kernels.len - self.kernel_used)
            return null;
        const state = self.states;
        self.states += 1;
        @memcpy(self.kernels[self.kernel_used..][0..set.len], set);
        self.kernel_start[state] = @intCast(self.kernel_used);
        self.kernel_len[state] = @intCast(set.len);
        self.kernel_used += set.len;
        self.context[state] = context;
        @memset(self.transitions[state * 256 ..][0..256], unknown);
        var position = hash(set, context) % self.index.len;
        while (self.live(self.index[position])) position = (position + 1) % self.index.len;
        self.index[position] = self.tagged(state);
        return state;
    }
};

fn hash(set: []const u32, context: Context) usize {
    var hasher = std.hash.Wyhash.init(@as(u8, @bitCast(context)));
    hasher.update(std.mem.sliceAsBytes(set));
    return @truncate(hasher.final());
}

/// Caller-owned closure scratch from the regex workspace; never retained.
pub const Buffers = struct {
    stack: []u32,
    kernel: []u32,
    visited: []usize,
};

/// Assertion inputs at one position: the previous byte from the state, the next byte
/// from the input and whether that next byte is the last one.
const Position = struct {
    context: Context,
    next: ?u8,
    last: bool,

    fn satisfies(self: Position, assertion: types.Assertion) bool {
        const end = self.next == null;
        const next_newline = if (self.next) |byte| byte == '\n' else false;
        return switch (assertion.kind) {
            .absolute_start => self.context.begin,
            .absolute_end => end,
            .start => self.context.begin or
                (assertion.multiline and !end and self.context.newline),
            .end => end or (next_newline and (assertion.multiline or self.last)),
            .final_end => end or (self.last and next_newline),
            .word, .not_word => blk: {
                const next_word = if (self.next) |byte| word(byte) else false;
                const boundary = self.context.word != next_word;
                break :blk if (assertion.kind == .word) boundary else !boundary;
            },
        };
    }
};

const Search = struct {
    program: *const types.Program,
    input: []const u8,
    cache: *Cache,
    buffers: Buffers,
    budget: *work.Budget,

    /// Epsilon closure of a kernel at one position. Returns true on acceptance;
    /// otherwise writes the sorted next kernel for `byte` into the kernel buffer.
    fn close(self: *Search, set: []const u32, at: Position) Error!union(enum) {
        accept,
        next: []u32,
    } {
        self.cache.stamp += 1;
        const stamp = self.cache.stamp;
        var stack_used: usize = 0;
        var next_used: usize = 0;
        const start_allowed = self.program.nullable or
            (if (at.next) |byte| self.program.first.contains(byte) else false);
        if (start_allowed) try self.push(&stack_used, self.program.start);
        for (set) |pc| try self.push(&stack_used, pc);
        while (stack_used > 0) {
            stack_used -= 1;
            const pc = self.buffers.stack[stack_used];
            try self.budget.debit(1);
            if (self.buffers.visited[pc] == stamp) continue;
            self.buffers.visited[pc] = stamp;
            const instruction = self.program.instructions[pc];
            switch (instruction.op) {
                .split => {
                    try self.push(&stack_used, instruction.alternative);
                    try self.push(&stack_used, instruction.next);
                },
                .jump, .save => try self.push(&stack_used, instruction.next),
                .assertion => |assertion| if (at.satisfies(assertion)) {
                    try self.push(&stack_used, instruction.next);
                },
                .class => |class| if (at.next) |byte| if (class.contains(byte)) {
                    if (next_used == self.buffers.kernel.len) return error.ScratchTooSmall;
                    self.buffers.kernel[next_used] = instruction.next;
                    next_used += 1;
                },
                .accept => return .accept,
            }
        }
        const next = self.buffers.kernel[0..next_used];
        std.mem.sort(u32, next, {}, std.sort.asc(u32));
        return .{ .next = next[0..dedupe(next)] };
    }

    fn push(self: *Search, used: *usize, pc: u32) Error!void {
        if (used.* == self.buffers.stack.len) return error.ScratchTooSmall;
        self.buffers.stack[used.*] = pc;
        used.* += 1;
    }

    /// Result of one transition: a state, acceptance, or a request to fall back.
    fn step(self: *Search, state: u32, position: usize) Error!?u32 {
        const byte = self.input[position];
        const last = position + 1 == self.input.len;
        const row = state * 256 + byte;
        if (!last) {
            const cached = self.cache.transitions[row];
            if (cached != unknown) return cached;
        }
        const at: Position = .{ .context = self.cache.context[state], .next = byte, .last = last };
        const next = switch (try self.close(self.cache.kernel(state), at)) {
            .accept => return accepted,
            .next => |set| set,
        };
        const context: Context = .{ .newline = byte == '\n', .word = word(byte) };
        const reset_before = self.cache.resets;
        const target = try self.intern(next, context) orelse return null;
        // A reset invalidated `state`'s row; only an unchanged cache may record the edge.
        if (!last and self.cache.resets == reset_before) self.cache.transitions[row] = target;
        return target;
    }

    fn intern(self: *Search, set: []const u32, context: Context) Error!?u32 {
        if (self.cache.find(set, context)) |state| return state;
        if (self.cache.insert(set, context)) |state| return state;
        if (self.cache.resets == resets_allowed) return null;
        self.cache.resets += 1;
        // The kernel buffer, not the cache, holds `set`, so clearing cannot lose it.
        self.cache.clear();
        return self.cache.insert(set, context) orelse error.ScratchTooSmall;
    }
};

fn dedupe(sorted: []u32) usize {
    if (sorted.len == 0) return 0;
    var used: usize = 1;
    for (sorted[1..]) |pc| {
        if (pc == sorted[used - 1]) continue;
        sorted[used] = pc;
        used += 1;
    }
    return used;
}

fn word(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

/// Returns the Boolean decision, or null when the bounded cache thrashed and the caller
/// must answer with the Pike simulation instead.
pub fn matches(
    program: *const types.Program,
    input: []const u8,
    cache: *Cache,
    buffers: Buffers,
    budget: *work.Budget,
) Error!?bool {
    const states = program.instructions.len;
    if (buffers.visited.len < states or buffers.stack.len < 2 * states or
        buffers.kernel.len < states or cache.kernels.len < states) return error.ScratchTooSmall;
    try budget.debit(1);
    cache.clear();
    cache.resets = 0;
    var search: Search = .{
        .program = program,
        .input = input,
        .cache = cache,
        .buffers = buffers,
        .budget = budget,
    };
    var state = cache.insert(&.{}, .{ .begin = true }).?;
    for (0..input.len) |position| {
        try budget.debit(1);
        state = try search.step(state, position) orelse return null;
        if (state == accepted) return true;
    }
    const end: Position = .{ .context = cache.context[state], .next = null, .last = false };
    return switch (try search.close(cache.kernel(state), end)) {
        .accept => true,
        .next => false,
    };
}
