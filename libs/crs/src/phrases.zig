//! Owned sparse phrase automata; compilation allocates, matching never does.
//! SID 0010 distinguishes complete Aho-Corasick from the pinned SecLang quirks.
const std = @import("std");
const work = @import("work.zig");

pub const Error = std.mem.Allocator.Error || work.Error || error{
    SourceLimit,
    PhraseLimit,
    NodeLimit,
    EmptyPhrase,
    NulPhrase,
    NonAsciiPhrase,
};
pub const Profile = enum { longest_suffix, modsecurity_3_0_14 };
pub const Options = struct {
    profile: Profile = .longest_suffix,
    bytes: usize = 4 * 1024 * 1024,
    phrases: usize = 8192,
    nodes: usize = 65536,
    compile_work: u64 = 64_000_000,
};
const Edge = struct { byte: u8, next: u32 };
const Node = struct {
    edge_start: u32 = 0,
    edge_count: u16 = 0,
    fail: u32 = 0,
    terminal: ?u32 = null,
    output: ?u32 = null,
    first_phrase: u32 = 0,
    depth: u32 = 0,
};
const Mutable = struct {
    byte: u8 = 0,
    child: ?u32 = null,
    sibling: ?u32 = null,
    first_phrase: u32 = 0,
    depth: u32 = 0,
    terminal: ?u32 = null,
};
pub const Match = struct { start: usize, end: usize, phrase: u32, capture: []const u8 };

const View = struct {
    nodes: []const Node,
    edges: []const Edge,

    fn outgoing(self: View, state: u32) []const Edge {
        const node = self.nodes[state];
        return self.edges[node.edge_start..][0..node.edge_count];
    }

    fn go(self: View, state: u32, byte: u8, budget: *work.Budget) work.Error!?u32 {
        // Empty edge lists still cost a lookup and may advance a failure chain.
        try budget.debit(1);
        const edges = self.outgoing(state);
        var left: usize = 0;
        var right = edges.len;
        while (left < right) {
            try budget.debit(1);
            const middle = left + (right - left) / 2;
            const edge = edges[middle];
            if (edge.byte == byte) return edge.next;
            if (edge.byte < byte) left = middle + 1 else right = middle;
        }
        return null;
    }
};

pub const Program = struct {
    owner: std.heap.ArenaAllocator,
    words: []const []const u8,
    view: View,
    profile: Profile,

    pub fn deinit(self: *Program) void {
        self.owner.deinit();
        self.* = undefined;
    }

    pub fn search(self: *const Program, input: []const u8, budget: *work.Budget) Error!?Match {
        var state: u32 = 0;
        for (input, 0..) |byte, index| {
            try budget.debit(1);
            while (true) {
                if (try self.view.go(state, std.ascii.toLower(byte), budget)) |next| {
                    state = next;
                    break;
                }
                if (state == 0) break;
                const fallback = self.view.nodes[state].fail;
                std.debug.assert(self.view.nodes[fallback].depth < self.view.nodes[state].depth);
                state = fallback;
            }
            const node = self.view.nodes[state];
            const phrase = node.output orelse continue;
            const capture = if (self.profile == .modsecurity_3_0_14)
                self.words[node.first_phrase][0..node.depth]
            else
                self.words[phrase];
            std.debug.assert(capture.len <= index + 1);
            return .{
                .start = index + 1 - capture.len,
                .end = index + 1,
                .phrase = phrase,
                .capture = capture,
            };
        }
        return null;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    words: []const []const u8,
    options: Options,
) Error!Program {
    if (options.nodes == 0 or options.nodes > std.math.maxInt(u32)) return error.NodeLimit;
    if (words.len > options.phrases or words.len > std.math.maxInt(u32)) return error.PhraseLimit;
    var owner = std.heap.ArenaAllocator.init(allocator);
    errdefer owner.deinit();
    const arena = owner.allocator();
    const owned = try arena.alloc([]const u8, words.len);
    var nodes: std.ArrayList(Mutable) = .empty;
    defer nodes.deinit(allocator);
    try nodes.append(allocator, .{});
    var budget: work.Budget = .{ .remaining = options.compile_work };
    var size: usize = 0;
    for (words, 0..) |word, index| {
        if (word.len == 0) return error.EmptyPhrase;
        if (word.len > options.bytes - size) return error.SourceLimit;
        size += word.len;
        const cost = std.math.mul(u64, @intCast(word.len), 3) catch return error.WorkLimit;
        try budget.debit(cost);
        if (std.mem.indexOfScalar(u8, word, 0) != null) return error.NulPhrase;
        if (options.profile == .modsecurity_3_0_14) {
            for (word) |byte| if (byte >= 128) return error.NonAsciiPhrase;
        }
        owned[index] = try arena.dupe(u8, word);
        try insert(allocator, &nodes, owned[index], @intCast(index), options, &budget);
    }
    const frozen = try arena.alloc(Node, nodes.items.len);
    const edges = try arena.alloc(Edge, nodes.items.len - 1);
    try freeze(nodes.items, frozen, edges, &budget);
    const view: View = .{ .nodes = frozen, .edges = edges };
    const queue = try allocator.alloc(u32, frozen.len);
    defer allocator.free(queue);
    try connect(view, frozen, queue, options.profile, &budget);
    return .{ .owner = owner, .words = owned, .view = view, .profile = options.profile };
}

fn insert(
    allocator: std.mem.Allocator,
    nodes: *std.ArrayList(Mutable),
    word: []const u8,
    phrase: u32,
    options: Options,
    budget: *work.Budget,
) Error!void {
    var state: u32 = 0;
    for (word) |byte| {
        try budget.debit(1);
        const folded = std.ascii.toLower(byte);
        var child = nodes.items[state].child;
        while (child) |index| {
            try budget.debit(1);
            if (nodes.items[index].byte == folded) break;
            child = nodes.items[index].sibling;
        }
        if (child == null) {
            if (nodes.items.len == options.nodes) return error.NodeLimit;
            const index: u32 = @intCast(nodes.items.len);
            const node: Mutable = .{
                .byte = folded,
                .first_phrase = phrase,
                .depth = nodes.items[state].depth + 1,
                .sibling = nodes.items[state].child,
            };
            try nodes.append(allocator, node);
            nodes.items[state].child = index;
            child = index;
        }
        state = child.?;
    }
    if (nodes.items[state].terminal == null) nodes.items[state].terminal = phrase;
}

fn sort(edges: []Edge, budget: *work.Budget) Error!void {
    for (0..edges.len) |index| {
        try budget.debit(1);
        const value = edges[index];
        var position = index;
        while (position > 0) {
            try budget.debit(2);
            if (edges[position - 1].byte <= value.byte) break;
            edges[position] = edges[position - 1];
            position -= 1;
        }
        edges[position] = value;
    }
}

fn freeze(source: []const Mutable, nodes: []Node, edges: []Edge, budget: *work.Budget) Error!void {
    var offset: usize = 0;
    for (source, nodes) |node, *out| {
        try budget.debit(1);
        const start = offset;
        var child = node.child;
        while (child) |index| {
            try budget.debit(1);
            edges[offset] = .{ .byte = source[index].byte, .next = index };
            offset += 1;
            child = source[index].sibling;
        }
        try sort(edges[start..offset], budget);
        out.* = .{
            .edge_start = @intCast(start),
            .edge_count = @intCast(offset - start),
            .terminal = node.terminal,
            .output = node.terminal,
            .first_phrase = node.first_phrase,
            .depth = node.depth,
        };
    }
    std.debug.assert(offset == edges.len);
}

test {
    _ = @import("phrases_test.zig");
}

fn connect(
    view: View,
    nodes: []Node,
    queue: []u32,
    profile: Profile,
    budget: *work.Budget,
) Error!void {
    var head: usize = 0;
    var tail: usize = 0;
    for (view.outgoing(0)) |edge| {
        try budget.debit(1);
        queue[tail] = edge.next;
        tail += 1;
    }
    while (head < tail) : (head += 1) {
        try budget.debit(1);
        const parent = queue[head];
        for (view.outgoing(parent)) |edge| {
            try budget.debit(1);
            var fallback = nodes[parent].fail;
            var target = try view.go(fallback, edge.byte, budget);
            if (profile == .longest_suffix) {
                while (target == null and fallback != 0) {
                    fallback = nodes[fallback].fail;
                    target = try view.go(fallback, edge.byte, budget);
                }
            }
            const fail = target orelse 0;
            nodes[edge.next].fail = fail;
            nodes[edge.next].output = nodes[edge.next].terminal orelse nodes[fail].output;
            std.debug.assert(nodes[fail].depth < nodes[edge.next].depth);
            std.debug.assert(tail < queue.len);
            queue[tail] = edge.next;
            tail += 1;
        }
    }
    std.debug.assert(tail + 1 == nodes.len);
}
