//! Prepared transaction controls. Entries borrow an immutable generation, never
//! request scratch; that generation must remain pinned through every HTTP phase.
const std = @import("std");
const collections = @import("collections.zig");
const work = @import("work.zig");
const macros = @import("macros.zig");

pub const Error = macros.Error || error{
    InvalidControl,
    UnsupportedControl,
    SourceLimit,
    ExclusionLimit,
    TransactionFailed,
};
pub const Processor = enum { automatic, urlencoded, json, xml };
pub const Audit = enum { inherited, on, off, relevant_only };
pub const Range = struct { first: u32, last: u32 };
pub const Selector = union(enum) { ids: Range, tag: []const u8 };
pub const Target = struct { collection: collections.Collection, key: ?[]const u8 };
pub const Exclusion = struct { selector: Selector, target: ?Target = null };
pub const Tags = union(enum) {
    values: []const []const u8,
    expanded: struct { programs: []const macros.Program, frame: macros.Frame },
};
pub const Filter = struct {
    state: *State,
    id: u32,
    tags: []const macros.Program,

    pub fn excludes(self: Filter, field: ?Target, frame: macros.Frame) Error!bool {
        return self.state.excludesTags(self.id, .{
            .expanded = .{ .programs = self.tags, .frame = frame },
        }, field, frame.budget);
    }
};
pub const Operation = union(enum) {
    exclude: []const Exclusion,
    processor: Processor,
    force_body: bool,
    audit: Audit,
};

pub const Program = struct {
    arena: std.heap.ArenaAllocator,
    operation: Operation,

    pub fn deinit(self: *Program) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Parsing is deliberately strict: unknown controls, malformed ranges and empty
/// keys cannot turn a requested protection change into a successful no-op.
pub fn compile(allocator: std.mem.Allocator, source: []const u8) Error!Program {
    if (source.len > 64 * 1024) return error.SourceLimit;
    const equal = std.mem.indexOfScalar(u8, source, '=') orelse return error.InvalidControl;
    const name = source[0..equal];
    const value = source[equal + 1 ..];
    if (value.len == 0 or std.mem.indexOfScalar(u8, source, 0) != null)
        return error.InvalidControl;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = try arena.allocator().dupe(u8, value);
    const operation = try parse(arena.allocator(), name, owned);
    return .{ .arena = arena, .operation = operation };
}

fn parse(allocator: std.mem.Allocator, name: []const u8, value: []const u8) Error!Operation {
    if (std.ascii.eqlIgnoreCase(name, "requestBodyProcessor")) {
        if (std.ascii.eqlIgnoreCase(value, "JSON")) return .{ .processor = .json };
        if (std.ascii.eqlIgnoreCase(value, "URLENCODED")) return .{ .processor = .urlencoded };
        if (std.ascii.eqlIgnoreCase(value, "XML")) return .{ .processor = .xml };
        return error.InvalidControl;
    }
    if (std.ascii.eqlIgnoreCase(name, "forceRequestBodyVariable")) {
        if (std.ascii.eqlIgnoreCase(value, "On")) return .{ .force_body = true };
        if (std.ascii.eqlIgnoreCase(value, "Off")) return .{ .force_body = false };
        return error.InvalidControl;
    }
    if (std.ascii.eqlIgnoreCase(name, "auditEngine")) {
        if (std.ascii.eqlIgnoreCase(value, "On")) return .{ .audit = .on };
        if (std.ascii.eqlIgnoreCase(value, "Off")) return .{ .audit = .off };
        if (std.ascii.eqlIgnoreCase(value, "RelevantOnly")) return .{ .audit = .relevant_only };
        return error.InvalidControl;
    }
    return .{ .exclude = try exclusions(allocator, name, value) };
}

fn exclusions(
    allocator: std.mem.Allocator,
    name: []const u8,
    value: []const u8,
) Error![]const Exclusion {
    const by_id = std.ascii.eqlIgnoreCase(name, "ruleRemoveById");
    const by_tag = std.ascii.eqlIgnoreCase(name, "ruleRemoveByTag");
    const target_id = std.ascii.eqlIgnoreCase(name, "ruleRemoveTargetById");
    const target_tag = std.ascii.eqlIgnoreCase(name, "ruleRemoveTargetByTag");
    if (!by_id and !by_tag and !target_id and !target_tag) return error.UnsupportedControl;
    var result: std.ArrayList(Exclusion) = .empty;
    if (by_id) {
        var words = std.mem.tokenizeAny(u8, value, " \t");
        while (words.next()) |word| {
            if (result.items.len == 256) return error.SourceLimit;
            try result.append(allocator, .{ .selector = .{ .ids = try range(word) } });
        }
        if (result.items.len == 0) return error.InvalidControl;
    } else if (by_tag) {
        try result.append(allocator, .{ .selector = .{ .tag = value } });
    } else {
        const semicolon = std.mem.indexOfScalar(u8, value, ';') orelse
            return error.InvalidControl;
        const selector = value[0..semicolon];
        if (selector.len == 0) return error.InvalidControl;
        const ids = if (target_id) try range(selector) else null;
        // The pinned v3 target-by-ID action accepts one ID, not an ID range.
        if (ids) |r| if (r.first != r.last) return error.InvalidControl;
        try result.append(allocator, .{
            .selector = if (ids) |r| .{ .ids = r } else .{ .tag = selector },
            .target = try target(value[semicolon + 1 ..]),
        });
    }
    return result.toOwnedSlice(allocator);
}

fn range(value: []const u8) Error!Range {
    const dash = std.mem.indexOfScalar(u8, value, '-');
    const first = try identifier(value[0 .. dash orelse value.len]);
    const last = if (dash) |index| try identifier(value[index + 1 ..]) else first;
    if (first > last) return error.InvalidControl;
    return .{ .first = first, .last = last };
}

fn identifier(value: []const u8) Error!u32 {
    if (value.len == 0) return error.InvalidControl;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidControl;
    const id = std.fmt.parseInt(u32, value, 10) catch return error.InvalidControl;
    if (id == 0 or id > std.math.maxInt(i32)) return error.InvalidControl;
    return id;
}

fn target(value: []const u8) Error!Target {
    if (std.mem.indexOfAny(u8, value, ";\r\n\x00") != null) return error.InvalidControl;
    const colon = std.mem.indexOfScalar(u8, value, ':');
    const collection = collections.lookup(value[0 .. colon orelse value.len]) orelse
        return error.InvalidControl;
    const key = if (colon) |index| value[index + 1 ..] else null;
    if (key) |bytes| if (bytes.len == 0 or !collection.keyed()) return error.InvalidControl;
    return .{ .collection = collection, .key = key };
}

pub const State = struct {
    exclusions: []Exclusion,
    used: usize = 0,
    processor: Processor = .automatic,
    force_body: bool = false,
    audit: Audit = .inherited,
    failed: bool = false,

    pub fn apply(self: *State, program: *const Program, budget: *work.Budget) Error!void {
        if (self.failed) return error.TransactionFailed;
        errdefer self.failed = true;
        switch (program.operation) {
            .exclude => |items| {
                if (items.len > self.exclusions.len - self.used) return error.ExclusionLimit;
                try budget.debit(items.len);
                @memcpy(self.exclusions[self.used..][0..items.len], items);
                self.used += items.len;
            },
            .processor => |value| {
                try budget.debit(1);
                self.processor = value;
            },
            .force_body => |value| {
                try budget.debit(1);
                self.force_body = value;
            },
            .audit => |value| {
                try budget.debit(1);
                self.audit = value;
            },
        }
    }

    /// Tags are the rule's expanded local tags. A target exclusion applies only
    /// to that field; it cannot suppress the entire rule or another collection.
    pub fn excludes(
        self: *State,
        id: u32,
        tags: []const []const u8,
        field: ?Target,
        budget: *work.Budget,
    ) Error!bool {
        return self.excludesTags(id, .{ .values = tags }, field, budget);
    }

    pub fn excludesTags(
        self: *State,
        id: u32,
        tags: Tags,
        field: ?Target,
        budget: *work.Budget,
    ) Error!bool {
        if (self.failed) return error.TransactionFailed;
        errdefer self.failed = true;
        for (self.exclusions[0..self.used]) |item| {
            try budget.debit(1);
            if (!try selected(item.selector, id, tags, budget)) continue;
            if (item.target) |wanted| {
                const actual = field orelse continue;
                if (wanted.collection != actual.collection) continue;
                if (wanted.key) |key| {
                    const actual_key = actual.key orelse continue;
                    try budget.debit(key.len + actual_key.len);
                    if (!std.mem.eql(u8, key, actual_key)) continue;
                }
            }
            return true;
        }
        return false;
    }
};

fn selected(
    selector: Selector,
    id: u32,
    tags: Tags,
    budget: *work.Budget,
) Error!bool {
    switch (selector) {
        .ids => |ids| return id >= ids.first and id <= ids.last,
        .tag => |wanted| return hasTag(tags, wanted, budget),
    }
}

fn hasTag(tags: Tags, wanted: []const u8, budget: *work.Budget) Error!bool {
    switch (tags) {
        .values => |values| for (values) |tag| {
            try budget.debit(wanted.len + tag.len);
            if (std.mem.eql(u8, wanted, tag)) return true;
        },
        .expanded => |expanded| {
            std.debug.assert(expanded.frame.budget == budget);
            for (expanded.programs) |*program| {
                const tag = try program.expand(expanded.frame);
                try budget.debit(wanted.len + tag.len);
                if (std.mem.eql(u8, wanted, tag)) return true;
            }
        },
    }
    return false;
}

test {
    _ = @import("controls_test.zig");
}
