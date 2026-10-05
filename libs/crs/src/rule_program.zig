//! Immutable prepared rule graph. HTTP acquisition and activation qualification
//! remain separate contracts; compiling this graph does not enable the daemon.
const std = @import("std");
const Diagnostic = @import("text").source_diagnostic.Diagnostic;
const model = @import("model.zig");
const selectors = @import("selectors.zig");
const condition = @import("condition.zig");
const post = @import("post_actions.zig");
const chains = @import("chains.zig");
const data = @import("rule_data.zig");
const variables = @import("variables.zig");
const review = @import("rule_review.zig");
const exclusions = @import("exclusion_review.zig");
pub const Error = condition.Error || post.Error || chains.Error || data.Error || error{
    InvalidTargetUpdate,
} || exclusions.Error;
pub const Limits = struct {
    condition: condition.Limits = .{},
    chains: chains.Limits = .{},
    data_bytes: usize = 32 * 1024 * 1024,
    diagnostic: ?*?Diagnostic = null,
};
pub const Program = struct {
    allocator: std.mem.Allocator,
    conditions: []condition.Program,
    actions: []post.Program,
    topology: chains.Program,
    signature: []const u8,
    regex_states: usize,
    review: []review.Fingerprint = &.{},
    exclusions: []exclusions.api.Row = &.{},

    pub fn deinit(self: *Program) void {
        for (self.conditions) |*program| program.deinit();
        for (self.actions) |*program| program.deinit();
        self.allocator.free(self.conditions);
        self.allocator.free(self.actions);
        self.allocator.free(self.signature);
        self.allocator.free(self.review);
        self.allocator.free(self.exclusions);
        self.topology.deinit();
        self.* = undefined;
    }

    pub fn requiredTransformScratch(self: *const Program, input: usize) Error!usize {
        var required: usize = input;
        for (self.conditions) |*program| {
            required = @max(required, try program.transforms.requiredScratch(input));
        }
        return required;
    }

    /// Count values fit the reserved decimal buffer; raw entities have different
    /// bounds from parsed fields. Reserve for each actual target, not every body
    /// multiplied by transforms that cannot select it.
    pub fn transformScratch(self: *const Program, bounds: [variables.count]usize) Error!usize {
        var required: usize = 0;
        for (self.conditions) |*program| {
            const targets = if (program.targets) |*targets| targets else continue;
            var input: usize = 0;
            for (targets.targets) |target| {
                const bound = if (target.mode == .count)
                    20
                else
                    bounds[@backingInt(target.collection)];
                input = @max(input, bound);
            }
            required = @max(required, try program.transforms.requiredScratch(input));
        }
        return required;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    source: *const model.Plan,
    files: []const data.File,
    limits: Limits,
) Error!Program {
    var fault: Fault = .{};
    return compileInner(allocator, source, files, limits, &fault) catch |err| {
        if (limits.diagnostic) |output| output.* = Diagnostic.capture(
            err,
            if (fault.site) |value| value.path else null,
            if (fault.site) |value| value.line else null,
            fault.rule,
        );
        return err;
    };
}

const Fault = struct { site: ?model.Site = null, rule: ?u32 = null };

fn compileInner(
    allocator: std.mem.Allocator,
    source: *const model.Plan,
    files: []const data.File,
    limits: Limits,
    fault: *Fault,
) Error!Program {
    try data.validate(files, limits.data_bytes);
    try validateUpdates(source);
    var topology = try chains.compile(allocator, source.conditions, limits.chains);
    errdefer topology.deinit();
    const conditions = try allocator.alloc(condition.Program, source.conditions.len);
    errdefer allocator.free(conditions);
    const actions = try allocator.alloc(post.Program, source.conditions.len);
    errdefer allocator.free(actions);
    var initialized: usize = 0;
    errdefer for (0..initialized) |index| {
        conditions[index].deinit();
        actions[index].deinit();
    };
    var states: usize = 0;
    var reviewed = try review.Builder.init(allocator, source.conditions);
    defer reviewed.deinit();
    var excluded: exclusions.Builder = .{ .allocator = allocator };
    defer excluded.deinit();
    for (source.conditions, 0..) |original, index| {
        fault.* = .{ .site = original.site, .rule = original.id };
        var targets: [128]selectors.Selector = undefined;
        var files_scratch: [256][]const u8 = undefined;
        var updated = original;
        updated.targets = try withUpdates(source, index, &targets);
        const bytes = try data.resolve(&updated, files, &files_scratch);
        conditions[index] = try condition.compile(allocator, &updated, bytes, limits.condition);
        errdefer conditions[index].deinit();
        actions[index] = try post.compile(allocator, &updated);
        initialized += 1;
        reviewed.append(&updated, source.conditions, index, bytes, &actions[index]);
        try excluded.append(&updated, index, &actions[index]);
        states = @max(states, conditions[index].regexStates());
    }
    fault.* = .{};
    const signature = try allocator.dupe(u8, source.signature orelse "");
    errdefer allocator.free(signature);
    const inventory = try excluded.take();
    return .{
        .allocator = allocator,
        .conditions = conditions,
        .actions = actions,
        .topology = topology,
        .signature = signature,
        .regex_states = states,
        .review = reviewed.take(),
        .exclusions = inventory,
    };
}

fn validateUpdates(source: *const model.Plan) Error!void {
    for (source.updates) |update| {
        const root = update.root orelse return error.InvalidTargetUpdate;
        if (root >= source.conditions.len or source.conditions[root].root != root or
            source.conditions[root].id != update.id or
            source.conditions[root].expression == null or update.targets.len == 0)
            return error.InvalidTargetUpdate;
    }
}

fn withUpdates(
    source: *const model.Plan,
    index: usize,
    output: []selectors.Selector,
) Error![]const selectors.Selector {
    const original = source.conditions[index].targets;
    if (original.len > output.len) return error.SelectorLimit;
    @memcpy(output[0..original.len], original);
    var used = original.len;
    for (source.updates) |update| {
        if (update.root.? != index) continue;
        if (update.targets.len > output.len - used) return error.SelectorLimit;
        @memcpy(output[used..][0..update.targets.len], update.targets);
        used += update.targets.len;
    }
    return output[0..used];
}

test {
    _ = @import("rule_program_test.zig");
}
