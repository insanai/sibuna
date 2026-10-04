//! Off-path source-plan compiler. Owns all text, validates ordering and resolves
//! symbolic references. This plan is not executable until runtime compatibility exists.
const std = @import("std");
const source = @import("source.zig");
const syntax = @import("syntax.zig");
const model = @import("model.zig");
const actions = @import("compiler_actions.zig");

pub const Error = actions.Error || error{
    InvalidState,
    CompiledLimit,
    PathLimit,
    SourceLimit,
    FileLimit,
    ConditionLimit,
    MarkerLimit,
    UpdateLimit,
    ChainLimit,
    MissingId,
    DuplicateId,
    InvalidChainAction,
    DanglingChain,
    DuplicateMarker,
    UnknownMarker,
    BackwardMarker,
    UnknownRuleId,
    UnknownOperator,
    DuplicateSignature,
    InvalidDefaults,
};

pub const Compiler = struct {
    backing: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    limits: model.Limits,
    conditions: std.ArrayList(model.Condition) = .empty,
    markers: std.ArrayList(model.Marker) = .empty,
    updates: std.ArrayList(model.TargetUpdate) = .empty,
    ids: std.AutoHashMapUnmanaged(u32, usize) = .empty,
    defaults: [5]?[]const model.Action = @splat(null),
    signature: ?[]const u8 = null,
    pending_chain: ?usize = null,
    chain_size: usize = 0,
    source_bytes: usize = 0,
    files: usize = 0,
    failed: bool = false,
    fault: ?model.Site = null,

    pub fn init(allocator: std.mem.Allocator, limits: model.Limits) Compiler {
        return .{ .backing = allocator, .arena = .init(allocator), .limits = limits };
    }

    pub fn deinit(self: *Compiler) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// On any failure the builder becomes unusable; no partial plan can escape.
    pub fn addSource(self: *Compiler, path: []const u8, bytes: []const u8) Error!void {
        if (self.failed) return error.InvalidState;
        errdefer self.failed = true;
        self.fault = null;
        if (path.len > self.limits.path_bytes) return error.PathLimit;
        if (bytes.len > self.limits.source_bytes - self.source_bytes) return error.SourceLimit;
        if (self.files == self.limits.files) return error.FileLimit;
        self.source_bytes += bytes.len;
        self.files += 1;
        const allocator = self.arena.allocator();
        const owned_path = try allocator.dupe(u8, path);
        const scratch = try self.backing.alloc(u8, self.limits.logical_line);
        defer self.backing.free(scratch);
        var reader: source.Reader = .{ .source = bytes };
        while (reader.next(scratch) catch |err| {
            self.fault = .{ .path = owned_path, .line = reader.fault.line };
            return err;
        }) |line| {
            self.fault = .{ .path = owned_path, .line = line.location.line };
            const owned = try allocator.dupe(u8, line.bytes);
            try self.add(try syntax.parse(owned), self.fault.?);
            if (self.arena.queryCapacity() > self.limits.compiled_bytes) {
                return error.CompiledLimit;
            }
        }
        if (self.pending_chain != null) return error.DanglingChain;
    }

    fn add(self: *Compiler, directive: syntax.Directive, site: model.Site) Error!void {
        if (self.pending_chain != null and directive != .rule) return error.DanglingChain;
        switch (directive) {
            .rule => |rule| {
                const raw = try syntax.Operator.parse(rule.operator.bytes);
                const expression: model.Expression = .{
                    .kind = model.operators.get(raw.name) orelse return error.UnknownOperator,
                    .argument = raw.argument,
                    .negated = raw.negated,
                };
                const text = if (rule.actions) |token| token.bytes else "";
                try self.addCondition(site, rule.selectors.bytes, expression, text);
            },
            .action => |token| try self.addCondition(site, "", null, token.bytes),
            .marker => |token| try self.addMarker(site, token.bytes),
            .defaults => |token| try self.addDefaults(token.bytes),
            .component => |token| {
                if (self.signature != null) return error.DuplicateSignature;
                self.signature = token.bytes;
            },
            .update_target => |update| {
                if (self.updates.items.len == self.limits.target_updates) return error.UpdateLimit;
                try self.updates.append(self.arena.allocator(), .{
                    .site = site,
                    .id = try actions.id(update.id.bytes),
                    .selectors = update.selectors.bytes,
                });
            },
        }
    }

    fn addCondition(
        self: *Compiler,
        site: model.Site,
        selectors: []const u8,
        expression: ?model.Expression,
        action_text: []const u8,
    ) Error!void {
        if (self.conditions.items.len == self.limits.conditions) return error.ConditionLimit;
        const allocator = self.arena.allocator();
        const compiled = try actions.parse(
            allocator,
            action_text,
            self.limits.actions_per_condition,
        );
        const index = self.conditions.items.len;
        const root = if (self.pending_chain) |previous|
            self.conditions.items[previous].root
        else
            index;
        const resolved = try self.identity(compiled, root, index);
        try self.conditions.append(allocator, .{
            .site = site,
            .id = resolved.id,
            .root = root,
            .phase = resolved.phase,
            .selectors = selectors,
            .expression = expression,
            .actions = compiled,
            .inherited_actions = self.defaults[@backingInt(resolved.phase) - 1] orelse &.{},
        });
        if (self.pending_chain) |previous| self.conditions.items[previous].chain_next = index;
        const chain = actions.find(compiled, .chain) != null;
        if (chain and expression == null) return error.InvalidChainAction;
        self.pending_chain = if (chain) index else null;
        self.chain_size = if (root == index) 1 else self.chain_size + 1;
        if (self.chain_size > self.limits.chain) return error.ChainLimit;
    }

    const Identity = struct { id: u32, phase: model.Phase };

    fn identity(
        self: *Compiler,
        compiled: []const model.Action,
        root: usize,
        index: usize,
    ) Error!Identity {
        if (root != index) {
            for (compiled) |action| switch (action.kind) {
                .id, .phase, .deny, .block, .pass, .skip_after => return error.InvalidChainAction,
                else => {},
            };
            const parent = self.conditions.items[root];
            return .{ .id = parent.id, .phase = parent.phase };
        }
        const id_action = actions.find(compiled, .id) orelse return error.MissingId;
        const id = try actions.id(id_action.value.?);
        const phase = if (actions.find(compiled, .phase)) |action|
            try actions.phase(action.value.?)
        else
            .request_body;
        const entry = try self.ids.getOrPut(self.arena.allocator(), id);
        if (entry.found_existing) return error.DuplicateId;
        entry.value_ptr.* = index;
        return .{ .id = id, .phase = phase };
    }

    fn addMarker(self: *Compiler, site: model.Site, name: []const u8) Error!void {
        if (self.markers.items.len == self.limits.markers) return error.MarkerLimit;
        for (self.markers.items) |marker| {
            if (std.mem.eql(u8, marker.name, name)) return error.DuplicateMarker;
        }
        try self.markers.append(self.arena.allocator(), .{
            .site = site,
            .name = name,
            .position = self.conditions.items.len,
        });
    }

    fn addDefaults(self: *Compiler, bytes: []const u8) Error!void {
        const compiled = try actions.parse(
            self.arena.allocator(),
            bytes,
            self.limits.actions_per_condition,
        );
        const phase = try actions.phase(
            (actions.find(compiled, .phase) orelse return error.InvalidDefaults).value.?,
        );
        if (actions.find(compiled, .id) != null or actions.find(compiled, .chain) != null) {
            return error.InvalidDefaults;
        }
        self.defaults[@backingInt(phase) - 1] = compiled;
    }

    /// Resolution occurs after all after-CRS exclusions have been read. Ownership
    /// transfers on success; the builder's new empty arena remains safe to deinit.
    pub fn finish(self: *Compiler) Error!model.Plan {
        if (self.failed) return error.InvalidState;
        errdefer self.failed = true;
        if (self.pending_chain != null) return error.DanglingChain;
        for (self.conditions.items, 0..) |*condition, index| {
            self.fault = condition.site;
            if (actions.find(condition.actions, .skip_after)) |action| {
                condition.skip_to = try self.resolveMarker(action.value.?, index);
            }
        }
        for (self.updates.items) |*update| {
            self.fault = update.site;
            update.root = self.ids.get(update.id) orelse return error.UnknownRuleId;
        }
        const allocator = self.arena.allocator();
        const conditions = try self.conditions.toOwnedSlice(allocator);
        const markers = try self.markers.toOwnedSlice(allocator);
        const updates = try self.updates.toOwnedSlice(allocator);
        if (self.arena.queryCapacity() > self.limits.compiled_bytes) return error.CompiledLimit;
        const result: model.Plan = .{
            .arena = self.arena,
            .conditions = conditions,
            .markers = markers,
            .updates = updates,
            .defaults = self.defaults,
            .signature = self.signature,
        };
        self.arena = .init(self.backing);
        self.failed = true;
        return result;
    }

    fn resolveMarker(self: *const Compiler, name: []const u8, index: usize) Error!usize {
        for (self.markers.items) |marker| {
            if (!std.mem.eql(u8, marker.name, name)) continue;
            if (marker.position <= index) return error.BackwardMarker;
            return marker.position;
        }
        return error.UnknownMarker;
    }
};

test "source plan owns text and resolves chains and exclusions" {
    var compiler = Compiler.init(std.testing.allocator, .{});
    defer compiler.deinit();
    var mutable = ("SecDefaultAction \"phase:1,log,pass\"\n" ++
        "SecRule ARGS \"@rx x\" \"id:7,phase:1,chain\"\n" ++
        "SecRule TX:n \"@eq 1\"\n" ++
        "SecRule ARGS \"!@contains y\" \"id:8,skipAfter:END\"\n" ++
        "SecMarker END\nSecRuleUpdateTargetById 7 \"!ARGS:token\"\n").*;
    try compiler.addSource("test.conf", &mutable);
    @memset(&mutable, 'x');
    var plan = try compiler.finish();
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 3), plan.conditions.len);
    try std.testing.expectEqual(@as(usize, 1), plan.conditions[0].chain_next.?);
    try std.testing.expectEqual(@as(u32, 7), plan.conditions[1].id);
    try std.testing.expectEqual(model.Phase.request_headers, plan.conditions[1].phase);
    try std.testing.expectEqual(@as(usize, 3), plan.conditions[2].skip_to.?);
    try std.testing.expectEqual(@as(usize, 0), plan.updates[0].root.?);
    try std.testing.expectEqualStrings("x", plan.conditions[0].expression.?.argument);
    try std.testing.expect(!model.Plan.executable);
}

test "failed candidate cannot finish or continue" {
    var compiler = Compiler.init(std.testing.allocator, .{});
    defer compiler.deinit();
    const duplicate = "SecAction \"id:1,phase:1\"\nSecAction \"id:1,phase:2\"\n";
    try std.testing.expectError(error.DuplicateId, compiler.addSource("bad.conf", duplicate));
    try std.testing.expectError(error.InvalidState, compiler.finish());
    try std.testing.expectError(error.InvalidState, compiler.addSource("other", ""));
}

test "dangling chains and marker jumps are rejected" {
    var dangling = Compiler.init(std.testing.allocator, .{});
    defer dangling.deinit();
    const chain = "SecRule ARGS x \"id:1,chain\"\n";
    try std.testing.expectError(error.DanglingChain, dangling.addSource("bad.conf", chain));
    var backward = Compiler.init(std.testing.allocator, .{});
    defer backward.deinit();
    try backward.addSource("bad.conf", "SecMarker BEGIN\nSecRule ARGS x \"id:1,skipAfter:BEGIN\"");
    try std.testing.expectError(error.BackwardMarker, backward.finish());
    var unknown = Compiler.init(std.testing.allocator, .{});
    defer unknown.deinit();
    try unknown.addSource("bad.conf", "SecRule ARGS x \"id:1,skipAfter:MISSING\"");
    try std.testing.expectError(error.UnknownMarker, unknown.finish());
}

test "source and instruction budgets reject before publication" {
    var compiler = Compiler.init(std.testing.allocator, .{ .conditions = 1 });
    defer compiler.deinit();
    const large = "SecAction \"id:1,phase:1\"\nSecAction \"id:2,phase:1\"";
    try std.testing.expectError(error.ConditionLimit, compiler.addSource("large.conf", large));
    var bounded = Compiler.init(std.testing.allocator, .{ .source_bytes = 3 });
    defer bounded.deinit();
    try std.testing.expectError(error.SourceLimit, bounded.addSource("too-large", "four"));
}

test "defaults are captured at each rule's source position" {
    var compiler = Compiler.init(std.testing.allocator, .{});
    defer compiler.deinit();
    try compiler.addSource("defaults.conf", "SecDefaultAction \"phase:2,deny,status:403\"\n" ++
        "SecRule ARGS x \"id:1\"\n" ++
        "SecDefaultAction \"phase:2,pass\"\n" ++
        "SecRule ARGS x \"id:2\"\n");
    var plan = try compiler.finish();
    defer plan.deinit();
    try std.testing.expect(actions.find(plan.conditions[0].inherited_actions, .deny) != null);
    try std.testing.expect(actions.find(plan.conditions[1].inherited_actions, .pass) != null);
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var compiler = Compiler.init(allocator, .{});
    defer compiler.deinit();
    try compiler.addSource("alloc.conf", "SecRule ARGS x \"id:1,phase:1,chain\"\n" ++
        "SecRule TX:n \"@eq 1\"\n" ++
        "SecMarker END\nSecRuleUpdateTargetById 1 \"!ARGS:token\"\n");
    var plan = try compiler.finish();
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.conditions.len);
}

test "candidate arena ownership survives every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailureCase, .{});
}
