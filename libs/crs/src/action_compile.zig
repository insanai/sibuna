//! Compile post-match timing separately from pre-chain captures and local writes.
const std = @import("std");
const model = @import("model.zig");
const macros = @import("macros.zig");
const controls = @import("controls.zig");
const set_var = @import("set_var.zig");
const state = @import("action_state.zig");
pub const Error = macros.Error || controls.Error || set_var.Error || error{
    InvalidAction,
    ActionLimit,
};
pub const Binding = struct { namespace: state.Namespace, key: macros.Program };
pub const Step = union(enum) {
    control: controls.Program,
    write: set_var.Program,
    binding: Binding,
    message: macros.Program,
    data: macros.Program,
    tag: macros.Program,
    severity: u3,
    status: u16,
    save: bool,
    audit: bool,
    deny,
    pass,
    block,

    pub fn deinit(self: *Step) void {
        switch (self.*) {
            .control => |*program| program.deinit(),
            .write => |*program| program.deinit(),
            .binding => |*item| item.key.deinit(),
            .message, .data, .tag => |*program| program.deinit(),
            else => {},
        }
    }
};

pub const Program = struct {
    allocator: std.mem.Allocator,
    steps: []Step,
    id: u32,
    phase: model.Phase,
    default_deny: bool,

    pub fn deinit(self: *Program) void {
        for (self.steps) |*step| step.deinit();
        self.allocator.free(self.steps);
        self.* = undefined;
    }
};

pub fn compile(allocator: std.mem.Allocator, condition: *const model.Condition) Error!Program {
    var steps: std.ArrayList(Step) = .empty;
    errdefer {
        for (steps.items) |*step| step.deinit();
        steps.deinit(allocator);
    }
    var default_deny = false;
    for (condition.inherited_actions) |action| {
        if (action.kind == .deny or action.kind == .pass) {
            default_deny = action.kind == .deny;
            continue;
        }
        try appendAction(allocator, &steps, action);
    }
    // The reference extracts tags and the last metadata action before processing
    // local runtime actions. Preserve that order even if source text interleaves them.
    for (condition.actions) |action| {
        if (action.kind == .tag) try appendAction(allocator, &steps, action);
    }
    for ([_]model.ActionKind{ .severity, .log_data, .message }) |kind| {
        var last: ?model.Action = null;
        for (condition.actions) |action| if (action.kind == kind) {
            last = action;
        };
        if (last) |action| try appendAction(allocator, &steps, action);
    }
    var disruption: ?model.Action = null;
    for (condition.actions) |action| {
        switch (action.kind) {
            .deny, .pass => disruption = action,
            .tag, .severity, .log_data, .message, .set_var => {},
            else => try appendAction(allocator, &steps, action),
        }
    }
    if (disruption) |action| try appendAction(allocator, &steps, action);
    return .{
        .allocator = allocator,
        .steps = try steps.toOwnedSlice(allocator),
        .id = condition.id,
        .phase = condition.phase,
        .default_deny = default_deny,
    };
}

fn appendAction(
    allocator: std.mem.Allocator,
    steps: *std.ArrayList(Step),
    action: model.Action,
) Error!void {
    if (steps.items.len == 1024) return error.ActionLimit;
    var step: Step = switch (action.kind) {
        .control => .{ .control = try controls.compile(allocator, try value(action)) },
        .set_var => .{ .write = try set_var.compile(allocator, try value(action)) },
        .init_collection => .{ .binding = try binding(allocator, try value(action)) },
        .message => .{ .message = try macros.compile(allocator, try value(action), .{}) },
        .log_data => .{ .data = try macros.compile(allocator, try value(action), .{}) },
        .tag => .{ .tag = try macros.compile(allocator, try value(action), .{}) },
        .severity => .{ .severity = try severity(try value(action)) },
        .status => .{ .status = try status(try value(action)) },
        .log => .{ .save = true },
        .no_log => .{ .save = false },
        .audit_log => .{ .audit = true },
        .no_audit_log => .{ .audit = false },
        .deny => .deny,
        .pass => .pass,
        .block => .block,
        .capture, .chain, .id, .multi_match, .phase, .skip_after, .transform, .version => return,
    };
    errdefer step.deinit();
    try steps.append(allocator, step);
}

fn value(action: model.Action) Error![]const u8 {
    return action.value orelse error.InvalidAction;
}

fn binding(allocator: std.mem.Allocator, source: []const u8) Error!Binding {
    const equal = std.mem.indexOfScalar(u8, source, '=') orelse return error.InvalidAction;
    const name = source[0..equal];
    const namespace: state.Namespace = std.meta.stringToEnum(state.Namespace, name) orelse
        return error.InvalidAction;
    return .{
        .namespace = namespace,
        .key = try macros.compile(allocator, source[equal + 1 ..], .{}),
    };
}

fn severity(source: []const u8) Error!u3 {
    const names = [_][]const u8{
        "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
    };
    for (names, 0..) |name, index| {
        if (std.ascii.eqlIgnoreCase(source, name)) return @intCast(index);
    }
    return decimal(u3, source);
}

fn status(source: []const u8) Error!u16 {
    const number = try decimal(u16, source);
    if (number < 100 or number > 599) return error.InvalidAction;
    return number;
}

fn decimal(comptime T: type, source: []const u8) Error!T {
    if (source.len == 0) return error.InvalidAction;
    for (source) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidAction;
    return std.fmt.parseInt(T, source, 10) catch error.InvalidAction;
}
