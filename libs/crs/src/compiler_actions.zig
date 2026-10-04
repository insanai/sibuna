//! Action decoding and source-plan validation; no transaction effects are executed.
const std = @import("std");
const model = @import("model.zig");
const syntax = @import("syntax.zig");

pub const Error = syntax.Error || std.mem.Allocator.Error || error{
    UnknownAction,
    UnknownTransform,
    TooManyActions,
    InvalidActionValue,
    InvalidId,
    InvalidPhase,
    DuplicateAction,
    ConflictingActions,
};

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limit: usize,
) Error![]const model.Action {
    var result: std.ArrayList(model.Action) = .empty;
    errdefer result.deinit(allocator);
    var iterator: syntax.Actions = .{ .bytes = bytes };
    var seen: std.EnumSet(model.ActionKind) = .{};
    while (try iterator.next()) |raw| {
        if (result.items.len == limit) return error.TooManyActions;
        const kind = model.actions.get(raw.name) orelse return error.UnknownAction;
        if (seen.contains(kind) and !repeatable(kind)) return error.DuplicateAction;
        seen.insert(kind);
        const transform = if (kind == .transform)
            model.transforms.get(raw.value orelse return error.InvalidActionValue) orelse
                return error.UnknownTransform
        else
            null;
        try validate(kind, raw.value);
        try result.append(allocator, .{
            .kind = kind,
            .value = raw.value,
            .transform = transform,
        });
    }
    const disruptive: usize = @intFromBool(seen.contains(.deny)) +
        @as(usize, @intFromBool(seen.contains(.pass))) + @intFromBool(seen.contains(.block));
    if (disruptive > 1) return error.ConflictingActions;
    return result.toOwnedSlice(allocator);
}

fn repeatable(kind: model.ActionKind) bool {
    return switch (kind) {
        .tag, .transform, .set_var, .control, .init_collection => true,
        else => false,
    };
}

fn validate(kind: model.ActionKind, value: ?[]const u8) Error!void {
    switch (kind) {
        .id => _ = try id(value orelse return error.InvalidActionValue),
        .phase => _ = try phase(value orelse return error.InvalidActionValue),
        .status => {
            const status = try decimal(u16, value orelse return error.InvalidActionValue);
            if (status < 100 or status > 599) return error.InvalidActionValue;
        },
        .log_data,
        .message,
        .control,
        .init_collection,
        .set_var,
        .severity,
        .skip_after,
        .transform,
        .tag,
        .version,
        => {
            if (value == null) return error.InvalidActionValue;
        },
        else => if (value != null) return error.InvalidActionValue,
    }
}

pub fn id(bytes: []const u8) Error!u32 {
    const value = decimal(u32, bytes) catch return error.InvalidId;
    if (value == 0) return error.InvalidId;
    return value;
}

pub fn phase(bytes: []const u8) Error!model.Phase {
    const value = decimal(u3, bytes) catch return error.InvalidPhase;
    if (value < 1 or value > 5) return error.InvalidPhase;
    return @fromBackingInt(@intCast(value));
}

fn decimal(comptime T: type, bytes: []const u8) Error!T {
    if (bytes.len == 0) return error.InvalidActionValue;
    for (bytes) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidActionValue;
    return std.fmt.parseInt(T, bytes, 10) catch return error.InvalidActionValue;
}

pub fn find(actions: []const model.Action, kind: model.ActionKind) ?model.Action {
    for (actions) |action| if (action.kind == kind) return action;
    return null;
}

test "action ordering and repeatable semantics survive source compilation" {
    const allocator = std.testing.allocator;
    const text = "id:9,t:none,t:lowercase,setvar:tx.a=1,setvar:tx.a=+2";
    const parsed = try parse(allocator, text, 8);
    defer allocator.free(parsed);
    try std.testing.expectEqual(model.Transform.none, parsed[1].transform.?);
    try std.testing.expectEqual(model.Transform.lowercase, parsed[2].transform.?);
    try std.testing.expectEqualStrings("tx.a=+2", parsed[4].value.?);
    try std.testing.expectError(error.DuplicateAction, parse(allocator, "id:9,id:10", 8));
    try std.testing.expectError(error.ConflictingActions, parse(allocator, "deny,pass", 8));
    try std.testing.expectError(error.UnknownTransform, parse(allocator, "t:surprise", 8));
    try std.testing.expectError(error.InvalidActionValue, parse(allocator, "status:99", 8));
}
