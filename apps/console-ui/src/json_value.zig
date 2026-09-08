//! Decode an already parsed browser event tree. Strings borrow the event arena; models
//! must copy anything retained. The caller erases that arena after dispatch, even on error.
const std = @import("std");
pub const Error = error{ InvalidResponse, OutOfMemory };

pub fn decode(comptime T: type, value: std.json.Value, allocator: std.mem.Allocator) Error!T {
    return switch (@typeInfo(T)) {
        .@"struct" => structure(T, value, allocator),
        .optional => |optional| if (value == .null) null else try decode(
            optional.child,
            value,
            allocator,
        ),
        .bool => if (value == .bool) value.bool else error.InvalidResponse,
        .int => integer(T, value),
        .float => floating(T, value),
        .@"enum" => if (value == .string)
            std.meta.stringToEnum(T, value.string) orelse error.InvalidResponse
        else
            error.InvalidResponse,
        .array => array(T, value, allocator),
        .pointer => slice(T, value, allocator),
        else => @compileError("Unsupported browser wire type: " ++ @typeName(T)),
    };
}

fn structure(comptime T: type, value: std.json.Value, allocator: std.mem.Allocator) Error!T {
    if (value != .object) return error.InvalidResponse;
    var result: T = undefined;
    inline for (@typeInfo(T).@"struct".fields) |field| {
        @field(result, field.name) = if (value.object.get(field.name)) |item|
            try decode(field.type, item, allocator)
        else
            field.defaultValue() orelse return error.InvalidResponse;
    }
    return result;
}

fn integer(comptime T: type, value: std.json.Value) Error!T {
    if (value == .integer) return std.math.cast(T, value.integer) orelse error.InvalidResponse;
    if (value == .number_string)
        return std.fmt.parseInt(T, value.number_string, 10) catch error.InvalidResponse;
    return error.InvalidResponse;
}

fn floating(comptime T: type, value: std.json.Value) Error!T {
    const result: T = switch (value) {
        .integer => |number| @floatFromInt(number),
        .float => |number| @floatCast(number),
        .number_string => |number| std.fmt.parseFloat(T, number) catch
            return error.InvalidResponse,
        else => return error.InvalidResponse,
    };
    if (!std.math.isFinite(result)) return error.InvalidResponse;
    return result;
}

fn array(comptime T: type, value: std.json.Value, allocator: std.mem.Allocator) Error!T {
    const info = @typeInfo(T).array;
    if (value != .array or value.array.items.len != info.len) return error.InvalidResponse;
    var result: T = undefined;
    for (value.array.items, &result) |item, *output| output.* = try decode(
        info.child,
        item,
        allocator,
    );
    return result;
}

fn slice(comptime T: type, value: std.json.Value, allocator: std.mem.Allocator) Error!T {
    const info = @typeInfo(T).pointer;
    if (info.size != .slice or !info.is_const) @compileError("Wire slices must be const");
    if (info.child == u8) return if (value == .string) value.string else error.InvalidResponse;
    // Only incident/similarity response rows are variable-length. Reject their capacity
    // before allocation; fixed histogram arrays have their own exact type-level bound.
    if (value != .array or value.array.items.len > 10) return error.InvalidResponse;
    const result = try allocator.alloc(info.child, value.array.items.len);
    for (value.array.items, result) |item, *output| output.* = try decode(
        info.child,
        item,
        allocator,
    );
    return result;
}

test "wire decoder preserves integer bounds, requires fields and bounds rows before allocation" {
    const t = std.testing;
    var empty: [0]u8 = .{};
    var arena = std.heap.FixedBufferAllocator.init(&empty);
    try t.expectEqual(std.math.maxInt(u64), try decode(u64, .{
        .number_string = "18446744073709551615",
    }, arena.allocator()));
    try t.expectError(error.InvalidResponse, decode(u8, .{ .integer = 256 }, arena.allocator()));
    try t.expectError(error.InvalidResponse, decode(u64, .{ .integer = -1 }, arena.allocator()));
    try t.expectError(error.InvalidResponse, decode(
        f64,
        .{ .float = std.math.inf(f64) },
        arena.allocator(),
    ));
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"rows\":[1,2,3,4,5,6,7,8,9,10,11]}",
        .{},
    );
    defer parsed.deinit();
    try t.expectError(error.InvalidResponse, decode(
        struct { rows: []const u64 },
        parsed.value,
        arena.allocator(),
    ));
    try t.expectError(error.InvalidResponse, decode(
        struct { missing: u64 },
        parsed.value,
        arena.allocator(),
    ));
    try t.expectEqual(@as(usize, 0), arena.end_index);
}
