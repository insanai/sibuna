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
    var result: T = undefined;
    try object(&result, value, allocator, comptime &fields(T));
    return result;
}

const Field = struct {
    name: []const u8,
    offset: usize,
    default: ?*const anyopaque,
    read: *const fn (*anyopaque, ?std.json.Value, std.mem.Allocator, ?*const anyopaque) Error!void,
};

/// All offsets, defaults and typed readers come from the compiler's own struct metadata.
/// Neither wire input nor callers can construct a descriptor or choose a destination.
fn fields(comptime T: type) [@typeInfo(T).@"struct".fields.len]Field {
    const members = @typeInfo(T).@"struct".fields;
    var result: [members.len]Field = undefined;
    for (members, &result) |member, *field| {
        if (member.is_comptime) @compileError("Wire fields must have runtime storage");
        const offset = @offsetOf(T, member.name);
        std.debug.assert(offset + @sizeOf(member.type) <= @sizeOf(T));
        field.* = .{
            .name = member.name,
            .offset = offset,
            .default = member.default_value_ptr,
            .read = Reader(member.type).read,
        };
    }
    return result;
}

// One loop handles every bounded object; otherwise every field expands a lookup/decoder
// into the Wasm module. Each concrete field type still owns its assignment and alignment.
noinline fn object(
    destination: *anyopaque,
    value: std.json.Value,
    allocator: std.mem.Allocator,
    members: []const Field,
) Error!void {
    if (value != .object) return error.InvalidResponse;
    const bytes: [*]u8 = @ptrCast(destination);
    for (members) |field| try field.read(
        bytes + field.offset,
        value.object.get(field.name),
        allocator,
        field.default,
    );
}

fn Reader(comptime T: type) type {
    return struct {
        fn read(
            destination: *anyopaque,
            value: ?std.json.Value,
            allocator: std.mem.Allocator,
            default: ?*const anyopaque,
        ) Error!void {
            const typed: *T = @ptrCast(@alignCast(destination));
            typed.* = if (value) |item| try decode(T, item, allocator) else if (default) |pointer|
                @as(*const T, @ptrCast(@alignCast(pointer))).*
            else
                return error.InvalidResponse;
        }
    };
}

fn integer(comptime T: type, value: std.json.Value) Error!T {
    if (value == .integer) return std.math.cast(T, value.integer) orelse error.InvalidResponse;
    if (value == .number_string)
        return std.fmt.parseInt(T, value.number_string, 10) catch error.InvalidResponse;
    if (@typeInfo(T).int.bits > 53 and value == .string) {
        if (value.string.len == 0 or value.string.len > 20) return error.InvalidResponse;
        for (value.string) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidResponse;
        return std.fmt.parseInt(T, value.string, 10) catch error.InvalidResponse;
    }
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
    // Reject response row capacity before allocating; fixed arrays have exact bounds.
    const minutes = @import("console_protocol").minutes;
    const capacity = if (info.child == minutes.Record) minutes.max_rows else 10;
    if (value != .array or value.array.items.len > capacity) return error.InvalidResponse;
    const result = try allocator.alloc(info.child, value.array.items.len);
    for (value.array.items, result) |item, *output| output.* = try decode(
        info.child,
        item,
        allocator,
    );
    return result;
}

test "object descriptors preserve defaults, nested alignment and required nullable fields" {
    const t = std.testing;
    const Child = struct { wide: u128, flag: bool = true };
    const Wire = struct {
        small: u8 = 7,
        child: Child,
        nullable: ?u64,
        optional: ?u8 = 9,
        empty: struct {} = .{},
    };
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"child\":{\"wide\":123},\"nullable\":null,\"ignored\":42}",
        .{},
    );
    defer parsed.deinit();
    var empty: [0]u8 = .{};
    var arena = std.heap.FixedBufferAllocator.init(&empty);
    const decoded = try decode(Wire, parsed.value, arena.allocator());
    try t.expectEqual(@as(u8, 7), decoded.small);
    try t.expectEqual(@as(u128, 123), decoded.child.wide);
    try t.expect(decoded.child.flag);
    try t.expectEqual(@as(?u64, null), decoded.nullable);
    try t.expectEqual(@as(?u8, 9), decoded.optional);
    try t.expectEqual(@as(usize, 0), arena.end_index);
    try t.expectError(error.InvalidResponse, decode(
        struct { missing_nullable: ?u64 },
        parsed.value,
        arena.allocator(),
    ));
    try t.expectError(error.InvalidResponse, decode(Wire, .null, arena.allocator()));
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

test "statistics encode UTF-8 boot bytes as an array and preserve full-width counters" {
    const p = @import("console_protocol");
    const t = std.testing;
    const maximum = std.math.maxInt(u64);
    const snapshot: p.StatsSnapshot = .{
        .outcomes_version = 1,
        .retention_failures = maximum,
        .boot = @splat('a'),
        .uptime_ms = maximum,
        .requests = maximum,
        .admitted = maximum,
        .challenged = 0,
        .denied = 0,
        .origin_4xx = 0,
        .origin_5xx = 0,
        .incidents = 0,
        .incidents_dropped = 0,
        .sample_loss = 0,
        .unknown_samples = 0,
        .timestamp = 100,
        .countries = @splat(.{ .code = 0x5553, .samples = maximum }),
    };
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try std.json.Stringify.value(snapshot, .{}, &writer);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer parsed.deinit();
    try t.expect(parsed.value.object.get("requests").? == .string);
    try t.expect(parsed.value.object.get("boot").? == .array);
    const restored = try decode(p.StatsSnapshot, parsed.value, t.allocator);
    try t.expectEqual(maximum, restored.requests);
    try t.expectEqual(@as(?u64, maximum), restored.retention_failures);
    try t.expectEqual(maximum, restored.countries[0].samples);
    try t.expectEqualSlices(u8, &snapshot.boot, &restored.boot);
    try t.expectError(error.InvalidResponse, decode(u64, .{ .string = "+1" }, t.allocator));
    try t.expectError(error.InvalidResponse, decode(u64, .{ .string = "1e3" }, t.allocator));
}
