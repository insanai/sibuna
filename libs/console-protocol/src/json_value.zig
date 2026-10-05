//! Decode a parsed protocol tree into caller-owned bounded records. Strings borrow
//! the parser arena; retained models must copy them before that arena is erased.
const std = @import("std");
pub const Error = error{ InvalidResponse, OutOfMemory };

pub fn decode(comptime T: type, value: std.json.Value, allocator: std.mem.Allocator) Error!T {
    var result: T = undefined;
    try into(&result, value, allocator);
    return result;
}

/// Fixed records decode without allocating. Borrowed strings still expire with the event;
/// a dynamically sized child fails with OutOfMemory instead of quietly allocating.
pub fn decodeFixed(comptime T: type, value: std.json.Value) Error!T {
    var memory: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    return decode(T, value, fixed.allocator());
}

/// Typed caller-owned decoding avoids large error-union payload images. On error the
/// output can be partial and must be discarded; retained state publishes a complete candidate.
pub fn into(output: anytype, value: std.json.Value, allocator: std.mem.Allocator) Error!void {
    const T = @typeInfo(@TypeOf(output)).pointer.child;
    if (comptime @typeInfo(T) == .@"struct") {
        if (comptime @hasDecl(T, "byte_capacity")) {
            if (value != .string) return error.InvalidResponse;
            output.set(value.string) catch return error.InvalidResponse;
            return;
        }
    }
    switch (@typeInfo(T)) {
        .@"struct" => try object(output, value, allocator, comptime &fields(T)),
        .optional => |optional| {
            if (value == .null) {
                output.* = null;
            } else {
                var child: optional.child = undefined;
                try into(&child, value, allocator);
                output.* = child;
            }
        },
        .array => |info| {
            if (value != .array or value.array.items.len != info.len) return error.InvalidResponse;
            for (value.array.items, output) |item, *child| try into(child, item, allocator);
        },
        .bool => output.* = if (value == .bool) value.bool else return error.InvalidResponse,
        .int => output.* = try integer(T, value),
        .float => output.* = try floating(T, value),
        .@"enum" => output.* = if (value == .string)
            std.meta.stringToEnum(T, value.string) orelse return error.InvalidResponse
        else
            return error.InvalidResponse,
        .pointer => output.* = try slice(T, value, allocator),
        else => @compileError("Unsupported protocol wire type: " ++ @typeName(T)),
    }
}

const Default = union(enum) {
    required,
    absent,
    zero,
    stored: *const anyopaque,
};
const Field = struct {
    name: []const u8,
    offset: usize,
    default: Default,
    read: *const fn (*anyopaque, ?std.json.Value, std.mem.Allocator, Default) Error!void,
};

/// All offsets, defaults and typed readers come from the compiler's own struct metadata.
/// Neither wire input nor callers can construct a descriptor or choose a destination.
fn fields(comptime T: type) [@typeInfo(T).@"struct".field_names.len]Field {
    const members = @typeInfo(T).@"struct";
    var result: [members.field_names.len]Field = undefined;
    for (members.field_names, members.field_types, members.field_attrs, &result) |
        name,
        F,
        attrs,
        *field,
    | {
        if (attrs.@"comptime") @compileError("Wire fields must have runtime storage");
        const offset = @offsetOf(T, name);
        std.debug.assert(offset + @sizeOf(F) <= @sizeOf(T));
        field.* = .{
            .name = name,
            .offset = offset,
            .default = defaultValue(F, attrs.default_value_ptr),
            .read = Reader(F).read,
        };
    }
    return result;
}

// Null optional payloads and zero-filled arrays need no initialized data image in Wasm.
// The private descriptor distinguishes optional null from a zero representation (which
// would be wrong for niche-encoded optionals such as ?bool). Other defaults retain values.
fn defaultValue(comptime T: type, pointer: ?*const anyopaque) Default {
    @setEvalBranchQuota(100_000);
    const source = pointer orelse return .required;
    const value = @as(*const T, @ptrCast(@alignCast(source))).*;
    if (@typeInfo(T) == .optional and value == null) return .absent;
    if (zeroValue(T, value)) return .zero;
    return .{ .stored = source };
}

fn zeroValue(comptime T: type, value: T) bool {
    @setEvalBranchQuota(100_000);
    return switch (@typeInfo(T)) {
        .bool => !value,
        .int => value == 0,
        .@"enum" => @backingInt(value) == 0,
        .array => |info| array: {
            for (value) |item| if (!zeroValue(info.child, item)) break :array false;
            break :array true;
        },
        .@"struct" => structure: {
            inline for (@typeInfo(T).@"struct".field_names) |field_name| {
                const FieldType = @FieldType(T, field_name);
                if (!zeroValue(FieldType, @field(value, field_name))) break :structure false;
            }
            break :structure true;
        },
        else => false,
    };
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
            default: Default,
        ) Error!void {
            const typed: *T = @ptrCast(@alignCast(destination));
            if (value) |item| {
                try into(typed, item, allocator);
                return;
            }
            switch (default) {
                .required => return error.InvalidResponse,
                .absent => if (@typeInfo(T) == .optional) {
                    typed.* = null;
                } else unreachable,
                .zero => @memset(std.mem.asBytes(typed), 0),
                .stored => |pointer| typed.* = @as(*const T, @ptrCast(@alignCast(pointer))).*,
            }
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

fn slice(comptime T: type, value: std.json.Value, allocator: std.mem.Allocator) Error!T {
    const info = @typeInfo(T).pointer;
    if (info.size != .slice or !info.attrs.@"const") @compileError("Wire slices must be const");
    if (info.child == u8) return if (value == .string) value.string else error.InvalidResponse;
    // Reject response row capacity before allocating; fixed arrays have exact bounds.
    const minutes = @import("root.zig").minutes;
    const capacity = if (info.child == minutes.Record) minutes.max_rows else 10;
    if (value != .array or value.array.items.len > capacity) return error.InvalidResponse;
    const result = try allocator.alloc(info.child, value.array.items.len);
    for (value.array.items, result) |item, *output| try into(output, item, allocator);
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
    const p = @import("root.zig");
    const t = std.testing;
    const maximum = std.math.maxInt(u64);
    const snapshot: p.StatsSnapshot = .{
        .incident_geo = .{
            .countries = @splat(.{ .code = 0x5553, .samples = maximum }),
            .unknown = maximum,
            .other = maximum,
            .dropped = maximum,
            .expired = maximum,
            .future = maximum,
            .started_at = maximum,
        },
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
    var buffer: [8192]u8 = undefined;
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
    try t.expectEqual(maximum, restored.incident_geo.?.countries[0].samples);
    try t.expectEqual(maximum, restored.incident_geo.?.unknown);
    // Keep headroom for the WebSocket envelope within its fixed 8 KiB payload buffer.
    try t.expect(writer.buffered().len + 256 < buffer.len);
    try t.expectEqualSlices(u8, &snapshot.boot, &restored.boot);
    try t.expectError(error.InvalidResponse, decode(u64, .{ .string = "+1" }, t.allocator));
    try t.expectError(error.InvalidResponse, decode(u64, .{ .string = "1e3" }, t.allocator));
}

test "shared defaults preserve optional false, null, nonzero values and bounded zero arrays" {
    const Wire = struct {
        missing: ?bool = null,
        present: ?bool = false,
        flags: [1024]u64 = @splat(0),
        count: u64 = 7,
    };
    const t = std.testing;
    const empty: std.json.Value = .{ .object = .{} };
    const value = try decode(Wire, empty, t.allocator);
    try t.expect(value.missing == null);
    try t.expectEqual(@as(?bool, false), value.present);
    try t.expectEqual(@as(u64, 7), value.count);
    try t.expect(std.mem.allEqual(u64, &value.flags, 0));
    const descriptors = comptime fields(Wire);
    try t.expect(descriptors[0].default == .absent);
    try t.expect(descriptors[1].default == .stored);
    try t.expect(descriptors[2].default == .zero);
    try t.expect(descriptors[3].default == .stored);
    try t.expectError(error.InvalidResponse, decode(struct { required: u64 }, empty, t.allocator));
}

test "owned wire bytes enforce capacity, erase old tails and survive their input arena" {
    const Bytes = @import("root.zig").Bytes(8);
    var source = [_]u8{ 'o', 'w', 'n', 'e', 'd' };
    var output: Bytes = undefined;
    try into(&output, .{ .string = &source }, std.testing.allocator);
    @memset(&source, 0);
    try std.testing.expectEqualStrings("owned", output.slice());
    try std.testing.expectError(error.InvalidResponse, into(
        &output,
        .{ .string = "too large" },
        std.testing.allocator,
    ));
    try std.testing.expectEqualStrings("owned", output.slice());
    try into(&output, .{ .string = "x" }, std.testing.allocator);
    try std.testing.expect(std.mem.allEqual(u8, output.data[1..], 0));
    try std.testing.expectError(error.InvalidResponse, into(
        &output,
        .{ .integer = 1 },
        std.testing.allocator,
    ));
}

/// Optional browser metadata uses zero for an absent or non-unsigned JSON number.
pub fn unsignedOrZero(value: std.json.Value, key: []const u8) u64 {
    if (value != .object) return 0;
    const item = value.object.get(key) orelse return 0;
    return if (item == .integer and item.integer >= 0) @intCast(item.integer) else 0;
}
