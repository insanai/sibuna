//! Flat browser command objects share a concrete serializer. Nested contracts continue
//! through std.json; names and field types are supplied by the compiler, never the wire.
const std = @import("std");
const Json = std.json.Stringify;
const Scalar = union(enum) { text: []const u8, signed: i64, unsigned: u64, flag: bool, absent };
const Field = struct { name: []const u8, value: Scalar };

pub fn write(json: *Json, value: anytype) Json.Error!void {
    const T = @TypeOf(value);
    if (comptime !supported(T)) return json.write(value);
    const members = @typeInfo(T).@"struct".fields;
    var fields: [members.len]Field = undefined;
    inline for (members, &fields) |member, *field| field.* = .{
        .name = member.name,
        .value = scalar(@field(value, member.name)),
    };
    try object(json, &fields);
}

fn supported(comptime T: type) bool {
    if (@typeInfo(T) != .@"struct") return false;
    const info = @typeInfo(T).@"struct";
    if (info.is_tuple or info.fields.len > 32 or @hasDecl(T, "jsonStringify")) return false;
    for (info.fields) |field| if (!primitive(field.type)) return false;
    return true;
}

fn primitive(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .bool, .null, .comptime_int, .@"enum" => true,
        .int => |info| info.bits <= 64,
        .optional => |info| primitive(info.child),
        .pointer => |info| pointer: {
            if (info.size == .slice) break :pointer info.child == u8;
            if (info.size != .one or @typeInfo(info.child) != .array) break :pointer false;
            break :pointer @typeInfo(info.child).array.child == u8;
        },
        else => false,
    };
}

fn scalar(value: anytype) Scalar {
    return switch (@typeInfo(@TypeOf(value))) {
        .bool => .{ .flag = value },
        .null => .absent,
        .@"enum" => .{ .text = @tagName(value) },
        .optional => if (value) |item| scalar(item) else .absent,
        .pointer => .{ .text = value },
        .comptime_int => if (value < 0) .{ .signed = value } else .{ .unsigned = value },
        .int => |info| if (info.signedness == .signed)
            .{ .signed = value }
        else
            .{ .unsigned = value },
        else => unreachable,
    };
}

noinline fn object(json: *Json, fields: []const Field) Json.Error!void {
    try json.beginObject();
    for (fields) |field| {
        try json.objectField(field.name);
        switch (field.value) {
            .text => |text| try json.write(text),
            .signed => |number| try json.write(number),
            .unsigned => |number| try json.write(number),
            .flag => |flag| try json.write(flag),
            .absent => try json.write(null),
        }
    }
    try json.endObject();
}

test "shared command encoding matches standard JSON for escaping, bounds, null and nesting" {
    const value = .{
        .text = "\"\\\n世界",
        .minimum = std.math.minInt(i64),
        .maximum = std.math.maxInt(u64),
        .signed = @as(i64, -5),
        .unsigned = @as(u64, 9),
        .optional = @as(?[]const u8, null),
        .present = @as(?[]const u8, "<script>"),
        .flag = true,
        .role = @import("console_protocol").Role.viewer,
    };
    var actual: [512]u8 = undefined;
    var expected: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&actual);
    var reference: std.Io.Writer = .fixed(&expected);
    var json: Json = .{ .writer = &writer };
    try write(&json, value);
    try Json.value(value, .{}, &reference);
    try std.testing.expectEqualStrings(reference.buffered(), writer.buffered());
    writer = .fixed(&actual);
    reference = .fixed(&expected);
    json = .{ .writer = &writer };
    const nested = .{ .body = .{ .topics = .{"stats"} } };
    try write(&json, nested);
    try Json.value(nested, .{}, &reference);
    try std.testing.expectEqualStrings(reference.buffered(), writer.buffered());
}
