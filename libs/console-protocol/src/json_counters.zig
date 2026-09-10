//! Browser-safe numeric fields for bounded value records. Full u64 values use decimal strings;
//! smaller integers remain JSON numbers. Nested records keep their own serialization contract.
const std = @import("std");
const p = @import("root.zig");
pub const Error = std.json.Stringify.Error;

pub fn object(record: anytype, w: *std.json.Stringify) Error!void {
    try w.beginObject();
    inline for (@typeInfo(@TypeOf(record)).@"struct".fields) |field| {
        try w.objectField(field.name);
        try value(@field(record, field.name), w);
    }
    try w.endObject();
}

fn value(item: anytype, w: *std.json.Stringify) Error!void {
    const T = @TypeOf(item);
    if (T == u64) return p.writeCounter(w, item);
    switch (@typeInfo(T)) {
        .optional => if (item) |present| try value(present, w) else try w.write(null),
        .array => {
            try w.beginArray();
            for (item) |element| try value(element, w);
            try w.endArray();
        },
        .@"struct" => if (@hasDecl(T, "byte_capacity"))
            try w.write(item.slice())
        else
            try w.write(item),
        else => try w.write(item),
    }
}

test "bounded record serialization preserves maximum counters and nullable array elements" {
    const Record = struct {
        key: p.Bytes(8),
        node: u32,
        values: [2]?u64,
        pub fn jsonStringify(self: @This(), w: *std.json.Stringify) Error!void {
            return object(self, w);
        }
    };
    var bytes: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(Record{
        .key = try p.Bytes(8).init("rule"),
        .node = 7,
        .values = .{ std.math.maxInt(u64), null },
    }, .{}, &writer);
    try std.testing.expectEqualStrings("{\"key\":\"rule\",\"node\":7," ++
        "\"values\":[\"18446744073709551615\",null]}", writer.buffered());
}
