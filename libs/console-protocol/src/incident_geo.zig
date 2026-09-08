//! Local recorded findings, never inferred from denial counters or sampled request totals.
const std = @import("std");
const root = @import("root.zig");

pub const Snapshot = struct {
    version: u8 = 1,
    started_at: u64 = 0,
    countries: [32]root.CountryCount = @splat(.{}),
    other: u64 = 0,
    unknown: u64 = 0,
    dropped: u64 = 0,
    expired: u64 = 0,
    future: u64 = 0,

    pub fn jsonStringify(
        self: Snapshot,
        writer: *std.json.Stringify,
    ) std.json.Stringify.Error!void {
        try writer.beginObject();
        inline for (@typeInfo(Snapshot).@"struct".fields) |field| {
            try writer.objectField(field.name);
            if (field.type == u64)
                try root.writeCounter(writer, @field(self, field.name))
            else
                try writer.write(@field(self, field.name));
        }
        try writer.endObject();
    }
};
