//! Native controller fixtures share the same caller-owned browser command buffer.
const std = @import("std");
pub const Commands = struct {
    memory: [16384]u8 = undefined,
    writer: std.Io.Writer = undefined,
    count: usize = 0,

    pub fn out(self: *Commands) @import("transport.zig").Outbox {
        self.writer = .fixed(&self.memory);
        self.count = 0;
        return .{ .writer = &self.writer, .count = &self.count, .csrf = "test csrf" };
    }
};
