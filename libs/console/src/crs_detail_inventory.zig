//! The ephemeral task owns safe copied templates, never the prepared generation.
const std = @import("std");
const p = @import("console_protocol");
const api = p.incident_crs.api;
pub const Inventory = struct {
    rows: []api.Detail = &.{},
    count: usize = 0,

    pub fn deinit(self: *Inventory, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.rows));
        allocator.free(self.rows);
        self.* = .{};
    }

    pub fn read(self: *const Inventory, offset: u8, out: *p.crs_tasks.sample_details.Page) !void {
        if (self.count > self.rows.len) return error.InvalidRequest;
        try p.crs_tasks.sample_details.page(self.rows[0..self.count], offset, out);
    }
};
