//! Session task owns copied descriptions independently of the prepared programs.
const std = @import("std");
const crs = @import("crs");
const api = @import("console_protocol").crs_tasks.review.exclusions;
pub const Inventory = struct {
    before: []api.Row = &.{},
    after: []api.Row = &.{},

    pub fn deinit(self: *Inventory, allocator: std.mem.Allocator) void {
        allocator.free(self.before);
        allocator.free(self.after);
        self.* = .{};
    }

    pub fn read(self: *const Inventory, side: api.Side, offset: u32, out: *api.Page) !void {
        const rows = if (side == .before) self.before else self.after;
        try crs.exclusion_review.page(rows, side, offset, out);
        try out.validate();
    }
};
