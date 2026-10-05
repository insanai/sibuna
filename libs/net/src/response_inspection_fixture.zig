//! Test-only exchange owner for the response publication boundary.
const std = @import("std");
const inspection = @import("response_inspection.zig");

pub const Fixture = struct {
    head: [512]u8 = undefined,
    body: [8192]u8 = undefined,
    writer: ?*std.Io.Writer = null,
    decision: inspection.Decision = .hold,
    refuse: enum { neither, headers, body } = .neither,
    head_calls: usize = 0,
    body_calls: usize = 0,
    body_length: usize = 0,
    status: u16 = 0,
    body_ceiling: usize = 64,
    head_ceiling: usize = 512,
    remaining: [64]u8 = undefined,
    remaining_length: usize = 0,

    pub fn hooks(self: *Fixture) inspection.Inspector {
        return .{
            .context = self,
            .headers = headers,
            .body = onBody,
            .head_storage = self.head[0..self.head_ceiling],
            .body_storage = self.body[0..self.body_ceiling],
        };
    }

    fn headers(context: *anyopaque, head: inspection.Head) inspection.Error!inspection.Decision {
        const self: *Fixture = @ptrCast(@alignCast(context));
        if (self.writer.?.buffered().len != 0) return error.InspectionFailed;
        self.head_calls += 1;
        self.status = head.status;
        if (self.refuse == .headers) return error.InspectionDenied;
        return self.decision;
    }

    fn onBody(context: *anyopaque, bytes: []const u8) inspection.Error!void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        if (self.writer.?.buffered().len != 0) return error.InspectionFailed;
        self.body_calls += 1;
        self.body_length = bytes.len;
        if (self.refuse == .body) return error.InspectionDenied;
    }
};
