//! Completed private findings are paged under the issuing task's immutable identity.
const std = @import("std");
const p = @import("console_protocol");
const ctx = @import("controller_context.zig");
const api = p.crs_tasks.sample_details;

pub fn action(c: ctx.Context, name: []const u8) !bool {
    if (!std.mem.startsWith(u8, name, "crs-test-details")) return false;
    const model = &c.state.crs;
    const result = model.test_result orelse return true;
    if (result.state != .complete or model.test_details_expired) return true;
    var offset: u8 = 0;
    if (std.mem.eql(u8, name, "crs-test-details-next")) {
        const page = model.test_details orelse return true;
        offset = page.page.next orelse return true;
    } else if (std.mem.eql(u8, name, "crs-test-details-previous")) {
        offset = model.test_details_offset -| api.page_capacity;
    } else if (std.mem.eql(u8, name, "crs-test-details-retry")) {
        offset = model.test_details_offset;
    } else if (!std.mem.eql(u8, name, "crs-test-details")) return true;
    model.clearTestDetails();
    model.test_details_offset = offset;
    try @import("crs_controller.zig").ticket(c, .test_details);
    errdefer model.busy = .idle;
    try c.out.post(model.ticket.slice(), "/console/api/crs/test/details", .{
        .id = result.id.slice(),
        .offset = offset,
    });
    return true;
}

pub fn response(c: ctx.Context, value: std.json.Value, allocator: std.mem.Allocator) !void {
    const model = &c.state.crs;
    const result = model.test_result orelse return error.InvalidResponse;
    const report = result.report orelse return error.InvalidResponse;
    const wire = try p.json_value.decode(p.crs_tasks.DetailWire, value, allocator);
    var output: p.crs_tasks.DetailPage = undefined;
    try wire.into(&output);
    if (result.state != .complete or !std.mem.eql(u8, output.id.slice(), result.id.slice()) or
        output.expected_revision != result.expected_revision or
        output.page.offset != model.test_details_offset or output.page.total != report.event_count)
        return error.InvalidResponse;
    for (output.page.rows[0..output.page.count], 0..) |row, index| {
        const scalar = report.events[output.page.offset + index].?;
        if (row.?.rule_id != scalar.rule_id or row.?.phase != scalar.phase)
            return error.InvalidResponse;
    }
    model.test_details = output;
    model.test_result.?.expires = output.expires;
    try c.out.emit(.{ .op = "focus", .selector = "#crs-test-details-heading" });
}
