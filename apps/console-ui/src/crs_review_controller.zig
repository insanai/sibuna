//! Rule comparisons use the same generation fencing and native worker as samples.
const std = @import("std");
const p = @import("console_protocol");
const ctx = @import("controller_context.zig");
const controller = @import("crs_controller.zig");
const fields = @import("events_state.zig");

pub fn start(c: ctx.Context, candidate: p.crs_api.Candidate) !void {
    const model = &c.state.crs;
    const snapshot = model.snapshot orelse return;
    if (model.stale or candidate.expected_revision != snapshot.revision) return;
    model.reviewed = candidate;
    model.review_job = null;
    model.review_result = null;
    try controller.ticket(c, .review_submit);
    errdefer model.busy = .idle;
    var revision: [20]u8 = undefined;
    try c.out.post(model.ticket.slice(), "/console/api/crs/review", .{
        .source = candidate.id.slice(),
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{snapshot.revision}),
    });
    try c.out.emit(.{ .op = "focus", .selector = "#crs-review-heading" });
}

pub fn poll(c: ctx.Context) !void {
    const id = c.state.crs.review_job orelse return;
    try controller.ticket(c, .review_read);
    errdefer c.state.crs.busy = .idle;
    try c.out.post(c.state.crs.ticket.slice(), "/console/api/crs/review/result", .{
        .id = id.slice(),
    });
}

pub fn response(
    c: ctx.Context,
    kind: @import("crs_state.zig").Kind,
    value: std.json.Value,
    allocator: std.mem.Allocator,
) !void {
    const model = &c.state.crs;
    if (kind == .review_submit) {
        const id = try p.crs_management.Id.init(fields.string(value, "id"));
        if (!p.crs_management.validId(id)) return error.InvalidResponse;
        model.review_job = id;
        return poll(c);
    }
    var result: p.crs_tasks.Status = undefined;
    try @import("json_value.zig").into(&result, value, allocator);
    try result.validate();
    const id = model.review_job orelse return error.InvalidResponse;
    if (result.kind != .review or !std.mem.eql(u8, result.id.slice(), id.slice()))
        return error.InvalidResponse;
    model.review_result = result;
}
