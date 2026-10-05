//! Only pages bound to the completed review may enter retained browser state.
const std = @import("std");
const p = @import("console_protocol");
const ctx = @import("controller_context.zig");
const api = p.crs_tasks.review.exclusions;

pub fn action(c: ctx.Context, name: []const u8) !bool {
    const model = &c.state.crs;
    if (!std.mem.startsWith(u8, name, "crs-exclusions-")) return false;
    if (!model.reviewReady()) return true;
    if (std.mem.eql(u8, name, "crs-exclusions-before")) {
        try read(c, .before, 0);
    } else if (std.mem.eql(u8, name, "crs-exclusions-after")) {
        try read(c, .after, 0);
    } else if (std.mem.eql(u8, name, "crs-exclusions-next")) {
        if (model.exclusion_page) |page| if (page.page.next) |offset|
            try read(c, model.exclusion_side, offset);
    } else if (std.mem.eql(u8, name, "crs-exclusions-previous")) {
        const offset = model.exclusion_offset -| api.page_capacity;
        try read(c, model.exclusion_side, offset);
    } else if (std.mem.eql(u8, name, "crs-exclusions-retry")) {
        try read(c, model.exclusion_side, model.exclusion_offset);
    }
    return true;
}

pub fn read(c: ctx.Context, side: api.Side, offset: u32) !void {
    const model = &c.state.crs;
    if (!model.reviewReady()) return;
    const id = model.review_job orelse return;
    model.clearExclusions();
    model.exclusion_side = side;
    model.exclusion_offset = offset;
    try @import("crs_controller.zig").ticket(c, .exclusions);
    errdefer model.busy = .idle;
    try c.out.post(model.ticket.slice(), "/console/api/crs/review/exclusions", .{
        .id = id.slice(),
        .side = side,
        .offset = offset,
    });
}

pub fn response(c: ctx.Context, value: std.json.Value, allocator: std.mem.Allocator) !void {
    const model = &c.state.crs;
    if (!model.reviewReady()) return error.InvalidResponse;
    var output: p.crs_tasks.ExclusionPage = undefined;
    try @import("json_value.zig").into(&output, value, allocator);
    try output.validate();
    const result = model.review_result.?;
    if (!std.mem.eql(u8, output.id.slice(), result.id.slice()) or
        output.expected_revision != result.expected_revision or
        output.page.side != model.exclusion_side or output.page.offset != model.exclusion_offset)
        return error.InvalidResponse;
    const summary = if (output.page.side == .before)
        result.comparison.?.before
    else
        result.comparison.?.after;
    const total = @as(u64, summary.target_exclusions) + summary.runtime_exclusions;
    if (output.page.total != total) return error.InvalidResponse;
    model.exclusion_page = output;
    model.review_result.?.expires = output.expires;
    try c.out.emit(.{ .op = "focus", .selector = "#crs-exclusions-heading" });
}

test "exclusion replies cannot cross review identities offsets or configuration totals" {
    const t = std.testing;
    const State = @import("state.zig").State;
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    state.* = .{};
    @import("crs_fixture.zig").configure(state, true, false);
    const original = state.crs.exclusion_page.?;
    const wire = try std.json.Stringify.valueAlloc(t.allocator, original, .{});
    defer t.allocator.free(wire);
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, wire, .{});
    defer parsed.deinit();
    var memory: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&memory);
    var count: usize = 0;
    const c: ctx.Context = .{
        .state = state,
        .out = .{ .writer = &writer, .count = &count, .csrf = "" },
    };
    state.crs.clearExclusions();
    try response(c, parsed.value, t.allocator);
    try t.expectEqualDeep(original, state.crs.exclusion_page.?);
    state.crs.exclusion_offset = 8;
    try t.expectError(error.InvalidResponse, response(c, parsed.value, t.allocator));
    state.crs.exclusion_offset = 0;
    state.crs.exclusion_side = .before;
    try t.expectError(error.InvalidResponse, response(c, parsed.value, t.allocator));
    state.crs.exclusion_side = .after;
    const other = try p.crs_management.Id.init("33333333333333333333333333333333");
    state.crs.review_result.?.id = other;
    try t.expectError(error.InvalidResponse, response(c, parsed.value, t.allocator));
    state.crs.review_result.?.id = original.id;
    state.crs.review_result.?.comparison.?.after.target_exclusions = 2;
    try t.expectError(error.InvalidResponse, response(c, parsed.value, t.allocator));
    state.crs.clearReview();
    try t.expect(state.crs.exclusion_page == null);
    try t.expectError(error.InvalidResponse, response(c, parsed.value, t.allocator));
}

test "expired exclusion reads keep the candidate and offer a fresh comparison with stable focus" {
    const t = std.testing;
    const State = @import("state.zig").State;
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    state.* = .{};
    @import("crs_fixture.zig").configure(state, true, false);
    state.crs.ticket = try p.Bytes(48).init("expired-review");
    state.crs.busy = .exclusions;
    var bytes: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    var count: usize = 0;
    const c: ctx.Context = .{
        .state = state,
        .out = .{ .writer = &writer, .count = &count, .csrf = "" },
    };
    try @import("crs_controller.zig").response(c, .{
        .id = state.crs.ticket.slice(),
        .status = 410,
        .body = .null,
        .allocator = t.allocator,
    });
    try t.expect(state.crs.reviewed != null and !state.crs.stale);
    try t.expect(state.crs.review_result == null and state.crs.exclusion_page == null);
    try t.expect(!state.crs.reviewReady());
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "#crs-review-heading") != null);
    writer.end = 0;
    try @import("crs_review_page.zig").render(&state.crs, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Compare again") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Preparing the rule comparison") == null);
}
