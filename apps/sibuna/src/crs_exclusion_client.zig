//! Full native reviews follow immutable cursors within one authenticated session.
//! Owned arrays are bounded by the compiler's inventory cap, not remote lengths.
const std = @import("std");
const p = @import("console").protocol;
const client = @import("console_client.zig");
const sessions = @import("console_session.zig");
const reply = @import("crs_management_reply.zig");
const Budget = @import("console_deadline.zig").Budget;
const api = p.crs_tasks.review.exclusions;
pub const Inventory = struct {
    before: []api.Row = &.{},
    after: []api.Row = &.{},

    pub fn deinit(self: *Inventory, allocator: std.mem.Allocator) void {
        allocator.free(self.before);
        allocator.free(self.after);
        self.* = .{};
    }
};

pub fn load(
    session: *client.Session,
    status: *const p.crs_tasks.Status,
    budget: Budget,
    out: *Inventory,
) sessions.Error!void {
    const report = status.comparison orelse return error.InvalidResponse;
    out.before = try read(session, status, .before, report.before, budget);
    out.after = try read(session, status, .after, report.after, budget);
}

fn read(
    session: *client.Session,
    status: *const p.crs_tasks.Status,
    side: api.Side,
    summary: p.crs_tasks.review.Summary,
    budget: Budget,
) sessions.Error![]api.Row {
    const total = @as(u64, summary.target_exclusions) + summary.runtime_exclusions;
    if (total > api.capacity) return error.InvalidResponse;
    const rows = try session.allocator.alloc(api.Row, @intCast(total));
    errdefer session.allocator.free(rows);
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    const output = try session.allocator.create(p.crs_tasks.ExclusionPage);
    defer session.allocator.destroy(output);
    var offset: u32 = 0;
    while (true) {
        var bytes: [256]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&bytes);
        try std.json.Stringify.value(.{
            .id = status.id.slice(),
            .side = side,
            .offset = offset,
        }, .{}, &writer);
        const timeout = @min(20 * std.time.ns_per_s, try budget.remaining(session.io));
        const body = writer.buffered();
        const received = try session.requestWithin(.crs_exclusions, body, &response, timeout);
        if (received.status == .too_many_requests) {
            try budget.wait(session.io);
            continue;
        }
        try sessions.requireOk(received.status);
        const payload = response[0..received.length];
        try reply.read(session.allocator, p.crs_tasks.ExclusionPage, output, payload);
        try output.validate();
        if (!std.mem.eql(u8, output.id.slice(), status.id.slice()) or
            output.expected_revision != status.expected_revision or output.page.side != side or
            output.page.offset != offset or output.page.total != total)
        {
            return error.InvalidResponse;
        }
        for (output.page.rows[0..output.page.count], 0..) |row, index|
            rows[offset + index] = row.?;
        if (output.page.next) |next| offset = next else break;
    }
    return rows;
}
