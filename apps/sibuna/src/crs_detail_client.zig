//! Copy every bounded evidence page before serializing a complete private report.
const std = @import("std");
const p = @import("console").protocol;
const client = @import("console_client.zig");
const sessions = @import("console_session.zig");
const reply = @import("crs_management_reply.zig");
const Budget = @import("console_deadline.zig").Budget;

pub fn load(
    session: *client.Session,
    status: *const p.crs_tasks.Status,
    budget: Budget,
) sessions.Error![]p.incident_crs.api.Detail {
    const report = status.report orelse return error.InvalidResponse;
    report.validate() catch return error.InvalidResponse;
    const rows = try session.allocator.alloc(p.incident_crs.api.Detail, report.event_count);
    errdefer session.allocator.free(rows);
    const output = try session.allocator.create(p.crs_tasks.DetailPage);
    defer session.allocator.destroy(output);
    defer std.crypto.secureZero(u8, std.mem.asBytes(output));
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    var offset: u8 = 0;
    while (true) {
        var bytes: [128]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&bytes);
        try std.json.Stringify.value(.{ .id = status.id.slice(), .offset = offset }, .{}, &writer);
        const timeout = @min(20 * std.time.ns_per_s, try budget.remaining(session.io));
        const received = try session.requestWithin(
            .crs_test_details,
            writer.buffered(),
            &response,
            timeout,
        );
        if (received.status == .too_many_requests) {
            try budget.wait(session.io);
            continue;
        }
        try sessions.requireOk(received.status);
        const payload = response[0..received.length];
        try reply.read(session.allocator, p.crs_tasks.DetailPage, output, payload);
        if (!std.mem.eql(u8, output.id.slice(), status.id.slice()) or
            output.expected_revision != status.expected_revision or output.page.offset != offset or
            output.page.total != rows.len) return error.InvalidResponse;
        for (output.page.rows[0..output.page.count], 0..) |detail, index| {
            const ordinal = offset + index;
            const scalar = report.events[ordinal].?;
            if (detail.?.rule_id != scalar.rule_id or detail.?.phase != scalar.phase)
                return error.InvalidResponse;
            rows[ordinal] = detail.?;
        }
        if (output.page.next) |next| offset = next else break;
    }
    return rows;
}
