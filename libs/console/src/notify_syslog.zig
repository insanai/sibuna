//! RFC 5424 messages for the syslog destination, with RFC 6587 octet-counting framing for
//! TCP. Fixed buffers; the message is truncated at the bound rather than split.
const std = @import("std");
pub const max_message = 1024;
pub const facility_local0: u8 = 16;
pub const Severity = enum(u8) { warning = 4, notice = 5 };

pub fn format(
    out: *[max_message]u8,
    severity: Severity,
    unix_seconds: u64,
    hostname: []const u8,
    event: []const u8,
    message: []const u8,
) []const u8 {
    const priority = facility_local0 * 8 + @backingInt(severity);
    const epoch = std.time.epoch.EpochSeconds{ .secs = unix_seconds };
    const day = epoch.getEpochDay().calculateYearDay();
    const month = day.calculateMonthDay();
    const time = epoch.getDaySeconds();
    var writer: std.Io.Writer = .fixed(out);
    writer.print("<{d}>1 {d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z {s} sibuna - {s} - ", .{
        priority,
        day.year,
        month.month.numeric(),
        month.day_index + 1,
        time.getHoursIntoDay(),
        time.getMinutesIntoHour(),
        time.getSecondsIntoMinute(),
        if (hostname.len == 0) "-" else hostname,
        if (event.len == 0) "-" else event,
    }) catch return writer.buffered();
    for (message) |byte| {
        const printable = byte >= 32 and byte < 127;
        writer.writeByte(if (printable) byte else '?') catch break;
    }
    return writer.buffered();
}

/// `<length> <message>` for TCP transports; UDP sends the bare message.
pub fn framed(out: *[max_message + 8]u8, message: []const u8) []const u8 {
    var writer: std.Io.Writer = .fixed(out);
    writer.print("{d} {s}", .{ message.len, message }) catch unreachable;
    return writer.buffered();
}

test "syslog lines carry the priority, UTC timestamp, event id and a sanitized message" {
    const t = std.testing;
    var out: [max_message]u8 = undefined;
    const line = format(&out, .warning, 1788922213, "edge-1", "denial_spike", "denied 240\n");
    const expected = "<132>1 2026-09-09T02:50:13Z edge-1 sibuna - denial_spike - denied 240?";
    try t.expectEqualStrings(expected, line);
    var frame: [max_message + 8]u8 = undefined;
    try t.expect(std.mem.startsWith(u8, framed(&frame, line), "70 <132>1 "));
    var long: [2048]u8 = @splat('x');
    const bounded = format(&out, .notice, 0, "", "", &long);
    try t.expectEqual(@as(usize, max_message), bounded.len);
}
