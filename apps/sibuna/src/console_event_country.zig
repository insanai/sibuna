//! Runs only on the storage owner, inside the existing idempotent incident transaction.
const std = @import("std");
const persistent = @import("persistent.zig");

pub fn append(
    owner: *persistent.Persistent,
    w: *std.Io.Writer,
    id: u64,
    record: *const persistent.IncidentRecord,
) !bool {
    const mapping = owner.console_geo.map(owner.io, record.ip[0..record.ip_len]) orelse
        return false;
    const digest = std.fmt.bytesToHex(mapping.generation, .lower);
    try w.print("INSERT INTO console_incident_country(incident_id,country,generation) " ++
        "SELECT {d},", .{id});
    if (mapping.country) |code| {
        std.debug.assert(code[0] >= 'A' and code[0] <= 'Z');
        std.debug.assert(code[1] >= 'A' and code[1] <= 'Z');
        try w.print("'{s}'", .{code});
    } else try w.writeAll("NULL");
    try w.print(",'{s}'", .{digest});
    return true;
}
