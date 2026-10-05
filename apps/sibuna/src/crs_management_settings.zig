//! Optional complete settings files keep resource controls shared with the console.
const std = @import("std");
const p = @import("console").protocol;
const client = @import("console_client.zig");
const Args = @import("crs_management_args.zig").Args;

pub fn read(
    session: *client.Session,
    args: Args,
    snapshot: *const p.crs_api.Status,
) error{InvalidConfiguration}!?p.crs_management.Settings {
    if (args.operation == .mode) {
        const current = snapshot.current orelse return error.InvalidConfiguration;
        var settings = current.artifact.?.settings;
        settings.mode = args.mode.?;
        return settings;
    }
    const path = args.settings orelse return null;
    const source = @import("crs_candidate.zig").readFile(
        session.allocator,
        session.io,
        path,
        4096,
    ) catch return error.InvalidConfiguration;
    defer session.allocator.free(source.buffer);
    defer std.crypto.secureZero(u8, source.buffer);
    const parsed = std.json.parseFromSlice(
        p.crs_management.Settings,
        session.allocator,
        source.value,
        .{},
    ) catch return error.InvalidConfiguration;
    defer parsed.deinit();
    const settings = parsed.value;
    settings.validate() catch return error.InvalidConfiguration;
    return settings;
}
