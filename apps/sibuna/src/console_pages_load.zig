//! Loads operator page templates into the engine being rebuilt. Defaults are installed
//! first; a stored template that fails to compile keeps the default and marks the entry as
//! a fallback with a warning, never failing the rebuild.
const std = @import("std");
const policy = @import("policy");
const page_template = policy.page_template;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const challenge_default = @import("challenge_page.zig").default;

pub fn source(kind: anytype) []const u8 {
    return switch (@intFromEnum(kind)) {
        0 => challenge_default,
        1 => page_template.default_denied,
        2 => page_template.default_rate_limited,
        3 => page_template.default_banned,
        else => page_template.default_overloaded,
    };
}

pub fn install(owner: *Persistent, pages: *page_template.Pages) !void {
    page_template.defaults(pages, challenge_default);
    if (!owner.console_initialized) return;
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT kind,html,revision FROM console_pages LIMIT 5",
        &.{},
    );
    defer rows.deinit();
    for (rows.rows) |cells| {
        const kind = std.meta.stringToEnum(page_template.Kind, cells[0] orelse continue) orelse
            continue;
        const entry = &pages.entries[@intFromEnum(kind)];
        page_template.compile(kind, cells[1] orelse "", entry) catch |err| {
            std.log.warn("page template {s} ignored: {t}; default retained", .{
                @tagName(kind),
                err,
            });
            page_template.compile(kind, source(kind), entry) catch unreachable;
            entry.customized = false;
            entry.fallback = true;
            continue;
        };
        entry.revision = try util.number(cells[2]);
    }
}
