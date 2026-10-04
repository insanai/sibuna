//! Global help/version handling must not consume a subcommand's value options.
const std = @import("std");
pub const Action = enum { run, help, version };

pub fn action(argv: []const []const u8) Action {
    const subcommand = argv.len != 0 and (std.mem.eql(u8, argv[0], "console") or
        std.mem.eql(u8, argv[0], "crs"));
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help")) return .help;
        if (!subcommand and std.mem.eql(u8, arg, "--version")) return .version;
    }
    return .run;
}

test "global version cannot intercept a management release version" {
    const t = std.testing;
    try t.expectEqual(Action.version, action(&.{"--version"}));
    try t.expectEqual(Action.help, action(&.{ "--gate", "--help" }));
    try t.expectEqual(Action.run, action(&.{ "crs", "check", "--version", "4.30.0" }));
    try t.expectEqual(Action.run, action(&.{
        "console", "geoip", "update", "--version", "2026-10",
    }));
    try t.expectEqual(Action.help, action(&.{ "crs", "check", "--help" }));
}
