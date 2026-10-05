//! Filesystem commands use explicit revisions and reuse daemon resource parsing.
//! No argument is silently dropped and rollback refuses all settings overrides.
const std = @import("std");
const crs = @import("crs");
const options = @import("crs_options.zig");
pub const Operation = enum { status, update, mode, rollback };
pub const Args = struct {
    operation: Operation,
    directory: []const u8 = "",
    revision: ?u64 = null,
    source: ?[]const u8 = null,
    configuration: ?[]const u8 = null,
    version: ?crs.release_version.Version = null,
    overrides: options.Config = .{},
    timeout: u32 = 120,
};
pub const Error = options.Error || crs.release_version.Error || error{
    InvalidLocalCommand,
    UnexpectedLocalOption,
    MissingLocalDirectory,
    MissingLocalRevision,
    MissingLocalMode,
};
const Option = enum { directory, revision, from, configuration, version, mode, timeout };
const names = .{
    "--directory", "--revision", "--from", "--configuration", "--version", "--mode", "--timeout",
};
const resource_names = [_][]const u8{
    "--crs-profile",           "--crs-paranoia",           "--crs-detection-paranoia",
    "--crs-inbound-threshold", "--crs-outbound-threshold", "--crs-request-limit",
    "--crs-response-limit",    "--crs-work-budget",        "--crs-slots",
};

pub fn parse(argv: []const []const u8) Error!Args {
    if (argv.len == 0) return error.InvalidLocalCommand;
    var args: Args = .{
        .operation = std.meta.stringToEnum(Operation, argv[0]) orelse
            return error.InvalidLocalCommand,
    };
    var seen: u8 = 0;
    var resource_seen: u16 = 0;
    var flags: [resource_names.len * 2][]const u8 = undefined;
    var count: usize = 0;
    var index: usize = 1;
    while (index < argv.len) : (index += 2) {
        if (index + 1 == argv.len) return error.MissingCrsValue;
        const flag = argv[index];
        const value = argv[index + 1];
        if (resourceIndex(flag)) |resource| {
            const bit = @as(u16, 1) << @intCast(resource);
            if (resource_seen & bit != 0) return error.DuplicateCrsOption;
            resource_seen |= bit;
            flags[count] = flag;
            flags[count + 1] = value;
            count += 2;
            continue;
        }
        const option = try optionName(flag);
        const bit = @as(u8, 1) << @backingInt(option);
        if (seen & bit != 0) return error.DuplicateCrsOption;
        seen |= bit;
        try assign(&args, option, value);
    }
    var remaining: [resource_names.len * 2][]const u8 = undefined;
    const resources = try options.parse(flags[0..count], &remaining);
    const chosen = args.overrides.choice;
    args.overrides = resources.config;
    args.overrides.choice = chosen;
    try validate(args, seen, count);
    return args;
}

fn optionName(text: []const u8) Error!Option {
    inline for (names, 0..) |name, index|
        if (std.mem.eql(u8, text, name)) return @fromBackingInt(@intCast(index));
    return error.UnknownCrsOption;
}

fn resourceIndex(text: []const u8) ?usize {
    for (resource_names, 0..) |name, index|
        if (std.mem.eql(u8, text, name)) return index;
    return null;
}

fn assign(args: *Args, option: Option, value: []const u8) Error!void {
    if (value.len == 0 or value.len > 1024 or std.mem.indexOfScalar(u8, value, 0) != null)
        return error.InvalidCrsDirectory;
    switch (option) {
        .directory => args.directory = value,
        .from => args.source = value,
        .configuration => args.configuration = value,
        .revision => args.revision = try number(value, std.math.maxInt(i64) - 1),
        .version => args.version = try crs.release_version.Version.parse(value),
        .mode => try args.overrides.choice.select(try crs.config.Mode.parse(value)),
        .timeout => {
            const seconds = try number(value, 300);
            if (seconds == 0) return error.InvalidCrsLimit;
            args.timeout = @intCast(seconds);
        },
    }
}

fn number(text: []const u8, maximum: u64) Error!u64 {
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidCrsLimit;
    const value = std.fmt.parseInt(u64, text, 10) catch return error.InvalidCrsLimit;
    if (value > maximum) return error.InvalidCrsLimit;
    return value;
}

fn validate(args: Args, seen: u8, resource_count: usize) Error!void {
    if (args.directory.len == 0) return error.MissingLocalDirectory;
    if (args.operation == .status) {
        if (seen != 1 << @backingInt(Option.directory) or resource_count != 0)
            return error.UnexpectedLocalOption;
        return;
    }
    if (args.revision == null) return error.MissingLocalRevision;
    if (args.operation == .update) {
        if (args.source != null and args.version != null) return error.UnexpectedLocalOption;
        return;
    }
    const base: u8 = 1 << @backingInt(Option.directory) | 1 << @backingInt(Option.revision);
    const allowed = if (args.operation == .mode) base | 1 << @backingInt(Option.mode) else base;
    if (seen & ~allowed != 0 or resource_count != 0) return error.UnexpectedLocalOption;
    if (args.operation == .mode) {
        if (args.overrides.choice.explicit == null) return error.MissingLocalMode;
    } else if (args.overrides.choice.explicit != null) return error.UnexpectedLocalOption;
}

test "local CRS commands require explicit authority and exact rollback settings" {
    const t = std.testing;
    const base = .{ "--directory", "/store" };
    try t.expectError(error.MissingLocalDirectory, parse(&.{"status"}));
    try t.expectError(error.MissingLocalRevision, parse(&.{ "update", "--directory", "/store" }));
    try t.expectError(error.UnexpectedLocalOption, parse(&(.{"rollback"} ++ base ++ .{
        "--revision", "1", "--mode", "audit",
    })));
    try t.expectError(error.UnexpectedLocalOption, parse(&(.{"update"} ++ base ++ .{
        "--revision", "0", "--from", "/candidate", "--version", "4.30.0",
    })));
    const args = try parse(&(.{"update"} ++ base ++ .{
        "--revision", "0", "--from", "/candidate", "--mode", "audit", "--crs-slots", "2",
    }));
    try t.expectEqual(@as(?u64, 0), args.revision);
    try t.expectEqual(@as(?usize, 2), args.overrides.slots);
    try t.expectEqual(crs.config.Mode.audit, args.overrides.choice.resolved());
    try t.expectError(error.DuplicateCrsOption, parse(&(.{"update"} ++ base ++ .{
        "--revision", "0", "--crs-slots", "2", "--crs-slots", "2",
    })));
}
