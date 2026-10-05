//! Native commands borrow argv and require explicit authority and review revisions.
const std = @import("std");
const p = @import("console").protocol;
const Version = @import("crs").release_version.Version;
const sessions = @import("console_session.zig");
pub const Operation = enum {
    status,
    check,
    update,
    mode,
    rollback,
    select,
    discard,
    @"test",
    review,
};
pub const Args = struct {
    operation: Operation,
    origin: []const u8 = "",
    credentials: sessions.Credentials = .{ .username = "", .password_file = "" },
    revision: ?u64 = null,
    id: ?p.crs_management.Id = null,
    mode: ?p.crs.Mode = null,
    version: ?Version = null,
    configuration: ?[]const u8 = null,
    settings: ?[]const u8 = null,
    sample_file: ?[]const u8 = null,
    timeout: u32 = 120,
};
pub const Error = error{
    InvalidCommand,
    MissingValue,
    DuplicateOption,
    UnknownOption,
    InvalidValue,
    UnexpectedOption,
    AuthenticationRequired,
    RevisionRequired,
    IdentifierRequired,
    ModeRequired,
    CaseRequired,
};
const Option = enum {
    origin,
    username,
    password_file,
    factor_file,
    revision,
    id,
    mode,
    version,
    configuration,
    settings,
    timeout,
    case_file,
};
const names = .{
    "--origin",        "--username", "--password-file", "--factor-file",
    "--revision",      "--id",       "--mode",          "--version",
    "--configuration", "--settings", "--timeout",       "--case",
};

pub fn parse(argv: []const []const u8) Error!Args {
    if (argv.len == 0) return error.InvalidCommand;
    var output: Args = .{
        .operation = std.meta.stringToEnum(Operation, argv[0]) orelse return error.InvalidCommand,
    };
    var seen: u16 = 0;
    var index: usize = 1;
    while (index < argv.len) : (index += 2) {
        if (index + 1 == argv.len) return error.MissingValue;
        const option = try optionName(argv[index]);
        const bit = @as(u16, 1) << @backingInt(option);
        if (seen & bit != 0) return error.DuplicateOption;
        seen |= bit;
        const value = argv[index + 1];
        if (value.len == 0 or value.len > 1024) return error.InvalidValue;
        switch (option) {
            .origin => output.origin = value,
            .username => output.credentials.username = value,
            .password_file => output.credentials.password_file = value,
            .factor_file => output.credentials.factor_file = value,
            .revision => output.revision = try number(value, std.math.maxInt(i64) - 1),
            .id => {
                const id = p.crs_management.Id.init(value) catch return error.InvalidValue;
                if (!p.crs_management.validId(id)) return error.InvalidValue;
                output.id = id;
            },
            .mode => output.mode = std.meta.stringToEnum(p.crs.Mode, value) orelse
                return error.InvalidValue,
            .version => output.version = Version.parse(value) catch return error.InvalidValue,
            .configuration => output.configuration = value,
            .settings => output.settings = value,
            .case_file => output.sample_file = value,
            .timeout => {
                const timeout = try number(value, 300);
                if (timeout == 0) return error.InvalidValue;
                output.timeout = @intCast(timeout);
            },
        }
    }
    try validate(output);
    return output;
}

fn optionName(text: []const u8) Error!Option {
    inline for (names, 0..) |name, index| {
        if (std.mem.eql(u8, text, name)) return @fromBackingInt(@intCast(index));
    }
    return error.UnknownOption;
}

fn number(text: []const u8, maximum: u64) Error!u64 {
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidValue;
    const value = std.fmt.parseInt(u64, text, 10) catch return error.InvalidValue;
    if (value > maximum) return error.InvalidValue;
    return value;
}

fn validate(args: Args) Error!void {
    if (args.origin.len == 0 or !p.validUsername(args.credentials.username) or
        args.credentials.password_file.len == 0) return error.AuthenticationRequired;
    const preparing = args.operation == .check or args.operation == .update;
    if (!preparing and
        (args.version != null or args.configuration != null or args.settings != null))
        return error.UnexpectedOption;
    if (args.operation == .mode) {
        if (args.mode == null) return error.ModeRequired;
    } else if (args.operation != .@"test" and args.mode != null) return error.UnexpectedOption;
    if (args.operation == .status) {
        if (args.revision != null or args.id != null) return error.UnexpectedOption;
    } else if (args.revision == null) return error.RevisionRequired;
    if (args.operation == .@"test") {
        if (args.sample_file == null) return error.CaseRequired;
    } else if (args.sample_file != null) return error.UnexpectedOption;
    const identified = args.operation == .select or args.operation == .discard or
        args.operation == .@"test" or args.operation == .review;
    if (identified and args.id == null)
        return error.IdentifierRequired;
}

test "managed CRS commands require explicit revisions and reject mixed rollback edits" {
    const t = std.testing;
    const auth = .{
        "--origin", "http://127.0.0.1:9443", "--username", "admin", "--password-file", "private",
    };
    try t.expectEqual(Operation.status, (try parse(&(.{"status"} ++ auth))).operation);
    try t.expectError(error.RevisionRequired, parse(&(.{"update"} ++ auth)));
    try t.expectError(error.IdentifierRequired, parse(&(.{"select"} ++ auth ++ .{
        "--revision", "1",
    })));
    try t.expectError(error.UnexpectedOption, parse(&(.{"rollback"} ++ auth ++ .{
        "--revision", "1", "--mode", "off",
    })));
    try t.expectError(error.CaseRequired, parse(&(.{"test"} ++ auth ++ .{
        "--revision", "1", "--id", "11111111111111111111111111111111",
    })));
    const testing = try parse(&(.{"test"} ++ auth ++ .{
        "--revision", "1",           "--id",   "11111111111111111111111111111111",
        "--case",     "sample.json", "--mode", "enforce",
    }));
    try t.expectEqual(Operation.@"test", testing.operation);
    try t.expectEqualStrings("sample.json", testing.sample_file.?);
    const command = try parse(&(.{"update"} ++ auth ++ .{
        "--revision", "0", "--version", "4.30.0", "--settings", "bounds.json",
    }));
    try t.expectEqual(@as(?u64, 0), command.revision);
    try t.expectError(error.DuplicateOption, parse(&(.{"status"} ++ auth ++ .{
        "--username", "second",
    })));
    try t.expectError(error.InvalidValue, parse(&(.{"mode"} ++ auth ++ .{
        "--mode", "audit", "--revision", "-1",
    })));
}

test "managed CRS commands require a source and reject sample or settings overrides" {
    const t = std.testing;
    const auth = .{
        "--origin", "http://127.0.0.1:9443", "--username", "admin", "--password-file", "private",
    };
    const source = .{ "--revision", "1", "--id", "11111111111111111111111111111111" };
    const command = try parse(&(.{"review"} ++ auth ++ source));
    try t.expectEqual(Operation.review, command.operation);
    try t.expectError(error.RevisionRequired, parse(&(.{"review"} ++ auth)));
    try t.expectError(error.IdentifierRequired, parse(&(.{"review"} ++ auth ++ .{
        "--revision", "1",
    })));
    try t.expectError(error.UnexpectedOption, parse(&(.{"review"} ++ auth ++ source ++ .{
        "--mode", "enforce",
    })));
    try t.expectError(error.UnexpectedOption, parse(&(.{"review"} ++ auth ++ source ++ .{
        "--case", "private.json",
    })));
    try t.expectError(error.UnexpectedOption, parse(&(.{"review"} ++ auth ++ source ++ .{
        "--settings", "override.json",
    })));
}
