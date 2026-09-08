//! Command arguments borrow argv for the duration of the command. No credential value is
//! accepted on the command line; private files keep it out of process listings.
const std = @import("std");
const p = @import("console").protocol;
pub const Error = error{
    InvalidArguments,
    UnknownCommand,
    MissingTarget,
    InvalidUsername,
    AuthenticationRequired,
    AccessFieldsRequired,
    RevisionRequired,
    MissingValue,
    DuplicateOption,
    UnknownOption,
    InvalidValue,
    InvalidOrigin,
    UnexpectedOption,
    InvalidRole,
    InvalidNumber,
};
pub const Kind = enum { users, add, access, password, revoke };
pub const Args = struct {
    kind: Kind,
    origin: []const u8 = "",
    actor: []const u8 = "",
    password_file: []const u8 = "",
    factor_file: ?[]const u8 = null,
    username: []const u8 = "",
    target: u64 = 0,
    revision: u64 = 0,
    after: u64 = 0,
    role: p.Role = .viewer,
    disabled: bool = false,
};
const Option = enum { origin, actor, password_file, factor_file, role, disabled, revision, after };

pub fn parse(args: []const []const u8) Error!Args {
    if (args.len == 0 or args.len > 32) return error.InvalidArguments;
    const kind: Kind = if (equal(args[0], "users")) .users else kind: {
        const names = .{ "add-user", "set-user", "reset-password", "revoke-sessions" };
        const kinds = [_]Kind{ .add, .access, .password, .revoke };
        inline for (names, kinds) |name, value| if (equal(args[0], name)) break :kind value;
        return error.UnknownCommand;
    };
    var result: Args = .{ .kind = kind };
    var index: usize = 1;
    if (kind != .users) {
        if (args.len < 2) return error.MissingTarget;
        if (kind == .add) {
            if (!p.validUsername(args[1])) return error.InvalidUsername;
            result.username = args[1];
        } else result.target = try number(args[1], false);
        index += 1;
    }
    var seen: u8 = 0;
    while (index < args.len) : (index += 2) {
        if (index + 1 == args.len) return error.MissingValue;
        const option = try optionName(args[index]);
        const bit = @as(u8, 1) << @intFromEnum(option);
        if (seen & bit != 0) return error.DuplicateOption;
        seen |= bit;
        try assign(&result, option, args[index + 1]);
    }
    if (result.origin.len == 0 or !p.validUsername(result.actor) or
        result.password_file.len == 0) return error.AuthenticationRequired;
    const access_fields = (@as(u8, 1) << @intFromEnum(Option.role)) |
        (@as(u8, 1) << @intFromEnum(Option.disabled));
    if (kind == .access and seen & access_fields != access_fields)
        return error.AccessFieldsRequired;
    if (kind != .users and kind != .add and result.revision == 0)
        return error.RevisionRequired;
    return result;
}

fn optionName(name: []const u8) Error!Option {
    const names = .{
        "--origin", "--username", "--password-file", "--factor-file",
        "--role",   "--disabled", "--revision",      "--after",
    };
    inline for (names, 0..) |value, index| {
        if (equal(name, value)) return @enumFromInt(index);
    }
    return error.UnknownOption;
}

fn assign(args: *Args, option: Option, value: []const u8) Error!void {
    if (value.len == 0 or value.len > 1024) return error.InvalidValue;
    switch (option) {
        .origin => {
            if (value.len > 255) return error.InvalidOrigin;
            args.origin = value;
        },
        .actor => args.actor = value,
        .password_file => args.password_file = value,
        .factor_file => args.factor_file = value,
        .role => {
            if (args.kind != .add and args.kind != .access) return error.UnexpectedOption;
            args.role = std.meta.stringToEnum(p.Role, value) orelse return error.InvalidRole;
        },
        .disabled => {
            if (args.kind != .access) return error.UnexpectedOption;
            args.disabled = if (equal(value, "true")) true else if (equal(value, "false"))
                false
            else
                return error.InvalidValue;
        },
        .revision => {
            if (args.kind == .users or args.kind == .add) return error.UnexpectedOption;
            args.revision = try number(value, false);
            if (args.revision == std.math.maxInt(i64)) return error.InvalidNumber;
        },
        .after => {
            if (args.kind != .users) return error.UnexpectedOption;
            args.after = try number(value, true);
        },
    }
}

fn number(value: []const u8, zero: bool) Error!u64 {
    if (value.len == 0 or value.len > 19) return error.InvalidNumber;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidNumber;
    const result = std.fmt.parseInt(u64, value, 10) catch return error.InvalidNumber;
    if ((!zero and result == 0) or result > std.math.maxInt(i64)) return error.InvalidNumber;
    return result;
}

fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test "account CLI requires explicit authority, exact revisions and complete access edits" {
    const t = std.testing;
    const auth = [_][]const u8{
        "--origin", "http://127.0.0.1:9443", "--username", "admin", "--password-file", "private",
    };
    const args = try parse(&(.{ "set-user", "9007199254740993" } ++ auth ++ .{
        "--revision", "9007199254740995", "--role", "operator", "--disabled", "false",
    }));
    try t.expectEqual(@as(u64, 9007199254740993), args.target);
    try t.expectEqual(@as(u64, 9007199254740995), args.revision);
    try t.expectEqual(p.Role.operator, args.role);
    try t.expectError(error.RevisionRequired, parse(&(.{ "reset-password", "2" } ++ auth)));
    try t.expectError(error.AccessFieldsRequired, parse(&(.{ "set-user", "2" } ++ auth)));
    try t.expectError(error.UnexpectedOption, parse(
        &(.{"users"} ++ auth ++ .{ "--role", "admin" }),
    ));
    try t.expectError(error.DuplicateOption, parse(
        &(.{"users"} ++ auth ++ .{ "--username", "x" }),
    ));
    try t.expectError(error.InvalidNumber, parse(&(.{ "reset-password", "-1" } ++ auth)));
    try t.expectError(error.InvalidNumber, parse(&(.{"users"} ++ auth ++ .{ "--after", "1e3" })));
}
