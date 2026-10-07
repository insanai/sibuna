//! Command arguments borrow argv for the duration of the command. No credential value is
//! accepted on the command line; private files keep it out of process listings.
const std = @import("std");
const p = @import("console").protocol;
const geoip = @import("console").geoip;
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
pub const Kind = enum {
    users,
    add,
    access,
    password,
    revoke,
    factor,
    geo_status,
    geo_update,
    tokens,
    mint_token,
    revoke_token,
    remove_token,
    policies_export,
    policies_import,

    pub fn managesTokens(self: Kind) bool {
        return switch (self) {
            .tokens, .mint_token, .revoke_token, .remove_token => true,
            else => false,
        };
    }

    fn needsRevision(self: Kind) bool {
        return switch (self) {
            .access, .password, .revoke, .factor, .revoke_token, .remove_token => true,
            else => false,
        };
    }
};
pub const Args = struct {
    kind: Kind,
    origin: []const u8 = "",
    actor: []const u8 = "",
    password_file: []const u8 = "",
    factor_file: ?[]const u8 = null,
    token_file: ?[]const u8 = null,
    scopes: u32 = 0,
    expires: ?u64 = null,
    username: []const u8 = "",
    target: u64 = 0,
    revision: u64 = 0,
    after: u64 = 0,
    role: p.Role = .viewer,
    disabled: bool = false,
    provider: []const u8 = "user-country",
    version: []const u8 = "",
    month_alias: bool = false,
    checksum: []const u8 = "",
    timeout: u32 = 1200,
    file: []const u8 = "",
};
const Option = enum {
    origin,
    actor,
    password_file,
    factor_file,
    role,
    disabled,
    revision,
    after,
    month,
    checksum,
    timeout,
    token_file,
    scope,
    expires,
    provider,
    version,
    file,
};

pub fn parse(args: []const []const u8) Error!Args {
    if (args.len == 0 or args.len > 32) return error.InvalidArguments;
    const kind = try command(args);
    var result: Args = .{ .kind = kind };
    var index: usize = if (kind == .geo_status or kind == .geo_update or
        kind == .policies_export or kind == .policies_import) 2 else 1;
    if (kind == .add or kind == .mint_token or kind.needsRevision()) {
        if (args.len < 2) return error.MissingTarget;
        if (kind == .add or kind == .mint_token) {
            if (kind == .add and !p.validUsername(args[1])) return error.InvalidUsername;
            if (kind == .mint_token and !p.tokens.validLabel(args[1])) return error.InvalidValue;
            result.username = args[1];
        } else result.target = try number(args[1], false);
        index += 1;
    }
    var seen: u32 = 0;
    while (index < args.len) : (index += 2) {
        if (index + 1 == args.len) return error.MissingValue;
        const option = try optionName(args[index]);
        const bit = @as(u32, 1) << @backingInt(option);
        if (seen & bit != 0 and option != .scope) return error.DuplicateOption;
        seen |= bit;
        try assign(&result, option, args[index + 1]);
    }
    try authentication(result);
    if (kind == .mint_token and !p.tokens.validScopes(result.scopes, result.role))
        return error.InvalidValue;
    const access_fields = (@as(u32, 1) << @backingInt(Option.role)) |
        (@as(u32, 1) << @backingInt(Option.disabled));
    if (kind == .access and seen & access_fields != access_fields)
        return error.AccessFieldsRequired;
    if (kind.needsRevision() and result.revision == 0)
        return error.RevisionRequired;
    if (kind == .geo_update) try geographicVersion(result);
    if (kind == .policies_import and result.file.len == 0) return error.MissingTarget;
    return result;
}

fn optionName(name: []const u8) Error!Option {
    const names = .{
        "--origin", "--username", "--password-file", "--factor-file",
        "--role",   "--disabled", "--revision",      "--after",
        "--month",  "--checksum", "--timeout",       "--token-file",
        "--scope",  "--expires",  "--provider",      "--version",
        "--file",
    };
    inline for (names, 0..) |value, index| {
        if (equal(name, value)) return @fromBackingInt(@intCast(index));
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
        .token_file => args.token_file = value,
        .scope, .expires => try tokenOption(args, option, value),
        .role => {
            if (args.kind != .add and args.kind != .access and args.kind != .mint_token)
                return error.UnexpectedOption;
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
            if (!args.kind.needsRevision())
                return error.UnexpectedOption;
            args.revision = try number(value, false);
            if (args.revision == std.math.maxInt(i64)) return error.InvalidNumber;
        },
        .month, .checksum, .timeout, .provider, .version => try geographic(args, option, value),
        .after => {
            if (args.kind != .users and args.kind != .tokens) return error.UnexpectedOption;
            args.after = try number(value, true);
        },
        .file => {
            if (args.kind != .policies_import) return error.UnexpectedOption;
            args.file = value;
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
    try t.expectError(error.RevisionRequired, parse(&(.{ "reset-factor", "2" } ++ auth)));
    const reset = try parse(&(.{ "reset-factor", "2" } ++ auth ++ .{ "--revision", "7" }));
    try t.expectEqual(Kind.factor, reset.kind);
    try t.expectEqual(@as(u64, 7), reset.revision);
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

fn command(args: []const []const u8) Error!Kind {
    if (equal(args[0], "geoip")) {
        if (args.len < 2) return error.MissingTarget;
        if (equal(args[1], "status")) return .geo_status;
        if (equal(args[1], "update")) return .geo_update;
        return error.UnknownCommand;
    }
    if (equal(args[0], "policies")) {
        if (args.len < 2) return error.MissingTarget;
        if (equal(args[1], "export")) return .policies_export;
        if (equal(args[1], "import")) return .policies_import;
        return error.UnknownCommand;
    }
    const names = .{
        "users",        "add-user", "set-user",   "reset-password", "revoke-sessions",
        "reset-factor", "tokens",   "mint-token", "revoke-token",   "remove-token",
    };
    const kinds = [_]Kind{
        .users,  .add,    .access,     .password,     .revoke,
        .factor, .tokens, .mint_token, .revoke_token, .remove_token,
    };
    inline for (names, kinds) |name, kind| if (equal(args[0], name)) return kind;
    return error.UnknownCommand;
}

fn geographic(args: *Args, option: Option, value: []const u8) Error!void {
    if (args.kind != .geo_update) return error.UnexpectedOption;
    switch (option) {
        .month => {
            if (!geoip.Provider.dbip.versionValid(value)) return error.InvalidValue;
            args.version = value;
            args.provider = "dbip";
            args.month_alias = true;
        },
        .version => args.version = value,
        .provider => {
            if (geoip.Provider.parse(value) == null) return error.InvalidValue;
            args.provider = value;
        },
        .checksum => {
            if (value.len != 64) return error.InvalidValue;
            for (value) |byte| if (!std.ascii.isHex(byte)) return error.InvalidValue;
            args.checksum = value;
        },
        .timeout => {
            const seconds = try number(value, false);
            if (seconds > 86400) return error.InvalidValue;
            args.timeout = @intCast(seconds);
        },
        else => unreachable,
    }
}

/// `--month` is the DB-IP alias; it cannot be combined with another provider.
fn geographicVersion(args: Args) Error!void {
    if (args.version.len == 0) return error.MissingValue;
    const provider = geoip.Provider.parse(args.provider) orelse return error.InvalidValue;
    if (args.month_alias and provider != .dbip) return error.InvalidValue;
    if (!provider.versionValid(args.version)) return error.InvalidValue;
}

test "GeoIP CLI requires a bounded explicit publisher version and scoped options" {
    const t = std.testing;
    const auth = [_][]const u8{
        "--origin", "http://127.0.0.1:9443", "--username", "admin", "--password-file", "private",
    };
    const args = try parse(&(.{ "geoip", "update" } ++ auth ++ .{
        "--month", "2026-09", "--timeout", "60",
    }));
    try t.expectEqual(Kind.geo_update, args.kind);
    try t.expectEqual(@as(u32, 60), args.timeout);
    try t.expectEqual(Kind.geo_status, (try parse(&(.{ "geoip", "status" } ++ auth))).kind);
    try t.expectError(error.MissingValue, parse(&(.{ "geoip", "update" } ++ auth)));
    try t.expectError(error.InvalidValue, parse(&(.{ "geoip", "update" } ++ auth ++ .{
        "--month", "2026-13",
    })));
    const daily = try parse(&(.{ "geoip", "update" } ++ auth ++ .{
        "--provider", "user-country", "--version", "2026-09-09",
    }));
    try t.expectEqualStrings("user-country", daily.provider);
    try t.expectEqualStrings("2026-09-09", daily.version);
    try t.expectEqualStrings("dbip", args.provider);
    try t.expectError(error.InvalidValue, parse(&(.{ "geoip", "update" } ++ auth ++ .{
        "--version", "2026-09",
    })));
    try t.expectError(error.InvalidValue, parse(&(.{ "geoip", "update" } ++ auth ++ .{
        "--month", "2026-09", "--provider", "user-country",
    })));
    try t.expectError(error.InvalidValue, parse(&(.{ "geoip", "update" } ++ auth ++ .{
        "--provider", "maxmind", "--version", "2026-09-09",
    })));
    try t.expectError(error.UnexpectedOption, parse(&(.{"users"} ++ auth ++ .{
        "--month", "2026-09",
    })));
    try t.expectError(error.UnexpectedOption, parse(&(.{ "geoip", "update" } ++ auth ++ .{
        "--revision", "1",
    })));
}

fn authentication(args: Args) Error!void {
    if (args.origin.len == 0) return error.AuthenticationRequired;
    if (args.token_file != null) {
        if (args.actor.len != 0 or args.password_file.len != 0 or args.factor_file != null)
            return error.UnexpectedOption;
        if (args.kind.managesTokens()) return error.UnexpectedOption;
        return;
    }
    if (!p.validUsername(args.actor) or args.password_file.len == 0)
        return error.AuthenticationRequired;
}

fn tokenOption(args: *Args, option: Option, value: []const u8) Error!void {
    if (args.kind != .mint_token) return error.UnexpectedOption;
    if (option == .expires) {
        args.expires = try number(value, false);
        return;
    }
    const scope = std.meta.stringToEnum(p.tokens.Scope, value) orelse return error.InvalidValue;
    if (args.scopes & scope.bit() != 0) return error.DuplicateOption;
    args.scopes |= scope.bit();
}

test "token CLI rejects delegation, mixed credentials and ambiguous capabilities" {
    const t = std.testing;
    const auth = [_][]const u8{
        "--origin", "http://127.0.0.1:9443", "--username", "admin", "--password-file", "private",
    };
    const args = try parse(&(.{ "mint-token", "deploy", "--role", "operator" } ++ auth ++ .{
        "--scope", "policy_read", "--scope", "policy_write", "--expires", "9007199254740993",
    }));
    try t.expectEqual(@as(?u64, 9007199254740993), args.expires);
    try t.expectEqual(
        p.tokens.Scope.policy_read.bit() | p.tokens.Scope.policy_write.bit(),
        args.scopes,
    );
    try t.expectError(error.InvalidValue, parse(&(.{ "mint-token", "empty" } ++ auth)));
    try t.expectError(error.InvalidValue, parse(&(.{ "mint-token", "above-role" } ++ auth ++ .{
        "--scope", "users_write",
    })));
    try t.expectError(error.DuplicateOption, parse(&(.{ "mint-token", "duplicate" } ++ auth ++ .{
        "--scope", "stats_read", "--scope", "stats_read",
    })));
    try t.expectError(error.UnexpectedOption, parse(&(.{"users"} ++ auth ++ .{
        "--token-file", "private-token",
    })));
    const bearer = [_][]const u8{
        "--origin", "http://127.0.0.1:9443", "--token-file", "private-token",
    };
    try t.expectEqualStrings("private-token", (try parse(&(.{"users"} ++ bearer))).token_file.?);
    try t.expectError(error.UnexpectedOption, parse(&(.{"tokens"} ++ bearer)));
    try t.expectError(error.RevisionRequired, parse(&(.{ "revoke-token", "1" } ++ auth)));
}
