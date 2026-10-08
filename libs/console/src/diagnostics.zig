//! Operator diagnostics retain typed causes; browser hints contain no internal traces.
const std = @import("std");
pub const Diagnostic = struct { code: []const u8, hint: []const u8 };

pub fn startup(err: anyerror) Diagnostic {
    return switch (err) {
        error.UnsupportedConsoleSchema => .{
            .code = "CONSOLESCHEMA",
            .hint = @import("console_protocol").diagnostics.schema_hint,
        },
        error.StorageUnavailable, error.StorageTimeout => .{
            .code = "CONSOLEQUORUM",
            .hint = "Storage could not answer. Check storage health " ++
                "and, for a cluster, quorum, then retry.",
        },
        error.InvalidStorageReply => .{
            .code = "CONSOLESTORE",
            .hint = "Storage returned an unexpected console result. " ++
                "Check binary compatibility and the operator log.",
        },
        error.AlreadyInitialized => .{
            .code = "CONSOLEBOOT",
            .hint = "An administrator already exists. Sign in to that account; " ++
                "keep the existing data directory.",
        },
        error.StorageRequired => .{
            .code = "CONSOLEBOOT",
            .hint = "Supply --data-dir with a stopped Sibuna instance to initialize the console.",
        },
        error.InvalidUsername => .{
            .code = "CONSOLEBOOT",
            .hint = "Use a username of 1 to 64 letters, digits, underscores, hyphens or dots.",
        },
        else => .{
            .code = "CONSOLESTART",
            .hint = "Check the console configuration and operator log. " ++
                "Keep the existing data directory.",
        },
    };
}

pub fn responseHint(status: std.http.Status, code: []const u8) []const u8 {
    return @import("console_protocol").diagnostics.responseHint(@backingInt(status), code);
}

test "diagnostics distinguish schema refusal, unexpected results and storage outages" {
    const t = std.testing;
    const schema = startup(error.UnsupportedConsoleSchema);
    try t.expectEqualStrings("CONSOLESCHEMA", schema.code);
    try t.expect(std.mem.indexOf(u8, schema.hint, "do not downgrade") != null);
    try t.expect(std.mem.indexOf(u8, schema.hint, "quorum") == null);
    try t.expectEqualStrings("CONSOLESTORE", startup(error.InvalidStorageReply).code);
    try t.expectEqualStrings("CONSOLEQUORUM", startup(error.StorageUnavailable).code);
    for ([_]std.http.Status{ .bad_request, .unauthorized, .forbidden, .conflict }) |status| {
        for ([_][]const u8{ "CONSOLEPOLICY", "CONSOLETOKENS", "CONSOLENODE" }) |code| {
            const hint = responseHint(status, code);
            try t.expect(std.mem.indexOf(u8, hint, "quorum") == null);
            try t.expect(std.mem.indexOf(u8, hint, "Storage is unavailable") == null);
            if (status != .conflict)
                try t.expect(std.mem.indexOf(u8, hint, "Outcome unknown") == null);
        }
    }
    const outage = responseHint(.service_unavailable, "CONSOLEQUORUM");
    try t.expect(std.mem.indexOf(u8, outage, "unknown outcome") != null);
    const invalid = responseHint(.bad_request, "CONSOLE002");
    try t.expect(!std.mem.eql(u8, invalid, responseHint(.unauthorized, "CONSOLE401")));
}
