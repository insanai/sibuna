//! Validate bounded command output before emitting it. Error pages and unexpected fields
//! never reach stdout; successful password operations intentionally return a one-time secret.
const std = @import("std");
const p = @import("console").protocol;
const Args = @import("console_command_args.zig").Args;
const Error = error{InvalidResponse};
const Row = struct {
    id: u64,
    username: []const u8,
    role: p.Role,
    revision: u64,
    disabled: bool,
    must_change: bool,
    totp_enabled: bool,
    password_expires: u64,
    last_login: ?u64,
};
const Page = struct { version: u8, rows: []const Row, next: ?u64 };
const Saved = struct { saved: bool, temporary_password: ?[]const u8, password_expires: u64 };

pub fn validate(args: Args, bytes: []const u8) Error!void {
    var arena: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &arena);
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    if (args.kind == .users) {
        const parsed = std.json.parseFromSlice(Page, fixed.allocator(), bytes, .{}) catch
            return error.InvalidResponse;
        defer parsed.deinit();
        const page = parsed.value;
        if (page.version != 1 or page.rows.len > p.users.page_rows) return error.InvalidResponse;
        var previous = args.after;
        for (page.rows) |row| {
            if (row.id <= previous or row.id > std.math.maxInt(i64) or row.revision == 0 or
                !p.validUsername(row.username)) return error.InvalidResponse;
            previous = row.id;
        }
        if (page.next) |next| {
            if (page.rows.len == 0 or next != previous) return error.InvalidResponse;
        }
        return;
    }
    const parsed = std.json.parseFromSlice(Saved, fixed.allocator(), bytes, .{}) catch
        return error.InvalidResponse;
    defer parsed.deinit();
    const saved = parsed.value;
    if (!saved.saved) return error.InvalidResponse;
    const mint = args.kind == .add or args.kind == .password;
    if (!mint) {
        if (saved.temporary_password != null or saved.password_expires != 0)
            return error.InvalidResponse;
        return;
    }
    const secret = saved.temporary_password orelse return error.InvalidResponse;
    if (secret.len != 64 or saved.password_expires == 0) return error.InvalidResponse;
    for (secret) |byte| if (!std.ascii.isHex(byte)) return error.InvalidResponse;
}

test "CLI replies retain decimal counters and refuse unexpected sensitive fields" {
    const t = std.testing;
    const args: Args = .{ .kind = .users };
    const row =
        \\{"id":"9007199254740993","username":"viewer","role":"viewer",
        \\"revision":"9007199254740995","disabled":false,"must_change":false,
        \\"totp_enabled":false,"password_expires":0,"last_login":null}
    ;
    try validate(args, "{\"version\":1,\"rows\":[" ++ row ++ "],\"next\":null}");
    const unsupported = "{\"version\":2,\"rows\":[],\"next\":null}";
    try t.expectError(error.InvalidResponse, validate(args, unsupported));
    const sensitive = "{\"version\":1,\"rows\":[],\"next\":null,\"password_hash\":\"private\"}";
    try t.expectError(error.InvalidResponse, validate(args, sensitive));
    const repeated = "{\"version\":1,\"rows\":[" ++ row ++ "," ++ row ++ "],\"next\":null}";
    try t.expectError(error.InvalidResponse, validate(args, repeated));
    const saved = "{\"saved\":true,\"temporary_password\":null,\"password_expires\":\"0\"}";
    try validate(.{ .kind = .access }, saved);
    try t.expectError(error.InvalidResponse, validate(.{ .kind = .password }, saved));
}
