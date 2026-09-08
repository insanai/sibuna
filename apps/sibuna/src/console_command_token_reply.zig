//! The CLI emits only validated, bounded contracts. In particular, catalog responses
//! cannot smuggle credential digests or values into redirected command output.
const std = @import("std");
const p = @import("console").protocol;
const Args = @import("console_command_args.zig").Args;
const Error = error{InvalidResponse};
const Row = struct {
    id: u64,
    revision: u64,
    label: []const u8,
    role: p.Role,
    scopes: []const p.tokens.Scope,
    created_by: u64,
    created_at: u64,
    expires: ?u64,
    disabled: bool,
    active: bool,
};
const Page = struct { version: u8, rows: []const Row, next: ?u64 };
const Created = struct { saved: bool, id: u64, token: []const u8, expires: ?u64 };
const Saved = struct { saved: bool, id: u64 };

pub fn validate(args: Args, bytes: []const u8) Error!void {
    var arena: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &arena);
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    if (args.kind == .tokens) {
        const parsed = std.json.parseFromSlice(Page, fixed.allocator(), bytes, .{}) catch
            return error.InvalidResponse;
        defer parsed.deinit();
        return page(args, parsed.value);
    }
    if (args.kind == .mint_token) {
        const parsed = std.json.parseFromSlice(Created, fixed.allocator(), bytes, .{}) catch
            return error.InvalidResponse;
        defer parsed.deinit();
        const saved = parsed.value;
        if (!saved.saved or !positive(saved.id) or saved.token.len != 64 or
            saved.expires != args.expires) return error.InvalidResponse;
        for (saved.token) |byte| if (!std.ascii.isHex(byte)) return error.InvalidResponse;
        return;
    }
    const parsed = std.json.parseFromSlice(Saved, fixed.allocator(), bytes, .{}) catch
        return error.InvalidResponse;
    defer parsed.deinit();
    if (!parsed.value.saved or parsed.value.id != args.target) return error.InvalidResponse;
}

fn page(args: Args, input: Page) Error!void {
    if (input.version != 1 or input.rows.len > p.tokens.page_rows) return error.InvalidResponse;
    var previous = args.after;
    for (input.rows) |row| {
        if (row.id <= previous or !positive(row.id) or !positive(row.revision) or
            !positive(row.created_by) or row.created_at > std.math.maxInt(i64) or
            !p.tokens.validLabel(row.label) or (row.disabled and row.active))
            return error.InvalidResponse;
        if (row.expires) |expires| {
            if (expires <= row.created_at or !positive(expires)) return error.InvalidResponse;
        }
        var scopes: u32 = 0;
        if (row.scopes.len > 8) return error.InvalidResponse;
        for (row.scopes) |scope| {
            if (scopes & scope.bit() != 0) return error.InvalidResponse;
            scopes |= scope.bit();
        }
        if (!p.tokens.validScopes(scopes, row.role)) return error.InvalidResponse;
        previous = row.id;
    }
    if (input.next) |next| {
        if (input.rows.len != p.tokens.page_rows or next != previous)
            return error.InvalidResponse;
    }
}

fn positive(value: u64) bool {
    return value != 0 and value <= std.math.maxInt(i64);
}

test "token CLI output checks authority, scope uniqueness and one-time disclosure" {
    const t = std.testing;
    const args: Args = .{ .kind = .tokens };
    const row =
        \\{"id":"9007199254740993","revision":"2","label":"deploy","role":"operator",
        \\"scopes":["policy_read","policy_write"],"created_by":"1","created_at":"12",
        \\"expires":null,"disabled":false,"active":true}
    ;
    try validate(args, "{\"version\":1,\"rows\":[" ++ row ++ "],\"next\":null}");
    const sensitive = "{\"version\":1,\"rows\":[],\"next\":null,\"digest\":\"redacted\"}";
    try t.expectError(error.InvalidResponse, validate(args, sensitive));
    const repeated = "{\"version\":1,\"rows\":[" ++ row ++ "," ++ row ++ "],\"next\":null}";
    try t.expectError(error.InvalidResponse, validate(args, repeated));
    const created = "{\"saved\":true,\"id\":\"1\",\"token\":\"" ++ "a" ** 64 ++
        "\",\"expires\":null}";
    try validate(.{ .kind = .mint_token }, created);
    try t.expectError(error.InvalidResponse, validate(.{ .kind = .tokens }, created));
    try t.expectError(error.InvalidResponse, validate(.{
        .kind = .mint_token,
        .expires = 999,
    }, created));
    const saved = "{\"saved\":true,\"id\":\"2\"}";
    try validate(.{ .kind = .revoke_token, .target = 2 }, saved);
    try t.expectError(error.InvalidResponse, validate(.{ .kind = .revoke_token }, saved));
}
