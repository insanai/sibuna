const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const Kind = @import("users_state.zig").Kind;
const string = @import("events_state.zig").string;
const equal = std.mem.eql;
var generation: u64 = 0;

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    if (equal(u8, name, "users") and state.fullAccess()) {
        state.users.clear();
        state.phase = .users;
        state.message = .{};
        state.stats_busy = false;
        state.stale = true;
        try out.emit(.{ .op = "disconnect" });
        try query(state, out);
        return true;
    }
    if (!std.mem.startsWith(u8, name, "users-")) return false;
    if (!state.fullAccess() or state.phase != .users or state.users.busy) return true;
    const model = &state.users;
    if (equal(u8, name, "users-dismiss")) {
        model.clearSecret();
        model.username = .{};
        model.confirmed = false;
        state.message = .{};
    } else if (equal(u8, name, "users-first")) {
        model.page = 0;
        try query(state, out);
    } else if (equal(u8, name, "users-next")) {
        if (model.next == null or model.page + 1 == model.pages.len) return true;
        model.page += 1;
        model.pages[model.page] = model.next.?;
        try query(state, out);
    } else if (equal(u8, name, "users-previous")) {
        if (model.page == 0) return true;
        model.page -= 1;
        try query(state, out);
    } else if (std.mem.startsWith(u8, name, "users-open-")) {
        const index = std.fmt.parseInt(usize, name[11..], 10) catch return true;
        if (index >= model.count or !state.allows(.manage_users)) return true;
        model.selected = index;
        model.role = model.rows[index].role;
        model.disabled = model.rows[index].disabled;
        model.confirmed = false;
        state.message = .{};
    } else if (equal(u8, name, "users-draft")) {
        try draft(state, fields);
    } else if (equal(u8, name, "users-create")) {
        if (!state.allows(.manage_users) or model.temporary.len != 0) return true;
        try draft(state, fields);
        if (!model.confirmed or !p.validUsername(model.username.slice())) return true;
        try ticket(state, .create);
        errdefer model.busy = false;
        try out.post(model.ticket.slice(), "/console/api/users/create", .{
            .username = model.username.slice(),
            .role = model.role,
        });
    } else if (equal(u8, name, "users-access") or equal(u8, name, "users-password") or
        equal(u8, name, "users-revoke"))
    {
        try mutate(state, name, fields, out);
    }
    return true;
}

fn draft(state: *State, fields: std.json.Value) !void {
    const model = &state.users;
    if (model.selected == null)
        model.username = try p.Bytes(64).init(string(fields, "username"));
    const role = string(fields, "role");
    if (role.len != 0) model.role = std.meta.stringToEnum(p.Role, role) orelse
        return error.InvalidResponse;
    if (role.len != 0) model.disabled = equal(u8, string(fields, "disabled"), "on");
    model.confirmed = equal(u8, string(fields, "confirmed"), "on");
}

fn ticket(state: *State, kind: Kind) !void {
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const model = &state.users;
    const name = try std.fmt.bufPrint(&model.ticket.data, "users-{d}", .{generation});
    model.ticket.len = name.len;
    model.kind = kind;
    model.busy = true;
    state.message = .{};
}

fn query(state: *State, out: Outbox) !void {
    const model = &state.users;
    try ticket(state, .query);
    model.loaded = false;
    model.count = 0;
    model.selected = null;
    model.next = null;
    errdefer model.busy = false;
    var cursor: [20]u8 = undefined;
    try out.post(model.ticket.slice(), "/console/api/users/query", .{
        .after = try std.fmt.bufPrint(&cursor, "{d}", .{model.pages[model.page]}),
    });
}

fn mutate(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !void {
    const model = &state.users;
    if (!state.allows(.manage_users) or model.temporary.len != 0) return;
    const index = model.selected orelse return;
    if (equal(u8, name, "users-access")) {
        try draft(state, fields);
    } else {
        model.confirmed = equal(u8, string(fields, "confirmed"), "on");
    }
    if (!model.confirmed) return;
    const row = &model.rows[index];
    const kind: Kind = if (equal(u8, name, "users-access")) .access else password: {
        break :password if (equal(u8, name, "users-password")) .password else .revoke;
    };
    if (row.id == state.user_id and kind != .revoke) return;
    model.username = row.username;
    model.self_revoke = row.id == state.user_id and kind == .revoke;
    var target: [20]u8 = undefined;
    var revision: [20]u8 = undefined;
    try ticket(state, kind);
    errdefer model.busy = false;
    try out.post(model.ticket.slice(), "/console/api/users/change", .{
        .target = try std.fmt.bufPrint(&target, "{d}", .{row.id}),
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{row.revision}),
        .operation = @tagName(kind),
        .role = if (kind == .access) model.role else @as(?p.Role, null),
        .disabled = if (kind == .access) model.disabled else @as(?bool, null),
    });
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    allocator: std.mem.Allocator,
    out: Outbox,
) !void {
    const model = &state.users;
    if (!state.fullAccess() or state.phase != .users) return;
    if (!equal(u8, id, model.ticket.slice())) return;
    model.busy = false;
    if (status == 401) return expired(state, out);
    if (status != 200) return message(state, switch (status) {
        403 => "An administrator is required. Use Account to change your own password.",
        409 => "Account conflict or capacity reached. Refresh the list before retrying.",
        429 => "Too many account operations. Wait a minute, then refresh.",
        0, 503 => "Outcome unknown. Refresh users before retrying; a change may have committed.",
        else => "Account request failed. Check the fields and refresh before retrying.",
    });
    if (model.kind == .query) {
        model.decode(body, allocator) catch {
            return message(state, "Could not read the account list.");
        };
        return out.emit(.{
            .op = "focus",
            .selector = if (model.temporary.len != 0) "#users-temporary" else "#users-catalog",
            .top = true,
        });
    }
    const saved = @import("json_value.zig").decode(struct {
        saved: bool,
        temporary_password: ?[]const u8,
        password_expires: u64,
    }, body, allocator) catch return message(state, "Outcome unknown. Refresh the account list.");
    if (!saved.saved) return message(state, "Outcome unknown. Refresh the account list.");
    if (model.self_revoke) return expired(state, out);
    const mint = model.kind == .create or model.kind == .password;
    if (mint) {
        const password = saved.temporary_password orelse return error.InvalidResponse;
        if (password.len != 64 or saved.password_expires == 0) return error.InvalidResponse;
        for (password) |byte| if (!std.ascii.isHex(byte)) return error.InvalidResponse;
        model.temporary = try p.Bytes(64).init(password);
        model.expires = saved.password_expires;
    } else if (saved.temporary_password != null or saved.password_expires != 0)
        return error.InvalidResponse;
    if (!mint) model.username = .{};
    model.confirmed = false;
    model.selected = null;
    model.role = .viewer;
    try query(state, out);
    message(state, "Account change saved. Affected sessions have been revoked.");
    state.message_success = true;
}

fn expired(state: *State, out: Outbox) !void {
    state.reset();
    state.phase = .login;
    message(state, "Your session ended. Sign in to continue.");
    try out.emit(.{ .op = "disconnect" });
}

fn message(state: *State, text: []const u8) void {
    state.message = p.Bytes(256).init(text) catch unreachable;
    state.message_success = false;
}

test {
    _ = @import("users_controller_test.zig");
}
