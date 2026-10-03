const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const Kind = @import("tokens_state.zig").Kind;
const string = @import("events_state.zig").string;
const equal = std.mem.eql;
var generation: u64 = 0;

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    if (equal(u8, name, "tokens") and state.allows(.manage_users)) {
        state.tokens.clear();
        state.phase = .tokens;
        state.message = .{};
        state.stats_busy = false;
        state.stale = true;
        try query(state, out);
        return true;
    }
    if (!std.mem.startsWith(u8, name, "tokens-")) return false;
    if (!state.allows(.manage_users) or state.phase != .tokens) return true;
    const model = &state.tokens;
    if (equal(u8, name, "tokens-dismiss")) {
        model.clearSecret();
        model.label = .{};
        model.confirmed = false;
        state.message = .{};
        try out.emit(.{ .op = "focus", .selector = "#page-heading" });
        return true;
    }
    if (model.busy) return true;
    if (equal(u8, name, "tokens-first")) {
        model.page = 0;
        try query(state, out);
    } else if (equal(u8, name, "tokens-next")) {
        if (model.next == null or model.page + 1 == model.pages.len) return true;
        model.page += 1;
        model.pages[model.page] = model.next.?;
        try query(state, out);
    } else if (equal(u8, name, "tokens-previous")) {
        if (model.page == 0) return true;
        model.page -= 1;
        try query(state, out);
    } else if (std.mem.startsWith(u8, name, "tokens-open-")) {
        const index = std.fmt.parseInt(usize, name[12..], 10) catch return true;
        if (index >= model.count) return true;
        model.selected = index;
        model.confirmed = false;
        state.message = .{};
        try out.emit(.{ .op = "focus", .selector = "#tokens-editor" });
    } else if (equal(u8, name, "tokens-draft")) {
        try draft(state, fields);
    } else if (equal(u8, name, "tokens-create")) {
        try create(state, fields, out);
    } else if (equal(u8, name, "tokens-revoke") or equal(u8, name, "tokens-remove")) {
        try mutate(state, name, fields, out);
    }
    return true;
}

fn draft(state: *State, fields: std.json.Value) !void {
    const model = &state.tokens;
    model.label = try p.Bytes(64).init(string(fields, "label"));
    model.role = std.meta.stringToEnum(p.Role, string(fields, "role")) orelse
        return error.InvalidResponse;
    model.scopes = 0;
    inline for (@typeInfo(p.tokens.Scope).@"enum".field_names) |field_name| {
        const scope: p.tokens.Scope = @field(p.tokens.Scope, field_name);
        if (model.role.allows(scope.action()) and equal(u8, string(fields, field_name), "on"))
            model.scopes |= scope.bit();
    }
    const days = try std.fmt.parseInt(u8, string(fields, "days"), 10);
    if (days != 0 and days != 7 and days != 30 and days != 90) return error.InvalidResponse;
    model.days = days;
    model.confirmed = equal(u8, string(fields, "confirmed"), "on");
}

fn ticket(state: *State, kind: Kind) !void {
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const model = &state.tokens;
    const name = try std.fmt.bufPrint(&model.ticket.data, "tokens-{d}", .{generation});
    model.ticket.len = name.len;
    model.kind = kind;
    model.busy = true;
    state.message = .{};
}

fn query(state: *State, out: Outbox) !void {
    const model = &state.tokens;
    try ticket(state, .query);
    model.loaded = false;
    model.count = 0;
    model.selected = null;
    model.next = null;
    errdefer model.busy = false;
    var cursor: [20]u8 = undefined;
    try out.post(model.ticket.slice(), "/console/api/tokens/query", .{
        .after = try std.fmt.bufPrint(&cursor, "{d}", .{model.pages[model.page]}),
    });
}

fn create(state: *State, fields: std.json.Value, out: Outbox) !void {
    const model = &state.tokens;
    if (model.secret.len != 0) return;
    try draft(state, fields);
    if (!model.confirmed) return;
    if (!p.tokens.validLabel(model.label.slice()) or
        !p.tokens.validScopes(model.scopes, model.role))
        return message(state, "Choose a label and at least one scope allowed by the role.");
    const duration = @as(u64, model.days) * 86400;
    const end = std.math.add(u64, state.browser_time, duration) catch
        return error.InvalidResponse;
    const expires: ?u64 = if (model.days == 0) null else end;
    try ticket(state, .create);
    errdefer model.busy = false;
    model.expires = expires;
    // Scope arrays use their bounded protocol serializer; the envelope remains shared.
    var json = try out.prefix(model.ticket.slice(), "/console/api/tokens/create");
    try json.beginObject();
    try json.objectField("label");
    try json.write(model.label.slice());
    try json.objectField("role");
    try json.write(model.role);
    try json.objectField("scopes");
    try p.tokens.writeScopes(model.scopes, &json);
    try json.objectField("expires");
    var deadline: [20]u8 = undefined;
    if (expires) |value| {
        try json.write(try std.fmt.bufPrint(&deadline, "{d}", .{value}));
    } else try json.write(null);
    try json.endObject();
    try json.endObject();
    out.count.* += 1;
}

fn mutate(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !void {
    const model = &state.tokens;
    if (model.secret.len != 0) return;
    const index = model.selected orelse return;
    model.confirmed = equal(u8, string(fields, "confirmed"), "on");
    if (!model.confirmed) return;
    const row = &model.rows[index];
    const remove = equal(u8, name, "tokens-remove");
    if ((remove and row.active) or (!remove and row.disabled)) return;
    var target: [20]u8 = undefined;
    var revision: [20]u8 = undefined;
    try ticket(state, if (remove) .remove else .revoke);
    errdefer model.busy = false;
    try out.post(model.ticket.slice(), "/console/api/tokens/revoke", .{
        .target = try std.fmt.bufPrint(&target, "{d}", .{row.id}),
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{row.revision}),
        .remove = remove,
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
    const model = &state.tokens;
    if (!state.allows(.manage_users) or state.phase != .tokens) return;
    if (!equal(u8, id, model.ticket.slice())) return;
    model.busy = false;
    if (status == 401) {
        state.reset();
        state.phase = .login;
        message(state, "Your session ended. Sign in to continue.");
        return out.emit(.{ .op = "disconnect" });
    }
    if (status != 200) return message(state, switch (status) {
        403 => "Token management requires an administrator with required two-factor enrollment.",
        409 => "Token conflict or capacity reached. Refresh the list before retrying.",
        429 => "Too many token operations. Wait a minute, then refresh.",
        0, 503 => "Outcome unknown. Refresh tokens before retrying; revoke any undisclosed token.",
        else => "Token request failed. Check the fields and refresh before retrying.",
    });
    if (model.kind == .query) {
        model.decode(body, allocator) catch {
            return message(state, "Could not read the token list.");
        };
        return out.emit(.{
            .op = "focus",
            .selector = if (model.secret.len != 0) "#tokens-secret" else "#tokens-catalog",
        });
    }
    try saved(state, body, allocator);
    model.confirmed = false;
    model.selected = null;
    try query(state, out);
    message(state, "Token change saved.");
    state.message_success = true;
}

fn saved(state: *State, body: std.json.Value, allocator: std.mem.Allocator) !void {
    const model = &state.tokens;
    const decode = @import("json_value.zig").decode;
    if (model.kind == .create) {
        const value = try decode(struct {
            saved: bool,
            id: u64,
            token: []const u8,
            expires: ?u64,
        }, body, allocator);
        if (!value.saved or !@import("tokens_state.zig").positive(value.id) or
            value.token.len != 64 or value.expires != model.expires) return error.InvalidResponse;
        for (value.token) |byte| if (!std.ascii.isHex(byte)) return error.InvalidResponse;
        model.secret = try p.Bytes(64).init(value.token);
        model.issued_id = value.id;
        return;
    }
    const value = try decode(struct { saved: bool, id: u64 }, body, allocator);
    const selected = model.selected orelse return error.InvalidResponse;
    if (!value.saved or value.id != model.rows[selected].id) return error.InvalidResponse;
}

fn message(state: *State, text: []const u8) void {
    state.message = p.Bytes(256).init(text) catch unreachable;
    state.message_success = false;
}

test {
    _ = @import("tokens_test.zig");
}
