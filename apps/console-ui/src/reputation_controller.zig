//! IP groups on the policies page: paged prefixes, revision-checked edits and removals
//! with a thirty-second undo that posts the inverse as a new mutation, and the country
//! builder's preview and apply.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const Kind = @import("reputation_state.zig").Kind;
const string = @import("events_state.zig").string;
const field = @import("events_state.zig").field;
const equal = std.mem.eql;
var generation: u64 = 0;

pub fn refresh(state: *State, out: Outbox) !void {
    const model = &state.reputation;
    if (model.busy or !state.allows(.manage_policy)) return;
    model.after = .{};
    try query(state, out);
}

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    const model = &state.reputation;
    const mine = std.mem.startsWith(u8, name, "reputation-") or
        std.mem.startsWith(u8, name, "country-");
    if (!mine) return false;
    if (!state.allows(.manage_policy) or state.phase != .policies or model.busy) return true;
    if (equal(u8, name, "reputation-refresh")) {
        model.after = .{};
        try query(state, out);
    } else if (equal(u8, name, "reputation-next") and model.next.len != 0) {
        model.after = model.next;
        try query(state, out);
    } else if (equal(u8, name, "reputation-edit")) {
        try edit(state, out, .{
            .prefix = string(fields, "prefix"),
            .action = string(fields, "action"),
            .note = string(fields, "note"),
            .hours = try hours(fields),
        });
    } else if (std.mem.startsWith(u8, name, "reputation-remove:")) {
        try remove(state, out, name["reputation-remove:".len..]);
    } else if (equal(u8, name, "reputation-undo") and model.undo.expires_at > state.browser_time) {
        const undo = model.undo;
        model.undo = .{};
        if (undo.restore) {
            try edit(state, out, .{
                .prefix = undo.prefix.slice(),
                .action = undo.action.slice(),
                .note = undo.note.slice(),
                .hours = undo.until,
            });
        } else try remove(state, out, undo.prefix.slice());
    } else if (equal(u8, name, "country-preview")) {
        try country(state, out, fields, .preview);
    } else if (equal(u8, name, "country-next") and model.country_next != null) {
        try country(state, out, fields, .preview_page);
    } else if (equal(u8, name, "country-apply") and model.country_review.len != 0) {
        try country(state, out, fields, .apply);
    }
    return true;
}

/// A blank duration keeps the row until removed; otherwise hours become an absolute time.
fn hours(fields: std.json.Value) error{InvalidInput}!u64 {
    const text = string(fields, "hours");
    if (text.len == 0) return 0;
    const value = std.fmt.parseInt(u64, text, 10) catch return error.InvalidInput;
    if (value == 0 or value > 87600) return error.InvalidInput;
    return value;
}

fn ticket(state: *State, kind: Kind) !void {
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const model = &state.reputation;
    const text = try std.fmt.bufPrint(&model.ticket.data, "reputation-{d}", .{generation});
    model.ticket.len = text.len;
    model.kind = kind;
    model.busy = true;
}

fn query(state: *State, out: Outbox) !void {
    try ticket(state, .query);
    errdefer state.reputation.busy = false;
    try out.post(state.reputation.ticket.slice(), "/console/api/reputation/query", .{
        .after = state.reputation.after.slice(),
    });
}

fn until(state: *State, buffer: *[20]u8, duration_hours: u64) !?[]const u8 {
    if (duration_hours == 0) return null;
    return try std.fmt.bufPrint(buffer, "{d}", .{state.browser_time + duration_hours * 3600});
}

const EditInput = struct { prefix: []const u8, action: []const u8, note: []const u8, hours: u64 };

fn edit(state: *State, out: Outbox, input: EditInput) !void {
    const model = &state.reputation;
    const prefix = input.prefix;
    const action_text = input.action;
    const note = input.note;
    const duration_hours = input.hours;
    if (prefix.len == 0 or prefix.len > 48 or note.len > 128) {
        try state.message.set("Enter an address or CIDR of at most 48 characters.");
        return;
    }
    try ticket(state, .edit);
    errdefer model.busy = false;
    model.undo = .{
        .prefix = try p.Bytes(48).init(prefix),
        .restore = false,
        .action = try p.Bytes(8).init(action_text),
        .note = try p.Bytes(128).init(note),
        .until = duration_hours,
    };
    var buffer: [20]u8 = undefined;
    try out.post(model.ticket.slice(), "/console/api/reputation/edit", .{
        .prefix = prefix,
        .expected_revision = model.committed.slice(),
        .action = action_text,
        .until = try until(state, &buffer, duration_hours),
        .note = note,
    });
}

fn remove(state: *State, out: Outbox, prefix: []const u8) !void {
    const model = &state.reputation;
    try ticket(state, .remove);
    errdefer model.busy = false;
    model.undo = try rowUndo(model, prefix);
    try out.post(model.ticket.slice(), "/console/api/reputation/remove", .{
        .prefix = prefix,
        .expected_revision = model.committed.slice(),
    });
}

/// The inverse of a removal restores the row as it was listed.
const Model = @import("reputation_state.zig").Model;
const Undo = @import("reputation_state.zig").Undo;

fn rowUndo(model: *const Model, prefix: []const u8) !Undo {
    var undo: Undo = .{
        .prefix = try p.Bytes(48).init(prefix),
        .restore = true,
        .action = try p.Bytes(8).init("deny"),
    };
    var memory: [16384]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        model.page(),
        .{},
    ) catch return undo;
    const rows = field(parsed, "rows") orelse return undo;
    if (rows != .array) return undo;
    for (rows.array.items) |row| {
        if (!equal(u8, string(row, "prefix"), prefix)) continue;
        const score = field(row, "score") orelse continue;
        if (score == .integer and score.integer > 0) undo.action = try p.Bytes(8).init("allow");
        try undo.note.set(string(row, "note"));
    }
    return undo;
}

fn country(state: *State, out: Outbox, fields: std.json.Value, kind: Kind) !void {
    const model = &state.reputation;
    if (kind == .preview) {
        model.clearSummary();
        const code = string(fields, "country");
        if (code.len != 2) {
            try state.message.set("Enter a two-letter country code.");
            return;
        }
        const upper: [2]u8 = .{ std.ascii.toUpper(code[0]), std.ascii.toUpper(code[1]) };
        model.country = try p.Bytes(2).init(&upper);
        model.country_action = try p.Bytes(8).init(string(fields, "action"));
        const duration = try hours(fields);
        model.country_until = if (duration == 0) 0 else state.browser_time + duration * 3600;
        model.country_revision = model.committed;
    }
    try ticket(state, kind);
    errdefer model.busy = false;
    var buffer: [20]u8 = undefined;
    const expiry = if (model.country_until == 0) null else try std.fmt.bufPrint(
        &buffer,
        "{d}",
        .{model.country_until},
    );
    try out.post(model.ticket.slice(), if (kind == .apply)
        "/console/api/geoip/country/apply"
    else
        "/console/api/geoip/country/preview", .{
        .country = model.country.slice(),
        .expected_revision = model.country_revision.slice(),
        .action = model.country_action.slice(),
        .until = expiry,
        .review = model.country_review.slice(),
        .offset = if (kind == .preview_page) model.country_next.? else @as(u16, 0),
    });
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    out: Outbox,
) !void {
    const model = &state.reputation;
    if (state.phase != .policies or !equal(u8, id, model.ticket.slice())) return;
    const kind = model.kind;
    model.busy = false;
    if (status == 401) {
        state.reset();
        state.phase = .login;
        return;
    }
    if (status != 200) {
        model.undo = .{};
        if (kind == .apply or kind == .preview or kind == .preview_page) model.clearSummary();
        const code = string(body, "error");
        try state.message.set(if (equal(u8, code, "CONSOLEGEOIP"))
            "No GeoIP generation is active. Import country data before building a block."
        else if (equal(u8, code, "CONSOLECAPACITY"))
            "Refused: the address trie would exceed its capacity."
        else switch (status) {
            409 => "Policy, GeoIP or ownership changed. Reload and preview again; " ++
                "independently managed prefixes cannot be overwritten by a country action.",
            400 => "The prefix or country was refused. Check the value and try again.",
            else => "The change could not be saved. Check the connection and try again.",
        });
        return;
    }
    switch (kind) {
        .query => {
            try model.setPage(body);
            try model.committed.set(string(body, "committed"));
            try model.next.set(string(body, "next"));
            model.loaded = true;
        },
        .edit, .remove, .apply => {
            state.message_success = true;
            try state.message.set(if (kind == .apply)
                "Country block applied. The data plane serves it after the next rebuild."
            else
                "Saved. Undo is available for thirty seconds.");
            if (kind == .apply) {
                model.undo = .{};
                model.clearSummary();
                model.summary_prefixes = 0;
            } else {
                model.undo.expires_at = state.browser_time + 30;
                try out.emit(.{ .op = "timer", .id = "reputation-undo", .delay_ms = 30_000 });
            }
            model.after = .{};
            try query(state, out);
        },
        .preview, .preview_page => {
            try model.setSummary(body);
            try model.country_review.set(string(body, "review"));
            if (model.country_review.len != 64) return error.InvalidResponse;
            const next = field(body, "next_offset") orelse .null;
            model.country_next = if (next == .integer and next.integer >= 0 and
                next.integer <= 2048) @intCast(next.integer) else null;
            const prefixes = field(body, "prefixes") orelse .null;
            model.summary_prefixes = if (prefixes == .integer)
                @intCast(@max(0, @min(prefixes.integer, 65535)))
            else
                0;
        },
    }
}

/// The undo window closed; the button disappears on the next render.
pub fn tick(state: *State) void {
    if (state.reputation.undo.expires_at <= state.browser_time) state.reputation.undo = .{};
}

test {
    _ = @import("reputation_controller_test.zig");
}
