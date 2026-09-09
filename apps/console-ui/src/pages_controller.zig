//! Template editing inside Settings. Save and reset carry the committed revision; preview
//! stores the draft for this session and offers a link that opens in a new tab, where the
//! reply is sandboxed by the server and never shares the console origin.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const string = @import("events_state.zig").string;
const equal = std.mem.eql;
var generation: u64 = 0;

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    if (!std.mem.startsWith(u8, name, "pages-")) return false;
    if (!state.allows(.manage_settings) or state.phase != .settings) return true;
    const model = &state.pages;
    if (model.busy) return true;
    if (std.mem.startsWith(u8, name, "pages-open-")) {
        model.kind = std.meta.stringToEnum(p.pages.Kind, name["pages-open-".len..]) orelse
            return true;
        model.result = .{};
        model.preview_path = .{};
        model.clearDraft();
        try read(state, out);
    } else if (equal(u8, name, "pages-save")) {
        model.setDraft(string(fields, "html"));
        try mutate(state, out, string(fields, "html"), false);
    } else if (equal(u8, name, "pages-reset")) {
        model.clearDraft();
        try mutate(state, out, "", true);
    } else if (equal(u8, name, "pages-preview")) {
        model.setDraft(string(fields, "html"));
        try ticket(state, .preview);
        errdefer model.busy = false;
        try out.post(model.ticket.slice(), "/console/api/pages/preview", .{
            .kind = @tagName(model.kind),
            .html = string(fields, "html"),
        });
    }
    return true;
}

pub fn read(state: *State, out: Outbox) !void {
    try ticket(state, .read);
    errdefer state.pages.busy = false;
    try out.post(state.pages.ticket.slice(), "/console/api/pages/read", .{
        .kind = @tagName(state.pages.kind),
    });
}

fn mutate(state: *State, out: Outbox, html: []const u8, reset: bool) !void {
    const model = &state.pages;
    if (!reset and html.len == 0) {
        try state.message.set("Enter the page markup or reset to the default.");
        return;
    }
    try ticket(state, .edit);
    errdefer model.busy = false;
    var revision: [20]u8 = undefined;
    try out.post(model.ticket.slice(), "/console/api/pages/edit", .{
        .kind = @tagName(model.kind),
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{model.revision}),
        .reset = reset,
        .html = html,
    });
}

fn ticket(state: *State, op: @import("pages_state.zig").Kind) !void {
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const model = &state.pages;
    const text = try std.fmt.bufPrint(&model.ticket.data, "pages-{d}", .{generation});
    model.ticket.len = text.len;
    model.op = op;
    model.busy = true;
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    out: Outbox,
) !void {
    const model = &state.pages;
    if (state.phase != .settings or !equal(u8, id, model.ticket.slice())) return;
    const op = model.op;
    model.busy = false;
    if (status == 401) {
        state.reset();
        state.phase = .login;
        return;
    }
    if (status != 200) {
        model.result_ok = false;
        try model.result.set(if (status == 409)
            "Another administrator changed this page; reload it and retry."
        else if (status == 400)
            "The template was refused: forbidden markup, an unknown placeholder or a bad size."
        else
            "The page could not be saved. Check the connection and try again.");
        return;
    }
    switch (op) {
        .read => model.decode(body) catch {
            try model.result.set("The page could not be decoded.");
        },
        .edit => {
            model.result_ok = true;
            try model.result.set("Saved. The data plane serves it after the next rebuild.");
            model.preview_path = .{};
            model.clearDraft();
            try read(state, out);
        },
        .preview => {
            const accepted = @import("events_state.zig").field(body, "accepted");
            model.result_ok = accepted != null and accepted.? == .bool and accepted.?.bool;
            if (model.result_ok) {
                try model.preview_path.set(string(body, "path"));
                try model.result.set("Draft accepted. Open the preview in a new tab.");
            } else {
                model.preview_path = .{};
                var text: [96]u8 = undefined;
                try model.result.set(std.fmt.bufPrint(&text, "Draft refused: {s}", .{
                    string(body, "diagnostic"),
                }) catch "Draft refused.");
            }
        },
    }
}
