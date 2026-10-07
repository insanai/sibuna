const html = @import("html");
const std = @import("std");
const State = @import("state.zig").State;
const render = @import("render.zig");
const Writer = std.Io.Writer;

pub fn page(state: *const State, w: *Writer) Writer.Error!void {
    try html.render(w, "<main class=\"sb-auth\"><section class=\"sb-auth-card\">" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Two-factor authentication</h1>", .{});
    try render.message(state, w);
    if (state.recovery_count != 0) {
        try html.render(w, "<h2>Save your recovery codes</h2><p>Each code works once. " ++
            "Store these somewhere safe before signing in again.</p><ol>", .{});
        for (state.recovery_codes[0..state.recovery_count]) |code| {
            try html.render(w, "<li><code>", .{});
            try render.escape(w, code.slice());
            try html.render(w, "</code></li>", .{});
        }
        try html.render(
            w,
            "</ol><button class=\"btn btn-primary\" " ++
                "data-action=\"recovery-saved\">{{ label }}</button></section></main>",
            .{ .label = if (state.recovery_sign_in)
                "I saved my codes · Sign in"
            else
                "I saved my codes" },
        );
        return;
    }
    if (state.totp_available == null) {
        try status(state, w);
    } else if (!state.totp_available.?) {
        try html.render(w, "<p>The console encryption key has not been provisioned. " ++
            "Ask your administrator to configure two-factor authentication.</p>", .{});
    } else if (state.totp_enabled) {
        try html.render(w, "<p>Two-factor authentication is enabled. Sign in with your " ++
            "password and an authenticator code or an unused recovery code.</p>", .{});
        try manage(state, w);
    } else {
        try enrollment(state, w);
    }
    try html.render(w, "<button class=\"btn btn-ghost\" data-action=\"account\">" ++
        "Back to account</button></section></main>", .{});
}

/// Both changes need the password and an authenticator code or unused recovery code.
fn manage(state: *const State, w: *Writer) Writer.Error!void {
    const forms = [_]struct { id: []const u8, title: []const u8, note: []const u8 }{
        .{
            .id = "totp-recovery",
            .title = "Replace recovery codes",
            .note = "New codes replace every earlier recovery code.",
        },
        .{
            .id = "totp-disable",
            .title = "Turn off two-factor",
            .note = "This removes the authenticator and recovery codes and ends your " ++
                "sessions. A recovery code also works when the authenticator is unavailable.",
        },
    };
    for (forms) |form| {
        try html.render(w, "<form id=\"{{ id }}\"><h2>{{ title }}</h2><p>{{ note }}</p>", .{
            .id = form.id,
            .title = form.title,
            .note = form.note,
        });
        var password: [32]u8 = undefined;
        var code: [32]u8 = undefined;
        try render.field(w, std.fmt.bufPrint(&password, "{s}-password", .{form.id}) catch
            unreachable, "Current password", "password", "", "current-password");
        try render.field(w, std.fmt.bufPrint(&code, "{s}-code", .{form.id}) catch
            unreachable, "Authenticator or recovery code", "text", "", "one-time-code");
        try html.render(w, "<button class=\"btn btn-outline\" type=\"submit\"", .{});
        if (state.busy) try w.writeAll(" disabled");
        try html.render(w, ">{{ title }}</button></form>", .{ .title = form.title });
    }
}

fn status(state: *const State, w: *Writer) Writer.Error!void {
    if (state.busy) return w.writeAll(
        "<p role=\"status\">Checking two-factor configuration…</p>",
    );
    try w.writeAll("<p>Two-factor configuration could not be loaded.</p>" ++
        "<button class=\"btn\" data-action=\"security\">Retry configuration</button>");
}

fn enrollment(state: *const State, w: *Writer) Writer.Error!void {
    const pending = state.totp_secret.len != 0;
    if (pending) {
        var qr = @import("qr.zig").encode(state.totp_uri.slice()) catch unreachable;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&qr));
        try qr.svg(w);
        try html.render(w, "<p>Add this key to your authenticator: Sibuna, six digits, " ++
            "30 seconds, SHA-1.</p><p><code>", .{});
        try render.escape(w, state.totp_secret.slice());
        try html.render(w, "</code></p><p>Enrollment expires after ten minutes.</p>", .{});
    } else try html.render(w, "<p>Use an authenticator app to protect your account. " ++
        "Confirm your password to begin.</p>", .{});
    try html.render(w, "<form id=\"{{ v0 }}\">", .{
        .v0 = if (pending) "totp-confirm" else "totp-enroll",
    });
    try render.field(w, "password", "Current password", "password", "", "current-password");
    if (pending) try render.field(w, "code", "Authenticator code", "text", "", "one-time-code");
    try html.render(w, "<button class=\"btn btn-primary\" type=\"submit\"", .{});
    if (state.busy) try w.writeAll(" disabled");
    try html.render(w, ">{{ v0 }}</button></form>", .{
        .v0 = if (pending) "Enable two-factor authentication" else "Set up authenticator",
    });
}

test "an enabled factor offers replacement codes and turning off with distinct fields" {
    const t = std.testing;
    var state: State = .{ .phase = .security, .totp_available = true, .totp_enabled = true };
    var buffer: [8192]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try page(&state, &writer);
    const output = writer.buffered();
    for ([_][]const u8{
        "id=\"totp-recovery\"",            "id=\"totp-disable\"",
        "name=\"totp-recovery-password\"", "name=\"totp-recovery-code\"",
        "name=\"totp-disable-password\"",  "name=\"totp-disable-code\"",
    }) |needle| try t.expect(std.mem.indexOf(u8, output, needle) != null);
    const code: [32]u8 = @splat('a');
    state.recovery_codes[0] = try @import("console_protocol").Bytes(32).init(&code);
    state.recovery_count = 1;
    state.recovery_sign_in = false;
    writer = .fixed(&buffer);
    try page(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "I saved my codes</button>") != null);
}

test "unconfirmed two-factor status never claims that the encryption key is absent" {
    const t = std.testing;
    var state: State = .{ .phase = .security, .busy = true };
    var buffer: [8192]u8 = undefined;
    for ([_]?bool{ null, null, false, true }, 0..) |available, index| {
        state.totp_available = available;
        state.busy = index == 0;
        var writer: Writer = .fixed(&buffer);
        try page(&state, &writer);
        const output = writer.buffered();
        try t.expectEqual(index == 0, std.mem.indexOf(u8, output, "Checking two-factor") != null);
        try t.expectEqual(index == 1, std.mem.indexOf(u8, output, "Retry configuration") != null);
        const missing_key = std.mem.indexOf(u8, output, "has not been provisioned") != null;
        try t.expectEqual(index == 2, missing_key);
        try t.expectEqual(index == 3, std.mem.indexOf(u8, output, "Set up authenticator") != null);
    }
}
