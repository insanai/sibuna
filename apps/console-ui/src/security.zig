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
                "data-action=\"recovery-saved\">" ++
                "I saved my codes · Sign in</button></section></main>",
            .{},
        );
        return;
    }
    if (!state.totp_available) {
        try html.render(w, "<p>The console encryption key has not been provisioned. " ++
            "Ask your administrator to configure two-factor authentication.</p>", .{});
    } else if (state.totp_enabled) {
        try html.render(w, "<p>Two-factor authentication is enabled. Sign in with your " ++
            "password and an authenticator code or an unused recovery code.</p>", .{});
    } else {
        try enrollment(state, w);
    }
    try html.render(w, "<button class=\"btn btn-ghost\" data-action=\"account\">" ++
        "Back to account</button></section></main>", .{});
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
