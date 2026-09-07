const std = @import("std");
const State = @import("state.zig").State;
const render = @import("render.zig");
const Writer = std.Io.Writer;

pub fn page(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<main class=\"sb-auth\"><section class=\"sb-auth-card\">" ++
        "<h1>Two-factor authentication</h1>");
    try render.message(state, w);
    if (state.recovery_count != 0) {
        try w.writeAll("<h2>Save your recovery codes</h2><p>Each code works once. " ++
            "Store these somewhere safe before signing in again.</p><ol>");
        for (state.recovery_codes[0..state.recovery_count]) |code| {
            try w.writeAll("<li><code>");
            try render.escape(w, code.slice());
            try w.writeAll("</code></li>");
        }
        try w.writeAll("</ol><button class=\"btn btn-primary\" data-action=\"recovery-saved\">" ++
            "I saved my codes · Sign in</button></section></main>");
        return;
    }
    if (!state.totp_available) {
        try w.writeAll("<p>The console encryption key has not been provisioned. " ++
            "Ask your administrator to configure two-factor authentication.</p>");
    } else if (state.totp_enabled) {
        try w.writeAll("<p>Two-factor authentication is enabled. Sign in with your " ++
            "password and an authenticator code or an unused recovery code.</p>");
    } else {
        try enrollment(state, w);
    }
    try w.writeAll("<button class=\"btn btn-ghost\" data-action=\"account\">" ++
        "Back to account</button></section></main>");
}

fn enrollment(state: *const State, w: *Writer) Writer.Error!void {
    const pending = state.totp_secret.len != 0;
    if (pending) {
        var qr = @import("qr.zig").encode(state.totp_uri.slice()) catch unreachable;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&qr));
        try qr.svg(w);
        try w.writeAll("<p>Add this key to your authenticator: Sibuna, six digits, " ++
            "30 seconds, SHA-1.</p><p><code>");
        try render.escape(w, state.totp_secret.slice());
        try w.writeAll("</code></p><p>Enrollment expires after ten minutes.</p>");
    } else try w.writeAll("<p>Use an authenticator app to protect your account. " ++
        "Confirm your password to begin.</p>");
    try w.print("<form id=\"{s}\">", .{if (pending) "totp-confirm" else "totp-enroll"});
    try render.field(w, "password", "Current password", "password", "", "current-password");
    if (pending) try render.field(w, "code", "Authenticator code", "text", "", "one-time-code");
    try w.writeAll("<button class=\"btn btn-primary\" type=\"submit\"");
    if (state.busy) try w.writeAll(" disabled");
    try w.print(">{s}</button></form>", .{
        if (pending) "Enable two-factor authentication" else "Set up authenticator",
    });
}
