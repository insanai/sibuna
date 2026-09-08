//! Console access administration and audit share the router's current principal.
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Handler = @import("routes.zig").Handler;

pub fn dispatch(app: *App, context: *http.Context, principal: p.Principal, kind: Handler) !void {
    switch (kind) {
        .audit_query, .audit_read, .audit_export => try @import("audit_routes.zig").handle(
            app,
            context,
            principal,
            kind,
        ),
        .users_query, .users_create, .users_change => try @import("user_routes.zig").dispatch(
            app,
            context,
            principal,
            kind,
        ),
        .tokens_query, .tokens_create, .tokens_revoke => try @import("token_routes.zig").handle(
            app,
            context,
            principal,
            kind,
        ),
        else => unreachable,
    }
}
