//! Authenticated observation dispatch; storage access remains behind App's owned mailbox.
const App = @import("app.zig").App;
const http = @import("http.zig");
const Handler = @import("routes.zig").Handler;

pub fn handle(app: *App, context: *http.Context, handler: Handler) !void {
    return switch (handler) {
        .challenges => @import("challenge_routes.zig").handle(app, context),
        .challenge_summary => @import("challenge_routes.zig").summary(app, context),
        .challenge_records => @import("challenge_routes.zig").records(app, context),
        .challenge_difficulty => @import("challenge_routes.zig").difficulty(app, context),
        .rule_hit_history => @import("rule_hit_history_routes.zig").handle(app, context),
        .ranking_history => @import("ranking_history_routes.zig").handle(app, context),
        .rankings => @import("ranking_routes.zig").handle(app, context),
        .timeline => @import("timeline_routes.zig").handle(app, context),
        .minutes, .minute_summary => @import("minute_routes.zig").handle(
            app,
            context,
            handler == .minute_summary,
        ),
        .security_query, .security_trends => @import("security_routes.zig").query(
            app,
            context,
            handler == .security_trends,
        ),
        .stats => http.json(context, app.stats.snapshot(
            app.io,
            app.telemetry,
            app.metrics,
            app.now(),
        ), &.{}),
        else => unreachable,
    };
}
