//! Every API route declares its authentication boundary and minimum application action.
//! Account routes remain usable during required password changes and TOTP enrollment.
const std = @import("std");
const p = @import("console_protocol");
pub const Access = enum { public, account, full };
pub const Handler = enum {
    policies,
    policies_test,
    policy_edit,
    policy_read,
    setup_status,
    login,
    session,
    logout,
    password,
    stats,
    rankings,
    challenges,
    events,
    events_similar,
    events_export,
    stream,
    geoip,
    totp,
};
pub const Route = struct {
    path: []const u8,
    method: std.http.Method,
    access: Access,
    action: p.Action = .read,
    handler: Handler,
};
const table = [_]Route{
    .{
        .path = "/console/api/rankings",
        .method = .GET,
        .access = .full,
        .handler = .rankings,
    },
    .{
        .path = "/console/api/policies/read",
        .method = .POST,
        .access = .full,
        .handler = .policy_read,
    },
    .{
        .path = "/console/api/policies/edit",
        .method = .POST,
        .access = .full,
        .action = .manage_policy,
        .handler = .policy_edit,
    },
    .{
        .path = "/console/api/policies/query",
        .method = .POST,
        .access = .full,
        .handler = .policies,
    },
    .{
        .path = "/console/api/policies/test",
        .method = .POST,
        .access = .full,
        .handler = .policies_test,
    },
    .{
        .path = "/console/api/events/similar",
        .method = .POST,
        .access = .full,
        .handler = .events_similar,
    },
    .{
        .path = "/console/api/challenges",
        .method = .POST,
        .access = .full,
        .handler = .challenges,
    },
    .{
        .path = "/console/api/events/export",
        .method = .POST,
        .access = .full,
        .handler = .events_export,
    },
    .{
        .path = "/console/api/events/query",
        .method = .POST,
        .access = .full,
        .handler = .events,
    },
    .{
        .path = "/console/api/setup",
        .method = .GET,
        .access = .public,
        .handler = .setup_status,
    },
    .{
        .path = "/console/api/login",
        .method = .POST,
        .access = .public,
        .handler = .login,
    },
    .{
        .path = "/console/api/session",
        .method = .GET,
        .access = .account,
        .handler = .session,
    },
    .{
        .path = "/console/api/logout",
        .method = .POST,
        .access = .account,
        .handler = .logout,
    },
    .{
        .path = "/console/api/password",
        .method = .POST,
        .access = .account,
        .handler = .password,
    },
    .{
        .path = "/console/api/stats",
        .method = .GET,
        .access = .full,
        .handler = .stats,
    },
    .{
        .path = "/console/stream",
        .method = .GET,
        .access = .full,
        .handler = .stream,
    },
    .{
        .path = "/console/api/geoip",
        .method = .GET,
        .access = .full,
        .handler = .geoip,
    },
    .{
        .path = "/console/api/geoip",
        .method = .POST,
        .access = .full,
        .action = .manage_settings,
        .handler = .geoip,
    },
    .{
        .path = "/console/api/totp",
        .method = .GET,
        .access = .account,
        .handler = .totp,
    },
    .{
        .path = "/console/api/totp/enroll",
        .method = .POST,
        .access = .account,
        .handler = .totp,
    },
    .{
        .path = "/console/api/totp/confirm",
        .method = .POST,
        .access = .account,
        .handler = .totp,
    },
};

pub fn find(path: []const u8, method: std.http.Method) ?Route {
    for (table) |route| {
        if (route.method == method and std.mem.eql(u8, route.path, path)) return route;
    }
    return null;
}
