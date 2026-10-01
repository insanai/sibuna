//! Renders denial, ban, limit, overload and challenge pages from the engine snapshot's
//! templates. The slot is pinned only while the template is copied to the stack, so a slow
//! client never delays publication of a rebuilt engine. Non-HTML clients keep the plain
//! text bodies this daemon always sent.
const std = @import("std");
const net = @import("net");
const policy = @import("policy");
const page_template = policy.page_template;
const server = @import("server.zig");
const challenge_page = @import("challenge_page.zig");

const security_policy = "Content-Security-Policy: default-src 'none'; base-uri 'none'; " ++
    "form-action 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'; img-src 'self'\r\n";

pub const Extra = struct {
    retry_after: u32 = 0,
    reason: []const u8 = "",
    headers: []const u8 = "",
    /// The challenged request's requirement ticket, carried in the interstitial's markup.
    ticket: []const u8 = "",
};

fn copy(st: *server.AppState, kind: page_template.Kind, out: *page_template.Template) void {
    const slot = st.acquireEngine();
    defer server.AppState.releaseEngine(slot);
    out.* = slot.engine.pages.get(kind).*;
}

fn requestId(ctx: *server.RequestContext, out: *[16]u8) []const u8 {
    var raw: [8]u8 = undefined;
    ctx.c.io.random(&raw);
    out.* = std.fmt.bytesToHex(raw, .lower);
    return out;
}

/// HTML for browsers, the historical text body otherwise.
pub fn respond(
    ctx: *server.RequestContext,
    kind: page_template.Kind,
    status: net.response.Status,
    text: []const u8,
    extra: Extra,
) !void {
    if (!ctx.req.acceptsHtml()) {
        return net.response.write(ctx.writer(), status, "text/plain; charset=utf-8", text, .{
            .keep_alive = ctx.keep_alive,
            .headers = extra.headers,
        });
    }
    var template: page_template.Template = undefined;
    copy(ctx.state(), kind, &template);
    var id: [16]u8 = undefined;
    var block: [challenge_page.block_capacity]u8 = undefined;
    const values: page_template.Values = .{
        .status = @intFromEnum(status),
        .reason = if (extra.reason.len != 0) extra.reason else text,
        .retry_after = extra.retry_after,
        .request_id = requestId(ctx, &id),
        .node = ctx.state().config.cluster_node,
        .challenge = if (kind == .challenge) challenge_page.block(extra.ticket, &block) else "",
    };
    const csp = if (kind == .challenge)
        @import("challenge_page.zig").security_policy
    else
        security_policy;
    const length = page_template.measure(&template, values);
    const w = ctx.writer();
    try w.print(
        "HTTP/1.1 {d} {s}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\n" ++
            "Connection: {s}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n" ++
            "{s}{s}\r\n",
        .{
            @intFromEnum(status),
            status.reason(),
            length,
            if (ctx.keep_alive) "keep-alive" else "close",
            csp,
            extra.headers,
        },
    );
    try page_template.write(&template, w, values);
    try w.flush();
}

/// Pre-parse rejections on the accept loop have no request to negotiate with; a customized
/// overload page is served as HTML, the built-in reply stays plain text.
pub fn rejectRaw(st: *server.AppState, writer: *std.Io.Writer, text: []const u8) void {
    var template: page_template.Template = undefined;
    copy(st, .overloaded, &template);
    if (!template.customized) {
        net.response.writeText(writer, .service_unavailable, text, false) catch {};
        return;
    }
    const values: page_template.Values = .{
        .status = 503,
        .reason = text,
        .retry_after = 5,
        .node = st.config.cluster_node,
    };
    const length = page_template.measure(&template, values);
    writer.print(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\nCache-Control: no-store\r\n" ++
            "X-Content-Type-Options: nosniff\r\nRetry-After: 5\r\n" ++ security_policy ++ "\r\n",
        .{length},
    ) catch return;
    page_template.write(&template, writer, values) catch return;
    writer.flush() catch {};
}
