//! Pin a generation through transport replay and final evidence consumption.
//! Wire bodies and acquired views have separate off-path reservations.
const std = @import("std");
const crs = @import("crs");
const net = @import("net");
const server = @import("server.zig");
const bridge = @import("crs_entity.zig");
const observe = @import("crs_observe.zig");

pub fn serve(
    connection: *server.Connection,
    request: *net.Request,
    head_length: usize,
    publisher: *crs.publication.Publisher,
) !bool {
    const declared = request.contentLength() orelse 0;
    var context = server.RequestContext.init(connection, request, declared);
    var captured: @import("core").incident_heads.ResponseCapture = .{
        .extra = &context.state().config.console_capture_headers,
    };
    if (@import("build_options").console and context.state().config.console_capture_heads)
        context.crs_evidence = &captured;
    if (!try server.restoreAuthorizationTarget(&context)) return false;
    const demand: crs.transaction_pool.Demand = .{
        .request_bytes = if (request.chunked or encodedBody(request)) null else declared,
    };
    var lease = publisher.lease(connection.io, demand, slot_wait) catch |err| {
        if (err == error.DisabledGeneration) {
            return buffered(&context, head_length);
        }
        observe.increment(&context.state().crs_counts.incomplete);
        return refuse(&context, .service_unavailable, "Security inspection is unavailable");
    };
    var leased = true;
    defer if (leased) lease.release(connection.io);
    connection.activity.deadline_ms.store(
        net.duplex.nowMs(connection.io) + context.state().crs_timeout_ms,
        .monotonic,
    );
    defer connection.activity.deadline_ms.store(0, .monotonic);
    var line_buffer: [server.max_head_bytes + 64]u8 = undefined;
    var nonce: [16]u8 = undefined;
    connection.io.random(&nonce);
    const id = std.fmt.bytesToHex(&nonce, .lower);
    const input = try metadata(&context, .{
        .head_length = head_length,
        .line = &line_buffer,
        .id = &id,
    });
    var transaction = lease.begin(input) catch {
        observe.increment(&context.state().crs_counts.incomplete);
        if (lease.generation().options.activation.mode == .audit) {
            return buffered(&context, head_length);
        }
        return refuse(&context, .forbidden, "Security inspection could not complete");
    };
    defer if (leased) complete(&context, &transaction, lease.generation());
    if (transaction.slot.state.denied) return denied(&context, transaction.slot.state.status);
    if (transaction.profile == .headers) {
        return buffered(&context, head_length);
    }
    var ownership: Ownership = .{
        .context = &context,
        .transaction = &transaction,
        .lease = &lease,
        .leased = &leased,
    };
    return full(&ownership, head_length);
}

/// Content-Length bounds the encoded representation, not decoded input. Only a
/// known identity representation can safely use the smaller request reservation.
fn encodedBody(request: *const net.Request) bool {
    for (request.headers[0..request.header_count]) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-encoding")) continue;
        const value = std.mem.trim(u8, header.value, " \t");
        if (!std.ascii.eqlIgnoreCase(value, "identity")) return true;
    }
    return false;
}

fn buffered(context: *server.RequestContext, head_length: usize) !bool {
    return server.serveBufferedWithEvidence(
        context.c,
        context.req,
        head_length,
        context.crs_evidence,
    );
}

/// A burst beyond the pool parks briefly for a slot release instead of failing at once.
/// The bound stays far below client and origin timeouts, so a saturated node still sheds
/// load quickly with 503 rather than queuing work it cannot finish.
const slot_wait: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(50), .clock = .awake };

const Ownership = struct {
    context: *server.RequestContext,
    transaction: *crs.http_transaction.Transaction,
    lease: *crs.publication.Lease,
    leased: *bool,

    fn releasePartial(context: *anyopaque, response: *bridge.Response) void {
        const self: *Ownership = @ptrCast(@alignCast(context));
        std.debug.assert(self.leased.*);
        finishResponse(response);
        complete(self.context, self.transaction, self.lease.generation());
        self.context.inspected_body = null;
        server.countOutcome(self.context, .admitted);
        self.context.c.activity.deadline_ms.store(0, .monotonic);
        self.lease.release(self.context.c.io);
        self.leased.* = false;
    }
};

const Metadata = struct { head_length: usize, line: []u8, id: []const u8 };

fn metadata(context: *server.RequestContext, storage: Metadata) !crs.http_acquisition.Request {
    const request = context.req;
    const raw = context.c.reader.buffered()[0..storage.head_length];
    const original_line = std.mem.sliceTo(raw, '\r');
    var tokens = std.mem.splitScalar(u8, original_line, ' ');
    _ = tokens.next();
    var target = tokens.next().?; // Validated by the HTTP parser.
    var line = original_line;
    if (context.state().config.mode == .forward_auth) {
        const trusted = context.state().config.trustsForwarded();
        if (try net.forwarded.target(request, trusted) != null) {
            target = request.getHeader("x-forwarded-uri") orelse
                request.getHeader("x-original-uri").?;
            line = try std.fmt.bufPrint(storage.line, "{s} {s} {s}", .{
                request.method_text, target, request.version,
            });
        }
    }
    return .{
        .method = request.method_text,
        .target = target,
        .protocol = request.version,
        .line = line,
        .client = context.client_ip,
        .id = storage.id,
        .headers = request.headers[0..request.header_count],
    };
}

fn full(owner: *Ownership, head_length: usize) !bool {
    const context = owner.context;
    const transaction = owner.transaction;
    const connection = context.c;
    const request = context.req;
    const slot = transaction.slot;
    if (!try server.preflight(context)) return false;
    const length = request.contentLength() orelse 0;
    if (!request.chunked and length > slot.request_wire.len)
        return refuse(context, .payload_too_large, "Request exceeds the inspection limit");
    if (!try server.expectContinue(connection, request, length)) return false;
    connection.reader.toss(head_length);
    const pin = net.retained_head.Pin.init(connection.reader, connection.reader.seek);
    defer pin.release();
    context.head_pinned = true;
    const wire = net.entity.read(.{
        .reader = connection.reader,
        .output = slot.request_wire,
        .progress = .{
            .io = connection.io,
            .activity = connection.activity,
            .mode = .minimum_rate,
        },
    }, if (request.chunked) .chunked else .{ .length = length }) catch |err| {
        transaction.poison();
        const oversized = err == error.EntityLimit;
        const status: net.Status = if (oversized) .payload_too_large else .bad_request;
        return refuse(context, status, "Request body could not be acquired");
    };
    request.body = wire;
    context.declared_body = wire.len;
    context.upload = .{ .length = wire.len };
    context.keep_alive = request.wantsKeepAlive() and !connection.last;
    const headers = request.headers[0..request.header_count];
    const result = bridge.requestBody(transaction, headers, wire) catch {
        if (slot.state.enforce)
            return refuse(context, .forbidden, "Security inspection could not complete");
        return server.dispatch(context);
    };
    if (result == .denied) return denied(context, slot.state.status);
    context.inspected_body = transaction.request_entity;
    var response: bridge.Response = undefined;
    try response.init(transaction);
    response.partial_release = .{ .context = owner, .call = Ownership.releasePartial };
    context.crs_response = &response;
    defer finishResponse(&response);
    return server.dispatch(context);
}

fn finishResponse(response: *bridge.Response) void {
    response.finish(response.fallback) catch |err| response.fail(err);
}

fn complete(
    context: *server.RequestContext,
    transaction: *crs.http_transaction.Transaction,
    generation: *const crs.generation.Generation,
) void {
    if (!transaction.slot.state.failed and transaction.end == null) {
        const headers = transaction.profile == .headers and !transaction.slot.state.denied;
        const End = crs.http_transaction.End;
        const ending: End = if (headers) .headers_profile else .local_response;
        transaction.finish(ending) catch transaction.poison();
    }
    context.state().crs_counts.finish(transaction);
    @import("crs_findings.zig").record(context, transaction, generation);
}

fn refuse(context: *server.RequestContext, status: net.Status, message: []const u8) !bool {
    const state = context.state();
    if (!context.preflight_done) server.Metrics.bump(&state.metrics.requests);
    if (status == .forbidden) server.Metrics.bump(&state.metrics.denied);
    const Outcome = @import("store").telemetry.Outcome;
    const outcome: Outcome = if (status == .forbidden) .denied else .other;
    server.recordOutcome(context, outcome, @backingInt(status));
    try net.response.writeRefusal(
        context.writer(),
        @backingInt(status),
        context.req.method == .HEAD,
        message,
    );
    return false;
}

fn denied(context: *server.RequestContext, code: u16) !bool {
    const state = context.state();
    if (!context.preflight_done) server.Metrics.bump(&state.metrics.requests);
    server.Metrics.bump(&state.metrics.denied);
    server.recordOutcome(context, .denied, code);
    try net.response.writeRefusal(
        context.writer(),
        code,
        context.req.method == .HEAD,
        "Request refused",
    );
    return false;
}
