//! Daemon composition of transport acquisition with the pure CRS coordinator.
//! One generation lease owns the slot through wire replay and final evidence.
const std = @import("std");
const crs = @import("crs");
const net = @import("net");
const Transaction = crs.http_transaction.Transaction;
const Result = crs.executor.Result;
const Header = @import("text").http_fields.Header;
pub const Error = crs.http_transaction.Error || net.content_coding.Error ||
    net.response_fields.Error || net.proxy.ProxyError || error{InvalidStreamingPolicy};

pub fn requestBody(
    transaction: *Transaction,
    headers: []const Header,
    wire: []const u8,
) Error!Result {
    errdefer transaction.poison();
    try transaction.checkPhase(.request_headers);
    if (transaction.profile != .full) return error.InvalidHttpPhase;
    const slot = transaction.slot;
    const plan = try net.content_coding.Plan.parse(headers, &slot.budget);
    const decoded = try plan.decode(wire, .{
        .output = slot.request,
        .alternate = slot.decode_alternate[0..slot.limits.request],
        .window = slot.inflate_window,
        .wire_limit = slot.limits.request,
    }, &slot.budget);
    return transaction.requestBody(decoded);
}

pub const Response = struct {
    transaction: *Transaction,
    policy: enum { inspect, streaming_excluded },
    // Audit may replay validated wire data after a semantic inspection failure.
    // Its poisoned transaction remains incomplete; transport failures still fail.
    audit_failure: enum { refuse, continue_uninspected } = .continue_uninspected,
    coding: net.content_coding.Plan = .{},
    bodyless: bool = false,
    completion: ?crs.http_transaction.End = null,
    fallback: crs.http_transaction.End = .local_response,
    failure: ?Error = null,
    partial_release: ?PartialRelease = null,
    partial_finalized: bool = false,
    pub const PartialRelease = struct {
        context: *anyopaque,
        // Consume logging/coverage before releasing the transaction lease. No
        // response callback may borrow that slot after this function returns.
        call: *const fn (*anyopaque, *Response) void,
    };

    /// Initialize at a stable address after request-body evaluation succeeds.
    pub fn init(self: *Response, transaction: *Transaction) Error!void {
        try transaction.checkPhase(.request_body);
        self.* = .{ .transaction = transaction, .policy = .inspect };
    }

    pub fn hooks(self: *Response) net.response_inspection.Inspector {
        std.debug.assert(!self.partial_finalized);
        const slot = self.transaction.slot;
        return .{
            .context = self,
            .headers = onHeaders,
            .body = onBody,
            .head_storage = slot.response_head,
            .body_storage = slot.response_wire,
        };
    }

    fn onHeaders(
        context: *anyopaque,
        head: net.response_inspection.Head,
    ) net.response_inspection.Error!net.response_inspection.Decision {
        const self: *Response = @ptrCast(@alignCast(context));
        if (self.partial_finalized) return error.InspectionFailed;
        var storage: [128]Header = undefined;
        const headers = net.response_fields.parse(head.bytes, &storage) catch |err|
            return self.failedHeaders(err);
        const result = self.transaction.responseHeaders(.{
            .status = head.status,
            .headers = headers,
        }) catch |err| return self.failedHeaders(err);
        if (result == .denied) return self.denied();
        const excluded = self.streaming() catch |err| return self.failedHeaders(err);
        if (head.upgrade or excluded) {
            self.completion = if (head.upgrade) .handshake_only else .streaming_excluded;
            self.releasePartial();
            return .stream;
        }
        self.bodyless = head.framing == .none;
        if (!self.bodyless) {
            const budget = &self.transaction.slot.budget;
            self.coding = net.content_coding.Plan.parse(headers, budget) catch |err|
                return self.failedHeaders(err);
        }
        return .hold;
    }

    fn onBody(context: *anyopaque, wire: []const u8) net.response_inspection.Error!void {
        const self: *Response = @ptrCast(@alignCast(context));
        if (self.partial_finalized) return error.InspectionFailed;
        const slot = self.transaction.slot;
        self.transaction.checkPhase(.response_headers) catch |err| return self.failedBody(err);
        std.debug.assert(!self.bodyless or wire.len == 0);
        const decoded = if (self.bodyless) wire else self.coding.decode(wire, .{
            .output = slot.response,
            .alternate = slot.decode_alternate[0..slot.limits.response],
            .window = slot.inflate_window,
            .wire_limit = slot.limits.response,
        }, &slot.budget) catch |err| return self.failedBody(err);
        const result = self.transaction.responseBody(decoded) catch |err|
            return self.failedBody(err);
        if (result == .denied) return self.denied();
        self.completion = .inspected;
    }

    fn denied(self: *Response) net.response_inspection.Error {
        self.completion = .local_response;
        return error.InspectionDenied;
    }

    fn failedHeaders(
        self: *Response,
        err: Error,
    ) net.response_inspection.Error!net.response_inspection.Decision {
        self.fail(err);
        if (self.canContinue()) {
            self.releasePartial();
            return .stream;
        }
        return error.InspectionFailed;
    }

    fn failedBody(self: *Response, err: Error) net.response_inspection.Error!void {
        self.fail(err);
        if (!self.canContinue()) return error.InspectionFailed;
    }

    fn canContinue(self: *const Response) bool {
        return !self.transaction.slot.state.enforce and
            self.audit_failure == .continue_uninspected;
    }

    fn streaming(self: *Response) Error!bool {
        if (self.policy == .streaming_excluded) return true;
        const slot = self.transaction.slot;
        const value = (try slot.store.get("sibuna_stream_response", &slot.budget)) orelse
            return false;
        if (std.mem.eql(u8, value, "1")) return true;
        if (std.mem.eql(u8, value, "0")) return false;
        return error.InvalidStreamingPolicy;
    }

    pub fn fail(self: *Response, err: Error) void {
        if (self.partial_finalized) return;
        if (self.failure == null) self.failure = err;
        self.transaction.poison();
    }

    fn releasePartial(self: *Response) void {
        if (self.partial_release) |owner| {
            owner.call(owner.context, self);
            self.partial_finalized = true;
        }
    }

    /// The owner supplies the actual ending if the origin produced no head.
    /// A failure exposes its bounded cause and cannot fabricate phase completion.
    pub fn finish(self: *Response, fallback: crs.http_transaction.End) Error!void {
        if (self.partial_finalized) return;
        if (self.failure) |err| return err;
        try self.transaction.finish(self.completion orelse fallback);
    }
};

test {
    _ = @import("crs_entity_test.zig");
}
