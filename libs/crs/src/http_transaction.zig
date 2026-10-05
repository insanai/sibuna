//! A transport-independent phase coordinator. One borrowed slot and generation
//! remain pinned until the caller releases its lease after final evidence handling.
const std = @import("std");
const slots = @import("transaction_slot.zig");
const executor = @import("executor.zig");
const http = @import("http_acquisition.zig");
const entities = @import("entity_acquisition.zig");
const config = @import("config.zig");
const model = @import("model.zig");
const decimal = @import("decimal_format.zig");
pub const Error = slots.Error || executor.Error || http.Error || entities.Error ||
    config.Error || error{
    InvalidHttpPhase,
    ResponseEntityLimit,
    DisabledTransaction,
};
pub const End = enum {
    inspected,
    headers_profile,
    local_response,
    origin_unavailable,
    handshake_only,
    streaming_excluded,
};
pub const Transaction = struct {
    slot: *slots.Slot,
    execution: executor.Executor,
    profile: config.Profile,
    phase: model.Phase = .request_headers,
    end: ?End = null,
    /// Complete decoded entity, retained separately from replay until lease release.
    request_entity: ?[]const u8 = null,

    /// Startup must validate activation separately. This method takes an already
    /// leased, inactive slot; no allocation or network access occurs in any phase.
    pub fn begin(
        slot: *slots.Slot,
        profile: config.Profile,
        enforce: bool,
        input: http.Request,
    ) Error!Transaction {
        return beginConfigured(slot, .{
            .activation = .{ .profile = profile, .mode = if (enforce) .enforce else .audit },
        }, input);
    }

    pub fn beginConfigured(
        slot: *slots.Slot,
        options: config.Execution,
        input: http.Request,
    ) Error!Transaction {
        try options.activation.validate(.request_response, .executable);
        try options.thresholds.validate();
        if (options.activation.mode == .off) return error.DisabledTransaction;
        const execution = try slot.begin(
            .{ .entries = &.{} },
            options.activation.mode == .enforce,
        );
        var self: Transaction = .{
            .slot = slot,
            .execution = execution,
            .profile = options.activation.profile,
        };
        errdefer self.poison();
        try self.configure(options);
        try http.request(input, &slot.input, slot.formScratch(), &slot.budget);
        try self.acquire();
        _ = try self.execution.run(.request_headers);
        return self;
    }

    fn configure(self: *Transaction, options: config.Execution) Error!void {
        const values = .{
            .{ "blocking_paranoia_level", options.activation.blocking_paranoia },
            .{ "detection_paranoia_level", options.activation.detection_paranoia },
            .{ "inbound_anomaly_score_threshold", options.thresholds.inbound },
            .{ "outbound_anomaly_score_threshold", options.thresholds.outbound },
        };
        inline for (values) |entry| {
            var bytes: [decimal.capacity(u16)]u8 = undefined;
            const value = try decimal.write(u16, entry[1], &bytes, &self.slot.budget);
            try self.slot.store.put(entry[0], value, &self.slot.budget);
        }
    }

    pub fn requestBody(self: *Transaction, entity: []const u8) Error!executor.Result {
        errdefer self.poison();
        try self.checkPhase(.request_headers);
        if (self.profile != .full) return error.InvalidHttpPhase;
        const view = try self.slot.input.view();
        const content_type = try view.lookupOptional(.{
            .collection = .request_headers,
            .key = "Content-Type",
        }, &self.slot.budget);
        const descriptor = try entities.Descriptor.parse(
            content_type,
            self.slot.state.control.processor,
            &self.slot.budget,
        );
        try entities.request(self.slot, entity, descriptor);
        self.request_entity = entity;
        try self.acquire();
        self.phase = .request_body;
        return self.execution.run(self.phase);
    }

    pub fn responseHeaders(self: *Transaction, input: http.Response) Error!executor.Result {
        errdefer self.poison();
        try self.checkPhase(.request_body);
        try http.response(input, &self.slot.input, &self.slot.budget);
        try self.acquire();
        self.phase = .response_headers;
        return self.execution.run(self.phase);
    }

    pub fn responseBody(self: *Transaction, entity: []const u8) Error!executor.Result {
        errdefer self.poison();
        try self.checkPhase(.response_headers);
        if (entity.len > self.slot.limits.response) return error.ResponseEntityLimit;
        // An empty selected response is still a complete entity. Borrow no phantom
        // occurrence, matching the request adapter's collection count convention.
        if (entity.len != 0) try self.slot.input.borrow(.{
            .collection = .response_body,
            .value = entity,
        }, &self.slot.budget);
        try self.slot.input.complete(&.{.response_body});
        try self.acquire();
        self.phase = .response_body;
        return self.execution.run(self.phase);
    }

    /// Explicit endings report omitted coverage instead of supplying empty body
    /// collections. Local/origin-failed paths may end after either request phase.
    pub fn finish(self: *Transaction, end: End) Error!void {
        std.debug.assert(self.slot.active);
        errdefer self.poison();
        if (self.end != null) return error.InvalidHttpPhase;
        const allowed = switch (end) {
            .inspected => self.phase == .response_body,
            .headers_profile => self.profile == .headers and self.phase == .request_headers,
            .local_response, .origin_unavailable => self.phase == .request_headers or
                self.phase == .request_body or self.slot.state.denied,
            .handshake_only, .streaming_excluded => self.phase == .response_headers,
        };
        if (!allowed) return error.InvalidHttpPhase;
        _ = try self.execution.run(.logging);
        self.phase = .logging;
        self.end = end;
    }

    fn acquire(self: *Transaction) Error!void {
        try self.slot.acquire(try self.slot.input.view());
    }

    /// Transport adapters check ordering before acquiring or decoding a body.
    pub fn checkPhase(self: *Transaction, phase: model.Phase) Error!void {
        std.debug.assert(self.slot.active);
        if (self.end != null or self.phase != phase)
            return error.InvalidHttpPhase;
        if (self.slot.state.failed) return error.TransactionFailed;
        if (self.slot.state.denied) return error.DisruptedTransaction;
    }

    /// Transport or decoding failure invalidates every owner, never a partial view.
    pub fn poison(self: *Transaction) void {
        std.debug.assert(self.slot.active);
        self.slot.input.poison();
        self.slot.context.poison();
        self.slot.state.poison();
    }
};

test {
    _ = @import("http_transaction_test.zig");
}
