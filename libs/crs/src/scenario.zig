//! Private, off-path phased evaluation. No publisher, telemetry producer, origin,
//! storage or daemon is reachable. Reports are copied before releasing the slot.
const std = @import("std");
const contract = @import("crs-test-protocol");
const rules = @import("rule_program.zig");
const slots = @import("transaction_slot.zig");
const transactions = @import("http_transaction.zig");
const config = @import("config.zig");
const coding = @import("compression").content_coding;
pub const Error = transactions.Error || coding.Error || @import("http_policy.zig").Error || error{
    InvalidSample,
    InvalidStreamingPolicy,
};
pub const Input = struct {
    allocator: std.mem.Allocator,
    program: *const rules.Program,
    execution: config.Execution,
    limits: slots.Limits = .{},
    sample: contract.Sample,
};

pub fn evaluate(input: Input, output: *contract.Report) Error!void {
    try input.sample.validate();
    try input.execution.activation.validate(.request_response, .executable);
    try input.execution.thresholds.validate();
    try @import("http_policy.zig").validate(input.program, input.execution.activation);
    if (input.limits.work > 1_000_000_000 or input.limits.reservation > 128 * 1024 * 1024)
        return error.InvalidSlotLimits;
    output.* = .{
        .mode = switch (input.execution.activation.mode) {
            .off => .off,
            .audit => .audit,
            .enforce => .enforce,
        },
        .profile = if (input.execution.activation.profile == .full) .full else .headers,
    };
    if (input.execution.activation.mode == .off) {
        output.coverage = .disabled;
        return;
    }
    _ = std.Io.net.IpAddress.parse(input.sample.request.client, 0) catch
        return error.InvalidSample;
    var erasing: @import("private_allocator.zig").Erasing = .{ .parent = input.allocator };
    var memory: @import("compiled_allocator.zig").Budget = .{
        .parent = erasing.allocator(),
        .limit = input.limits.reservation,
    };
    var slot: slots.Slot = undefined;
    try slot.init(memory.allocator(), input.program, input.limits);
    defer slot.deinit();
    defer if (slot.active) slot.finish();
    run(&slot, input, output) catch |err| {
        const name = @errorName(err);
        output.failure = @import("text").buffers.Bytes(64).init(
            name[0..@min(name.len, 64)],
        ) catch unreachable;
        output.coverage = .incomplete;
    };
    if (slot.active) {
        output.work_used = @intCast(slot.limits.work - slot.budget.remaining);
        observe(&slot, output);
    }
}

fn run(slot: *slots.Slot, input: Input, output: *contract.Report) Error!void {
    const sample = input.sample;
    const request = sample.request;
    var line: [8250]u8 = undefined;
    output.attempted_phase = 1;
    var transaction = try transactions.Transaction.beginConfigured(slot, input.execution, .{
        .method = request.method,
        .target = request.target,
        .protocol = request.protocol,
        .client = request.client,
        .id = "private-crs-test",
        .line = std.fmt.bufPrint(&line, "{s} {s} {s}", .{
            request.method, request.target, request.protocol,
        }) catch return error.InvalidSample,
        .headers = request.headers,
    });
    if (slot.state.denied) return finish(&transaction, .local_response, output);
    if (transaction.profile == .headers) return finish(&transaction, .headers_profile, output);
    output.attempted_phase = 2;
    const request_wire = try request.entity.bytes(slot.request_wire);
    _ = try transaction.requestBody(try decode(slot, request.headers, request_wire, true));
    if (slot.state.denied) return finish(&transaction, .local_response, output);
    const response = sample.response orelse
        return finish(&transaction, .origin_unavailable, output);
    output.attempted_phase = 3;
    _ = try transaction.responseHeaders(.{
        .status = response.status,
        .headers = response.headers,
    });
    if (slot.state.denied) return finish(&transaction, .local_response, output);
    if (response.ending == .handshake) return finish(&transaction, .handshake_only, output);
    if (response.ending == .streaming or try streaming(slot))
        return finish(&transaction, .streaming_excluded, output);
    output.attempted_phase = 4;
    const response_wire = try response.entity.bytes(slot.response_wire);
    const bodyless = std.mem.eql(u8, request.method, "HEAD") or response.status == 204 or
        response.status == 304 or response.status < 200;
    if (bodyless and response_wire.len != 0) return error.InvalidSample;
    const body = if (bodyless)
        response_wire
    else
        try decode(slot, response.headers, response_wire, false);
    _ = try transaction.responseBody(body);
    return finish(&transaction, if (slot.state.denied) .local_response else .inspected, output);
}

fn decode(
    slot: *slots.Slot,
    headers: []const @import("text").http_fields.Header,
    wire: []const u8,
    request: bool,
) Error![]const u8 {
    const maximum = if (request) slot.limits.request else slot.limits.response;
    const plan = try coding.Plan.parse(headers, &slot.budget);
    return plan.decode(wire, .{
        .output = if (request) slot.request else slot.response,
        .alternate = slot.decode_alternate[0..maximum],
        .window = slot.inflate_window,
        .wire_limit = maximum,
    }, &slot.budget);
}

fn streaming(slot: *slots.Slot) Error!bool {
    const value = (try slot.store.get("sibuna_stream_response", &slot.budget)) orelse return false;
    if (std.mem.eql(u8, value, "1")) return true;
    if (std.mem.eql(u8, value, "0")) return false;
    return error.InvalidStreamingPolicy;
}

fn finish(
    transaction: *transactions.Transaction,
    ending: transactions.End,
    output: *contract.Report,
) Error!void {
    output.attempted_phase = 5;
    try transaction.finish(ending);
    output.coverage = switch (ending) {
        .inspected => .inspected,
        .headers_profile => .headers_profile,
        .local_response => .local_response,
        .origin_unavailable => .response_not_supplied,
        .handshake_only => .handshake_only,
        .streaming_excluded => .streaming_excluded,
    };
}

fn observe(slot: *const slots.Slot, output: *contract.Report) void {
    const state = &slot.state;
    output.denied = state.denied;
    output.would_deny = state.would_deny;
    if (state.denied or state.would_deny) output.selected_status = state.status;
    for (state.events[0..state.event_used]) |event| {
        // Setup actions and intentionally unlogged matches must not displace
        // security findings. Terminal decisions stay visible even with nolog.
        if ((!event.save or event.no_audit) and !event.would_deny) {
            output.unlogged_matches += 1;
            continue;
        }
        if (event.message.len == 0 and event.tags.len == 0 and !event.would_deny) continue;
        if (output.event_count == output.events.len) {
            output.omitted_events += 1;
            continue;
        }
        output.events[output.event_count] = .{
            .rule_id = event.id,
            .phase = @backingInt(event.phase),
            .severity = event.severity,
            .would_deny = event.would_deny,
            .saved = event.save,
            .audit_suppressed = event.no_audit,
        };
        output.event_count += 1;
    }
    // Reporting cannot spend evaluation work or turn a completed decision into
    // exhaustion. Bounded immutable observation happens after all rule phases.
    if (output.failure != null or slot.store.failed) return;
    for (slot.store.entries[0..slot.store.used]) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key, "blocking_inbound_anomaly_score"))
            output.inbound_score = std.fmt.parseInt(i32, entry.value, 10) catch null;
        if (std.ascii.eqlIgnoreCase(entry.key, "blocking_outbound_anomaly_score"))
            output.outbound_score = std.fmt.parseInt(i32, entry.value, 10) catch null;
        if (std.ascii.eqlIgnoreCase(entry.key, "detection_inbound_anomaly_score"))
            output.detection_inbound_score = std.fmt.parseInt(i32, entry.value, 10) catch null;
        if (std.ascii.eqlIgnoreCase(entry.key, "detection_outbound_anomaly_score"))
            output.detection_outbound_score = std.fmt.parseInt(i32, entry.value, 10) catch null;
    }
}

test {
    _ = @import("scenario_test.zig");
}
