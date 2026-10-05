//! Consume saved findings before releasing the generation and slot. Hooks must
//! copy their input; no expanded messages, tags or matched values escape here.
const crs = @import("crs");
const core = @import("core");
const server = @import("server.zig");

pub fn record(
    context: *server.RequestContext,
    transaction: *const crs.http_transaction.Transaction,
    generation: *const crs.generation.Generation,
) void {
    const state = context.state();
    const hook = state.hooks.record_incident orelse return;
    const actions = &transaction.slot.state;
    var request: [core.incident_heads.request_bytes]u8 = undefined;
    var head: ?core.incident_heads.Head = null;
    const response = context.crs_evidence;
    const incomplete = actions.failed or transaction.end == null;
    const coverage: core.security_evidence.Coverage = if (incomplete)
        .incomplete
    else switch (transaction.end.?) {
        .inspected => .inspected,
        .headers_profile => .headers_profile,
        .local_response => .local_response,
        .origin_unavailable => .origin_unavailable,
        .handshake_only => .handshake_only,
        .streaming_excluded => .streaming_excluded,
    };
    for (actions.events[0..actions.event_used]) |event| {
        if (!event.save or event.no_audit) continue;
        // Configuration actions can publish an empty bookkeeping event. They
        // are not security findings and must not overwhelm the incident queue.
        if (event.message.len == 0 and event.tags.len == 0 and !event.would_deny) continue;
        // Avoid redacting a head when evaluation produced no retained finding.
        if (head == null) head = server.requestHead(context, &request);
        const denial = actions.enforce and actions.denied and event.would_deny and
            event.phase != .logging;
        var detail: core.security_evidence.detail.Detail = undefined;
        if (@import("build_options").console) {
            crs.finding_detail.copy(&detail, &event, &transaction.slot.scores);
        }
        hook(state.hooks.context, .{
            .client_ip = context.client_ip,
            .user_agent = context.user_agent,
            .method = context.req.method_text,
            .path = context.req.path,
            .category = if (denial) "waf:crs" else "audit:crs",
            .payload = "",
            .now = context.now,
            .crs_detail = if (@import("build_options").console) &detail else null,
            .request_head = request[0..head.?.len],
            .request_truncated = head.?.truncated,
            .response_head = if (response) |r| r.bytes[0..r.head.len] else "",
            .response_truncated = if (response) |r| r.head.truncated else false,
            .response_state = if (response) |r| r.response_state else .unknown,
            .crs = .{
                .rule_id = event.id,
                .phase = @backingInt(event.phase),
                .severity = event.severity,
                .revision = generation.options.revision,
                .source_digest = generation.package.?.receipt.digest,
                .enforcing = actions.enforce,
                .denied = actions.denied,
                .would_deny = event.would_deny,
                .coverage = coverage,
                .selected_status = if (actions.denied or actions.would_deny) actions.status else 0,
                .blocking_paranoia = generation.options.activation.blocking_paranoia,
                .detection_paranoia = generation.options.activation.detection_paranoia,
            },
        });
    }
}
