//! Static UI fixtures are presentation data, never native verification witnesses.
const p = @import("console_protocol");
const State = @import("state.zig").State;

pub fn configure(state: *State, reviewing: bool, stale: bool) void {
    const current = candidate("11111111111111111111111111111111", 4, .selected, .audit);
    const prepared = candidate("22222222222222222222222222222222", 5, .verified, .enforce);
    state.phase = .crs;
    state.crs.snapshot = .{
        .available = true,
        .next_id = p.crs_management.Id.init("33333333333333333333333333333333") catch unreachable,
        .revision = 4,
        .selected_at = 172799,
        .current = current,
        .previous = null,
        .candidates = .{ prepared, current, null, null },
        .count = 2,
        .nodes = .{ .{
            .node = 1,
            .boot = current.id,
            .revision = 4,
            .applied = true,
            .observed_at = 172799,
        }, null, null, null, null, null, null, null, null },
        .node_count = 1,
        .local = .{ .selection = .{
            .mode = .audit,
            .profile = .full,
            .revision = 4,
            .release = current.artifact.?.release,
            .source_digest = current.artifact.?.source_digest,
            .operator_digest = current.artifact.?.operator_digest,
            .blocking_paranoia = 1,
            .detection_paranoia = 1,
            .inbound_threshold = 5,
            .outbound_threshold = 4,
            .compiled_peak = 21 * 1024 * 1024,
            .reserved_bytes = 114 * 1024 * 1024,
            .slots = 2,
            .request_bytes = 4 * 1024 * 1024,
            .response_bytes = 1024 * 1024,
            .work_budget = 16_000_000,
            .timeout_ms = 30_000,
        } },
        .job = prepared.id,
        .stage = .verified,
        .reason = .none,
    };
    state.crs.reviewed = if (reviewing) prepared else null;
    if (reviewing) configureReview(state, current, prepared);
    state.crs.received_at = 172799;
    state.crs.editor_loaded = true;
    state.crs.editor_revision = 4;
    state.crs.stale = stale;
    state.crs.editor.set("# Keep exclusions specific to the application's parameters.\n") catch
        unreachable;
}

fn candidate(
    id: []const u8,
    revision: u64,
    status: p.crs_management.State,
    mode: p.crs.Mode,
) p.crs_api.Candidate {
    return .{
        .id = p.crs_management.Id.init(id) catch unreachable,
        .kind = .mode,
        .state = status,
        .expected_revision = revision - 1,
        .created_at = 172798,
        .expires = 259198,
        .verified_at = 172799,
        .completed_at = if (status == .selected) 172799 else null,
        .reason = .none,
        .artifact = .{
            .revision = revision,
            .previous_revision = revision - 1,
            .release = p.Bytes(17).init("4.30.0") catch unreachable,
            .source_digest = p.Bytes(64).init(&@as([64]u8, @splat('a'))) catch unreachable,
            .operator_digest = p.Bytes(64).init(&@as([64]u8, @splat('b'))) catch unreachable,
            .conditions = 701,
            .compiled_peak = 21 * 1024 * 1024,
            .settings = .{ .mode = mode, .slots = 2 },
        },
    };
}

fn configureReview(
    state: *State,
    current: p.crs_api.Candidate,
    prepared: p.crs_api.Candidate,
) void {
    state.crs.review_job = prepared.id;
    state.crs.review_result = .{
        .id = prepared.id,
        .kind = .review,
        .state = .complete,
        .expires = 172859,
        .source = prepared.id,
        .expected_revision = 4,
        .artifact = prepared.artifact,
        .baseline = current.artifact,
        .comparison = .{
            .before = .{ .rules = 628, .target_exclusions = 1, .runtime_exclusions = 1 },
            .after = .{ .rules = 628, .target_exclusions = 1, .runtime_exclusions = 1 },
            .unchanged = 628,
        },
    };
    const api = p.crs_tasks.review.exclusions;
    state.crs.exclusion_page = .{
        .id = prepared.id,
        .expected_revision = 4,
        .expires = 172859,
        .page = .{ .side = .after, .total = 2, .offset = 0, .count = 2, .next = null },
    };
    state.crs.exclusion_page.?.page.rows[0] = .{
        .rule_id = 942100,
        .phase = 2,
        .chain_link = 0,
        .scope = .static_target,
        .selector = .rule_id,
        .first = 942100,
        .last = 942100,
        .collection = p.Bytes(32).init("args") catch unreachable,
        .selection = .exact,
        .key = api.Text.init("application_field"),
    };
    state.crs.exclusion_page.?.page.rows[1] = .{
        .rule_id = 900130,
        .phase = 1,
        .chain_link = 0,
        .scope = .conditional_rule,
        .selector = .tag,
        .tag = api.Text.init("attack-sqli"),
    };
}
