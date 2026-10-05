//! Translate native verified metadata into bounded, browser-safe management views.
const std = @import("std");
const crs = @import("crs");
const p = @import("console_protocol");
const m = p.crs_management;
pub fn candidate(job: m.Job) !p.crs_api.Candidate {
    const manifest = if (job.manifest.len == 0) null else blk: {
        break :blk try crs.artifact_manifest.decode(job.manifest.slice());
    };
    return .{
        .id = job.id,
        .kind = job.kind,
        .state = job.state,
        .expected_revision = job.expected_revision,
        .created_at = job.created_at,
        .expires = job.expires,
        .verified_at = job.verified_at,
        .completed_at = job.completed_at,
        .reason = job.reason,
        .artifact = if (manifest) |value| try artifact(value) else null,
    };
}

pub fn settings(manifest: crs.artifact_manifest.Manifest) m.Settings {
    return .{
        .mode = switch (manifest.activation.mode) {
            .off => .off,
            .audit => .audit,
            .enforce => .enforce,
        },
        .profile = if (manifest.activation.profile == .full) .full else .headers,
        .blocking_paranoia = manifest.activation.blocking_paranoia,
        .detection_paranoia = manifest.activation.detection_paranoia,
        .inbound_threshold = manifest.thresholds.inbound,
        .outbound_threshold = manifest.thresholds.outbound,
        .request_bytes = @intCast(manifest.limits.request),
        .response_bytes = @intCast(manifest.limits.response),
        .work_budget = manifest.limits.work,
        .slots = manifest.slots,
        .reservation = manifest.reservation,
    };
}

fn artifact(manifest: crs.artifact_manifest.Manifest) !p.crs_api.Artifact {
    var release: [17]u8 = undefined;
    const source = std.fmt.bytesToHex(manifest.archive_digest, .lower);
    const operator = std.fmt.bytesToHex(manifest.operator_digest, .lower);
    return .{
        .revision = manifest.revision,
        .previous_revision = manifest.previous_revision,
        .release = try p.Bytes(17).init(try manifest.version.write(&release)),
        .source_digest = try p.Bytes(64).init(&source),
        .operator_digest = try p.Bytes(64).init(&operator),
        .conditions = manifest.conditions,
        .compiled_peak = manifest.compiled_peak,
        .settings = settings(manifest),
    };
}
