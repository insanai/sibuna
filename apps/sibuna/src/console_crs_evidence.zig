//! Owner-thread serialization. The caller appends its batch receipt guard to
//! this SELECT, making retries atomic and idempotent with the forensic row.
const std = @import("std");
const Crs = @import("core").security_evidence.Crs;
const Detail = @import("core").security_evidence.detail.Detail;

pub fn append(writer: *std.Io.Writer, id: u64, evidence: Crs, detail: ?Detail) !void {
    try evidence.validate();
    if (detail) |*value| {
        try value.validate();
        if (value.rule_id != evidence.rule_id or value.phase != evidence.phase)
            return error.InvalidEvidence;
    }
    const digest = std.fmt.bytesToHex(&evidence.source_digest, .lower);
    try writer.print("INSERT INTO console_crs_evidence(" ++
        "incident_id,rule_id,phase,severity,revision,source_digest,enforcing,denied," ++
        "would_deny,coverage,selected_status,blocking_paranoia,detection_paranoia,detail) " ++
        "SELECT {d},{d},{d},{d},'{d}','{s}',{d},{d},{d},{d},{d},{d},{d},", .{
        id,
        evidence.rule_id,
        evidence.phase,
        evidence.severity,
        evidence.revision,
        &digest,
        @intFromBool(evidence.enforcing),
        @intFromBool(evidence.denied),
        @intFromBool(evidence.would_deny),
        @backingInt(evidence.coverage),
        evidence.selected_status,
        evidence.blocking_paranoia,
        evidence.detection_paranoia,
    });
    if (detail) |value| {
        var bytes: [4096]u8 = undefined;
        var output: std.Io.Writer = .fixed(&bytes);
        try std.json.Stringify.value(value, .{}, &output);
        try writer.print("CAST(X'{x}' AS TEXT)", .{output.buffered()});
    } else try writer.writeAll("NULL");
}
