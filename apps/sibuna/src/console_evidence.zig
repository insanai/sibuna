//! Durable evidence metadata is part of the incident's idempotent transaction.
const std = @import("std");
const Evidence = @import("core").IncidentEvidence;

pub fn append(w: *std.Io.Writer, id: u64, evidence: Evidence) !void {
    std.debug.assert(evidence.version == 1);
    try w.print(
        "INSERT INTO console_incident_evidence(incident_id,version,selected_status," ++
            "query_bytes,body_bytes,declared_body_bytes,truncated) " ++
            "SELECT {d},1,{d},{d},{d},{d},{d}",
        .{
            id,
            evidence.selected_status,
            evidence.query_bytes,
            evidence.body_bytes,
            evidence.declared_body_bytes,
            evidence.truncated,
        },
    );
}
