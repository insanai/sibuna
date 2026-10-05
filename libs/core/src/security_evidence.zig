//! Scalar evidence shared by native producers and the browser. No expanded rule
//! message, tag, selector value or body belongs here: each can contain secrets.
const std = @import("std");
pub const detail = @import("crs_detail.zig");
test {
    _ = detail;
}
pub const Coverage = enum(u8) {
    incomplete,
    inspected,
    headers_profile,
    local_response,
    origin_unavailable,
    handshake_only,
    streaming_excluded,
};
pub const Crs = struct {
    rule_id: u32,
    phase: u8,
    severity: u8,
    revision: u64,
    source_digest: [32]u8,
    enforcing: bool,
    denied: bool,
    would_deny: bool,
    coverage: Coverage,
    selected_status: u16,
    blocking_paranoia: u8,
    detection_paranoia: u8,

    pub fn validate(self: Crs) error{InvalidEvidence}!void {
        if (self.revision == 0 or self.phase < 1 or self.phase > 5 or self.severity > 7 or
            self.blocking_paranoia < 1 or self.blocking_paranoia > 4 or
            self.detection_paranoia < self.blocking_paranoia or self.detection_paranoia > 4)
            return error.InvalidEvidence;
        if (self.selected_status != 0 and
            (self.selected_status < 100 or self.selected_status > 599))
            return error.InvalidEvidence;
        if (self.denied and (!self.enforcing or self.selected_status < 400))
            return error.InvalidEvidence;
    }

    pub fn jsonStringify(self: Crs, json: *std.json.Stringify) !void {
        const digest = std.fmt.bytesToHex(&self.source_digest, .lower);
        var revision: [20]u8 = undefined;
        const id = std.fmt.bufPrint(&revision, "{d}", .{self.revision}) catch unreachable;
        try json.write(.{
            .rule_id = self.rule_id,
            .phase = self.phase,
            .severity = self.severity,
            .revision = id,
            .source_digest = &digest,
            .enforcing = self.enforcing,
            .denied = self.denied,
            .would_deny = self.would_deny,
            .coverage = self.coverage,
            .selected_status = self.selected_status,
            .blocking_paranoia = self.blocking_paranoia,
            .detection_paranoia = self.detection_paranoia,
        });
    }
};

pub const Wire = struct {
    rule_id: u32,
    phase: u8,
    severity: u8,
    revision: []const u8,
    source_digest: []const u8,
    enforcing: bool,
    denied: bool,
    would_deny: bool,
    coverage: Coverage,
    selected_status: u16,
    blocking_paranoia: u8,
    detection_paranoia: u8,

    pub fn decode(self: Wire) error{InvalidEvidence}!Crs {
        if (self.source_digest.len != 64 or self.revision.len == 0 or self.revision.len > 20)
            return error.InvalidEvidence;
        for (self.revision) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidEvidence;
        var digest: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&digest, self.source_digest) catch return error.InvalidEvidence;
        const result: Crs = .{
            .rule_id = self.rule_id,
            .phase = self.phase,
            .severity = self.severity,
            .revision = std.fmt.parseInt(u64, self.revision, 10) catch
                return error.InvalidEvidence,
            .source_digest = digest,
            .enforcing = self.enforcing,
            .denied = self.denied,
            .would_deny = self.would_deny,
            .coverage = self.coverage,
            .selected_status = self.selected_status,
            .blocking_paranoia = self.blocking_paranoia,
            .detection_paranoia = self.detection_paranoia,
        };
        try result.validate();
        return result;
    }
};

test "CRS evidence round trips full-width revisions and rejects dishonest decisions" {
    const t = std.testing;
    const evidence: Crs = .{
        .rule_id = 942100,
        .phase = 2,
        .severity = 2,
        .revision = std.math.maxInt(u64),
        .source_digest = @splat(0xab),
        .enforcing = false,
        .denied = false,
        .would_deny = true,
        .coverage = .incomplete,
        .selected_status = 403,
        .blocking_paranoia = 1,
        .detection_paranoia = 4,
    };
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, evidence, .{});
    defer t.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(Wire, t.allocator, bytes, .{});
    defer parsed.deinit();
    try t.expectEqualDeep(evidence, try parsed.value.decode());
    var invalid = evidence;
    invalid.denied = true;
    try t.expectError(error.InvalidEvidence, invalid.validate());
    var bad_wire = parsed.value;
    bad_wire.revision = "18446744073709551616";
    try t.expectError(error.InvalidEvidence, bad_wire.decode());
}
