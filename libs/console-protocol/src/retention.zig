//! Internal maintenance commands contain only owned identity and fencing values.
const std = @import("std");
pub const incident_days = 30;
pub const audit_days = 365;
pub const batch_rows = 16;
pub const lease_seconds = 30;
pub const Holder = struct {
    node: u32,
    boot: [16]u8,

    pub fn validate(self: Holder) error{InvalidLease}!void {
        if (std.mem.allEqual(u8, &self.boot, 0)) return error.InvalidLease;
    }
};
pub const Lease = struct {
    holder: Holder,
    fence: u64,
    expires: u64,

    pub fn validate(self: Lease) error{InvalidLease}!void {
        try self.holder.validate();
        if (self.fence == 0 or self.fence > std.math.maxInt(i64) or
            self.expires > std.math.maxInt(i64)) return error.InvalidLease;
    }
};
pub const Kind = enum {
    incidents,
    audit,
    sessions,
    kiosk_grants,
    stages,
    import_stages,
    notification_history,
};
pub const Prune = struct { lease: Lease, kind: Kind };
