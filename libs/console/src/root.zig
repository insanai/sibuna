//! Application contracts. The daemon supplies storage and control execution.
pub const protocol = @import("console_protocol");
pub const Budget = @import("budget.zig").Budget;
pub const ConsoleConfig = @import("config.zig").ConsoleConfig;
pub const Mailbox = @import("mailbox.zig").Mailbox;

test {
    _ = @import("budget.zig");
    _ = @import("config.zig");
    _ = @import("ingress.zig");
    _ = @import("bearer.zig");
    _ = @import("mailbox.zig");
    _ = @import("topic_ring.zig");
    _ = @import("topic_store.zig");
    _ = @import("subscription_hub_test.zig");
    _ = @import("subscription_queue.zig");
}

pub const geoip = @import("geoip");
pub const GeoRegistry = @import("geoip_generation.zig").Registry;
pub const rankings_archive = @import("rankings_archive.zig");
pub const minute_archive = @import("minute_archive.zig");
pub const schema = @import("schema.zig");
pub const Password = @import("password.zig").Password;
test {
    _ = @import("password.zig");
    _ = @import("totp.zig");
    _ = @import("auth_secrets.zig");
    _ = @import("stats.zig");
    _ = @import("incident_geo.zig");
    _ = @import("timeline_test.zig");
    _ = @import("minute_archive.zig");
    _ = @import("minute_journal_test.zig");
    _ = @import("geoip_maintenance.zig");
    _ = @import("retention_job.zig");
    _ = @import("space_saving.zig");
    _ = @import("rankings_archive.zig");
    _ = @import("rankings_journal_test.zig");
    _ = @import("geoip_generation.zig");
    _ = @import("geoip_embedded.zig");
    _ = @import("cluster_probe.zig");
    _ = @import("peer_auth.zig");
    _ = @import("peer_config.zig");
    _ = @import("peer_store_test.zig");
    _ = @import("dashboard_stats_test.zig");
    _ = @import("notify_target.zig");
    _ = @import("notify_syslog.zig");
    _ = @import("notify_events.zig");
    _ = @import("geoip_cidr.zig");
}

pub const RetentionJob = @import("retention_job.zig").Job;
pub const App = @import("app.zig").App;
pub const Kernel = @import("serve").Kernel;
