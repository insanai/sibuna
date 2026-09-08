//! Application contracts. The daemon supplies storage and control execution.
pub const protocol = @import("console_protocol");
pub const Budget = @import("budget.zig").Budget;
pub const ConsoleConfig = @import("config.zig").ConsoleConfig;
pub const Mailbox = @import("mailbox.zig").Mailbox;

test {
    _ = @import("budget.zig");
    _ = @import("config.zig");
    _ = @import("ingress.zig");
    _ = @import("mailbox.zig");
}

pub const geoip_gzip = @import("geoip_gzip.zig");
pub const geoip = @import("geoip.zig");
pub const rankings_archive = @import("rankings_archive.zig");
pub const minute_archive = @import("minute_archive.zig");
pub const schema = @import("schema.zig");
pub const Password = @import("password.zig").Password;
test {
    _ = @import("password.zig");
    _ = @import("totp.zig");
    _ = @import("auth_secrets.zig");
    _ = @import("stats.zig");
    _ = @import("timeline_test.zig");
    _ = @import("minute_archive.zig");
    _ = @import("minute_journal_test.zig");
    _ = @import("geoip_maintenance.zig");
    _ = @import("space_saving.zig");
    _ = @import("rankings_archive.zig");
    _ = @import("rankings_journal_test.zig");
    _ = @import("geoip.zig");
    _ = @import("geoip_generation.zig");
    _ = @import("geoip_gzip.zig");
}

pub const App = @import("app.zig").App;
pub const Kernel = @import("serve").Kernel;
