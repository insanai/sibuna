//! Application contracts. The daemon supplies storage and control execution.
pub const protocol = @import("console_protocol");
pub const Budget = @import("budget.zig").Budget;
pub const ConsoleConfig = @import("config.zig").ConsoleConfig;
pub const Mailbox = @import("mailbox.zig").Mailbox;

test {
    _ = @import("budget.zig");
    _ = @import("config.zig");
    _ = @import("mailbox.zig");
}

pub const schema = @import("schema.zig");
pub const Password = @import("password.zig").Password;
test {
    _ = @import("password.zig");
    _ = @import("stats.zig");
}

pub const App = @import("app.zig").App;
pub const Kernel = @import("serve").Kernel;
