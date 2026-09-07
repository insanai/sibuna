//! Bounded transport primitives; no firewall, storage or application dependencies.
pub const websocket = @import("websocket.zig");
pub const Admission = @import("admission.zig").Admission;

test {
    _ = @import("websocket.zig");
    _ = @import("admission.zig");
}

pub const Context = @import("context.zig").Context;
pub const Kernel = @import("kernel.zig").Kernel;
test {
    _ = @import("kernel_test.zig");
}
