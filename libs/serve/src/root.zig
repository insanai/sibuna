//! Bounded transport primitives; no firewall, storage or application dependencies.
pub const websocket = @import("websocket.zig");
pub const Admission = @import("admission.zig").Admission;

test {
    _ = @import("websocket.zig");
    _ = @import("admission.zig");
}
