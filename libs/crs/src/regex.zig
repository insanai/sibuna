//! Bounded regex backend, separate from full SecLang/CRS execution compatibility.
pub const types = @import("regex_types.zig");
pub const compile = @import("regex_compile.zig").compile;
pub const Workspace = @import("regex_workspace.zig").Workspace;
pub const match = @import("regex_match.zig");

test {
    _ = @import("regex_test.zig");
}
