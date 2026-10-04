//! Native Core Rule Set support. Source recognition is separate from executable
//! compatibility: no runtime protection is implied by a successfully parsed file.
pub const compiler = @import("compiler.zig");
pub const model = @import("model.zig");
pub const source = @import("source.zig");
pub const inventory = @import("inventory.zig");
pub const syntax = @import("syntax.zig");

test {
    _ = @import("release_test.zig");
    _ = compiler;
    _ = source;
    _ = syntax;
    _ = inventory;
}
