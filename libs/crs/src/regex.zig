//! Bounded regex backend, separate from full SecLang/CRS execution compatibility.
pub const types = @import("regex_types.zig");
pub const compile = @import("regex_compile.zig").compile;
pub const Config = @import("regex_compile.zig").Config;
pub const configured = @import("regex_compile.zig").configured;
pub const Workspace = @import("regex_workspace.zig").Workspace;
pub const match = @import("regex_match.zig");
pub const dfa = @import("regex_dfa.zig");

/// ModSecurity 3.0.14's Regex constructor uses DOTALL | MULTILINE and substitutes
/// ".*" for an empty expression. Key selection additionally uses CASELESS.
pub fn secLang(
    allocator: @import("std").mem.Allocator,
    bytes: []const u8,
    insensitive: bool,
) types.Error!types.Program {
    return configured(allocator, if (bytes.len == 0) ".*" else bytes, .{
        .flags = .{ .dotall = true, .multiline = true, .insensitive = insensitive },
    });
}

test {
    _ = @import("regex_test.zig");
}
