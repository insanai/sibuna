//! Shared caller-owned transform contracts; implementations never allocate.
const work = @import("work.zig");

pub const Error = error{ UnsupportedTransform, OutputLimit } || work.Error;
pub const Buffer = struct {
    input: []const u8,
    output: []u8,
    budget: *work.Budget,
};
pub const Result = struct { bytes: []const u8, changed: bool };
pub const Write = struct { length: usize, changed: bool };
