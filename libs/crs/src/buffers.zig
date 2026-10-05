//! Compatibility names for shared buffer ownership invariants.
const buffers = @import("text").buffers;
pub const assertDisjoint = buffers.assertDisjoint;
pub const assertExclusive = buffers.assertExclusive;
