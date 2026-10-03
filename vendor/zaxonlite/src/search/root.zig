//! zaxon_search: pure fusion formulas and vector distance kernels
//! (ZDS 0009). This module has no SQLite, Paxos, filesystem, or network
//! dependency; the build compiles it standalone for every supported
//! vector target to prove that boundary.

pub const fusion = @import("fusion.zig");
pub const vector = @import("vector.zig");

test {
    _ = fusion;
    _ = vector;
}
