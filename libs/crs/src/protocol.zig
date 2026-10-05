//! Pure shared contracts compile for native clients and Wasm without the engine.
pub const tests = @import("scenario_contract.zig");
pub const review = @import("review_contract.zig");
pub const evidence = @import("security-evidence").detail;
