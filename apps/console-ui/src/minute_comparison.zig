//! Native storage and Wasm comparison use the same exact arithmetic and coverage rules.
const shared = @import("console_protocol").minute_summary;
pub const Window = shared.Window;
pub const Deviation = shared.Deviation;
pub const deviation = shared.deviation;
pub const Metric = shared.Metric;
pub const value = shared.value;
pub const total = shared.total;
