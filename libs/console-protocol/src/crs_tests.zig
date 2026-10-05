//! Private-test samples borrow their decoder owner. Pollable results own scalar
//! metadata and never contain a sample, expanded message or matched value.
const p = @import("root.zig");
pub const sample = @import("crs-protocol").tests;
pub const Request = struct {
    source: []const u8,
    expected_revision: []const u8,
    mode: ?sample.Mode = null,
    sample: sample.Sample,

    pub fn validate(self: Request) error{InvalidRequest}!void {
        try (p.crs_tasks.Source{
            .source = self.source,
            .expected_revision = self.expected_revision,
        }).validate();
        self.sample.validate() catch return error.InvalidRequest;
    }
};
// Compatibility names share the common worker result contract.
pub const State = p.crs_tasks.State;
pub const Status = p.crs_tasks.Status;
