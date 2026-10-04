//! Shared in-place slot for post-match and phased executor contract tests.
const evaluation = @import("evaluation_test_support.zig");
const controls = @import("controls.zig");
const state = @import("action_state.zig");
const post = @import("post_actions.zig");
pub const Slot = struct {
    evaluation: evaluation.Slot = .{},
    exclusions: [16]controls.Exclusion = undefined,
    events: [16]state.Event = undefined,
    tags: [32][]const u8 = undefined,
    bytes: [4096]u8 = undefined,
    state: state.State = undefined,

    pub fn init(self: *Slot, enforce: bool) !void {
        try self.evaluation.init(&.{});
        self.state = state.State.init(
            &self.exclusions,
            &self.events,
            &self.tags,
            &self.bytes,
            enforce,
        );
    }

    pub fn frame(self: *Slot) post.Frame {
        const evaluator = &self.evaluation;
        return .{
            .context = &evaluator.context,
            .state = &self.state,
            .pieces = &evaluator.pieces,
            .key_output = &evaluator.key_output,
            .value_output = &evaluator.value_output,
            .budget = &evaluator.budget,
        };
    }
};
