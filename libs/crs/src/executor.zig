//! Phased execution over one borrowed immutable rule program and reserved slot.
//! The caller acquires complete phase inputs and retains their immutable bytes.
const model = @import("model.zig");
const rules = @import("rule_program.zig");
const condition = @import("condition.zig");
const post = @import("post_actions.zig");
const cursor = @import("phase_cursor.zig");
pub const Error = rules.Error || cursor.Error || error{DisruptedTransaction};
pub const Result = enum { complete, denied };
pub const Executor = struct {
    program: *const rules.Program,
    cursor: cursor.Cursor,
    condition: condition.Frame,
    state: *post.State,
    unwind: []usize,
    roots_run: usize = 0,

    pub fn init(
        program: *const rules.Program,
        frame: condition.Frame,
        state: *post.State,
        unwind: []usize,
    ) Executor {
        var owned_frame = frame;
        owned_frame.control = &state.control;
        owned_frame.evidence = state;
        return .{
            .program = program,
            .cursor = cursor.Cursor.init(&program.topology),
            .condition = owned_frame,
            .state = state,
            .unwind = unwind,
        };
    }

    pub fn run(self: *Executor, phase: model.Phase) Error!Result {
        if (self.state.failed or self.condition.context.failed) return error.TransactionFailed;
        errdefer {
            self.cursor.failed = true;
            self.condition.context.poison();
            self.state.poison();
        }
        if (self.state.denied and phase != .logging) return error.DisruptedTransaction;
        try self.cursor.begin(phase);
        while (try self.cursor.next(self.condition.budget)) |root| {
            const result = try self.program.topology.evaluate(
                self.program.conditions,
                root,
                self.condition,
                self.unwind,
            );
            if (result.matched) {
                try post.executeChain(
                    self.program.actions,
                    result.unwind,
                    self.condition.actions(self.state),
                );
            }
            try self.cursor.complete(result.matched);
            self.roots_run += 1;
            if (self.state.denied and phase != .logging) {
                try self.cursor.halt();
                return .denied;
            }
        }
        return .complete;
    }
};

test {
    _ = @import("executor_test.zig");
}
