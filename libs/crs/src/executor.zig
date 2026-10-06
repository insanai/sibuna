//! Phased execution over one borrowed immutable rule program and reserved slot.
//! The caller acquires complete phase inputs and retains their immutable bytes.
const std = @import("std");
const model = @import("model.zig");
const rules = @import("rule_program.zig");
const condition = @import("condition.zig");
const post = @import("post_actions.zig");
const cursor = @import("phase_cursor.zig");
const buffers = @import("buffers.zig");
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
        // Every scratch region is slot-owned and fixed; only the acquired view changes, and
        // it changes between phases. One proof per phase covers every condition in it.
        self.condition.assertExclusive();
        // Shared transform outputs never cross phases; each phase recomputes them once.
        if (self.condition.cache) |cache| cache.clear();
        const unwind = std.mem.sliceAsBytes(self.unwind);
        self.condition.assertDisjoint(unwind);
        buffers.assertDisjoint(unwind, std.mem.sliceAsBytes(self.program.topology.rows));
        buffers.assertDisjoint(unwind, std.mem.sliceAsBytes(self.program.conditions));
        try self.cursor.begin(phase);
        while (try self.cursor.next(self.condition.budget)) |root| {
            const journal = self.condition.context.store.journal;
            if (journal) |value| value.bind(root, self.program.actions[root].id, phase);
            const event_start = self.state.event_used;
            defer self.finishScores(journal, root, event_start);
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

    fn finishScores(
        self: *Executor,
        journal: ?*@import("score_journal.zig").Journal,
        root: usize,
        event_start: usize,
    ) void {
        const value = journal orelse return;
        value.unbind();
        // A root may publish repeated multiMatch events, or none for a false chain.
        // One reference denotes its net total and prevents duplicated contributions.
        if (self.state.event_used != event_start) {
            self.state.events[event_start].score_owner = root;
        }
    }
};

test {
    _ = @import("executor_test.zig");
}
