//! Phase order and forward root scheduling, separate from input and action execution.
const model = @import("model.zig");
const chains = @import("chains.zig");
const work = @import("work.zig");
pub const Error = work.Error || error{
    InvalidCursor,
    InvalidPhaseOrder,
    UnfinishedPhase,
    NoActivePhase,
    PendingRoot,
    NoPendingRoot,
};

pub const Cursor = struct {
    program: *const chains.Program,
    phase: ?model.Phase = null,
    completed: u3 = 0,
    position: usize = 0,
    pending: ?usize = null,
    failed: bool = false,

    /// One cursor borrows the pinned topology for the complete transaction lifetime.
    pub fn init(program: *const chains.Program) Cursor {
        return .{ .program = program };
    }

    pub fn begin(self: *Cursor, phase: model.Phase) Error!void {
        if (self.failed) return error.InvalidCursor;
        errdefer self.failed = true;
        if (self.phase != null) return error.UnfinishedPhase;
        if (@backingInt(phase) <= self.completed) return error.InvalidPhaseOrder;
        self.phase = phase;
        self.position = 0;
    }

    /// Only exhaustion with no pending root completes a phase. Callers cannot treat
    /// work failure or an unfinished rule's post-match effects as normal exhaustion.
    pub fn next(self: *Cursor, budget: *work.Budget) Error!?usize {
        if (self.failed) return error.InvalidCursor;
        errdefer self.failed = true;
        const phase = self.phase orelse return error.NoActivePhase;
        if (self.pending != null) return error.PendingRoot;
        while (self.position < self.program.rows.len) {
            try budget.debit(1);
            const root = self.position;
            const row = self.program.rows[root];
            self.position = row.end;
            if (row.phase != phase) continue;
            self.pending = root;
            return root;
        }
        self.completed = @backingInt(phase);
        self.phase = null;
        return null;
    }

    /// Invoke after complete chain truth and successful post-match handling. A false
    /// chain advances normally; it cannot activate the root's skipAfter instruction.
    pub fn complete(self: *Cursor, matched: bool) Error!void {
        if (self.failed) return error.InvalidCursor;
        errdefer self.failed = true;
        const root = self.pending orelse return error.NoPendingRoot;
        if (matched) {
            if (self.program.rows[root].skip_to) |destination| self.position = destination;
        }
        self.pending = null;
    }
};

test {
    _ = @import("phase_cursor_test.zig");
}
