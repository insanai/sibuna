//! Two pure transform passes preserve pre-effect validation with constant scratch space.
//! SID 0010 states the input immutability and stable-address invariants.
const pipeline = @import("pipeline.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = pipeline.Error || error{InvalidReplay};
pub const Replay = struct {
    iterator: pipeline.Iterator = undefined,
    reserved: work.Budget = .{ .remaining = 0 },
    state: enum { failed, ready, finished } = .failed,

    /// Initialize in place and do not move afterwards: iterator borrows reserved.
    /// Input bytes and program stay immutable; scratch is disjoint and dedicated.
    pub fn init(
        self: *Replay,
        program: *const pipeline.Pipeline,
        frame: pipeline.Frame,
    ) Error!void {
        self.state = .failed;
        buffers.assertDisjoint(frame.input, frame.scratch[0]);
        buffers.assertDisjoint(frame.input, frame.scratch[1]);
        buffers.assertDisjoint(frame.scratch[0], frame.scratch[1]);
        const before = frame.budget.remaining;
        var preview = pipeline.Iterator.init(program, frame);
        while (try preview.next() != null) {}
        const cost = before - frame.budget.remaining;
        try frame.budget.debit(cost);
        self.reserved = .{ .remaining = cost };
        var replay_frame = frame;
        replay_frame.budget = &self.reserved;
        self.iterator = pipeline.Iterator.init(program, replay_frame);
        self.state = .ready;
    }

    /// Values borrow input or scratch until the next call, exactly like Iterator.
    pub fn next(self: *Replay) Error!?pipeline.Value {
        if (self.state == .failed) return error.InvalidReplay;
        if (self.state == .finished) return null;
        errdefer self.state = .failed;
        const value = try self.iterator.next();
        if (value == null) self.state = .finished;
        return value;
    }
};

test {
    _ = @import("pipeline_replay_test.zig");
}
