//! Pure transform passes complete before any effect with constant scratch space. multiMatch
//! replays a validated pass to yield each stage; a single final value needs one pass.
//! SID 0010 states the input immutability and stable-address invariants.
const pipeline = @import("pipeline.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = pipeline.Error || error{InvalidReplay};
pub const Replay = struct {
    iterator: pipeline.Iterator = undefined,
    reserved: work.Budget = .{ .remaining = 0 },
    state: enum { failed, ready, finished } = .failed,
    /// Without multiMatch the validating pass already produced the only value.
    single: ?pipeline.Value = null,
    replays: bool = false,

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
        if (!program.multi_match) {
            // One pass completes every stage before any effect; its final value is the
            // only one this pipeline yields, so a second pass would only repeat work.
            var pass = pipeline.Iterator.init(program, frame);
            self.single = try pass.next();
            self.replays = false;
            self.state = .ready;
            return;
        }
        const before = frame.budget.remaining;
        var preview = pipeline.Iterator.init(program, frame);
        while (try preview.next() != null) {}
        const cost = before - frame.budget.remaining;
        try frame.budget.debit(cost);
        self.reserved = .{ .remaining = cost };
        var replay_frame = frame;
        replay_frame.budget = &self.reserved;
        self.iterator = pipeline.Iterator.init(program, replay_frame);
        self.replays = true;
        self.state = .ready;
    }

    /// Values borrow input or scratch until the next call, exactly like Iterator.
    pub fn next(self: *Replay) Error!?pipeline.Value {
        if (self.state == .failed) return error.InvalidReplay;
        if (self.state == .finished) return null;
        if (!self.replays) {
            const value = self.single;
            self.single = null;
            self.state = .finished;
            return value;
        }
        errdefer self.state = .failed;
        const value = try self.iterator.next();
        if (value == null) self.state = .finished;
        return value;
    }
};

test {
    _ = @import("pipeline_replay_test.zig");
}
