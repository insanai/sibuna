//! Fixed-capacity ownership transfer between management tasks. Contract payloads must be
//! owned, or held by their executor until completion; cancellation never reuses executing
//! slots. Completion events remain pinned until their single waiter has returned.
const std = @import("std");
const ops = @import("bounded_mailbox_ops.zig");
pub const Common = struct {
    pub const Ticket = struct { slot: usize, id: u64 };
    pub const Priority = enum { urgent, background };
    pub const State = enum { free, queued, executing, abandoned, completed };
    pub const Error = error{
        Full,
        Stopping,
        StaleTicket,
        NotExecuting,
        IdExhausted,
        WaiterActive,
    };
};

pub fn Mailbox(comptime contract: type, comptime capacity: usize) type {
    return struct {
        pub const Contract = contract;
        pub const Ticket = Common.Ticket;
        pub const Priority = Common.Priority;
        pub const State = Common.State;
        pub const Error = Common.Error;
        pub const Work = struct { ticket: Ticket, request: contract.Request };
        pub const Slot = struct {
            id: u64 = 0,
            completion: std.Io.Event = .unset,
            waiter: bool = false,
            state: State = .free,
            priority: Priority = .background,
            request: contract.Request = undefined,
            result: contract.Result = undefined,
        };
        wake: std.Io.Event = .unset,
        mutex: std.Io.Mutex = .init,
        /// Frees request and result payloads that no party will receive (abandoned, discarded
        /// at stop, or left at shutdown). Set by the storage owner before the first submission.
        gpa: ?std.mem.Allocator = null,
        slots: [capacity]Slot = @splat(.{}),
        next_id: u64 = 1,
        urgent_streak: u8 = 0,
        stopping: bool = false,

        pub const submit = ops.submit;
        pub const take = ops.take;
        pub const complete = ops.complete;
        pub const poll = ops.poll;
        pub const abandon = ops.abandon;
        pub const deinit = ops.deinit;
        pub const stop = ops.stop;
        pub const waitFor = ops.waitFor;
        pub const wait = ops.wait;
        pub const lookup = ops.lookup;
    };
}
