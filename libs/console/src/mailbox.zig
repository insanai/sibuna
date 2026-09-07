const std = @import("std");
const protocol = @import("console_protocol");

/// Storage executes a copied Work outside the mutex. A caller abandoning executing work
/// cannot reuse its slot until completion; cancellation does not promise SQL rollback.
/// This mutex is private to management tasks and must never be used on request workers.
pub const Mailbox = struct {
    const capacity = 32;
    const Self = @This();
    pub const Ticket = struct { slot: usize, id: u64 };
    pub const Priority = enum { urgent, background };
    pub const State = enum { free, queued, executing, abandoned, completed };
    pub const Work = struct { ticket: Ticket, request: protocol.StorageRequest };
    const Slot = struct {
        id: u64 = 0,
        state: State = .free,
        priority: Priority = .background,
        request: protocol.StorageRequest = undefined,
        result: protocol.StorageResult = undefined,
    };
    pub const Error = error{ Full, Stopping, StaleTicket, NotExecuting, IdExhausted };

    mutex: std.Io.Mutex = .init,
    slots: [capacity]Slot = @splat(.{}),
    next_id: u64 = 1,
    urgent_streak: u8 = 0,
    stopping: bool = false,

    pub fn submit(
        self: *Self,
        io: std.Io,
        request: protocol.StorageRequest,
        priority: Priority,
    ) (Error || error{ InvalidLimit, TooLarge })!Ticket {
        try protocol.validate(request);
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.stopping) return error.Stopping;
        if (self.next_id == std.math.maxInt(u64)) return error.IdExhausted;
        for (&self.slots, 0..) |*slot, index| {
            if (slot.state != .free) continue;
            slot.* = .{
                .id = self.next_id,
                .state = .queued,
                .priority = priority,
                .request = request,
            };
            self.next_id += 1;
            return .{ .slot = index, .id = slot.id };
        }
        return error.Full;
    }

    /// At most eight urgent operations can overtake a waiting background operation.
    /// The storage tick separately reserves time for incident/policy maintenance.
    pub fn take(self: *Self, io: std.Io) ?Work {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var urgent: ?usize = null;
        var background: ?usize = null;
        for (self.slots, 0..) |slot, index| {
            if (slot.state != .queued) continue;
            const candidate = if (slot.priority == .urgent) &urgent else &background;
            if (candidate.* == null or slot.id < self.slots[candidate.*.?].id)
                candidate.* = index;
        }
        const index = if (background != null and (urgent == null or self.urgent_streak == 8))
            background.?
        else
            urgent orelse background orelse return null;
        const slot = &self.slots[index];
        if (slot.priority == .urgent) {
            self.urgent_streak = @min(8, self.urgent_streak + 1);
        } else self.urgent_streak = 0;
        slot.state = .executing;
        return .{ .ticket = .{ .slot = index, .id = slot.id }, .request = slot.request };
    }

    pub fn complete(
        self: *Self,
        io: std.Io,
        ticket: Ticket,
        result: protocol.StorageResult,
    ) Error!void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const slot = try self.lookup(ticket);
        if (slot.state == .abandoned) {
            slot.* = .{};
            return;
        }
        if (slot.state != .executing) return error.NotExecuting;
        slot.result = result;
        slot.state = .completed;
    }

    /// Null means pending. A result is transferred exactly once, releasing the slot.
    pub fn poll(self: *Self, io: std.Io, ticket: Ticket) Error!?protocol.StorageResult {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const slot = try self.lookup(ticket);
        if (slot.state == .abandoned) return error.StaleTicket;
        if (slot.state != .completed) return null;
        const result = slot.result;
        slot.* = .{};
        return result;
    }

    pub fn abandon(self: *Self, io: std.Io, ticket: Ticket) Error!void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const slot = try self.lookup(ticket);
        if (slot.state == .executing or slot.state == .abandoned) {
            slot.state = .abandoned;
        } else slot.* = .{};
    }

    /// Stop admission and discard queued work. The owner must still join execution
    /// before deallocating this mailbox; executing commands may already have committed.
    pub fn stop(self: *Self, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.stopping = true;
        for (&self.slots) |*slot| {
            switch (slot.state) {
                .queued => {
                    slot.result = .{ .failed = .cancelled };
                    slot.state = .completed;
                },
                else => {},
            }
        }
    }

    fn lookup(self: *Self, ticket: Ticket) Error!*Slot {
        if (ticket.slot >= capacity) return error.StaleTicket;
        const slot = &self.slots[ticket.slot];
        if (slot.state == .free or slot.id != ticket.id) return error.StaleTicket;
        return slot;
    }
};

test "disconnect cannot recycle executing work or consume another caller's result" {
    const t = std.testing;
    const io = t.io;
    var mailbox: Mailbox = .{};
    const request: protocol.StorageRequest = .{ .incidents = .{ .before_id = null, .limit = 1 } };
    const first = try mailbox.submit(io, request, .urgent);
    const work = mailbox.take(io).?;
    try mailbox.abandon(io, first);
    const second = try mailbox.submit(io, request, .background);
    for (0..30) |_| _ = try mailbox.submit(io, request, .background);
    try t.expectError(error.Full, mailbox.submit(io, request, .urgent));
    try mailbox.complete(io, work.ticket, .command_recorded);
    const third = try mailbox.submit(io, request, .urgent);
    try t.expectEqual(first.slot, third.slot);
    try t.expectError(error.StaleTicket, mailbox.poll(io, first));
    mailbox.stop(io);
    try t.expectEqual(protocol.Failure.cancelled, (try mailbox.poll(io, second)).?.failed);
    try t.expectEqual(protocol.Failure.cancelled, (try mailbox.poll(io, third)).?.failed);
    try t.expectError(error.Stopping, mailbox.submit(io, request, .urgent));
}

test "urgent work overtakes background but cannot starve it" {
    const t = std.testing;
    const io = t.io;
    var mailbox: Mailbox = .{};
    const request: protocol.StorageRequest = .{ .incidents = .{ .before_id = null, .limit = 1 } };
    const background = try mailbox.submit(io, request, .background);
    for (0..8) |_| {
        const urgent = try mailbox.submit(io, request, .urgent);
        try t.expectEqual(urgent.id, mailbox.take(io).?.ticket.id);
        try mailbox.complete(io, urgent, .command_recorded);
        _ = try mailbox.poll(io, urgent);
    }
    _ = try mailbox.submit(io, request, .urgent);
    try t.expectEqual(background.id, mailbox.take(io).?.ticket.id);
}
