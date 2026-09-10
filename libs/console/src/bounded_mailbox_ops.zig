//! Operations are separate from the generic state declaration so each ownership transition
//! has one implementation and an independently checked function bound.
const std = @import("std");
const common = @import("bounded_mailbox.zig").Common;
const Error = common.Error;
const Ticket = common.Ticket;
const Priority = common.Priority;

pub fn submit(
    self: anytype,
    io: std.Io,
    request: @TypeOf(self.*).Contract.Request,
    priority: Priority,
) (Error || error{ InvalidLimit, TooLarge })!Ticket {
    try @TypeOf(self.*).Contract.validate(request);
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
        self.wake.set(io);
        return .{ .slot = index, .id = slot.id };
    }
    return error.Full;
}

/// At most eight urgent operations can overtake a waiting background operation.
/// The storage tick separately reserves time for incident/policy maintenance.
pub fn take(self: anytype, io: std.Io) ?@TypeOf(self.*).Work {
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
    self: anytype,
    io: std.Io,
    ticket: Ticket,
    result: @TypeOf(self.*).Contract.Result,
) Error!void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const slot = try self.lookup(ticket);
    if (slot.state == .abandoned) {
        if (self.gpa) |gpa| @TypeOf(self.*).Contract.releaseResult(result, gpa);
        slot.* = .{};
        return;
    }
    if (slot.state != .executing) return error.NotExecuting;
    slot.result = result;
    slot.state = .completed;
    slot.completion.set(io);
}

/// Null means pending. A result is transferred exactly once, releasing the slot.
pub fn poll(self: anytype, io: std.Io, ticket: Ticket) Error!?@TypeOf(self.*).Contract.Result {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const slot = try self.lookup(ticket);
    if (slot.waiter) return error.WaiterActive;
    if (slot.state == .abandoned) return error.StaleTicket;
    if (slot.state != .completed) return null;
    const result = slot.result;
    slot.* = .{};
    return result;
}

pub fn abandon(self: anytype, io: std.Io, ticket: Ticket) Error!void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const slot = try self.lookup(ticket);
    if (slot.waiter) return error.WaiterActive;
    if (slot.state == .executing or slot.state == .abandoned) {
        slot.state = .abandoned;
        return;
    }
    if (slot.state == .queued) {
        if (self.gpa) |gpa| @TypeOf(self.*).Contract.releaseRequest(slot.request, gpa);
    } else if (slot.state == .completed) {
        if (self.gpa) |gpa| @TypeOf(self.*).Contract.releaseResult(slot.result, gpa);
    }
    slot.* = .{};
}

/// Releases every payload still held after the owner has stopped executing.
pub fn deinit(self: anytype, io: std.Io) void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const gpa = self.gpa orelse return;
    for (&self.slots) |*slot| {
        switch (slot.state) {
            .queued => @TypeOf(self.*).Contract.releaseRequest(slot.request, gpa),
            .completed => @TypeOf(self.*).Contract.releaseResult(slot.result, gpa),
            else => {},
        }
        slot.* = .{};
    }
}

/// Stop admission and discard queued work. The owner must still join execution
/// before deallocating this mailbox; executing commands may already have committed.
pub fn stop(self: anytype, io: std.Io) void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    self.stopping = true;
    self.wake.set(io);
    for (&self.slots) |*slot| {
        switch (slot.state) {
            .queued => {
                if (self.gpa) |gpa| @TypeOf(self.*).Contract.releaseRequest(slot.request, gpa);
                slot.result = @TypeOf(self.*).Contract.cancelled;
                slot.state = .completed;
                slot.completion.set(io);
            },
            else => {},
        }
    }
}

/// One ticket owner may wait. Prevent slot reuse until that wait has returned, including
/// timeout and cancellation; execution completion may signal while the mutex is released.
pub fn waitFor(
    self: anytype,
    io: std.Io,
    ticket: Ticket,
    timeout: std.Io.Timeout,
) (Error || std.Io.Event.WaitTimeoutError)!void {
    self.mutex.lockUncancelable(io);
    const slot = self.lookup(ticket) catch |err| {
        self.mutex.unlock(io);
        return err;
    };
    if (slot.waiter or slot.state == .abandoned) {
        self.mutex.unlock(io);
        return error.WaiterActive;
    }
    slot.waiter = true;
    self.mutex.unlock(io);
    defer {
        self.mutex.lockUncancelable(io);
        std.debug.assert(slot.id == ticket.id and slot.waiter);
        slot.waiter = false;
        self.mutex.unlock(io);
    }
    try slot.completion.waitTimeout(io, timeout);
}

/// Only the storage owner waits. Reset and inspect under the submission mutex so
/// an arrival between the inspection and futex wait cannot lose its notification.
pub fn wait(self: anytype, io: std.Io, milliseconds: u64) std.Io.Cancelable!void {
    self.mutex.lockUncancelable(io);
    self.wake.reset();
    var queued = false;
    for (self.slots) |slot| queued = queued or slot.state == .queued;
    self.mutex.unlock(io);
    if (queued) return;
    self.wake.waitTimeout(io, .{ .duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(@intCast(milliseconds)),
    } }) catch |err| switch (err) {
        error.Timeout => {},
        error.Canceled => return error.Canceled,
    };
}

pub fn lookup(self: anytype, ticket: Ticket) Error!*@TypeOf(self.*).Slot {
    if (ticket.slot >= self.slots.len) return error.StaleTicket;
    const slot = &self.slots[ticket.slot];
    if (slot.state == .free or slot.id != ticket.id) return error.StaleTicket;
    return slot;
}
