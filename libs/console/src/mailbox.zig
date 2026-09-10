const std = @import("std");
const protocol = @import("console_protocol");

pub const Mailbox = @import("bounded_mailbox.zig").Mailbox(struct {
    pub const Request = protocol.StorageRequest;
    pub const Result = protocol.StorageResult;
    pub const validate = protocol.validate;
    pub const releaseRequest = protocol.releaseRequest;
    pub const releaseResult = protocol.releaseResult;
    pub const cancelled: Result = .{ .failed = .cancelled };
}, 32);

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

const WaitTest = struct {
    mailbox: *Mailbox,
    ticket: Mailbox.Ticket,
    failure: ?anyerror = null,

    fn run(self: *WaitTest) void {
        self.mailbox.waitFor(std.testing.io, self.ticket, .{ .duration = .{
            .clock = .awake,
            .raw = .fromSeconds(5),
        } }) catch |err| {
            self.failure = err;
        };
    }
};

test "completion waiter pins the ticket and queued shutdown wakes it" {
    const t = std.testing;
    var box: Mailbox = .{};
    const ticket = try box.submit(t.io, .setup_status, .urgent);
    var context: WaitTest = .{ .mailbox = &box, .ticket = ticket };
    const thread = try std.Thread.spawn(.{}, WaitTest.run, .{&context});
    var joined = false;
    defer if (!joined) {
        box.stop(t.io);
        thread.join();
    };
    var waiting = false;
    for (0..1000) |_| {
        box.mutex.lockUncancelable(t.io);
        waiting = box.slots[ticket.slot].waiter;
        box.mutex.unlock(t.io);
        if (waiting) break;
        try std.Io.sleep(t.io, .fromMilliseconds(1), .awake);
    }
    try t.expect(waiting);
    try t.expectError(error.WaiterActive, box.poll(t.io, ticket));
    try t.expectError(error.WaiterActive, box.abandon(t.io, ticket));
    box.stop(t.io);
    thread.join();
    joined = true;
    try t.expectEqual(null, context.failure);
    try t.expectEqual(protocol.Failure.cancelled, (try box.poll(t.io, ticket)).?.failed);
}
