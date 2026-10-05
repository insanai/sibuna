//! Retain a consumed head in place while body or origin reads reuse its tail.
//! This scope owns no bytes; the connection buffer and reader outlive its release.
const std = @import("std");
const Io = std.Io;
pub const Pin = struct {
    reader: *Io.Reader,
    buffer: []u8,
    head_end: usize,

    /// The prefix must already be consumed. Borrowed metadata in that prefix is
    /// immutable until release; prefetched body/pipeline bytes remain readable.
    pub fn init(reader: *Io.Reader, head_end: usize) Pin {
        std.debug.assert(head_end <= reader.seek and head_end < reader.buffer.len);
        const pin: Pin = .{ .reader = reader, .buffer = reader.buffer, .head_end = head_end };
        reader.buffer = reader.buffer[head_end..];
        reader.seek -= head_end;
        reader.end -= head_end;
        return pin;
    }

    /// Release after final evidence and telemetry reads, before parsing another
    /// request. The next fill may reclaim the original prefix once it is unpinned.
    pub fn release(self: Pin) void {
        std.debug.assert(self.reader.buffer.ptr == self.buffer[self.head_end..].ptr);
        self.reader.buffer = self.buffer;
        self.reader.seek += self.head_end;
        self.reader.end += self.head_end;
    }
};

test "retained heads survive complete holdback and preserve pipelined input on release" {
    const source = @import("test_reader.zig");
    const entity = @import("entity.zig");
    const t = std.testing;
    const head = "POST /retained HTTP/1.1\r\nHost: example.test\r\nContent-Length: 8192\r\n\r\n";
    const next = "GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const body: [8192]u8 = @splat('b');
    const raw = head ++ body ++ next;
    for ([_]usize{ 1, 7, 128, 4096 }) |piece| {
        var input: source.Fragmented = undefined;
        input.init(raw, piece);
        try input.interface.fill(head.len);
        const retained = input.interface.buffered()[0..head.len];
        input.interface.toss(head.len);
        const pin = Pin.init(&input.interface, input.interface.seek);
        var output: [8192]u8 = undefined;
        const held = try entity.read(.{
            .reader = &input.interface,
            .output = &output,
        }, .{ .length = output.len });
        try t.expectEqualStrings(&body, held);
        try t.expectEqualStrings(head, retained);
        pin.release();
        try t.expectEqual(@intFromPtr(&input.buffer), @intFromPtr(input.interface.buffer.ptr));
        var pipelined: [next.len]u8 = undefined;
        try input.interface.readSliceAll(&pipelined);
        try t.expectEqualStrings(next, &pipelined);
    }
}

test "retained head release preserves a body prefix already consumed by admission" {
    const t = std.testing;
    var bytes: [12]u8 = "HEADbodyNEXT".*;
    var reader: Io.Reader = .fixed(&bytes);
    reader.toss(8);
    const pin = Pin.init(&reader, 4);
    try t.expectEqualStrings("NEXT", reader.buffered());
    try t.expectEqual(@as(usize, 4), reader.seek);
    pin.release();
    try t.expectEqual(@as(usize, 8), reader.seek);
    try t.expectEqualStrings("NEXT", reader.buffered());
}
