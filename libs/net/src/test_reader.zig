//! Test reader with controlled fragmentation and injected empty reads.
const std = @import("std");
const Io = std.Io;

pub const Fragmented = struct {
    interface: Io.Reader,
    buffer: [4096]u8 = undefined,
    bytes: []const u8,
    offset: usize = 0,
    piece: usize,
    empty_reads: usize = 0,

    pub fn init(self: *Fragmented, bytes: []const u8, piece: usize) void {
        std.debug.assert(piece > 0);
        self.* = .{
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = &self.buffer,
                .seek = 0,
                .end = 0,
            },
            .bytes = bytes,
            .piece = piece,
        };
    }

    fn stream(
        reader: *Io.Reader,
        writer: *Io.Writer,
        limit: Io.Limit,
    ) Io.Reader.StreamError!usize {
        const self: *Fragmented = @fieldParentPtr("interface", reader);
        if (self.empty_reads != 0) {
            self.empty_reads -= 1;
            return 0;
        }
        if (self.offset == self.bytes.len) return error.EndOfStream;
        const count = limit.minInt(@min(self.piece, self.bytes.len - self.offset));
        try writer.writeAll(self.bytes[self.offset..][0..count]);
        self.offset += count;
        return count;
    }
};
