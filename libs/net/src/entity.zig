//! Bounded entity holdback, independent of policy or CRS. The caller supplies
//! disjoint reserved storage and retains metadata before the reader can refill.
const std = @import("std");
const Io = std.Io;
const chunks = @import("chunked.zig");
const duplex = @import("duplex.zig");
pub const Error = error{
    EntityLimit,
    IncompleteEntity,
    MalformedEntity,
    FramingLimit,
    FramingBufferLimit,
    InvalidEntityLimits,
    ReadFailed,
    ReaderProgressLimit,
};
pub const Framing = union(enum) { none, length: u64, chunked, until_close };
pub const Progress = struct {
    io: Io,
    activity: *duplex.Activity,
    mode: enum { minimum_rate, any_bytes },
};
pub const Options = struct {
    reader: *Io.Reader,
    output: []u8,
    // A separate bound prevents tiny chunks with huge extensions from spending
    // unbounded framing work inside a small decoded entity ceiling.
    framing_limit: usize = 64 * 1024,
    progress: ?Progress = null,
};
const maximum_entity = 64 * 1024 * 1024;
const maximum_framing = 16 * 1024 * 1024;
const upload_credit = 16 * 1024;
const decode_window = 16 * 1024;

/// Transfer framing is removed exactly once. On success, only entity bytes are
/// consumed: a following pipelined request remains in the reader. No origin or
/// client writer exists here, so partial or refused acquisition cannot deliver bytes.
pub fn read(options: Options, framing: Framing) Error![]const u8 {
    if (options.output.len > maximum_entity or options.framing_limit > maximum_framing)
        return error.InvalidEntityLimits;
    @import("text").buffers.assertDisjoint(options.output, options.reader.buffer);
    var source: Source = .{ .options = options };
    switch (framing) {
        .none => {},
        .length => |length| try source.exact(length),
        .chunked => try source.chunked(),
        .until_close => try source.untilClose(),
    }
    if (options.progress) |progress| progress.activity.touch(progress.io);
    return options.output[0..source.used];
}

const Source = struct {
    options: Options,
    used: usize = 0,
    credited: usize = 0,
    stalled: u8 = 0,

    fn exact(self: *Source, length: u64) Error!void {
        if (length > self.options.output.len) return error.EntityLimit;
        const expected: usize = @intCast(length);
        while (self.used < expected) {
            if (!try self.available()) return error.IncompleteEntity;
            const bytes = self.options.reader.buffered();
            const count = @min(bytes.len, expected - self.used);
            try self.copy(bytes[0..count]);
            self.options.reader.toss(count);
            self.advance(count);
        }
    }

    fn untilClose(self: *Source) Error!void {
        while (try self.available()) {
            const bytes = self.options.reader.buffered();
            try self.copy(bytes);
            self.options.reader.toss(bytes.len);
            self.advance(bytes.len);
        }
    }

    fn chunked(self: *Source) Error!void {
        var decoder: chunks.Decoder = .{};
        var overhead: usize = 0;
        while (!decoder.done()) {
            if (!try self.available()) return error.IncompleteEntity;
            const reader = self.options.reader;
            const bytes = reader.buffered();
            const window = bytes[0..@min(bytes.len, decode_window)];
            const decoded = decoder.decode(window) catch return error.MalformedEntity;
            std.debug.assert(decoded.consumed >= decoded.output);
            const framing = decoded.consumed - decoded.output;
            if (framing > self.options.framing_limit - overhead) return error.FramingLimit;
            overhead += framing;
            try self.copy(bytes[0..decoded.output]);
            reader.toss(decoded.consumed);
            self.advance(decoded.consumed);
            if (decoded.consumed == 0) try self.pendingDelimiter();
        }
    }

    fn available(self: *Source) Error!bool {
        const reader = self.options.reader;
        while (reader.bufferedLen() == 0) if (!try self.more()) return false;
        return true;
    }

    fn more(self: *Source) Error!bool {
        const reader = self.options.reader;
        if (reader.buffer.len == 0) return error.FramingBufferLimit;
        const before = reader.bufferedLen();
        reader.fillMore() catch |err| return switch (err) {
            error.EndOfStream => false,
            error.ReadFailed => error.ReadFailed,
        };
        if (reader.bufferedLen() == before) {
            self.stalled += 1;
            if (self.stalled == 8) return error.ReaderProgressLimit;
        } else {
            self.stalled = 0;
            if (self.options.progress) |progress| {
                if (progress.mode == .any_bytes) progress.activity.touch(progress.io);
            }
        }
        return true;
    }

    fn pendingDelimiter(self: *Source) Error!void {
        const reader = self.options.reader;
        var scanned = reader.bufferedLen();
        // The decoder consumes all available data runs. Zero consumption means
        // either an incomplete control line or the first CR of a two-byte delimiter.
        const pair = scanned == 1 and reader.buffered()[0] == '\r';
        while (true) {
            if (reader.bufferedLen() == reader.buffer.len) return error.FramingBufferLimit;
            if (!try self.more()) return error.IncompleteEntity;
            if (pair) return;
            const bytes = reader.buffered();
            const end = @min(bytes.len, chunks.max_line);
            if (std.mem.indexOfScalar(u8, bytes[scanned..end], '\n') != null) return;
            scanned = end;
            if (scanned == chunks.max_line) return error.MalformedEntity;
        }
    }

    fn copy(self: *Source, bytes: []const u8) Error!void {
        if (bytes.len > self.options.output.len - self.used) return error.EntityLimit;
        @memcpy(self.options.output[self.used..][0..bytes.len], bytes);
        self.used += bytes.len;
    }

    fn advance(self: *Source, count: usize) void {
        if (count == 0) return;
        if (self.options.progress) |progress| {
            // Both entity and framing visits are independently bounded. Credit
            // therefore cannot overflow, even with a 32-bit connection owner.
            self.credited += count;
            if (progress.mode == .any_bytes or self.credited >= upload_credit) {
                progress.activity.touch(progress.io);
                self.credited = 0;
            }
        }
    }
};

test {
    _ = @import("entity_test.zig");
}
