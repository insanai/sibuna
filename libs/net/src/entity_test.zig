const std = @import("std");
const entity = @import("entity.zig");
const Io = std.Io;
const t = std.testing;

const Fragmented = @import("test_reader.zig").Fragmented;

test "held lengths and chunks preserve payload and pipelined bytes across every read size" {
    const raw = "3;test=\"x\"\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: good\r\n\r\nGET /next";
    for (1..raw.len + 1) |piece| {
        var source: Fragmented = undefined;
        source.init(raw, piece);
        var output: [5]u8 = undefined;
        const options: entity.Options = .{ .reader = &source.interface, .output = &output };
        const body = try entity.read(options, .chunked);
        try t.expectEqualStrings("abcde", body);
        var next: [9]u8 = undefined;
        try source.interface.readSliceAll(&next);
        try t.expectEqualStrings("GET /next", &next);
        source.init("abcdeGET /next", piece);
        const length = entity.Framing{ .length = 5 };
        try t.expectEqualStrings("abcde", try entity.read(.{
            .reader = &source.interface,
            .output = &output,
        }, length));
        try source.interface.readSliceAll(&next);
        try t.expectEqualStrings("GET /next", &next);
    }
}

test "holdback refuses oversized entities, incomplete bodies and malformed framing" {
    const cases = [_]struct { raw: []const u8, framing: entity.Framing, err: entity.Error }{
        .{ .raw = "abcde", .framing = .{ .length = 6 }, .err = error.EntityLimit },
        .{ .raw = "abcd", .framing = .{ .length = 5 }, .err = error.IncompleteEntity },
        .{ .raw = "6\r\nabcdef\r\n0\r\n\r\n", .framing = .chunked, .err = error.EntityLimit },
        .{ .raw = "5\r\nabc", .framing = .chunked, .err = error.IncompleteEntity },
        .{ .raw = "1\nX\n0\n\n", .framing = .chunked, .err = error.MalformedEntity },
        .{ .raw = "abcdef", .framing = .until_close, .err = error.EntityLimit },
    };
    for (cases) |case| for (1..case.raw.len + 1) |piece| {
        var source: Fragmented = undefined;
        source.init(case.raw, piece);
        var output: [5]u8 = undefined;
        try t.expectError(case.err, entity.read(.{
            .reader = &source.interface,
            .output = &output,
        }, case.framing));
    };
}

test "close-delimited bodies check EOF at the exact ceiling and no-body framing consumes nothing" {
    var source: Fragmented = undefined;
    var output: [5]u8 = undefined;
    source.init("abcde", 1);
    try t.expectEqualStrings("abcde", try entity.read(.{
        .reader = &source.interface,
        .output = &output,
    }, .until_close));
    source.init("GET /next", 1);
    try t.expectEqualStrings("", try entity.read(.{
        .reader = &source.interface,
        .output = &.{},
    }, .none));
    try t.expectEqual(@as(usize, 0), source.offset);
    source.init("", 1);
    try t.expectEqualStrings("", try entity.read(.{
        .reader = &source.interface,
        .output = &.{},
    }, .{ .length = 0 }));
}

test "framing overhead has its own bound and cannot hide behind a small decoded body" {
    const raw = "1;longextension=abcdefghijklmnop\r\nX\r\n0\r\n\r\n";
    for (1..raw.len + 1) |piece| {
        var source: Fragmented = undefined;
        source.init(raw, piece);
        var output: [1]u8 = undefined;
        try t.expectError(error.FramingLimit, entity.read(.{
            .reader = &source.interface,
            .output = &output,
            .framing_limit = 16,
        }, .chunked));
    }
    var source: Fragmented = undefined;
    source.init(raw, 1);
    var output: [1]u8 = undefined;
    try t.expectEqualStrings("X", try entity.read(.{
        .reader = &source.interface,
        .output = &output,
        .framing_limit = raw.len - 1,
    }, .chunked));
}

test "maximum chunk lines tolerate one-byte reads without repeatedly decoding the pending prefix" {
    var raw: [4130]u8 = undefined;
    const prefix = "1;name=";
    @memcpy(raw[0..prefix.len], prefix);
    @memset(raw[prefix.len..4094], 'x');
    const tail = "\r\nX\r\n0\r\n\r\nNEXT";
    @memcpy(raw[4094..][0..tail.len], tail);
    var source: Fragmented = undefined;
    source.init(raw[0 .. 4094 + tail.len], 1);
    var output: [1]u8 = undefined;
    try t.expectEqualStrings("X", try entity.read(.{
        .reader = &source.interface,
        .output = &output,
    }, .chunked));
    var next: [4]u8 = undefined;
    try source.interface.readSliceAll(&next);
    try t.expectEqualStrings("NEXT", &next);
    raw[4094] = 'x';
    source.init(raw[0 .. 4094 + tail.len], 1);
    try t.expectError(error.MalformedEntity, entity.read(.{
        .reader = &source.interface,
        .output = &output,
    }, .chunked));
}

test "zero-progress readers are bounded and incomplete control lines do not refresh activity" {
    var source: Fragmented = undefined;
    source.init("1\r\nX\r\n0\r\n\r\n", 1);
    source.empty_reads = 3;
    var output: [1]u8 = undefined;
    try t.expectEqualStrings("X", try entity.read(.{
        .reader = &source.interface,
        .output = &output,
    }, .chunked));
    source.init("X", 1);
    source.empty_reads = 8;
    var activity: @import("duplex.zig").Activity = .{};
    try t.expectError(error.ReaderProgressLimit, entity.read(.{
        .reader = &source.interface,
        .output = &output,
        .progress = .{ .io = t.io, .activity = &activity, .mode = .minimum_rate },
    }, .{ .length = 1 }));
    try t.expectEqual(@as(u64, 0), activity.at_ms.load(.monotonic));
    source.init("1;incomplete", 1);
    try t.expectError(error.IncompleteEntity, entity.read(.{
        .reader = &source.interface,
        .output = &output,
        .progress = .{ .io = t.io, .activity = &activity, .mode = .minimum_rate },
    }, .chunked));
    try t.expectEqual(@as(u64, 0), activity.at_ms.load(.monotonic));
}
