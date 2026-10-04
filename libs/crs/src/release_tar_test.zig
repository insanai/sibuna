const std = @import("std");
const tar = @import("release_tar.zig");
const work = @import("work.zig");

fn header(output: *[512]u8, name: []const u8, size: usize, kind: u8) void {
    @memset(output, 0);
    @memcpy(output[0..name.len], name);
    @memcpy(output[257..265], "ustar\x0000");
    output[156] = kind;
    var number: [12]u8 = undefined;
    _ = std.fmt.bufPrint(&number, "{o:0>11}\x00", .{size}) catch unreachable;
    @memcpy(output[124..136], &number);
    checksum(output);
}

fn checksum(output: *[512]u8) void {
    @memset(output[148..156], ' ');
    var sum: usize = 0;
    for (output) |byte| sum += byte;
    var text: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&text, "{o:0>6}\x00 ", .{sum}) catch unreachable;
    @memcpy(output[148..156], &text);
}

test "canonical release tar borrows file bytes and owns normalized relative names" {
    var input: [2048]u8 = @splat(0);
    header(input[0..512], "coreruleset-4.30.0/rules/test.conf", 3, '0');
    @memcpy(input[512..515], "abc");
    var entries: [8]tar.Entry = undefined;
    var names: [512]u8 = undefined;
    var reader: tar.Reader = .{ .entries = &entries, .names = &names };
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    const files = try reader.parse(&input, "coreruleset-4.30.0", &budget);
    try std.testing.expectEqual(@as(usize, 1), files.len);
    try std.testing.expectEqualStrings("rules/test.conf", files[0].path);
    try std.testing.expectEqualStrings("abc", files[0].bytes);
    input[0] = '!';
    try std.testing.expectEqualStrings("rules/test.conf", files[0].path);
}

test "tar rejects path escapes, links, devices, sparse and extended entries" {
    const paths = [_][]const u8{
        "coreruleset-4.30.0/../outside",
        "coreruleset-4.30.0/rules//double",
        "coreruleset-4.30.0/C:\\outside",
        "/coreruleset-4.30.0/outside",
        "coreruleset-4.30.0-other/rules/test.conf",
    };
    var input: [1536]u8 = @splat(0);
    var entries: [8]tar.Entry = undefined;
    var names: [512]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    for (paths) |path| {
        header(input[0..512], path, 0, '0');
        var reader: tar.Reader = .{ .entries = &entries, .names = &names };
        try std.testing.expectError(
            error.InvalidArchivePath,
            reader.parse(&input, "coreruleset-4.30.0", &budget),
        );
    }
    for ([_]u8{ '1', '2', '3', '4', '6', '7', 'S', 'x', 'g', 'L', 'K' }) |kind| {
        header(input[0..512], "coreruleset-4.30.0/test", 0, kind);
        var reader: tar.Reader = .{ .entries = &entries, .names = &names };
        try std.testing.expectError(
            error.UnsupportedArchiveEntry,
            reader.parse(&input, "coreruleset-4.30.0", &budget),
        );
    }
}

test "tar refuses duplicate names and bounds numeric sizes before block rounding" {
    var input: [2048]u8 = @splat(0);
    header(input[0..512], "coreruleset-4.30.0/test", 0, '0');
    header(input[512..1024], "coreruleset-4.30.0/test", 0, '0');
    var entries: [8]tar.Entry = undefined;
    var names: [512]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    var reader: tar.Reader = .{ .entries = &entries, .names = &names };
    try std.testing.expectError(
        error.DuplicateArchiveEntry,
        reader.parse(&input, "coreruleset-4.30.0", &budget),
    );
    @memset(input[124..136], '7');
    checksum(input[0..512]);
    reader = .{ .entries = &entries, .names = &names };
    try std.testing.expectError(
        error.ArchiveByteLimit,
        reader.parse(&input, "coreruleset-4.30.0", &budget),
    );
}

test "tar requires intact checksums, data padding and two complete terminal blocks" {
    var input: [2048]u8 = @splat(0);
    header(input[0..512], "coreruleset-4.30.0/test", 3, '0');
    @memcpy(input[512..515], "abc");
    var entries: [8]tar.Entry = undefined;
    var names: [512]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    const faults = [_]usize{ 0, 516, 2047 };
    for (faults) |index| {
        const original = input[index];
        input[index] ^= 1;
        var reader: tar.Reader = .{ .entries = &entries, .names = &names };
        try std.testing.expectError(
            error.InvalidArchive,
            reader.parse(&input, "coreruleset-4.30.0", &budget),
        );
        input[index] = original;
    }
    var reader: tar.Reader = .{ .entries = &entries, .names = &names };
    try std.testing.expectError(
        error.InvalidArchive,
        reader.parse(input[0..1536], "coreruleset-4.30.0", &budget),
    );
}
