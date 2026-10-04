const std = @import("std");
const addresses = @import("address_set.zig");
const work = @import("work.zig");
const t = std.testing;

test "families remain distinct and interval unions include both boundary hosts" {
    var program = try addresses.compile(
        t.allocator,
        "10.1.1.1/8,192.0.2.0/25,192.0.2.128/25\n# ignored\n2001:db8::/32,::1,",
        .{},
    );
    defer program.deinit();
    try t.expectEqual(@as(usize, 4), program.intervals.len);
    const cases = [_]struct { text: []const u8, matched: bool }{
        .{ .text = "10.0.0.0", .matched = true },
        .{ .text = "10.255.255.255", .matched = true },
        .{ .text = "11.0.0.0", .matched = false },
        .{ .text = "192.0.2.255", .matched = true },
        .{ .text = "192.0.3.0", .matched = false },
        .{ .text = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", .matched = true },
        .{ .text = "2001:db9::", .matched = false },
        .{ .text = "::1", .matched = true },
        .{ .text = "::ffff:10.1.2.3", .matched = false },
        .{ .text = "host.invalid", .matched = false },
        .{ .text = "10.1.2.3\x00ignored", .matched = false },
        .{ .text = "fe80::1%en0", .matched = false },
        .{ .text = "::ffff:010.1.2.3", .matched = false },
    };
    for (cases) |case| {
        var budget: work.Budget = .{ .remaining = 4096 };
        try t.expectEqual(case.matched, try program.contains(case.text, &budget));
    }
}

test "zero and host prefixes avoid integer-width shifts and family cross matching" {
    const cases = [_]struct { source: []const u8, input: []const u8, matched: bool }{
        .{ .source = "0.0.0.0/0", .input = "255.255.255.255", .matched = true },
        .{ .source = "::/0", .input = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", .matched = true },
        .{ .source = "::/0", .input = "1.2.3.4", .matched = false },
        .{ .source = "0.0.0.0/0", .input = "::ffff:1.2.3.4", .matched = false },
        .{ .source = "::1/128", .input = "::1", .matched = true },
        .{ .source = "::1/128", .input = "::2", .matched = false },
        .{ .source = "255.255.255.255/32", .input = "255.255.255.255", .matched = true },
        .{ .source = "", .input = "1.2.3.4", .matched = false },
    };
    for (cases) |case| {
        var program = try addresses.compile(t.allocator, case.source, .{});
        defer program.deinit();
        var budget: work.Budget = .{ .remaining = 4096 };
        try t.expectEqual(case.matched, try program.contains(case.input, &budget));
    }
}

test "malformed prefix input and exhausted work fail rather than publishing a partial set" {
    for ([_][]const u8{
        "1.2.3",     " 1.2.3.4",        "1.2.3.4/",    "1.2.3.4/33",  "::1/129",
        "::1/+128",  "1.2.3.4/8junk",   "1.2.3.4/2/3", "1.2.3.4\x00", "fe80::1%en0",
        "010.1.2.3", "::ffff:01.2.3.4", "::1//128",    "1.2.3.4/-1",  "1.2.3.4/1.0",
    }) |invalid| {
        try t.expectError(error.InvalidPrefix, addresses.compile(t.allocator, invalid, .{}));
    }
    try t.expectError(error.SourceLimit, addresses.compile(t.allocator, "::1", .{ .bytes = 2 }));
    try t.expectError(
        error.PrefixLimit,
        addresses.compile(t.allocator, "::1", .{ .prefixes = 0 }),
    );
    try t.expectError(
        error.WorkLimit,
        addresses.compile(t.allocator, "::1", .{ .compile_work = 0 }),
    );
    var program = try addresses.compile(t.allocator, "::1", .{});
    defer program.deinit();
    var budget: work.Budget = .{ .remaining = 0 };
    try t.expectError(error.WorkLimit, program.contains("::2", &budget));
    try t.expectError(error.WorkLimit, program.containsAddress(addresses.parse("::2").?, &budget));
}

const Prefix = struct { address: addresses.Address, length: u8 };

fn oracle(prefix: Prefix, address: addresses.Address) bool {
    if (prefix.address.family != address.family) return false;
    const width: u8 = if (address.family == .ip4) 32 else 128;
    // Independent bit comparison, with no interval conversion or integer masks.
    for (0..prefix.length) |position| {
        const shift: u7 = @intCast(width - 1 - position);
        if ((prefix.address.value >> shift) & 1 != (address.value >> shift) & 1) return false;
    }
    return true;
}

fn appendPrefix(writer: *std.Io.Writer, prefix: Prefix) !void {
    const value = prefix.address.value;
    if (prefix.address.family == .ip4) {
        try writer.print("{d}.{d}.{d}.{d}/{d},", .{
            (value >> 24) & 255, (value >> 16) & 255, (value >> 8) & 255, value & 255,
            prefix.length,
        });
    } else {
        for (0..8) |position| {
            if (position != 0) try writer.writeByte(':');
            const shift: u7 = @intCast((7 - position) * 16);
            try writer.print("{x}", .{(value >> shift) & 65535});
        }
        try writer.print("/{d},", .{prefix.length});
    }
}

test "merged interval membership agrees with independent prefix oracle for randomized sets" {
    var random: std.Random.DefaultPrng = .init(0x6372736970736574);
    const rng = random.random();
    for (0..128) |_| {
        var prefixes: [24]Prefix = undefined;
        var storage: [2048]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&storage);
        for (&prefixes) |*entry| {
            const family: addresses.Family = if (rng.boolean()) .ip4 else .ip6;
            const width: u8 = if (family == .ip4) 32 else 128;
            entry.* = .{
                .address = .{ .family = family, .value = if (family == .ip4)
                    rng.int(u32)
                else
                    rng.int(u128) },
                .length = rng.intRangeAtMost(u8, 0, width),
            };
            try appendPrefix(&writer, entry.*);
        }
        var program = try addresses.compile(t.allocator, writer.buffered(), .{});
        defer program.deinit();
        for (0..128) |_| {
            const family: addresses.Family = if (rng.boolean()) .ip4 else .ip6;
            const address: addresses.Address = .{
                .family = family,
                .value = if (family == .ip4) rng.int(u32) else rng.int(u128),
            };
            var expected = false;
            for (prefixes) |entry| expected = expected or oracle(entry, address);
            var budget: work.Budget = .{ .remaining = 4096 };
            try t.expectEqual(expected, try program.containsAddress(address, &budget));
        }
    }
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var program = try addresses.compile(allocator, "127.0.0.1,::1,10.0.0.0/8,::/64", .{});
    defer program.deinit();
}

test "address compilation owns source and releases every partial allocation" {
    try t.checkAllAllocationFailures(t.allocator, allocationScenario, .{});
    var source = "127.0.0.1,::1".*;
    var program = try addresses.compile(t.allocator, &source, .{});
    defer program.deinit();
    @memset(&source, '?');
    var budget: work.Budget = .{ .remaining = 4096 };
    try t.expect(try program.contains("127.0.0.1", &budget));
    try t.expect(try program.contains("::1", &budget));
}
