//! Owned Boolean CIDR sets. SID 0010 proves interval merging and family isolation.
//! Unlike policy routing, IPv4 and IPv4-mapped IPv6 never share a key space.
const std = @import("std");
const work = @import("work.zig");

pub const Error = std.mem.Allocator.Error || work.Error || error{
    SourceLimit,
    PrefixLimit,
    InvalidPrefix,
};
pub const Options = struct {
    bytes: usize = 64 * 1024,
    prefixes: usize = 4096,
    compile_work: u64 = 4_000_000,
};
const literal = @import("address_parse.zig");
pub const Family = literal.Family;
pub const Address = literal.Address;
pub const parse = literal.parse;
const Interval = struct { family: Family, first: u128, last: u128 };

pub const Program = struct {
    owner: std.heap.ArenaAllocator,
    intervals: []const Interval,

    pub fn deinit(self: *Program) void {
        self.owner.deinit();
        self.* = undefined;
    }

    pub fn contains(self: *const Program, text: []const u8, budget: *work.Budget) Error!bool {
        // All accepted literals are at most 45 bytes. Eight visits per byte
        // covers family selection, delimiter scans and the pure numeric parser.
        try budget.debit(1);
        if (text.len > 45) return false;
        try budget.debit(@as(u64, @intCast(text.len)) * 8);
        const address = parse(text) orelse return false;
        return self.containsAddress(address, budget);
    }

    pub fn containsAddress(
        self: *const Program,
        address: Address,
        budget: *work.Budget,
    ) Error!bool {
        std.debug.assert(address.family != .ip4 or address.value <= std.math.maxInt(u32));
        var left: usize = 0;
        var right = self.intervals.len;
        while (left < right) {
            try budget.debit(3);
            const middle = left + (right - left) / 2;
            const candidate = self.intervals[middle];
            const precedes = @backingInt(candidate.family) < @backingInt(address.family) or
                (candidate.family == address.family and candidate.first <= address.value);
            if (precedes) left = middle + 1 else right = middle;
        }
        try budget.debit(2);
        if (left == 0) return false;
        const candidate = self.intervals[left - 1];
        return candidate.family == address.family and address.value <= candidate.last;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    source: []const u8,
    options: Options,
) Error!Program {
    if (source.len > options.bytes) return error.SourceLimit;
    var budget: work.Budget = .{ .remaining = options.compile_work };
    // Charge delimiter/comment scans and validation before reading any source.
    const scan_work = std.math.mul(u64, @intCast(source.len), 4) catch return error.WorkLimit;
    try budget.debit(std.math.add(u64, scan_work, 1) catch return error.WorkLimit);
    if (std.mem.indexOfScalar(u8, source, 0) != null) return error.InvalidPrefix;
    var entries: std.ArrayList(Interval) = .empty;
    defer entries.deinit(allocator);
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const end = std.mem.indexOfScalar(u8, line, '#') orelse line.len;
        var tokens = std.mem.tokenizeScalar(u8, line[0..end], ',');
        while (tokens.next()) |token| {
            if (entries.items.len == options.prefixes) return error.PrefixLimit;
            try budget.debit(@as(u64, @intCast(@min(token.len, 49))) * 8 + 1);
            try entries.append(allocator, try prefix(token));
        }
    }
    const scratch = try allocator.alloc(Interval, entries.items.len);
    defer allocator.free(scratch);
    try sort(entries.items, scratch, &budget);
    const count = try merge(entries.items, &budget);
    var owner = std.heap.ArenaAllocator.init(allocator);
    errdefer owner.deinit();
    try budget.debit(@intCast(count));
    const intervals = try owner.allocator().dupe(Interval, entries.items[0..count]);
    return .{ .owner = owner, .intervals = intervals };
}

fn prefix(text: []const u8) Error!Interval {
    if (text.len > 49) return error.InvalidPrefix;
    const slash = std.mem.indexOfScalar(u8, text, '/');
    const address = parse(text[0 .. slash orelse text.len]) orelse return error.InvalidPrefix;
    const width: u8 = if (address.family == .ip4) 32 else 128;
    var length = width;
    if (slash) |position| {
        const digits = text[position + 1 ..];
        if (digits.len == 0 or digits.len > 3) return error.InvalidPrefix;
        length = 0;
        for (digits) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidPrefix;
            const next = @as(u16, length) * 10 + byte - '0';
            if (next > width) return error.InvalidPrefix;
            length = @intCast(next);
        }
    }
    const host: u128 = if (width - length == 128)
        std.math.maxInt(u128)
    else
        (@as(u128, 1) << @intCast(width - length)) - 1;
    return .{
        .family = address.family,
        .first = address.value & ~host,
        .last = address.value | host,
    };
}

fn before(left: Interval, right: Interval) bool {
    if (left.family != right.family) {
        return @backingInt(left.family) < @backingInt(right.family);
    }
    return left.first < right.first;
}

fn mergeRuns(
    input: []const Interval,
    output: []Interval,
    middle: usize,
    budget: *work.Budget,
) Error!void {
    var left: usize = 0;
    var right = middle;
    for (output) |*entry| {
        try budget.debit(4);
        if (left < middle and (right == input.len or before(input[left], input[right]))) {
            entry.* = input[left];
            left += 1;
        } else {
            entry.* = input[right];
            right += 1;
        }
    }
    std.debug.assert(left == middle and right == input.len);
}

fn sort(entries: []Interval, scratch: []Interval, budget: *work.Budget) Error!void {
    std.debug.assert(entries.len == scratch.len);
    var width: usize = 1;
    while (width < entries.len) {
        var offset: usize = 0;
        while (offset < entries.len) {
            const middle = offset + @min(width, entries.len - offset);
            const end = middle + @min(width, entries.len - middle);
            try mergeRuns(entries[offset..end], scratch[offset..end], middle - offset, budget);
            offset = end;
        }
        try budget.debit(@intCast(entries.len));
        @memcpy(entries, scratch);
        if (width > entries.len / 2) break;
        width *= 2;
    }
}

fn merge(entries: []Interval, budget: *work.Budget) Error!usize {
    var count: usize = 0;
    for (entries) |entry| {
        try budget.debit(4);
        if (count > 0) {
            const prior = &entries[count - 1];
            // Saturating successor handles the top IPv6 address without overflow.
            if (prior.family == entry.family and entry.first <= prior.last +| 1) {
                prior.last = @max(prior.last, entry.last);
                continue;
            }
        }
        entries[count] = entry;
        count += 1;
    }
    return count;
}

test {
    _ = @import("address_set_test.zig");
}
