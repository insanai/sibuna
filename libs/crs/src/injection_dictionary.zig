//! Immutable libinjection dictionary, pinned and reproduced by crs_detector_data.py.
//! Copyright (c) 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const std = @import("std");
const work = @import("work.zig");
const asset = @import("libinjection-data").bytes;

pub const count = 9352;
const header_size = 12;
const entry_size = 8;
const payload_start = header_size + count * entry_size;
pub const Kind = enum(u8) {
    none = 0,
    keyword = 'k',
    sql_union = 'U',
    group = 'B',
    expression = 'E',
    sql_type = 't',
    function = 'f',
    bareword = 'n',
    number = '1',
    variable = 'v',
    string = 's',
    operator = 'o',
    logical = '&',
    comment = 'c',
    collate = 'A',
    left_paren = '(',
    right_paren = ')',
    left_brace = '{',
    right_brace = '}',
    dot = '.',
    comma = ',',
    colon = ':',
    semicolon = ';',
    tsql = 'T',
    unknown = '?',
    evil = 'X',
    fingerprint = 'F',
    backslash = '\\',
};

comptime {
    @setEvalBranchQuota(4_000_000);
    if (!validate(asset)) @compileError("invalid pinned native SQL dictionary");
}

/// Validation is off-path, bounded to the pinned asset. Canonical contiguous offsets
/// prevent aliasing, hidden payload and pointers beyond the immutable byte owner.
pub fn validate(bytes: []const u8) bool {
    if (bytes.len != 133433 or !std.mem.eql(u8, bytes[0..8], "SBSQ001\x00")) return false;
    if (std.mem.readInt(u32, bytes[8..12], .little) != count) return false;
    var offset: usize = 0;
    var previous: []const u8 = "";
    for (0..count) |index| {
        const record = bytes[header_size + index * entry_size ..][0..entry_size];
        const position = std.mem.readInt(u32, record[0..4], .little);
        const length = std.mem.readInt(u16, record[4..6], .little);
        if (position != offset or length == 0 or length > 29 or record[7] != 0) return false;
        if (length > bytes.len - payload_start - offset) return false;
        const key = bytes[payload_start + offset ..][0..length];
        for (key) |byte| {
            if (byte == 0 or byte >= 128 or std.ascii.toUpper(byte) != byte) return false;
        }
        if (std.mem.order(u8, previous, key) != .lt) return false;
        if (std.mem.indexOfScalar(u8, "FfktonTvEUB1&A", record[6]) == null) return false;
        offset += length;
        previous = key;
    }
    return offset == bytes.len - payload_start;
}

const Entry = struct { key: []const u8, kind: Kind };

fn entry(index: usize) Entry {
    std.debug.assert(index < count);
    const record = asset[header_size + index * entry_size ..][0..entry_size];
    const offset = std.mem.readInt(u32, record[0..4], .little);
    const length = std.mem.readInt(u16, record[4..6], .little);
    return .{
        .key = asset[payload_start + offset ..][0..length],
        .kind = @fromBackingInt(@intCast(record[6])),
    };
}

fn compare(key: []const u8, input: []const u8, budget: *work.Budget) work.Error!std.math.Order {
    for (0..@min(key.len, input.len)) |index| {
        try budget.debit(1);
        const order = std.math.order(key[index], std.ascii.toUpper(input[index]));
        if (order != .eq) return order;
    }
    try budget.debit(1);
    return std.math.order(key.len, input.len);
}

pub fn lookup(input: []const u8, budget: *work.Budget) work.Error!Kind {
    try budget.debit(1);
    if (input.len == 0 or input.len > 29) return .none;
    for (input) |byte| {
        try budget.debit(1);
        if (byte == 0 or byte >= 128) return .none;
    }
    var left: usize = 0;
    var right: usize = count;
    while (left < right) {
        try budget.debit(1);
        const middle = left + (right - left) / 2;
        const candidate = entry(middle);
        switch (try compare(candidate.key, input, budget)) {
            .lt => left = middle + 1,
            .gt => right = middle,
            .eq => return candidate.kind,
        }
    }
    return .none;
}

test "every pinned SQL dictionary entry round trips through folded bounded lookup" {
    for (0..count) |index| {
        const candidate = entry(index);
        var lower: [29]u8 = undefined;
        for (candidate.key, lower[0..candidate.key.len]) |byte, *out| {
            out.* = std.ascii.toLower(byte);
        }
        var budget: work.Budget = .{ .remaining = 1024 };
        try std.testing.expectEqual(candidate.kind, try lookup(candidate.key, &budget));
        try std.testing.expectEqual(
            candidate.kind,
            try lookup(lower[0..candidate.key.len], &budget),
        );
    }
    const absent = [_][]const u8{
        "", "SELECT\x00", "\xffSELECT", "nonexistent_dictionary_keyword",
    };
    for (absent) |key| {
        var budget: work.Budget = .{ .remaining = 1024 };
        try std.testing.expectEqual(Kind.none, try lookup(key, &budget));
    }
    var exhausted: work.Budget = .{ .remaining = 0 };
    try std.testing.expectError(error.WorkLimit, lookup("SELECT", &exhausted));
}

test "native SQL dictionary retains its exact pinned generated digest and rejects corruption" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(asset, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectEqualStrings(
        "d605afb245c66a19b97d58cc3daa87fd389be8d8249637aa3f7dd7d7908c2125",
        &hex,
    );
    const copy = try std.testing.allocator.dupe(u8, asset);
    defer std.testing.allocator.free(copy);
    for ([_]usize{ 0, 8, 12, 18, 19, payload_start }) |position| {
        copy[position] ^= 255;
        try std.testing.expect(!validate(copy));
        copy[position] ^= 255;
    }
    try std.testing.expect(!validate(copy[0 .. copy.len - 1]));
}
