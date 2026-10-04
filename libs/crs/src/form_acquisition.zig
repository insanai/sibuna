//! Complete, length-aware URL-encoded fields. Scratch is caller-owned and may be
//! reused after each field because the builder owns immutable copies and aliases.
const std = @import("std");
const values = @import("acquired_values.zig");
const decode = @import("percent_decode.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = values.Error || decode.Error || error{InvalidFormOrigin};
pub const Scratch = struct { key: []u8, value: []u8 };

pub fn parse(
    input: []const u8,
    origin: values.Origin,
    builder: *values.Builder,
    scratch: Scratch,
    budget: *work.Budget,
) Error!void {
    errdefer builder.poison();
    if (origin == .json) return error.InvalidFormOrigin;
    buffers.assertExclusive(&.{ input, scratch.key, scratch.value, builder.bytes });
    const cost = std.math.mul(u64, input.len, 2) catch return error.WorkLimit;
    try budget.debit(std.math.add(u64, cost, 1) catch return error.WorkLimit);
    var cursor: usize = 0;
    while (cursor < input.len) {
        const end = if (std.mem.indexOfScalar(u8, input[cursor..], '&')) |relative|
            cursor + relative
        else
            input.len;
        const pair = input[cursor..end];
        const equal = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const raw_value = if (equal == pair.len) "" else pair[equal + 1 ..];
        const key = try decode.decode(pair[0..equal], scratch.key, true, budget);
        const value = try decode.decode(raw_value, scratch.value, true, budget);
        try builder.field(origin, .{ .key = key, .value = value }, budget);
        if (end == input.len) break;
        cursor = end + 1;
    }
    switch (origin) {
        .query => try builder.complete(&.{ .args_get, .args_get_names }),
        .form => try builder.complete(&.{ .args_post, .args_post_names }),
        .json => unreachable,
    }
    // ARGS is completed only after all contributing processors finish, not here.
    try builder.sizes(budget);
}

test {
    _ = @import("form_acquisition_test.zig");
}
