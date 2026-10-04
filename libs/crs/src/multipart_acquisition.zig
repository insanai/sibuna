//! Complete multipart entities, without temporary files or payload copies for
//! uploaded files. Rule selection sees metadata; raw-body selection sees the entity.
const std = @import("std");
const boundaries = @import("multipart_boundary.zig");
const heads = @import("multipart_head.zig");
const values = @import("acquired_values.zig");
const work = @import("work.zig");
const decimal = @import("decimal_format.zig");
pub const Error = boundaries.Error || heads.Error || values.Error || error{
    MultipartMissingBoundary,
    MultipartMissingClose,
    MultipartPartLimit,
    MultipartHeadLimit,
    InvalidMultipartLimits,
};
pub const Limits = struct { parts: usize = 256, head_bytes: usize = 8192 };

pub fn parse(
    input: []const u8,
    boundary: []const u8,
    builder: *values.Builder,
    scratch: heads.Scratch,
    limits: Limits,
    budget: *work.Budget,
) Error!void {
    errdefer builder.poison();
    if (limits.parts == 0 or limits.parts > 4096 or
        limits.head_bytes == 0 or limits.head_bytes > 64 * 1024)
        return error.InvalidMultipartLimits;
    var iterator: boundaries.Iterator = undefined;
    try iterator.init(input, boundary, budget);
    var delimiter = (try iterator.next()) orelse return error.MultipartMissingBoundary;
    var count: usize = 0;
    var file_bytes: u64 = 0;
    while (!delimiter.closing) {
        if (count == limits.parts) return error.MultipartPartLimit;
        count += 1;
        const next = (try iterator.next()) orelse return error.MultipartMissingClose;
        const part = input[delimiter.after..next.start];
        const bound = @min(part.len, limits.head_bytes + 4);
        try budget.debit(bound * 2 + 1);
        const end = std.mem.indexOf(u8, part[0..bound], "\r\n\r\n") orelse
            return error.MultipartHeadLimit;
        if (end > limits.head_bytes) return error.MultipartHeadLimit;
        const metadata = try heads.parse(part[0..end], scratch, budget);
        const payload = part[end + 4 ..];
        try recordHeaders(part[0..end], metadata.name, builder, budget);
        if (metadata.filename) |filename| {
            if (filename.len != 0) {
                try builder.named(.files, .files_names, .{
                    .key = metadata.name,
                    .value = filename,
                }, budget);
                file_bytes = std.math.add(u64, file_bytes, payload.len) catch
                    return error.AcquisitionByteLimit;
            } else try builder.field(.form, .{ .key = metadata.name, .value = payload }, budget);
        } else try builder.field(.form, .{ .key = metadata.name, .value = payload }, budget);
        delimiter = next;
    }
    var digits: [decimal.capacity(u64)]u8 = undefined;
    try builder.scalar(
        .files_combined_size,
        try decimal.write(u64, file_bytes, &digits, budget),
        budget,
    );
    try builder.sizes(budget);
    try builder.complete(&.{
        .files,                  .files_names, .files_combined_size,
        .multipart_part_headers, .args_post,   .args_post_names,
    });
}

fn recordHeaders(
    head: []const u8,
    name: []const u8,
    builder: *values.Builder,
    budget: *work.Budget,
) Error!void {
    try budget.debit(head.len + 1);
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        try builder.add(.multipart_part_headers, .{ .key = name, .value = line }, budget);
    }
}

test {
    _ = @import("multipart_acquisition_test.zig");
}
