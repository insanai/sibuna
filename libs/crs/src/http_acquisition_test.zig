const std = @import("std");
const http = @import("http_acquisition.zig");
const acquired = @import("acquired_values.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");
const Header = @import("text").http_fields.Header;

fn input(target: []const u8, headers: []const Header) http.Request {
    return .{
        .method = "GET",
        .target = target,
        .protocol = "HTTP/1.1",
        .line = "GET / HTTP/1.1",
        .client = "2001:db8::1",
        .id = "transaction-1",
        .headers = headers,
    };
}

fn lookup(builder: *acquired.Builder, collection: variables.Collection) ![]const u8 {
    var budget: work.Budget = .{ .remaining = 100000 };
    return (try builder.view()).lookup(.{ .collection = collection }, &budget);
}

test "HTTP metadata keeps decoded URI delimiters distinct from query parsing" {
    var entries: [96]variables.Entry = undefined;
    var bytes: [4096]u8 = undefined;
    var key: [1024]u8 = undefined;
    var value: [1024]u8 = undefined;
    var builder = acquired.Builder.init(&entries, &bytes);
    var budget: work.Budget = .{ .remaining = 100000 };
    const target = "/a%3fb+c?q=x%26y&q=second#fragment";
    try http.request(
        input(target, &.{}),
        &builder,
        .{ .key = &key, .value = &value },
        &budget,
    );
    try std.testing.expectEqualStrings("/a?b+c", try lookup(&builder, .request_filename));
    try std.testing.expectEqualStrings("a?b+c", try lookup(&builder, .request_basename));
    try std.testing.expectEqualStrings(
        "/a?b+c?q=x&y&q=second",
        try lookup(&builder, .request_uri),
    );
    try std.testing.expectEqualStrings(target, try lookup(&builder, .request_uri_raw));
    try std.testing.expectEqualStrings("q=x%26y&q=second", try lookup(&builder, .query_string));
    var args: usize = 0;
    for ((try builder.view()).entries) |entry| {
        if (entry.collection != .args) continue;
        try std.testing.expectEqualStrings("q", entry.key);
        try std.testing.expectEqualStrings(if (args == 0) "x&y" else "second", entry.value);
        args += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), args);
    try (try builder.view()).require(.args_post);
    try std.testing.expectError(error.UnavailableCollection, (try builder.view()).require(.xml));
    try std.testing.expectError(
        error.UnavailableCollection,
        (try builder.view()).require(.response_body),
    );
}

test "cookies preserve reference whitespace, bare keys, duplicates and binary values" {
    var entries: [96]variables.Entry = undefined;
    var bytes: [4096]u8 = undefined;
    var key: [1024]u8 = undefined;
    var value: [1024]u8 = undefined;
    var builder = acquired.Builder.init(&entries, &bytes);
    var budget: work.Budget = .{ .remaining = 100000 };
    const headers = [_]Header{
        .{ .name = "Cookie", .value = ";; first = a=b ;bare; =skip;last=\"x\"  " },
        .{ .name = "cookie", .value = "first=duplicate;binary=x\x00y" },
        .{ .name = "X-Duplicate", .value = "one" },
        .{ .name = "X-Duplicate", .value = "two" },
    };
    try http.request(input("/", &headers), &builder, .{ .key = &key, .value = &value }, &budget);
    const expected = [_]acquired.Record{
        .{ .key = "first ", .value = " a=b " },
        .{ .key = "bare", .value = "" },
        .{ .key = "last", .value = "\"x\"" },
        .{ .key = "first", .value = "duplicate" },
        .{ .key = "binary", .value = "x\x00y" },
    };
    var count: usize = 0;
    for ((try builder.view()).entries) |entry| {
        if (entry.collection != .request_cookies) continue;
        try std.testing.expectEqualStrings(expected[count].key, entry.key);
        try std.testing.expectEqualStrings(expected[count].value, entry.value);
        count += 1;
    }
    try std.testing.expectEqual(expected.len, count);
    try std.testing.expectEqualStrings("", try lookup(&builder, .reqbody_processor));
}

test "absolute URI metadata and media processor are acquired before phase one" {
    var entries: [64]variables.Entry = undefined;
    var bytes: [2048]u8 = undefined;
    var key: [512]u8 = undefined;
    var value: [512]u8 = undefined;
    var builder = acquired.Builder.init(&entries, &bytes);
    var budget: work.Budget = .{ .remaining = 100000 };
    const headers = [_]Header{.{
        .name = "Content-Type",
        .value = "Application/X-Www-Form-Urlencoded; charset=utf-8",
    }};
    const target = "https://example.test/a?q=x";
    try http.request(
        input(target, &headers),
        &builder,
        .{ .key = &key, .value = &value },
        &budget,
    );
    try std.testing.expectEqualStrings("/a?q=x", try lookup(&builder, .request_uri));
    try std.testing.expectEqualStrings("https://example.test/a", try lookup(
        &builder,
        .request_filename,
    ));
    try std.testing.expectEqualStrings("URLENCODED", try lookup(&builder, .reqbody_processor));
}

test "metadata refuses malformed escapes, ambiguous media and exhausted acquisition" {
    var entries: [64]variables.Entry = undefined;
    var bytes: [2048]u8 = undefined;
    var key: [512]u8 = undefined;
    var value: [512]u8 = undefined;
    const scratch: @import("form_acquisition.zig").Scratch = .{ .key = &key, .value = &value };
    var builder = acquired.Builder.init(&entries, &bytes);
    var budget: work.Budget = .{ .remaining = 100000 };
    try std.testing.expectError(
        error.InvalidPercentEscape,
        http.request(input("/bad%zz", &.{}), &builder, scratch, &budget),
    );
    try std.testing.expectError(error.AcquisitionFailed, builder.view());
    builder = acquired.Builder.init(&entries, &bytes);
    const headers = [_]Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    try std.testing.expectError(
        error.AmbiguousContentType,
        http.request(input("/", &headers), &builder, scratch, &budget),
    );
    try std.testing.expectError(error.AcquisitionFailed, builder.view());
    builder = acquired.Builder.init(entries[0..3], &bytes);
    try std.testing.expectError(
        error.AcquisitionEntryLimit,
        http.request(input("/", &.{}), &builder, scratch, &budget),
    );
    builder = acquired.Builder.init(&entries, &bytes);
    budget.remaining = 0;
    try std.testing.expectError(
        error.WorkLimit,
        http.request(input("/", &.{}), &builder, scratch, &budget),
    );
    try std.testing.expectError(error.AcquisitionFailed, builder.view());
}
