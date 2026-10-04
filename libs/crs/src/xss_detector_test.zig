const std = @import("std");
const detector = @import("xss_detector.zig");
const profile = @import("xss_profile.zig");
const work = @import("work.zig");
const t = std.testing;

test "XSS contexts detect tags URL encoding and event values with bounded failures" {
    const samples = [_]struct { []const u8, bool }{
        .{ "<script>alert(1)</script>", true },
        .{ "<a href='&#106;avascript:alert(1)'>", true },
        .{ "<a onclick='alert(1)'>", true },
        .{ "<a style=''>", true },
        .{ "<a onclick>", false },
        .{ "<a href='https://example.com'>", false },
        .{ "' ><iframe>", true },
        .{ "hello world", false },
        .{ "", false },
    };
    for (samples) |sample| {
        var budget: work.Budget = .{ .remaining = 1_000_000 };
        var context: detector.Context = .{ .input = sample[0], .budget = &budget };
        try t.expectEqual(sample[1], try detector.detect(&context));
        budget.remaining = 0;
        try t.expectError(error.WorkLimit, detector.detect(&context));
        budget.remaining = 1_000_000;
        try t.expectError(error.WorkLimit, detector.detect(&context));
    }
}

test "short HTML entities and event names never borrow bytes beyond their field" {
    for ([_][]const u8{ "&", "&#", "&#x", "&#X", "&#q", "&#xq", "&#9999999999;" }) |value| {
        var budget: work.Budget = .{ .remaining = 1000 };
        try t.expect(!try profile.url(value, &budget));
    }
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    try t.expectEqual(profile.Attribute.none, try profile.attribute("onlo", &budget));
    try t.expectEqual(profile.Attribute.black, try profile.attribute("onloadextra", &budget));
    try t.expect(try profile.url("&#x1004a;ava", &budget));
}
