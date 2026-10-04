const std = @import("std");
const stock = @import("stock_test_support.zig");
const slots = @import("transaction_slot.zig");
const http = @import("http_transaction.zig");
const Result = @import("executor.zig").Result;

test "pinned stock generation evaluates benign and malicious complete HTTP transactions" {
    var program = try stock.prepare();
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(std.testing.allocator, &program, .{});
    defer slot.deinit();
    const cases = [_]struct { target: []const u8, score: ?[]const u8 = null }{
        .{ .target = "/index?q=ordinary" },
        .{ .target = "/index?q=1%27%20OR%20%271%27=%271", .score = "sql_injection_score" },
        .{ .target = "/index?q=%3Cscript%3Ealert(1)%3C/script%3E", .score = "xss_score" },
    };
    for (cases) |case| {
        var line: [1024]u8 = undefined;
        var transaction = try http.Transaction.begin(&slot, .full, true, .{
            .method = "GET",
            .target = case.target,
            .protocol = "HTTP/1.1",
            .line = try std.fmt.bufPrint(&line, "GET {s} HTTP/1.1", .{case.target}),
            .client = "192.0.2.1",
            .id = "stock-transaction",
            .headers = &.{
                .{ .name = "Host", .value = "example.test" },
                .{ .name = "User-Agent", .value = "Mozilla/5.0" },
                .{ .name = "Accept", .value = "text/html" },
            },
        });
        const result = if (slot.state.denied) Result.denied else try transaction.requestBody("");
        try std.testing.expectEqual(case.score != null, result == .denied);
        if (case.score) |name| {
            const score = (try slot.store.get(name, &slot.budget)).?;
            try std.testing.expect((try std.fmt.parseInt(i32, score, 10)) >= 5);
            try transaction.finish(.local_response);
        } else {
            try std.testing.expectEqual(Result.complete, try transaction.responseHeaders(.{
                .status = 200,
                .headers = &.{.{ .name = "Content-Type", .value = "text/html" }},
            }));
            try std.testing.expectEqual(Result.complete, try transaction.responseBody(
                "<!doctype html><title>Ordinary page</title>",
            ));
            try transaction.finish(.inspected);
        }
        try std.testing.expect(!slot.state.failed);
        slot.finish();
    }
}
