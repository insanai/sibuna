const std = @import("std");
const options = @import("crs_options.zig");
const crs = @import("crs");
const t = std.testing;

test "CRS options preserve unrelated argv and disabled startup performs no preparation" {
    var remaining: [16][]const u8 = undefined;
    const input = &.{ "--port", "8080", "--no-crs", "--crs-dir", "/missing", "--waf" };
    const parsed = try options.parse(input, &remaining);
    try t.expectEqualSlices([]const u8, &.{ "--port", "8080", "--waf" }, parsed.remaining);
    try t.expectEqual(crs.config.Mode.off, parsed.config.choice.resolved());
    try parsed.config.validate(.request_metadata);
    try t.expectError(error.CrsArgumentBufferLimit, options.parse(input, remaining[0..1]));
}

test "CRS startup rejects conflicts, unobserved enforcement and invalid bounds" {
    var remaining: [16][]const u8 = undefined;
    for ([_][]const []const u8{
        &.{ "--crs", "--no-crs" },            &.{ "--no-crs", "--crs" },
        &.{ "--crs-mode", "audit", "--crs" },
    }) |input| try t.expectError(error.ConflictingMode, options.parse(input, &remaining));
    const missing = try options.parse(&.{"--crs"}, &remaining);
    try t.expectError(error.MissingArtifact, missing.config.validate(.request_response));
    const full = try options.parse(&.{ "--crs", "--crs-dir", "/rules" }, &remaining);
    try t.expectError(error.UnobservableProfile, full.config.validate(.request_metadata));
    const headers = try options.parse(&.{
        "--crs", "--crs-dir", "/rules", "--crs-profile", "headers",
    }, &remaining);
    try headers.config.validate(.request_metadata);
    for ([_][]const []const u8{
        &.{ "--crs-request-limit", "67108865" }, &.{ "--crs-response-limit", "0" },
        &.{ "--crs-slots", "32" },               &.{ "--crs-work-budget", "-1" },
        &.{ "--crs-work-budget", "1000000001" }, &.{ "--crs-paranoia", "5" },
        &.{ "--crs-timeout", "0" },              &.{ "--crs-timeout", "301" },
        &.{ "--crs-work-budget", "+12" },        &.{ "--crs-work-budget", "1x" },
        &.{ "--crs-inbound-threshold", "0" },    &.{ "--crs-outbound-threshold", "65536" },
    }) |input| try t.expectError(error.InvalidCrsLimit, options.parse(input, &remaining));
    try t.expectError(error.UnknownCrsOption, options.parse(&.{ "--crs-url", "x" }, &remaining));
    try t.expectError(error.MissingCrsValue, options.parse(&.{"--crs-dir"}, &remaining));
    try t.expectError(error.DuplicateCrsOption, options.parse(&.{
        "--crs-slots", "2", "--crs-slots", "2",
    }, &remaining));
}

test "startup overrides preserve signed identity and the independent Gate profile" {
    var remaining: [20][]const u8 = undefined;
    const parsed = try options.parse(&.{
        "--crs-mode",               "audit",
        "--crs-dir",                "/rules",
        "--crs-paranoia",           "3",
        "--crs-request-limit",      "8192",
        "--crs-work-budget",        "1000000",
        "--crs-slots",              "2",
        "--crs-inbound-threshold",  "9",
        "--crs-outbound-threshold", "8",
    }, &remaining);
    var selected: crs.generation.Options = .{
        .revision = 17,
        .activation = .{ .mode = .enforce },
        .observation = .request_response,
    };
    try parsed.config.validate(.request_response);
    try parsed.config.apply(&selected);
    try t.expectEqual(@as(u64, 17), selected.revision);
    try t.expectEqual(crs.config.Mode.audit, selected.activation.mode);
    try t.expectEqual(@as(u8, 3), selected.activation.blocking_paranoia);
    try t.expectEqual(@as(u8, 3), selected.activation.detection_paranoia);
    try t.expectEqual(@as(usize, 8192), selected.limits.request);
    try t.expectEqual(@as(u64, 1_000_000), selected.limits.work);
    try t.expectEqual(@as(usize, 2), selected.slots);
    try t.expectEqual(@as(u16, 9), selected.thresholds.inbound);
    try t.expectEqual(@as(u16, 8), selected.thresholds.outbound);
    const bad = try options.parse(&.{
        "--crs-paranoia", "3", "--crs-detection-paranoia", "2",
    }, &remaining);
    try t.expectError(error.DetectionBelowBlocking, bad.config.validate(.request_response));
}
