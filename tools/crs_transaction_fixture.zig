//! Shared signed-package ownership and decision qualification.
const std = @import("std");
const crs = @import("crs");

pub fn evaluate(
    allocator: std.mem.Allocator,
    program: *const crs.rule_program.Program,
    configured: bool,
) !void {
    var slot: crs.transaction_slot.Slot = undefined;
    try slot.init(allocator, program, .{});
    defer slot.deinit();
    for ([_][]const u8{ "/?q=ordinary", "/?q=1%27%20OR%20%271%27=%271" }, 0..) |target, index| {
        var line: [256]u8 = undefined;
        var transaction = try crs.http_transaction.Transaction.begin(&slot, .full, true, .{
            .method = "GET",
            .target = target,
            .protocol = "HTTP/1.1",
            .line = try std.fmt.bufPrint(&line, "GET {s} HTTP/1.1", .{target}),
            .client = "192.0.2.1",
            .id = "package-probe",
            .headers = &.{
                .{ .name = "Host", .value = "example.test" },
                .{ .name = "User-Agent", .value = "Mozilla/5.0" },
                .{ .name = "Accept", .value = "text/html" },
            },
        });
        defer slot.finish();
        if (configured) {
            const marker = (try slot.store.get("operator_marker", &slot.budget)) orelse
                return error.OperatorMarkerMissing;
            if (!std.mem.eql(u8, marker, "present")) return error.OperatorMarkerMismatch;
        }
        const result = try transaction.requestBody("");
        if ((result == .denied) != (index == 1)) return error.PackageDecisionMismatch;
        if (index == 1) {
            const score = (try slot.store.get("sql_injection_score", &slot.budget)).?;
            if (try std.fmt.parseInt(i32, score, 10) < 5) return error.PackageDecisionMismatch;
            try transaction.finish(.local_response);
        } else {
            _ = try transaction.responseHeaders(.{ .status = 200, .headers = &.{} });
            _ = try transaction.responseBody("ordinary page");
            try transaction.finish(.inspected);
        }
    }
    try privateScenarios(allocator, program);
}

fn privateScenarios(allocator: std.mem.Allocator, program: *const crs.rule_program.Program) !void {
    var report: crs.scenario_contract.Report = undefined;
    var input: crs.scenario.Input = .{
        .allocator = allocator,
        .program = program,
        .execution = .{ .activation = .{ .mode = .enforce } },
        .sample = .{
            .request = .{
                .target = "/?q=ordinary",
                .headers = &.{
                    .{ .name = "Host", .value = "example.test" },
                    .{ .name = "User-Agent", .value = "Mozilla/5.0" },
                    .{ .name = "Accept", .value = "text/html" },
                },
            },
            .response = .{ .entity = .{ .body = "ordinary page" } },
        },
    };
    try crs.scenario.evaluate(input, &report);
    if (report.failure != null or report.denied or report.coverage != .inspected)
        return error.PrivateBenignScenarioMismatch;
    input.sample.request.target = "/?q=1%27%20OR%20%271%27=%271";
    try crs.scenario.evaluate(input, &report);
    if (report.failure != null or !report.denied or report.coverage != .local_response)
        return error.PrivateEnforcingScenarioMismatch;
    if ((report.inbound_score orelse return error.PrivateScoreMissing) < 5)
        return error.PrivateScoreMismatch;
    input.execution.activation.mode = .audit;
    try crs.scenario.evaluate(input, &report);
    if (report.failure != null or report.denied or !report.would_deny or
        report.coverage != .inspected) return error.PrivateAuditScenarioMismatch;
}
