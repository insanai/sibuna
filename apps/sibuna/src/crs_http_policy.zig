//! HTTP connector restrictions are checked off-path before pool publication.
//! The pure executor retains SecLang's numeric status semantics for comparison.
const crs = @import("crs");
const std = @import("std");
pub const Error = error{UnsupportedInterventionStatus};

pub fn validate(
    program: *const crs.rule_program.Program,
    activation: crs.config.Activation,
) Error!void {
    if (activation.mode != .enforce) return;
    for (program.actions) |action| {
        if (action.phase == .logging or !activation.observes(action.phase)) continue;
        for (action.steps) |step| switch (step) {
            .status => |code| {
                // A status can survive a passing rule and affect a later denial.
                // 200 is the native default, converted to 403 by deny itself.
                if (code != 200 and (code < 400 or code > 599))
                    return error.UnsupportedInterventionStatus;
            },
            else => {},
        };
    }
}

test "enforcing HTTP activation refuses nonterminal intervention statuses before publication" {
    const t = std.testing;
    const source =
        \\SecAction "id:1,phase:1,pass,status:302"
        \\SecAction "id:2,phase:2,deny"
    ;
    var compiler = crs.compiler.Compiler.init(t.allocator, .{});
    defer compiler.deinit();
    try compiler.addSource("operator.conf", source);
    var plan = try compiler.finish();
    defer plan.deinit();
    var program = try crs.rule_program.compile(t.allocator, &plan, &.{}, .{});
    defer program.deinit();
    const enforcing = validate(&program, .{ .mode = .enforce });
    try t.expectError(error.UnsupportedInterventionStatus, enforcing);
    try validate(&program, .{ .mode = .audit });
    try validate(&program, .{ .mode = .off });
}
