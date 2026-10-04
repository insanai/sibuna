const std = @import("std");

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
) void {
    _ = b.addModule("sibuna-crs", .{
        .root_source_file = b.path("libs/crs/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const host = b.createModule(.{
        .root_source_file = b.path("libs/crs/src/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const fixture = b.createModule(.{
        .root_source_file = b.path("vendor/crs/fixture.zig"),
    });
    host.addImport("crs-fixture", fixture);
    const tests = b.addTest(.{ .root_module = host });
    const test_step = b.step("crs-test", "Test bounded native CRS source contracts");
    test_step.dependOn(&b.addRunArtifact(tests).step);
    b.top_level_steps.get("test").?.step.dependOn(test_step);
    const audit = b.addExecutable(.{
        .name = "sibuna-crs-audit",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/crs_audit.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "crs", .module = host }},
        }),
    });
    addRegexCheck(b, host, fixture);
    const run = b.addRunArtifact(audit);
    run.addPassthruArgs();
    b.step("crs-audit", "Inventory an extracted CRS release; does not activate rules")
        .dependOn(&run.step);
}

fn addRegexCheck(
    b: *std.Build,
    crs: *std.Build.Module,
    fixture: *std.Build.Module,
) void {
    const probe = b.addExecutable(.{
        .name = "sibuna-crs-regex-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/crs_regex_probe.zig"),
            .target = b.graph.host,
            .optimize = .safe,
            .imports = &.{
                .{ .name = "crs", .module = crs },
                .{ .name = "crs-fixture", .module = fixture },
            },
        }),
    });
    const python = if (@import("builtin").os.tag == .windows) "python" else "python3";
    const check = b.addSystemCommand(&.{ python, "tools/crs_regex_check.py" });
    check.addArtifactArg(probe);
    b.step("crs-regex-check", "Compare native regex matches and captures against PCRE2")
        .dependOn(&check.step);
}
