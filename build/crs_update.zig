const std = @import("std");

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    crs: *std.Build.Module,
    net: *std.Build.Module,
) *std.Build.Module {
    const module = b.addModule("sibuna-crs-update", .{
        .root_source_file = b.path("libs/crs-update/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "crs", .module = crs },
            .{ .name = "net", .module = net },
        },
    });
    const tests = b.addTest(.{ .root_module = module });
    const step = b.step("crs-update-test", "Test bounded authenticated update preparation");
    step.dependOn(&b.addRunArtifact(tests).step);
    addCommandTest(b, step, target, crs, module);
    const startup = addStartupTest(b, target, crs, module);
    addArtifactCheck(b, target, crs, module, startup);
    b.top_level_steps.get("test").?.step.dependOn(step);
    return module;
}

fn addStartupTest(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    crs: *std.Build.Module,
    update: *std.Build.Module,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("apps/sibuna/src/crs_start.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "crs", .module = crs },
            .{ .name = "crs-update", .module = update },
        },
    });
    const tests = b.addTest(.{ .root_module = module });
    const step = b.step("crs-start-test", "Test strict CRS startup and disabled lifecycle");
    step.dependOn(&b.addRunArtifact(tests).step);
    b.top_level_steps.get("test").?.step.dependOn(step);
    return module;
}

fn addArtifactCheck(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    crs: *std.Build.Module,
    update: *std.Build.Module,
    startup: *std.Build.Module,
) void {
    const probe = b.addExecutable(.{
        .name = "sibuna-crs-artifact-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/crs_artifact_probe.zig"),
            .target = target,
            .optimize = .safe,
            .imports = &.{
                .{ .name = "crs", .module = crs },
                .{ .name = "crs-update", .module = update },
                .{ .name = "crs-start", .module = startup },
            },
        }),
    });
    const python = if (@import("builtin").os.tag == .windows) "python" else "python3";
    const check = b.addSystemCommand(&.{ python, "tools/crs_package_check.py" });
    check.addArtifactArg(probe);
    check.addPassthruArgs();
    b.step("crs-artifact-check", "Verify bounded disk reload against the signed stock package")
        .dependOn(&check.step);
}

fn addCommandTest(
    b: *std.Build,
    step: *std.Build.Step,
    target: std.Build.ResolvedTarget,
    crs: *std.Build.Module,
    update: *std.Build.Module,
) void {
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("apps/sibuna/src/crs_command.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "crs", .module = crs },
            .{ .name = "crs-update", .module = update },
        },
    }) });
    step.dependOn(&b.addRunArtifact(tests).step);
}
