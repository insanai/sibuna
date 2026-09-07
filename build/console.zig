const std = @import("std");

pub const Modules = struct {
    protocol: *std.Build.Module,
    console: *std.Build.Module,
};

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Modules {
    const protocol = b.addModule("console-protocol", .{
        .root_source_file = b.path("libs/console-protocol/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const console = b.addModule("sibuna-console", .{
        .root_source_file = b.path("libs/console/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "console_protocol", .module = protocol }},
    });
    const serve = b.addModule("sibuna-serve", .{
        .root_source_file = b.path("libs/serve/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    console.addImport("serve", serve);
    addUi(b, protocol, console);
    addAssets(b);
    addGeoCheck(b, console);
    const step = b.step("console-test", "Test console contracts and bounded ownership");
    step.dependOn(&b.top_level_steps.get("console-render-test").?.step);
    step.dependOn(&b.top_level_steps.get("console-assets-check").?.step);
    for ([_]*std.Build.Module{ protocol, console, serve }) |module| {
        const tests = b.addTest(.{ .root_module = module });
        step.dependOn(&b.addRunArtifact(tests).step);
    }
    // Compile the same protocol for the browser without importing native service code.
    const wasm = b.addObject(.{
        .name = "console-protocol-wasm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("libs/console-protocol/src/root.zig"),
            .target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
            .optimize = .ReleaseSmall,
        }),
    });
    step.dependOn(&wasm.step);
    return .{ .protocol = protocol, .console = console };
}

fn addUi(b: *std.Build, protocol: *std.Build.Module, console: *std.Build.Module) void {
    const target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_protocol = b.createModule(.{
        .root_source_file = b.path("libs/console-protocol/src/root.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
    });
    const wasm = b.addExecutable(.{
        .name = "console",
        .root_module = b.createModule(.{
            .root_source_file = b.path("apps/console-ui/src/main.zig"),
            .target = target,
            .optimize = .ReleaseSmall,
            .imports = &.{.{ .name = "console_protocol", .module = wasm_protocol }},
        }),
    });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    wasm.stack_size = 256 * 1024;
    console.addAnonymousImport("console_wasm", .{ .root_source_file = wasm.getEmittedBin() });
    const paths = .{ "shell.html", "glue.js", "assets/console.css" };
    const names = .{ "console_shell", "console_glue", "console_css" };
    inline for (paths, names) |path, name| {
        console.addAnonymousImport(name, .{
            .root_source_file = b.path("apps/console-ui/web/" ++ path),
        });
    }
    console.addAnonymousImport("console_world", .{
        .root_source_file = b.path("apps/console-ui/web/assets/world-110m.bin"),
    });
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("apps/console-ui/src/main.zig"),
        .target = b.graph.host,
        .imports = &.{.{ .name = "console_protocol", .module = protocol }},
    }) });
    const step = b.step("console-ui", "Build the Zig console WebAssembly interface");
    step.dependOn(&wasm.step);
    const render_step = b.step("console-render-test", "Test native console rendering");
    render_step.dependOn(&b.addRunArtifact(tests).step);
}

fn addAssets(b: *std.Build) void {
    const assets = b.step(
        "console-assets",
        "Regenerate pinned console CSS and digests (needs npm)",
    );
    const build = b.addSystemCommand(&.{ "python3", "tools/console_assets.py", "build" });
    assets.dependOn(&build.step);
    const check = b.step("console-assets-check", "Verify committed console assets without npm");
    const verify = b.addSystemCommand(&.{ "python3", "tools/console_assets.py", "check" });
    check.dependOn(&verify.step);
}

fn addGeoCheck(b: *std.Build, console: *std.Build.Module) void {
    const executable = b.addExecutable(.{
        .name = "console-geoip-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/console_geoip_check.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "console", .module = console }},
        }),
    });
    const run = b.addRunArtifact(executable);
    if (b.args) |args| run.addArgs(args);
    b.step("console-geoip-check", "Validate a downloaded DB-IP country gzip").dependOn(&run.step);
}
