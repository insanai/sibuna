const std = @import("std");
const python = if (@import("builtin").os.tag == .windows) "python" else "python3";

pub const Modules = struct {
    protocol: *std.Build.Module,
    console: *std.Build.Module,
};

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    geoip_data: ?[]const u8,
    socket: *std.Build.Module,
) Modules {
    const protocol = b.addModule("console-protocol", .{
        .root_source_file = b.path("libs/console-protocol/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    protocol.addImport("security-evidence", b.modules.get("security-evidence").?);
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
    serve.addImport("socket", socket);
    const html = htmlModule(b, target, optimize);
    const geoip = @import("geoip.zig").add(b, target, optimize);
    console.addImport("serve", serve);
    console.addImport("geoip", geoip);
    console.addAnonymousImport("geoip_snapshot", .{
        .root_source_file = @import("geoip.zig").snapshot(b, geoip_data),
    });
    addUi(b, protocol, console);
    addAssets(b);
    @import("geoip.zig").addTools(b, geoip);
    const step = b.step("console-test", "Test console contracts and bounded ownership");
    step.dependOn(&b.top_level_steps.get("console-ui").?.step);
    step.dependOn(&b.top_level_steps.get("console-render-test").?.step);
    step.dependOn(&b.top_level_steps.get("console-golden-check").?.step);
    step.dependOn(&b.top_level_steps.get("console-assets-check").?.step);
    const abi_test = b.addSystemCommand(&.{ python, "tools/console_wasm_check_test.py" });
    step.dependOn(&abi_test.step);
    for ([_]*std.Build.Module{ protocol, console, serve, html, geoip }) |module| {
        const tests = b.addTest(.{ .root_module = module });
        step.dependOn(&b.addRunArtifact(tests).step);
    }
    // Compile the same protocol for the browser without importing native service code.
    const wasm = b.addObject(.{
        .name = "console-protocol-wasm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("libs/console-protocol/src/root.zig"),
            .target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
            .optimize = .small,
        }),
    });
    wasm.root_module.addImport("text", b.modules.get("sibuna-text").?);
    const browser = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    wasm.root_module.addImport("security-evidence", evidenceModule(b, browser));
    step.dependOn(&wasm.step);
    return .{ .protocol = protocol, .console = console };
}

fn addUi(b: *std.Build, protocol: *std.Build.Module, console: *std.Build.Module) void {
    const target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_protocol = b.createModule(.{
        .root_source_file = b.path("libs/console-protocol/src/root.zig"),
        .target = target,
        .optimize = .small,
    });
    const wasm = b.addObject(.{
        .name = "console",
        .root_module = b.createModule(.{
            .root_source_file = b.path("apps/console-ui/src/main.zig"),
            .target = target,
            .optimize = .small,
            .imports = &.{.{ .name = "console_protocol", .module = wasm_protocol }},
        }),
    });
    wasm_protocol.addImport("text", b.modules.get("sibuna-text").?);
    wasm_protocol.addImport("security-evidence", evidenceModule(b, target));
    wasm.root_module.addImport("text", b.modules.get("sibuna-text").?);
    wasm.root_module.addImport("html", htmlModule(b, target, .small));
    wasm.bundle_compiler_rt = true;
    const artifact = linkUi(b, wasm);
    const size = b.addSystemCommand(&.{ python, "tools/console_wasm_check.py" });
    size.addFileArg(artifact);
    const checked = size.addOutputFileArg("console.wasm");
    // Every embedding build consumes verified bytes, including ordinary daemon builds.
    console.addAnonymousImport("console_wasm", .{ .root_source_file = checked });
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
    tests.root_module.addImport("text", b.modules.get("sibuna-text").?);
    tests.root_module.addImport("html", htmlModule(b, b.graph.host, .debug));
    tests.root_module.addAnonymousImport("console_world", .{
        .root_source_file = b.path("apps/console-ui/web/assets/world-110m.bin"),
    });
    const step = b.step("console-ui", "Build the Zig console WebAssembly interface");
    step.dependOn(&size.step);
    const render_step = b.step("console-render-test", "Test native console rendering");
    const render_check = b.addRunArtifact(tests);
    render_check.setCwd(b.path("."));
    render_check.setEnvironmentVariable("SIBUNA_UPDATE_CONSOLE_GOLDENS", "");
    render_step.dependOn(&render_check.step);
    addGolden(b, tests, render_step);
}

fn evidenceModule(b: *std.Build, target: std.Build.ResolvedTarget) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("libs/core/src/security_evidence.zig"),
        .target = target,
        .optimize = .small,
    });
}

fn linkUi(b: *std.Build, object: *std.Build.Step.Compile) std.Build.LazyPath {
    // Zig's bundled linker removes reserved relocation padding after resolving symbols.
    // Use the pinned toolchain, and keep the runtime's stack and memory bounds explicit.
    const link = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "wasm-ld",
        "--no-entry",
        "--export-memory",
        "--compress-relocations",
        "--strip-all",
        "--stack-first",
        "-z",
        "stack-size=262144",
        "--initial-memory=4194304",
        "--max-memory=4194304",
    });
    // Explicit exports keep compiler runtime globals outside the fixed browser ABI.
    const exports = .{
        "sb_event",          "sb_init",            "sb_geometry_loaded", "sb_geometry_capacity",
        "sb_geometry_input", "sb_commands_length", "sb_commands",        "sb_html_length",
        "sb_html",           "sb_input_capacity",  "sb_input",           "sb_frame_html",
        "sb_frame",
    };
    inline for (exports) |name| link.addArg("--export=" ++ name);
    link.addArg("-o");
    const artifact = link.addOutputFileArg("console.wasm");
    link.addFileArg(object.getEmittedBin());
    return artifact;
}

fn htmlModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("libs/html/src/root.zig"),
        .imports = &.{.{ .name = "text", .module = b.modules.get("sibuna-text").? }},
        .target = target,
        .optimize = optimize,
    });
}

fn addAssets(b: *std.Build) void {
    const assets = b.step(
        "console-assets",
        "Regenerate pinned console CSS and digests (needs npm)",
    );
    const build = b.addSystemCommand(&.{ python, "tools/console_assets.py", "build" });
    assets.dependOn(&build.step);
    const check = b.step("console-assets-check", "Verify committed console assets without npm");
    const verify = b.addSystemCommand(&.{ python, "tools/console_assets.py", "check" });
    check.dependOn(&verify.step);
}

fn addGolden(b: *std.Build, tests: *std.Build.Step.Compile, render: *std.Build.Step) void {
    b.step("console-golden-check", "Verify reviewed native console HTML").dependOn(render);
    const step = b.step("console-golden", "Review native HTML (-- --update to regenerate)");
    // Runtime arguments are unavailable during Zig 0.17's configure phase.
    const update = b.addSystemCommand(&.{ python, "tools/console_golden.py" });
    update.addArtifactArg(tests);
    update.addPassthruArgs();
    update.setCwd(b.path("."));
    step.dependOn(&update.step);
}
