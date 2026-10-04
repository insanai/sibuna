const std = @import("std");

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
) *std.Build.Module {
    const dictionary = b.createModule(.{
        .root_source_file = b.path("vendor/libinjection/table.zig"),
    });
    const trust = b.createModule(.{
        .root_source_file = b.path("vendor/crs/trust.zig"),
    });
    const module = b.addModule("sibuna-crs", .{
        .root_source_file = b.path("libs/crs/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("libinjection-data", dictionary);
    module.addImport("crs-trust", trust);
    module.addImport("text", b.modules.get("sibuna-text").?);
    const host = b.createModule(.{
        .root_source_file = b.path("libs/crs/src/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    host.addImport("libinjection-data", dictionary);
    host.addImport("crs-trust", trust);
    host.addImport("text", b.modules.get("sibuna-text").?);
    const fixture = b.createModule(.{
        .root_source_file = b.path("vendor/crs/fixture.zig"),
    });
    host.addImport("crs-fixture", fixture);
    const tests = b.addTest(.{ .root_module = host });
    const test_step = b.step("crs-test", "Test bounded native CRS source contracts");
    test_step.dependOn(&b.addRunArtifact(tests).step);
    test_step.dependOn(addCompilationChecks(b));
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
    for (probes) |contract| addProbeCheck(b, host, contract);
    addDataCheck(b);
    const run = b.addRunArtifact(audit);
    run.addPassthruArgs();
    b.step("crs-audit", "Inventory an extracted CRS release; does not activate rules")
        .dependOn(&run.step);
    return module;
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

fn addCompilationChecks(b: *std.Build) *std.Build.Step {
    const step = b.step("crs-compile-check", "Compile native CRS contracts for Windows and Wasm");
    const targets: []const std.Target.Query = &.{
        .{ .cpu_arch = .x86_64, .os_tag = .windows },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
        .{ .cpu_arch = .wasm32, .os_tag = .freestanding },
    };
    for (targets) |query| {
        const target = b.resolveTargetQuery(query);
        const module = b.createModule(.{
            .root_source_file = b.path("libs/crs/src/root.zig"),
            .target = target,
            .optimize = .small,
        });
        module.addImport("text", b.modules.get("sibuna-text").?);
        module.addImport("libinjection-data", b.createModule(.{
            .root_source_file = b.path("vendor/libinjection/table.zig"),
        }));
        module.addImport("crs-trust", b.createModule(.{
            .root_source_file = b.path("vendor/crs/trust.zig"),
        }));
        const probe = b.addObject(.{
            .name = "crs-compile-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tools/crs_compile_probe.zig"),
                .target = target,
                .optimize = .small,
                .imports = &.{.{ .name = "crs", .module = module }},
            }),
        });
        step.dependOn(&probe.step);
    }
    return step;
}

const Probe = struct {
    name: []const u8,
    source: []const u8,
    checker: []const u8,
    step: []const u8,
    description: []const u8,
};

const probes: []const Probe = &.{
    .{
        .name = "sibuna-crs-acquisition-probe",
        .source = "tools/crs_acquisition_probe.zig",
        .checker = "tools/crs_acquisition_check.py",
        .step = "crs-acquisition-check",
        .description = "Check bounded structured acquisition against independent decoders",
    },
    .{
        .name = "sibuna-crs-signature-probe",
        .source = "tools/crs_signature_probe.zig",
        .checker = "tools/crs_signature_check.py",
        .step = "crs-signature-check",
        .description = "Verify native CRS archive signatures against the pinned GnuPG receipt",
    },
    .{
        .name = "sibuna-crs-primitive-probe",
        .source = "tools/crs_primitive_probe.zig",
        .checker = "tools/crs_primitive_check.py",
        .step = "crs-primitive-check",
        .description = "Check the supported subset against pinned SecLang vectors",
    },
    .{
        .name = "sibuna-crs-detector-probe",
        .source = "tools/crs_detector_probe.zig",
        .checker = "tools/crs_detector_check.py",
        .step = "crs-detector-check",
        .description = "Compare native detector stages with pinned libinjection",
    },
};

fn addProbeCheck(b: *std.Build, crs: *std.Build.Module, contract: Probe) void {
    const probe = b.addExecutable(.{
        .name = contract.name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(contract.source),
            .target = b.graph.host,
            .optimize = .safe,
            .imports = &.{.{ .name = "crs", .module = crs }},
        }),
    });
    const python = if (@import("builtin").os.tag == .windows) "python" else "python3";
    const check = b.addSystemCommand(&.{ python, contract.checker });
    check.addArtifactArg(probe);
    check.addPassthruArgs();
    b.step(contract.step, contract.description).dependOn(&check.step);
}

fn addDataCheck(b: *std.Build) void {
    const python = if (@import("builtin").os.tag == .windows) "python" else "python3";
    const check = b.addSystemCommand(&.{ python, "tools/crs_detector_data.py", "--check" });
    check.addPassthruArgs();
    const xss = b.addSystemCommand(&.{ python, "tools/crs_xss_data.py", "--check" });
    xss.addPassthruArgs();
    const step = b.step("crs-detector-data", "Reproduce native detector data from pinned source");
    step.dependOn(&check.step);
    step.dependOn(&xss.step);
}
