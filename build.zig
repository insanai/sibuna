const std = @import("std");
const python = if (@import("builtin").os.tag == .windows) "python" else "python3";
const console_build = @import("build/console.zig");

pub const Modules = struct {
    socket: *std.Build.Module,
    core: *std.Build.Module,
    crypto: *std.Build.Module,
    net: *std.Build.Module,
    policy: *std.Build.Module,
    challenge: *std.Build.Module,
    store: *std.Build.Module,
    crypto_pow: *std.Build.Module,
    crypto_posw: *std.Build.Module,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const storage = b.option(
        bool,
        "storage",
        "Link Zaxonlite for persistent policies, reputation, and forensics (default: true)",
    ) orelse true;
    const cluster = b.option(
        bool,
        "cluster",
        "Enable multi-node replication; links OpenSSL 3 for Zaxonlite mTLS (default: false)",
    ) orelse false;

    const console_enabled = b.option(
        bool,
        "console",
        "Compile console support (default: follows storage)",
    ) orelse storage;
    if (console_enabled and !storage) {
        std.log.err(
            "CONSOLE001: console support requires persistent storage. " ++
                "Use -Dstorage=true or -Dconsole=false.",
            .{},
        );
        b.invalid_user_input = true;
    }
    const geoip_data = b.option(
        []const u8,
        "geoip-data",
        "Embed a validated GeoIP snapshot from zig build geoip-snapshot (default: none)",
    );
    if (geoip_data != null and !console_enabled) {
        std.log.err(
            "GEOIP001: an embedded GeoIP snapshot requires console support. " ++
                "Use -Dconsole=true or omit -Dgeoip-data.",
            .{},
        );
        b.invalid_user_input = true;
    }
    const modules = addModules(b, target, optimize);
    const console_modules = console_build.add(b, target, optimize, geoip_data, modules.socket);
    console_modules.console.addImport("core", modules.core);
    console_modules.console.addImport("store", modules.store);
    console_modules.console.addImport("net", modules.net);
    // Template previews compile drafts with the same validator the storage owner uses.
    console_modules.console.addImport("policy", modules.policy);
    const wasm_pow = addWasmSolver(b);
    const app = addServer(
        b,
        target,
        optimize,
        modules,
        wasm_pow,
        storage,
        cluster,
        if (console_enabled) console_modules.console else null,
    );
    addTextImports(b);
    addTests(b, modules, app);
    if (console_enabled) {
        b.top_level_steps.get("test").?.step.dependOn(
            &b.top_level_steps.get("console-test").?.step,
        );
        b.top_level_steps.get("test").?.step.dependOn(
            &b.top_level_steps.get("console-e2e").?.step,
        );
    }
    addBenchmarks(b, target, optimize, modules);
    addDocs(b);
    addFormatting(b);
}

fn addText(b: *std.Build) *std.Build.Module {
    return b.addModule("sibuna-text", .{
        .root_source_file = b.path("libs/text/src/root.zig"),
    });
}

fn addTextImports(b: *std.Build) void {
    const text = b.modules.get("sibuna-text").?;
    for (b.modules.values()) |module| {
        if (module != text) module.addImport("text", text);
    }
}

fn addSocket(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
) *std.Build.Module {
    const socket = b.addModule("sibuna-socket", .{
        .root_source_file = b.path("libs/socket/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = socket });
    b.step("socket-test", "Test native socket interruption ownership")
        .dependOn(&b.addRunArtifact(tests).step);
    return socket;
}

fn addModules(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
) Modules {
    _ = addText(b);
    const socket = addSocket(b, target, optimize);
    const core = b.addModule("sibuna-core", .{
        .root_source_file = b.path("libs/core/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const crypto = b.addModule("sibuna-crypto", .{
        .root_source_file = b.path("libs/crypto/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto.addImport("core", core);

    const net = b.addModule("sibuna-net", .{
        .root_source_file = b.path("libs/net/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    net.addImport("core", core);
    net.addImport("socket", socket);

    const policy = b.addModule("sibuna-policy", .{
        .root_source_file = b.path("libs/policy/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    policy.addImport("core", core);

    const store = b.addModule("sibuna-store", .{
        .root_source_file = b.path("libs/store/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    store.addImport("core", core);

    const challenge = b.addModule("sibuna-challenge", .{
        .root_source_file = b.path("libs/challenge/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    challenge.addImport("core", core);
    challenge.addImport("crypto", crypto);
    challenge.addImport("store", store);

    const crypto_pow = b.createModule(.{
        .root_source_file = b.path("libs/crypto/src/pow.zig"),
        .target = target,
        .optimize = optimize,
    });
    const crypto_posw = b.createModule(.{
        .root_source_file = b.path("libs/crypto/src/posw.zig"),
        .target = target,
        .optimize = optimize,
    });

    return .{
        .socket = socket,
        .core = core,
        .crypto = crypto,
        .net = net,
        .policy = policy,
        .challenge = challenge,
        .store = store,
        .crypto_pow = crypto_pow,
        .crypto_posw = crypto_posw,
    };
}

fn addCrs(
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
    host.addImport("crs-fixture", b.createModule(.{
        .root_source_file = b.path("vendor/crs/fixture.zig"),
    }));
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
    const run = b.addRunArtifact(audit);
    run.addPassthruArgs();
    b.step("crs-audit", "Inventory an extracted CRS release; does not activate rules")
        .dependOn(&run.step);
}

fn addWasmSolver(b: *std.Build) *std.Build.Step.Compile {
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
        .cpu_features_add = std.Target.wasm.featureSet(&.{
            .bulk_memory,
            .mutable_globals,
            .sign_ext,
        }),
    });

    // The solver imports the exact server-side hashcash and PoSW sources so
    // the browser prover and the native verifier are one implementation.
    const wasm_pow_mod = b.createModule(.{
        .root_source_file = b.path("libs/crypto/src/pow.zig"),
        .target = wasm_target,
        .optimize = .small,
    });
    const wasm_posw_mod = b.createModule(.{
        .root_source_file = b.path("libs/crypto/src/posw.zig"),
        .target = wasm_target,
        .optimize = .small,
    });
    const wasm_pow = b.addExecutable(.{
        .name = "sibuna-pow",
        .root_module = b.createModule(.{
            .root_source_file = b.path("apps/wasm-pow/src/entry.zig"),
            .target = wasm_target,
            .optimize = .small,
            .imports = &.{
                .{ .name = "pow", .module = wasm_pow_mod },
                .{ .name = "posw", .module = wasm_posw_mod },
            },
        }),
    });
    wasm_pow.entry = .disabled;
    wasm_pow.rdynamic = true;
    const install_wasm = b.addInstallArtifact(wasm_pow, .{
        .dest_dir = .{ .override = .{ .custom = "web/wasm" } },
    });
    const wasm_step = b.step("wasm", "Build the browser WebAssembly proof-of-work solver");
    wasm_step.dependOn(&install_wasm.step);
    return wasm_pow;
}

const AppModules = struct {
    imports: [6]std.Build.Module.Import,
    wasm_bin: std.Build.LazyPath,
    options: *std.Build.Step.Options,
    zaxonlite: ?*std.Build.Module,
    console: ?*std.Build.Module,
};

fn addServer(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    modules: Modules,
    wasm_pow: *std.Build.Step.Compile,
    storage: bool,
    cluster: bool,
    console: ?*std.Build.Module,
) AppModules {
    const options = b.addOptions();
    options.addOption([]const u8, "version", @import("build.zig.zon").version);
    options.addOption(bool, "storage", storage);
    options.addOption(bool, "console", console != null);
    options.addOption(bool, "cluster", storage and cluster);
    // The embedded single-node store needs no transport, so OpenSSL stays
    // out of the binary unless clustering is requested.
    const zaxonlite: ?*std.Build.Module = if (storage)
        @import("build/storage.zig").add(b, target, optimize, cluster)
    else
        null;

    const app = AppModules{
        .imports = .{
            .{ .name = "core", .module = modules.core },
            .{ .name = "crypto", .module = modules.crypto },
            .{ .name = "net", .module = modules.net },
            .{ .name = "policy", .module = modules.policy },
            .{ .name = "challenge", .module = modules.challenge },
            .{ .name = "store", .module = modules.store },
        },
        .wasm_bin = wasm_pow.getEmittedBin(),
        .options = options,
        .zaxonlite = zaxonlite,
        .console = console,
    };

    const root = b.createModule(.{
        .root_source_file = b.path("apps/sibuna/src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = b.option(bool, "strip", "Remove debug symbols from the daemon") orelse false,
    });
    wireApp(b, root, app);
    const exe = b.addExecutable(.{ .name = "sibuna", .root_module = root });
    b.installArtifact(exe);
    const proxy_e2e = b.step("proxy-e2e", "Verify HTTP and WebSocket proxy compatibility");
    const proxy_check = b.addSystemCommand(&.{ python, "tools/proxy_e2e.py" });
    proxy_check.addArtifactArg(exe);
    proxy_e2e.dependOn(&proxy_check.step);
    const modes_check = b.addSystemCommand(&.{ python, "tools/ingress_e2e.py" });
    modes_check.addArtifactArg(exe);
    proxy_e2e.dependOn(&modes_check.step);
    addConsoleLiveChecks(b, exe, console != null);
    // The isolation gate builds its own ReleaseFast binaries (with and without the
    // console) into a temporary prefix; `-- --quick` runs the short CI matrix.
    const impact = b.step("console-impact", "Measure data-plane cost of the console");
    if (console != null) {
        const acceptance = b.addSystemCommand(&.{
            python, "benchmarks/console_impact_test.py",
        });
        const measure = b.addSystemCommand(&.{ python, "benchmarks/console_impact.py" });
        measure.step.dependOn(&acceptance.step);
        measure.addPassthruArgs();
        impact.dependOn(&measure.step);
    } else impact.dependOn(&b.addFail("console-impact requires -Dconsole=true").step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run the Sibuna daemon");
    run_step.dependOn(&run_cmd.step);
    return app;
}

/// Attaches the library modules, embedded browser assets, build options,
/// and (when enabled) Zaxonlite to a daemon root module. The end-to-end
/// test module receives exactly the same graph as the executable.
fn wireApp(b: *std.Build, root: *std.Build.Module, app: AppModules) void {
    root.addImport("text", b.modules.get("sibuna-text").?);
    for (app.imports) |imp| root.addImport(imp.name, imp.module);
    root.addAnonymousImport("wasm_solver", .{ .root_source_file = app.wasm_bin });
    root.addAnonymousImport(
        "challenge_html",
        .{ .root_source_file = b.path("apps/web/src/challenge.html") },
    );
    root.addAnonymousImport(
        "worker_js",
        .{ .root_source_file = b.path("apps/web/src/worker.js") },
    );
    root.addOptions("build_options", app.options);
    if (app.zaxonlite) |z| root.addImport("zaxonlite", z);
    if (app.console) |module| root.addImport("console", module);
}

fn addTests(b: *std.Build, modules: Modules, app: AppModules) void {
    const test_step = b.step("test", "Run all unit and end-to-end tests");
    addCrs(b, modules.core.resolved_target.?, modules.core.optimize.?);
    test_step.dependOn(&b.top_level_steps.get("proxy-e2e").?.step);
    const e2e_root = b.createModule(.{
        .root_source_file = b.path("apps/sibuna/src/e2e_test.zig"),
        .target = b.graph.host,
    });
    wireApp(b, e2e_root, app);
    const e2e_tests = b.addTest(.{ .root_module = e2e_root });
    const server_root = b.createModule(.{
        .root_source_file = b.path("apps/sibuna/src/server.zig"),
        .target = b.graph.host,
    });
    wireApp(b, server_root, app);
    const server_tests = b.addTest(.{ .root_module = server_root });
    const text_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("libs/text/src/root.zig"),
        .target = b.graph.host,
    }) });
    test_step.dependOn(&b.addRunArtifact(text_tests).step);
    const core_tests = b.addTest(.{ .root_module = modules.core });
    const crypto_tests = b.addTest(.{ .root_module = modules.crypto });
    const net_tests = b.addTest(.{ .root_module = modules.net });
    const policy_tests = b.addTest(.{ .root_module = modules.policy });
    const challenge_tests = b.addTest(.{ .root_module = modules.challenge });
    const store_tests = b.addTest(.{ .root_module = modules.store });
    const solver_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("apps/wasm-pow/src/entry.zig"),
            .target = b.graph.host,
            .imports = &.{
                .{ .name = "pow", .module = modules.crypto_pow },
                .{ .name = "posw", .module = modules.crypto_posw },
            },
        }),
    });

    test_step.dependOn(&b.top_level_steps.get("socket-test").?.step);
    test_step.dependOn(&b.addRunArtifact(core_tests).step);
    test_step.dependOn(&b.addRunArtifact(crypto_tests).step);
    test_step.dependOn(&b.addRunArtifact(net_tests).step);
    test_step.dependOn(&b.addRunArtifact(policy_tests).step);
    test_step.dependOn(&b.addRunArtifact(challenge_tests).step);
    test_step.dependOn(&b.addRunArtifact(store_tests).step);
    test_step.dependOn(&b.addRunArtifact(solver_tests).step);
    test_step.dependOn(&b.addRunArtifact(server_tests).step);
    test_step.dependOn(&b.addRunArtifact(e2e_tests).step);
}

fn addBenchmarks(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    modules: Modules,
) void {
    const bench_exe = b.addExecutable(.{
        .name = "sibuna-benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/benchmark.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    bench_exe.root_module.addImport("core", modules.core);
    bench_exe.root_module.addImport("crypto", modules.crypto);
    bench_exe.root_module.addImport("net", modules.net);
    bench_exe.root_module.addImport("policy", modules.policy);
    bench_exe.root_module.addImport("challenge", modules.challenge);
    bench_exe.root_module.addImport("store", modules.store);

    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    run_bench.addPassthruArgs();
    const bench_step = b.step("benchmark-zig", "Run the Sibuna benchmark suite");
    bench_step.dependOn(&run_bench.step);

    const run_all = b.addSystemCommand(&.{ "sh", "benchmarks/run-all.sh" });
    const run_all_step = b.step("benchmark", "Run full benchmark matrix and update results");
    run_all_step.dependOn(&run_all.step);
}

fn addDocs(b: *std.Build) void {
    addBook(b);
    addWhitepaper(b);
    addSid(b);
}

fn addBook(b: *std.Build) void {
    const make_dir = b.addSystemCommand(&.{ "mkdir", "-p", "docs/build" });
    const book_cmd = b.addSystemCommand(&.{
        "typst",
        "compile",
        "--root",
        ".",
        "docs/book.typ",
        "docs/build/sibuna-book.pdf",
    });
    book_cmd.step.dependOn(&make_dir.step);
    const book_step = b.step("book", "Build the Sibuna book PDF (docs/build/sibuna-book.pdf)");
    book_step.dependOn(&book_cmd.step);
}

fn addWhitepaper(b: *std.Build) void {
    const make_dir = b.addSystemCommand(&.{ "mkdir", "-p", "docs/build" });
    const whitepaper_cmd = b.addSystemCommand(&.{
        "typst",
        "compile",
        "--root",
        ".",
        "docs/whitepaper/whitepaper.typ",
        "docs/build/sibuna-whitepaper.pdf",
    });
    whitepaper_cmd.step.dependOn(&make_dir.step);
    const whitepaper_step = b.step(
        "whitepaper",
        "Build the Sibuna architecture whitepaper PDF (docs/build/sibuna-whitepaper.pdf)",
    );
    whitepaper_step.dependOn(&whitepaper_cmd.step);

    const make_site_dir = b.addSystemCommand(&.{ "mkdir", "-p", "docs/build/whitepaper-site" });
    const html_cmd = b.addSystemCommand(&.{
        "typst",
        "compile",
        "--features",
        "html,bundle",
        "--root",
        ".",
        "--format",
        "bundle",
        "docs/whitepaper/bundle.typ",
        "docs/build/whitepaper-site",
    });
    html_cmd.step.dependOn(&make_site_dir.step);
    const html_step = b.step(
        "whitepaper-html",
        "Build the Sibuna architecture whitepaper HTML site (docs/build/whitepaper-site)",
    );
    html_step.dependOn(&html_cmd.step);
}

fn addFormatting(b: *std.Build) void {
    const fmt = b.addFmt(.{
        .paths = b.pathList(&.{ "build.zig", "build", "apps", "libs", "tools", "benchmarks" }),
        .check = true,
    });
    const style = b.addSystemCommand(&.{ "sh", "tools/check-style.sh" });
    const fmt_step = b.step("fmt", "Check zig fmt and project code style rules");
    fmt_step.dependOn(&fmt.step);
    fmt_step.dependOn(&style.step);
}

fn addSid(b: *std.Build) void {
    const make_dir = b.addSystemCommand(&.{ "mkdir", "-p", "docs/build" });

    const filter = b.option(
        []const u8,
        "sid",
        "Build only the SID record matching this number (e.g. 2 or 0002) or slug",
    ) orelse b.option(
        []const u8,
        "shd",
        "Alias for -Dsid",
    );

    const sid_step = b.step("sid", "Build the Shibuna Discussion (SID) record PDFs");
    const shd_step = b.step("shd", "Alias for zig build sid");
    shd_step.dependOn(sid_step);

    const stems = sidRecordStems(b, filter);
    if (stems.len == 0) {
        const message = if (filter) |value|
            b.fmt("no SID record in docs/sid/records matches -Dsid={s}", .{value})
        else
            "no numbered SID records found in docs/sid/records";
        sid_step.dependOn(&b.addFail(message).step);
    }
    for (stems) |stem| {
        const compile = b.addSystemCommand(&.{
            "typst",
            "compile",
            "--root",
            "docs",
            b.fmt("docs/sid/records/{s}.typ", .{stem}),
            b.fmt("docs/build/sid-{s}.pdf", .{stem}),
        });
        compile.step.dependOn(&make_dir.step);
        sid_step.dependOn(&compile.step);
    }

    const index_step = b.step("sid-index", "Build the SID index PDF");
    const compile_index = b.addSystemCommand(&.{
        "typst",              "compile",
        "--root",             "docs",
        "docs/sid/index.typ", "docs/build/sid-index.pdf",
    });
    compile_index.step.dependOn(&make_dir.step);
    index_step.dependOn(&compile_index.step);

    const site_step = b.step("sid-site", "Build the experimental SID HTML bundle");
    const make_site_dir = b.addSystemCommand(&.{ "mkdir", "-p", "docs/build/sid-site" });
    const compile_site = b.addSystemCommand(&.{
        "typst",               "compile",
        "--features",          "html,bundle",
        "--root",              "docs",
        "--format",            "bundle",
        "docs/sid/bundle.typ", "docs/build/sid-site",
    });
    compile_site.step.dependOn(&make_site_dir.step);
    site_step.dependOn(&compile_site.step);

    addSidTool(b);
}

fn sidRecordStems(b: *std.Build, filter: ?[]const u8) [][]const u8 {
    b.dependOnDirectoryContents(b.path("docs/sid/records"));
    const io = b.graph.io;
    var stems = std.ArrayList([]const u8).empty;
    var dir = b.root.openDir(io, "docs/sid/records", .{ .iterate = true }) catch
        return stems.items;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".typ")) continue;
        const stem = entry.name[0 .. entry.name.len - ".typ".len];
        if (stem.len < "0000-a".len) continue;
        const numbered = for (stem[0..4]) |byte| {
            if (!std.ascii.isDigit(byte)) break false;
        } else stem[4] == '-';
        const selected = if (filter) |value|
            sidRecordMatches(stem, numbered, value)
        else
            numbered;
        if (selected) stems.append(b.allocator, b.dupe(stem)) catch @panic("OOM");
    }
    std.mem.sort([]const u8, stems.items, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    return stems.items;
}

fn sidRecordMatches(stem: []const u8, numbered: bool, filter: []const u8) bool {
    if (std.mem.eql(u8, stem, filter)) return true;
    const slug = if (numbered)
        stem["0000-".len..]
    else if (std.mem.startsWith(u8, stem, "XXXXX-"))
        stem["XXXXX-".len..]
    else
        stem;
    if (std.mem.eql(u8, slug, filter)) return true;
    if (numbered) {
        const wanted = std.fmt.parseInt(u16, filter, 10) catch return false;
        const actual = std.fmt.parseInt(u16, stem[0..4], 10) catch return false;
        return wanted == actual;
    }
    return false;
}

fn addSidTool(b: *std.Build) void {
    const tool = b.addExecutable(.{
        .name = "sid-tool",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/sid.zig"),
            .target = b.graph.host,
            .optimize = .debug,
        }),
    });

    const list_run = b.addRunArtifact(tool);
    list_run.has_side_effects = true;
    list_run.addArg("--root");
    list_run.addDirectoryArg(b.path("."));
    list_run.addArg("list");
    const list_step = b.step("sid-list", "List SID registry entries and placeholder drafts");
    list_step.dependOn(&list_run.step);

    const new_run = b.addRunArtifact(tool);
    new_run.has_side_effects = true;
    new_run.addArg("--root");
    new_run.addDirectoryArg(b.path("."));
    new_run.addArg("new");
    new_run.addPassthruArgs();
    const new_step = b.step(
        "sid-new",
        "Create a placeholder SID draft: zig build sid-new -- <slug>",
    );
    new_step.dependOn(&new_run.step);

    const promote_run = b.addRunArtifact(tool);
    promote_run.has_side_effects = true;
    promote_run.addArg("--root");
    promote_run.addDirectoryArg(b.path("."));
    promote_run.addArg("promote");
    promote_run.addPassthruArgs();
    const promote_step = b.step(
        "sid-promote",
        "Assign next number to draft and register: zig build sid-promote -- <slug>",
    );
    promote_step.dependOn(&promote_run.step);
}

fn addConsoleLiveChecks(b: *std.Build, exe: *std.Build.Step.Compile, enabled: bool) void {
    const scenarios = .{
        .{ "console-e2e", "tools/console_e2e.py", "Test live daemon authentication" },
        .{
            "console-ui-e2e",
            "tools/console_ui_live_test.py",
            "Test shipped UI against daemon (Node)",
        },
    };
    inline for (scenarios) |scenario| {
        const step = b.step(scenario[0], scenario[2]);
        if (enabled) {
            const check = b.addSystemCommand(&.{ python, scenario[1] });
            check.addArtifactArg(exe);
            step.dependOn(&check.step);
        } else step.dependOn(&b.addFail("console live checks require -Dconsole=true").step);
    }
}
