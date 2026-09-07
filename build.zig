const std = @import("std");

pub const Modules = struct {
    core: *std.Build.Module,
    crypto: *std.Build.Module,
    net: *std.Build.Module,
    policy: *std.Build.Module,
    challenge: *std.Build.Module,
    store: *std.Build.Module,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const modules = addModules(b, target, optimize);
    const wasm_pow = addWasmSolver(b);
    addServer(b, target, optimize, modules, wasm_pow);
    addTests(b, modules);
    addBenchmarks(b, target, optimize, modules);
    addBook(b);

    addFormatting(b);
    addSid(b);
}

fn addModules(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Modules {
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

    return .{
        .core = core,
        .crypto = crypto,
        .net = net,
        .policy = policy,
        .challenge = challenge,
        .store = store,
    };
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

    const wasm_pow = b.addExecutable(.{
        .name = "sibuna-pow",
        .root_module = b.createModule(.{
            .root_source_file = b.path("apps/wasm-pow/src/entry.zig"),
            .target = wasm_target,
            .optimize = .ReleaseSmall,
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

fn addServer(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    modules: Modules,
    wasm_pow: *std.Build.Step.Compile,
) void {
    const exe = b.addExecutable(.{
        .name = "sibuna",
        .root_module = b.createModule(.{
            .root_source_file = b.path("apps/sibuna/src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addAnonymousImport("wasm_solver", .{
        .root_source_file = wasm_pow.getEmittedBin(),
    });
    exe.root_module.addAnonymousImport("challenge_html", .{
        .root_source_file = b.path("apps/web/src/challenge.html"),
    });
    exe.root_module.addAnonymousImport("worker_js", .{
        .root_source_file = b.path("apps/web/src/worker.js"),
    });

    exe.root_module.addImport("core", modules.core);
    exe.root_module.addImport("crypto", modules.crypto);
    exe.root_module.addImport("net", modules.net);
    exe.root_module.addImport("policy", modules.policy);
    exe.root_module.addImport("challenge", modules.challenge);
    exe.root_module.addImport("store", modules.store);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the Sibuna daemon");
    run_step.dependOn(&run_cmd.step);
}

fn addTests(b: *std.Build, modules: Modules) void {
    const test_step = b.step("test", "Run all unit tests");
    const core_tests = b.addTest(.{ .root_module = modules.core });
    const crypto_tests = b.addTest(.{ .root_module = modules.crypto });
    const net_tests = b.addTest(.{ .root_module = modules.net });
    const policy_tests = b.addTest(.{ .root_module = modules.policy });
    const challenge_tests = b.addTest(.{ .root_module = modules.challenge });
    const store_tests = b.addTest(.{ .root_module = modules.store });

    test_step.dependOn(&b.addRunArtifact(core_tests).step);
    test_step.dependOn(&b.addRunArtifact(crypto_tests).step);
    test_step.dependOn(&b.addRunArtifact(net_tests).step);
    test_step.dependOn(&b.addRunArtifact(policy_tests).step);
    test_step.dependOn(&b.addRunArtifact(challenge_tests).step);
    test_step.dependOn(&b.addRunArtifact(store_tests).step);
}

fn addBenchmarks(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
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
    if (b.args) |args| {
        run_bench.addArgs(args);
    }
    const bench_step = b.step("benchmark-zig", "Run the Sibuna benchmark suite");
    bench_step.dependOn(&run_bench.step);

    const run_all = b.addSystemCommand(&.{ "sh", "benchmarks/run-all.sh" });
    const run_all_step = b.step("benchmark", "Run full benchmark matrix and update results");
    run_all_step.dependOn(&run_all.step);
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

fn addFormatting(b: *std.Build) void {
    const fmt = b.addFmt(.{
        .paths = &.{ "build.zig", "apps", "libs", "tools", "benchmarks" },
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
    const io = b.graph.io;
    var stems = std.ArrayList([]const u8).empty;
    var dir = b.build_root.handle.openDir(io, "docs/sid/records", .{ .iterate = true }) catch
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
            .optimize = .Debug,
        }),
    });

    const list_run = b.addRunArtifact(tool);
    list_run.has_side_effects = true;
    list_run.addArgs(&.{ "--root", b.pathFromRoot("."), "list" });
    const list_step = b.step("sid-list", "List SID registry entries and placeholder drafts");
    list_step.dependOn(&list_run.step);

    const new_run = b.addRunArtifact(tool);
    new_run.has_side_effects = true;
    new_run.addArgs(&.{ "--root", b.pathFromRoot("."), "new" });
    if (b.args) |args| new_run.addArgs(args);
    const new_step = b.step(
        "sid-new",
        "Create a placeholder SID draft: zig build sid-new -- <slug>",
    );
    new_step.dependOn(&new_run.step);

    const promote_run = b.addRunArtifact(tool);
    promote_run.has_side_effects = true;
    promote_run.addArgs(&.{ "--root", b.pathFromRoot("."), "promote" });
    if (b.args) |args| promote_run.addArgs(args);
    const promote_step = b.step(
        "sid-promote",
        "Assign next number to draft and register: zig build sid-promote -- <slug>",
    );
    promote_step.dependOn(&promote_run.step);
}
