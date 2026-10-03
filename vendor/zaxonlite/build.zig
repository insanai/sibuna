const std = @import("std");

const ProductGraph = struct {
    sqlite_lib: *std.Build.Step.Compile,
    c_mod: *std.Build.Module,
    search: *std.Build.Module,
    zaxonlite: *std.Build.Module,
};

/// One optimization mode's full product graph: the static SQLite library
/// (FTS5 plus the pinned sqlite-vec compiled in), the translated C import,
/// the pure `zaxon_search` module, and the zaxonlite module itself. The
/// normal and benchmark builds share this helper so extension and SIMD
/// flags can never diverge (ZDS 0009).
fn addProductGraph(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    tls_enabled: bool,
    openssl_prefix: []const u8,
    public_name: ?[]const u8,
) ProductGraph {
    const sqlite_dep = b.dependency("sqlite", .{});
    const vec_dep = b.dependency("sqlite_vec", .{});
    const paxos = b.dependency("paxos", .{
        .target = target,
        .optimize = optimize,
    }).module("paxos");

    const sqlite_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sqlite_mod.addIncludePath(sqlite_dep.path(""));
    sqlite_mod.addIncludePath(vec_dep.path(""));
    // The compile-time mmap ceiling permits the runtime opt-in profiles on
    // 64-bit targets; the runtime default stays zero everywhere, and
    // 32-bit or wasm targets compile mapped I/O out entirely (ZDS 0009).
    const mmap_flag = if (target.result.ptrBitWidth() >= 64)
        "-DSQLITE_MAX_MMAP_SIZE=1073741824"
    else
        "-DSQLITE_MAX_MMAP_SIZE=0";
    sqlite_mod.addCSourceFile(.{
        .file = sqlite_dep.path("sqlite3.c"),
        .flags = &.{
            "-DSQLITE_THREADSAFE=1",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
            "-DSQLITE_OMIT_DEPRECATED",
            "-DSQLITE_DQS=0",
            "-DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1",
            "-DHAVE_USLEEP=1",
            "-DSQLITE_ENABLE_FTS5",
            mmap_flag,
        },
    });
    // Pinned sqlite-vec, statically registered per connection. The
    // filesystem helpers stay out, and no AVX or NEON flag is set: the
    // portable artifact must never contain instructions the resolved
    // target does not guarantee (ZDS 0009).
    sqlite_mod.addCSourceFile(.{
        .file = vec_dep.path("sqlite-vec.c"),
        .flags = &.{
            "-DSQLITE_CORE",
            "-DSQLITE_VEC_STATIC",
            "-DSQLITE_VEC_OMIT_FS",
            // sqlite-vec 0.1.9 aliases the fixed-width names through BSD
            // u_int* typedefs on every non-Windows target. musl does not
            // expose those legacy names, so map only this compilation unit
            // back to the equivalent <stdint.h> types.
            "-Du_int8_t=uint8_t",
            "-Du_int16_t=uint16_t",
            "-Du_int64_t=uint64_t",
        },
    });
    const sqlite_lib = b.addLibrary(.{
        .name = "sqlite3",
        .root_module = sqlite_mod,
    });

    const translate_c = b.addTranslateC(.{
        .root_source_file = sqlite_dep.path("sqlite3.h"),
        .target = target,
        .optimize = optimize,
    });
    const c_mod = translate_c.createModule();

    // Pure fusion and distance kernels: deliberately created with no
    // imports so a SQLite, Paxos, or network dependency cannot creep in.
    const search = b.createModule(.{
        .root_source_file = b.path("src/search/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const module_options: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "paxos", .module = paxos },
            .{ .name = "c", .module = c_mod },
            .{ .name = "zaxon_search", .module = search },
        },
    };
    const zaxonlite = if (public_name) |name|
        b.addModule(name, module_options)
    else
        b.createModule(module_options);
    zaxonlite.linkLibrary(sqlite_lib);
    if (tls_enabled) linkOpenSsl(b, zaxonlite, target, openssl_prefix);

    return .{
        .sqlite_lib = sqlite_lib,
        .c_mod = c_mod,
        .search = search,
        .zaxonlite = zaxonlite,
    };
}

/// Links the system OpenSSL 3 (libssl/libcrypto) that backs the optional
/// mTLS transport in `src/tls.zig`.
fn linkOpenSsl(
    b: *std.Build,
    module: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    prefix: []const u8,
) void {
    if (prefix.len > 0) {
        module.addLibraryPath(b.graph.cwdRelativePath(b.fmt("{s}/lib", .{prefix})));
    }
    // MSVC import libraries are named libssl.lib/libcrypto.lib; the
    // windows-gnu (mingw-style) static build produces libssl.a, which the
    // posix names resolve. A native Windows target can leave the ABI as
    // `.none`; that uses the MSVC toolchain unless GNU was explicit.
    const msvc = target.result.os.tag == .windows and
        target.result.abi != .gnu;
    module.linkSystemLibrary(if (msvc) "libssl" else "ssl", .{
        .use_pkg_config = .no,
    });
    module.linkSystemLibrary(if (msvc) "libcrypto" else "crypto", .{
        .use_pkg_config = .no,
    });
    if (target.result.os.tag != .windows) return;
    // A static OpenSSL leaves its platform dependencies to the caller:
    // sockets and name lookup, the certificate and CSP stores, and the
    // registry reads behind RAND_poll.
    for ([_][]const u8{ "ws2_32", "crypt32", "advapi32", "user32" }) |name| {
        module.linkSystemLibrary(name, .{ .use_pkg_config = .no });
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    // Embedded-only consumers (`Node`, no transport) can drop the OpenSSL
    // link entirely: `node.zig` never imports `tls.zig`, and Zig's lazy
    // analysis emits no OpenSSL externs unless the TLS transport is
    // referenced. With `-Dtls=false` nothing in the build graph links
    // libssl/libcrypto, so the consumer's binary carries no OpenSSL
    // dependency. The `zaxon` executable and the transport hosts require
    // TLS and are only built with the default `-Dtls=true`.
    const tls_enabled = b.option(
        bool,
        "tls",
        "Link OpenSSL 3 for the mTLS transport (false: embedded Node only)",
    ) orelse true;
    const openssl_prefix = b.option(
        []const u8,
        "openssl-prefix",
        "Target OpenSSL 3 SDK prefix (default: Homebrew openssl@3 on macOS)",
    ) orelse if (target.result.os.tag == .macos)
        "/opt/homebrew/opt/openssl@3"
    else
        "";

    _ = addProductGraph(b, target, optimize, tls_enabled, openssl_prefix, "zaxonlite");
}
