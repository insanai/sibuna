//! The country lookup library: a standard-library-only module shared by the console, its
//! tools and tests, plus the optional embedded snapshot chosen with -Dgeoip-data.
const std = @import("std");

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.addModule("sibuna-geoip", .{
        .root_source_file = b.path("libs/geoip/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
}

/// `geoip-snapshot` validates provider files or a snapshot and can write one; the
/// executable is shared with `console-geoip-check`.
pub fn addTools(b: *std.Build, geoip: *std.Build.Module) void {
    const executable = b.addExecutable(.{
        .name = "geoip-snapshot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/geoip_snapshot.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "geoip", .module = geoip }},
        }),
    });
    const names = .{ "geoip-snapshot", "console-geoip-check" };
    const descriptions = .{
        "Validate country data files or a snapshot and optionally write a snapshot",
        "Validate downloaded country data or a snapshot without opening storage",
    };
    inline for (names, descriptions) |name, description| {
        const run = b.addRunArtifact(executable);
        if (b.args) |args| run.addArgs(args);
        b.step(name, description).dependOn(&run.step);
    }
}

pub const max_snapshot_bytes = 32 * 1024 * 1024;

/// Validates an operator-supplied snapshot's header and size at build time. Without a path
/// an empty generated file keeps the embedded import compiling; `present` is then false.
pub fn snapshot(b: *std.Build, path: ?[]const u8) std.Build.LazyPath {
    const empty = b.addWriteFiles().add("geoip-snapshot.bin", "");
    const file = path orelse return empty;
    validate(b, file) catch |err| {
        std.log.err(
            "GEOIP002: cannot embed GeoIP snapshot {s}: {t}. Create one with " ++
                "zig build geoip-snapshot -- --provider <name> --version <v> <files> " ++
                "--snapshot-out {s}",
            .{ file, err, file },
        );
        b.invalid_user_input = true;
        return empty;
    };
    return .{ .cwd_relative = b.dupe(file) };
}

fn validate(b: *std.Build, path: []const u8) !void {
    const io = b.graph.io;
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const size = (try file.stat(io)).size;
    if (size < 160 or size > max_snapshot_bytes) return error.InvalidSnapshot;
    var header: [160]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var reader = file.reader(io, &scratch);
    if (try reader.interface.readSliceShort(&header) != header.len) return error.InvalidSnapshot;
    if (!std.mem.eql(u8, header[0..8], "SBGEOIP1")) return error.InvalidSnapshot;
    const rows = std.mem.readInt(u32, header[20..24], .big);
    const payload = std.mem.readInt(u32, header[24..28], .big);
    if (rows == 0 or rows > 1024 * 1024 or payload != size - header.len)
        return error.InvalidSnapshot;
}
