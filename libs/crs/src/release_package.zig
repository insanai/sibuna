//! Off-path signed-package preparation. Authentication precedes decompression;
//! the returned program owns every source/table byte and survives staging cleanup.
//! Preparation never publishes a generation or establishes compatibility acceptance.
const std = @import("std");
const signatures = @import("release_signature.zig");
const versions = @import("release_version.zig");
const gzip = @import("release_gzip.zig");
const tar = @import("release_tar.zig");
const compiler = @import("compiler.zig");
const rules = @import("rule_program.zig");
const data = @import("rule_data.zig");
const work = @import("work.zig");
const compiled = @import("compiled_allocator.zig");
pub const Error = signatures.Error || versions.Error || gzip.Error || tar.Error ||
    compiler.Error || rules.Error || std.mem.Allocator.Error || error{
    MissingReleaseConfiguration,
    MissingReleaseRules,
    ReleaseVersionMismatch,
    CompiledProgramLimit,
};
pub const Input = struct {
    archive: []const u8,
    signature: []const u8,
    version: versions.Version,
    now: u64,
};
pub const Package = struct {
    allocator: std.mem.Allocator,
    bounded: compiled.Budget,
    program: rules.Program,
    receipt: signatures.Receipt,
    version: versions.Version,

    pub fn deinit(self: *Package) void {
        const allocator = self.allocator;
        self.program.deinit();
        std.debug.assert(self.bounded.used == 0);
        allocator.destroy(self);
    }
};

pub const compiled_capacity = 64 * 1024 * 1024;

/// The returned pointer has stable allocator identity. Moving the payload budget
/// by value would invalidate allocator interfaces retained by the prepared program.
pub fn prepare(allocator: std.mem.Allocator, input: Input) Error!*Package {
    var verification: signatures.Scratch = .{};
    const verifier = try signatures.Verifier.init(&verification);
    const receipt = try verifier.verify(input.archive, input.signature, input.now, &verification);
    var owner: std.heap.ArenaAllocator = .init(allocator);
    defer owner.deinit();
    const arena = owner.allocator();
    var budget: work.Budget = .{ .remaining = 1_000_000_000 };
    const expanded = try gzip.decode(input.archive, .{
        .output = try arena.alloc(u8, tar.maximum_expanded),
        .window = try arena.alloc(u8, std.compress.flate.max_window_len),
    }, &budget);
    var reader: tar.Reader = .{
        .entries = try arena.alloc(tar.Entry, tar.maximum_entries),
        .names = try arena.alloc(u8, tar.maximum_names),
    };
    var version_buffer: [17]u8 = undefined;
    const version = try input.version.write(&version_buffer);
    var prefix: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&prefix, "coreruleset-{s}", .{version}) catch unreachable;
    const entries = try reader.parse(expanded, root, &budget);
    const package = try allocator.create(Package);
    errdefer allocator.destroy(package);
    package.* = .{
        .allocator = allocator,
        .bounded = .{ .parent = allocator, .limit = compiled_capacity },
        .program = undefined,
        .receipt = receipt,
        .version = input.version,
    };
    package.program = compile(package.bounded.allocator(), entries) catch |err| switch (err) {
        error.OutOfMemory => return if (package.bounded.exhausted)
            error.CompiledProgramLimit
        else
            error.OutOfMemory,
        else => return err,
    };
    errdefer package.program.deinit();
    const marker = "OWASP_CRS/";
    if (!std.mem.startsWith(u8, package.program.signature, marker) or
        !std.mem.eql(u8, package.program.signature[marker.len..], version))
        return error.ReleaseVersionMismatch;
    return package;
}

fn compile(allocator: std.mem.Allocator, entries: []const tar.Entry) Error!rules.Program {
    var configuration: ?[]const u8 = null;
    var selected: [tar.maximum_entries]tar.Entry = undefined;
    var files: [tar.maximum_entries]data.File = undefined;
    var count: usize = 0;
    var file_count: usize = 0;
    for (entries) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.eql(u8, entry.path, "crs-setup.conf.example")) configuration = entry.bytes;
        if (!std.mem.startsWith(u8, entry.path, "rules/")) continue;
        const name = entry.path[6..];
        if (std.mem.indexOfScalar(u8, name, '/') != null) return error.InvalidArchivePath;
        if (std.mem.endsWith(u8, name, ".conf")) {
            selected[count] = entry;
            count += 1;
        } else if (std.mem.endsWith(u8, name, ".data")) {
            files[file_count] = .{ .path = entry.path, .bytes = entry.bytes };
            file_count += 1;
        }
    }
    if (count == 0) return error.MissingReleaseRules;
    std.mem.sort(tar.Entry, selected[0..count], {}, struct {
        fn less(_: void, left: tar.Entry, right: tar.Entry) bool {
            return std.mem.lessThan(u8, left.path, right.path);
        }
    }.less);
    var builder = compiler.Compiler.init(allocator, .{});
    defer builder.deinit();
    try builder.addSource("crs-setup.conf.example", configuration orelse
        return error.MissingReleaseConfiguration);
    for (selected[0..count]) |entry| try builder.addSource(entry.path, entry.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    return rules.compile(allocator, &plan, files[0..file_count], .{});
}
