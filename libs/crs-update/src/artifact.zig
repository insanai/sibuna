//! Restart preparation re-authenticates local bytes. It returns a private candidate;
//! no filesystem metadata, mode value or successful load publishes protection.
const std = @import("std");
const crs = @import("crs");
const ownership = @import("prepared.zig");
const files = @import("artifact_files.zig");
const manifests = crs.artifact_manifest;
pub const Error = files.Error || manifests.Error || crs.release_package.Error;
pub const Config = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: std.Io.Dir,
    now: u64,
    observation: crs.config.Observation,
};
pub const Candidate = struct {
    manifest: manifests.Manifest,
    prepared: ownership.Prepared,

    pub fn deinit(self: *Candidate) void {
        self.prepared.deinit();
        self.* = undefined;
    }
};

pub fn load(config: Config) Error!Candidate {
    const reader: files.Reader = .{
        .allocator = config.allocator,
        .io = config.io,
        .directory = config.directory,
    };
    const encoded = try reader.read("manifest.bin", .{ .maximum = manifests.capacity });
    defer config.allocator.free(encoded.buffer);
    const manifest = try manifests.decode(encoded.value);
    _ = try manifest.options(config.observation);
    const archive = try reader.read("archive.tar.gz", .{ .exact = manifest.archive_bytes });
    errdefer config.allocator.free(archive.buffer);
    const signature = try reader.read("signature.asc", .{ .exact = manifest.signature_bytes });
    errdefer config.allocator.free(signature.buffer);
    const configuration_size = manifest.configuration_bytes;
    const configuration = try reader.read("operator.conf", .{ .exact = configuration_size });
    errdefer config.allocator.free(configuration.buffer);
    const package = try crs.release_package.prepare(config.allocator, .{
        .archive = archive.value,
        .signature = signature.value,
        .configuration = configuration.value,
        .version = manifest.version,
        .now = config.now,
    });
    errdefer package.deinit();
    try manifest.bind(package);
    return .{
        .manifest = manifest,
        .prepared = .{
            .allocator = config.allocator,
            .archive = archive,
            .signature = signature,
            .configuration = configuration,
            .package = package,
        },
    };
}

test {
    _ = files;
}
