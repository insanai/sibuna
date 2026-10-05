//! Private staging writes immutable files and its manifest last. This is not a
//! committed revision: namespace synchronization and selection belong to the store.
const std = @import("std");
const crs = @import("crs");
const ownership = @import("prepared.zig");
const manifests = crs.artifact_manifest;
const Io = std.Io;
pub const Error = manifests.Error || crs.release_signature.Error ||
    Io.Dir.CreateFileAtomicError || Io.File.Writer.Error || Io.File.SyncError ||
    Io.File.Atomic.LinkError || error{ PreparedPackageTransferred, StagingSourceMismatch };
pub const Config = struct { io: Io, directory: Io.Dir, now: u64 };

/// The caller reserves an empty, exclusive staging directory within its quota.
/// Failures may leave private files for reclamation but never replace existing files.
pub fn write(
    config: Config,
    manifest: manifests.Manifest,
    prepared: *const ownership.Prepared,
) Error!void {
    const package = prepared.package orelse return error.PreparedPackageTransferred;
    try manifest.bind(package);
    try validateSource(config.now, manifest, prepared);
    try writeFile(config, "archive.tar.gz", prepared.archive.value);
    try writeFile(config, "signature.asc", prepared.signature.value);
    try writeFile(config, "operator.conf", prepared.configuration.value);
    var buffer: [manifests.capacity]u8 = undefined;
    try writeFile(config, "manifest.bin", try manifest.encode(&buffer));
}

fn validateSource(
    now: u64,
    manifest: manifests.Manifest,
    prepared: *const ownership.Prepared,
) Error!void {
    if (prepared.archive.value.len != manifest.archive_bytes or
        prepared.signature.value.len != manifest.signature_bytes or
        prepared.configuration.value.len != manifest.configuration_bytes)
        return error.StagingSourceMismatch;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(prepared.configuration.value, &digest, .{});
    if (!std.mem.eql(u8, &digest, &manifest.operator_digest)) return error.StagingSourceMismatch;
    // A corrupted source buffer cannot be persisted merely because the separately
    // compiled package is still valid. Authenticate the actual bytes to be written.
    var scratch: crs.release_signature.Scratch = .{};
    const verifier = try crs.release_signature.Verifier.init(&scratch);
    const receipt = try verifier.verify(
        prepared.archive.value,
        prepared.signature.value,
        now,
        &scratch,
    );
    if (!std.mem.eql(u8, &receipt.digest, &manifest.archive_digest) or
        receipt.created != manifest.signed_at) return error.StagingSourceMismatch;
}

fn writeFile(config: Config, name: []const u8, bytes: []const u8) Error!void {
    var atomic = try config.directory.createFileAtomic(config.io, name, .{
        .replace = false,
        .permissions = if (@import("builtin").os.tag == .windows)
            .default_file
        else
            @fromBackingInt(0o600),
    });
    defer atomic.deinit(config.io);
    try atomic.file.writeStreamingAll(config.io, bytes);
    try atomic.file.sync(config.io);
    try atomic.link(config.io);
}
