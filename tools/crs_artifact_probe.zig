//! Disk reload qualification, independent of daemon publication and management jobs.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
const fixture = @import("crs_transaction_fixture.zig");
const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    var buffer: [4096]u8 = undefined;
    var output = Io.File.stdout().writerStreaming(init.io, &buffer);
    defer output.interface.flush() catch {};
    return run(init, &output.interface) catch |err| {
        try output.interface.print("rejected {t}\n", .{err});
        return 1;
    };
}

fn run(init: std.process.Init, out: *Io.Writer) !u8 {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const archive_path = args.next() orelse return error.MissingArchive;
    const signature_path = args.next() orelse return error.MissingSignature;
    const version = try crs.release_version.Version.parse(args.next() orelse
        return error.MissingVersion);
    const now = try std.fmt.parseInt(u64, args.next() orelse return error.MissingClock, 10);
    const configuration_path = args.next();
    if (args.next() != null) return error.TooManyArguments;
    const archive = try read(init, archive_path, 8 * 1024 * 1024 + 1);
    defer init.gpa.free(archive);
    const signature = try read(init, signature_path, 16 * 1024 + 1);
    defer init.gpa.free(signature);
    const configuration = if (configuration_path) |path|
        try read(init, path, 64 * 1024 + 2)
    else
        try init.gpa.alloc(u8, 0);
    defer init.gpa.free(configuration);
    const package = try crs.release_package.prepare(init.gpa, .{
        .archive = archive,
        .signature = signature,
        .version = version,
        .now = now,
        .configuration = configuration,
    });
    defer package.deinit();
    const parent = std.fs.path.dirname(archive_path) orelse return error.MissingFixtureDirectory;
    const directory = try Io.Dir.cwd().openDir(init.io, parent, .{ .follow_symlinks = false });
    defer directory.close(init.io);
    const options: crs.generation.Options = .{
        .revision = 1,
        .activation = .{ .mode = .enforce },
        .observation = .request_response,
    };
    const manifest = try crs.artifact_manifest.Manifest.create(package, options, .{
        .previous_revision = 0,
        .signature_bytes = signature.len,
        .configuration_bytes = configuration.len,
    });
    var nonce: [8]u8 = undefined;
    init.io.random(&nonce);
    const name = std.fmt.bytesToHex(&nonce, .lower);
    try directory.createDir(init.io, &name, .default_dir);
    const staged = try directory.openDir(init.io, &name, .{ .follow_symlinks = false });
    defer staged.close(init.io);
    var source: updater.Prepared = .{
        .allocator = init.gpa,
        .archive = .{ .buffer = archive, .value = archive },
        .signature = .{ .buffer = signature, .value = signature },
        .configuration = .{ .buffer = configuration, .value = configuration },
        .package = package,
    };
    const staging: updater.staging.Config = .{ .io = init.io, .directory = staged, .now = now };
    try sourceRefusals(staging, manifest, &source);
    try updater.staging.write(staging, manifest, &source);
    try duplicateRefusal(staging, manifest, &source);
    try candidateDirectory(init, staged, manifest, &source, now);
    try @import("crs_startup_fixture.zig").qualify(init, staged, manifest, now);
    @memset(archive, '!');
    @memset(signature, '!');
    @memset(configuration, '!');
    try qualify(init, staged, manifest, now, configuration.len != 0);
    try out.print("prepared {d} {d} {x} {d}\n", .{
        package.program.conditions.len, package.program.regex_states,
        &package.receipt.digest,        package.bounded.peak,
    });
    return 0;
}

fn candidateDirectory(
    init: std.process.Init,
    parent: Io.Dir,
    manifest: crs.artifact_manifest.Manifest,
    source: *const updater.Prepared,
    now: u64,
) !void {
    const config: updater.candidate_directory.Config = .{
        .io = init.io,
        .parent = parent,
        .name = "saved-candidate",
        .now = now,
    };
    try updater.candidate_directory.write(config, manifest, source);
    if (updater.candidate_directory.write(config, manifest, source)) |_|
        return error.CandidateDirectoryWasReplaced
    else |err| if (err != error.PathAlreadyExists) return err;
    const saved = try parent.openDir(init.io, config.name, .{ .follow_symlinks = false });
    defer saved.close(init.io);
    try @import("crs_startup_fixture.zig").qualify(init, saved, manifest, now);
}

fn sourceRefusals(
    config: updater.staging.Config,
    manifest: crs.artifact_manifest.Manifest,
    source: *updater.Prepared,
) !void {
    const package = source.package;
    source.package = null;
    try expectStagingFailure(config, manifest, source, error.PreparedPackageTransferred);
    source.package = package;
    var changed = manifest;
    changed.signature_bytes += 1;
    try expectStagingFailure(config, changed, source, error.StagingSourceMismatch);
    const last = source.archive.value.len - 1;
    source.archive.buffer[last] ^= 1;
    try expectStagingFailure(config, manifest, source, error.InvalidSignature);
    source.archive.buffer[last] ^= 1;
    if (source.configuration.value.len != 0) {
        source.configuration.buffer[0] ^= 1;
        try expectStagingFailure(config, manifest, source, error.StagingSourceMismatch);
        source.configuration.buffer[0] ^= 1;
    }
    if (config.directory.statFile(config.io, "archive.tar.gz", .{})) |_| {
        return error.InvalidSourceWasStaged;
    } else |err| if (err != error.FileNotFound) return err;
}

fn expectStagingFailure(
    config: updater.staging.Config,
    manifest: crs.artifact_manifest.Manifest,
    source: *const updater.Prepared,
    expected: anyerror,
) !void {
    if (updater.staging.write(config, manifest, source)) {
        return error.InvalidSourceWasAccepted;
    } else |err| if (err != expected) return error.UnexpectedStagingRefusal;
}

fn read(init: std.process.Init, path: []const u8, limit: usize) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(limit));
}

fn duplicateRefusal(
    config: updater.staging.Config,
    manifest: crs.artifact_manifest.Manifest,
    source: *const updater.Prepared,
) !void {
    if (updater.staging.write(config, manifest, source)) {
        return error.StagingOverwroteExistingArtifact;
    } else |err| if (err != error.PathAlreadyExists) return err;
}

fn writeManifest(io: Io, directory: Io.Dir, manifest: crs.artifact_manifest.Manifest) !void {
    var buffer: [crs.artifact_manifest.capacity]u8 = undefined;
    try directory.writeFile(io, .{
        .sub_path = "manifest.bin",
        .data = try manifest.encode(&buffer),
    });
}

fn qualify(
    init: std.process.Init,
    directory: Io.Dir,
    manifest: crs.artifact_manifest.Manifest,
    now: u64,
    configured: bool,
) !void {
    const config: updater.artifact.Config = .{
        .allocator = init.gpa,
        .io = init.io,
        .directory = directory,
        .now = now,
        .observation = .request_response,
    };
    var candidate = try updater.artifact.load(config);
    defer candidate.deinit();
    var changed = manifest;
    changed.archive_digest[0] ^= 1;
    try writeManifest(init.io, directory, changed);
    try expectRefusal(config, error.ManifestPackageMismatch);
    try writeManifest(init.io, directory, manifest);
    try directory.writeFile(init.io, .{ .sub_path = "operator.conf", .data = "" });
    if (configured) try expectRefusal(config, error.ArtifactFileLength);
    // Restore the immutable source, then corrupt the archive under the same manifest.
    try directory.writeFile(init.io, .{
        .sub_path = "operator.conf",
        .data = candidate.prepared.configuration.value,
    });
    const corrupted = try init.gpa.dupe(u8, candidate.prepared.archive.value);
    defer init.gpa.free(corrupted);
    corrupted[corrupted.len - 1] ^= 1;
    try directory.writeFile(init.io, .{ .sub_path = "archive.tar.gz", .data = corrupted });
    try expectRefusal(config, error.InvalidSignature);
    try directory.deleteFile(init.io, "archive.tar.gz");
    try expectRefusal(config, error.FileNotFound);
    var unobservable = config;
    unobservable.observation = .request_metadata;
    try expectRefusal(unobservable, error.UnobservableProfile);
    // Rejected reloads cannot revoke the previously loaded package. The compiled
    // program must also retain no borrows into its own disk-read source buffers.
    @memset(candidate.prepared.archive.buffer, '!');
    @memset(candidate.prepared.signature.buffer, '!');
    @memset(candidate.prepared.configuration.buffer, '!');
    try fixture.evaluate(init.gpa, &candidate.prepared.package.?.program, configured);
}

fn expectRefusal(config: updater.artifact.Config, expected: anyerror) !void {
    if (updater.artifact.load(config)) |value| {
        var candidate = value;
        candidate.deinit();
        return error.UnexpectedReloadSuccess;
    } else |err| {
        if (err != expected) {
            std.debug.print("expected {t}, received {t}\n", .{ expected, err });
            return error.ReloadRefusalMismatch;
        }
    }
}
