//! The operator's private directory authorizes native engine updates. Selection
//! is durable intent; a separate worker observation reports a boot and effect.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
const local = updater.local;
const arguments = @import("crs_local_args.zig");
const candidate_files = @import("crs_candidate.zig");
const Io = std.Io;
const Writer = Io.Writer;
const Error = local.Error || updater.Error || arguments.Error || candidate_files.ReadError ||
    error{WriteFailed};
const Snapshot = struct {
    selection: ?local.Selection,
    receipt: ?local.Receipt,
    manifest: ?crs.artifact_manifest.Manifest,
};
const Sources = struct { prepared: updater.Prepared, defaults: crs.generation.Options };

pub fn execute(allocator: std.mem.Allocator, io: Io, argv: []const []const u8) u8 {
    const args = arguments.parse(argv) catch |err| {
        std.debug.print("CRSLOCALARGS: invalid local command ({t}). Hint: use --directory " ++
            "and an explicit --revision for changes; rollback accepts no overrides.\n", .{err});
        return 1;
    };
    var bytes: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &bytes);
    run(allocator, io, args, &writer.interface) catch |err| {
        std.debug.print("CRSLOCALCOMMAND: local command failed ({t}). Hint: query local " ++
            "status before retrying an unknown outcome. Keep the store private, use a " ++
            "local filesystem and review signed sources and resource bounds.\n", .{err});
        return 1;
    };
    writer.interface.flush() catch {
        std.debug.print("CRSLOCALWRITE: report delivery failed. Query local status " ++
            "before retrying a change.\n", .{});
        return 1;
    };
    return 0;
}

fn run(allocator: std.mem.Allocator, io: Io, args: arguments.Args, writer: *Writer) Error!void {
    const directory = try Io.Dir.cwd().openDir(io, args.directory, .{
        .follow_symlinks = false,
        .iterate = true,
    });
    defer directory.close(io);
    const store: local.Store = .{ .allocator = allocator, .io = io, .directory = directory };
    var before = try snapshot(store);
    if (args.operation != .status) {
        const expected = args.revision.?;
        const revision = if (before.selection) |selected| selected.current.revision else 0;
        if (revision != expected) return error.LocalStoreConflict;
        const configuration = try operatorText(store, args, before);
        defer allocator.free(configuration.buffer);
        defer std.crypto.secureZero(u8, configuration.buffer);
        var sources = try prepare(store, args, before, configuration.value);
        defer sources.prepared.deinit();
        var options = sources.defaults;
        if (args.operation != .rollback) {
            var overrides = args.overrides;
            if (overrides.choice.explicit == null)
                try overrides.choice.select(options.activation.mode);
            try overrides.apply(&options);
        }
        options.revision = expected + 1;
        const manifest = try crs.artifact_manifest.Manifest.create(
            sources.prepared.package.?,
            options,
            .{
                .previous_revision = expected,
                .signature_bytes = sources.prepared.signature.value.len,
                .configuration_bytes = sources.prepared.configuration.value.len,
            },
        );
        _ = try store.select(expected, manifest, &sources.prepared);
        before = try snapshot(store);
    }
    try std.json.Stringify.value(.{
        .saved_selection = before.selection,
        .settings = before.manifest,
        .last_application_observation = before.receipt,
        .process_liveness = "not observed",
    }, .{}, writer);
    try writer.writeByte('\n');
}

fn snapshot(store: local.Store) Error!Snapshot {
    var locked = try store.lock(.shared);
    defer locked.deinit();
    const selected = try locked.selection();
    return .{
        .selection = selected,
        .receipt = try locked.observation(),
        .manifest = if (selected) |value| try locked.manifest(value.current) else null,
    };
}

fn operatorText(
    store: local.Store,
    args: arguments.Args,
    before: Snapshot,
) Error!updater.files.Bytes {
    if (args.operation == .update and args.source == null and args.configuration == null) {
        if (before.selection) |selected| {
            var locked = try store.lock(.shared);
            defer locked.deinit();
            return locked.configuration(selected.current);
        }
    }
    return candidate_files.readConfiguration(store.allocator, store.io, args.configuration);
}

fn prepare(
    store: local.Store,
    args: arguments.Args,
    before: Snapshot,
    configuration: []const u8,
) Error!Sources {
    if (args.operation == .mode or args.operation == .rollback) {
        var locked = try store.lock(.shared);
        defer locked.deinit();
        const selected = try locked.selection() orelse return error.LocalStoreConflict;
        if (selected.current.revision != args.revision.?) return error.LocalStoreConflict;
        const source = if (args.operation == .rollback)
            selected.previous orelse return error.LocalStoreConflict
        else
            selected.current;
        var candidate = try locked.load(source);
        errdefer candidate.deinit();
        return .{
            .prepared = candidate.prepared,
            .defaults = try candidate.manifest.options(.request_response),
        };
    }
    if (args.source) |path| {
        const directory = try Io.Dir.cwd().openDir(store.io, path, .{ .follow_symlinks = false });
        defer directory.close(store.io);
        var candidate = try updater.artifact.load(.{
            .allocator = store.allocator,
            .io = store.io,
            .directory = directory,
            .now = try store.now(),
            .observation = .request_response,
        });
        errdefer candidate.deinit();
        if (args.configuration != null)
            try replaceConfiguration(&candidate.prepared, configuration, try store.now());
        return .{
            .prepared = candidate.prepared,
            .defaults = try (before.manifest orelse candidate.manifest).options(.request_response),
        };
    }
    var stopping: std.atomic.Value(bool) = .init(false);
    var prepared = try updater.prepare(.{
        .allocator = store.allocator,
        .io = store.io,
        .stopping = &stopping,
        .deadline_ms = args.timeout * 1000,
        .configuration = configuration,
    }, args.version);
    errdefer prepared.deinit();
    return .{
        .prepared = prepared,
        .defaults = if (before.manifest) |manifest|
            try manifest.options(.request_response)
        else
            .{ .revision = 1, .activation = .{ .mode = .off }, .observation = .request_response },
    };
}

fn replaceConfiguration(prepared: *updater.Prepared, text: []const u8, now: u64) Error!void {
    const package = prepared.package.?;
    const version = package.version;
    const replacement = try prepared.allocator.dupe(u8, text);
    package.deinit();
    prepared.package = null;
    std.crypto.secureZero(u8, prepared.configuration.buffer);
    prepared.allocator.free(prepared.configuration.buffer);
    prepared.configuration = .{ .buffer = replacement, .value = replacement };
    prepared.package = try crs.release_package.prepare(prepared.allocator, .{
        .archive = prepared.archive.value,
        .signature = prepared.signature.value,
        .configuration = replacement,
        .version = version,
        .now = now,
    });
}

test {
    _ = arguments;
}
