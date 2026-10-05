//! Signed source has one off-path owner. Mailbox chunks are copied, not borrowed;
//! cancellation cannot leave a database executor referencing a download buffer.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
const App = @import("app.zig").App;
const p = @import("console_protocol");
const m = p.crs_management;

pub fn store(app: *App, id: m.Id, auth: ?p.users.Auth, prepared: *const updater.Prepared) !void {
    inline for (.{ "archive", "signature", "configuration" }) |name| {
        const bytes = @field(prepared, name).value;
        var offset: usize = 0;
        var ordinal: u32 = 0;
        while (offset < bytes.len) : (ordinal += 1) {
            if (app.stopping.load(.acquire)) return error.Canceled;
            const count = @min(m.chunk_bytes, bytes.len - offset);
            var input: m.SourceWrite = .{
                .id = id,
                .file = @field(m.File, name),
                .ordinal = ordinal,
                .bytes = try p.Bytes(m.chunk_bytes).init(bytes[offset..][0..count]),
            };
            defer std.crypto.secureZero(u8, std.mem.asBytes(&input.bytes));
            const operation: m.Request = if (auth) |credentials| .{ .chunk = .{
                .auth = credentials,
                .id = input.id,
                .file = input.file,
                .ordinal = input.ordinal,
                .bytes = input.bytes,
            } } else .{ .startup_chunk = input };
            const result = try app.background(.{ .crs_management = operation });
            if (result != .command_recorded) return error.CrsSourceRejected;
            offset += count;
        }
    }
}

pub fn load(app: *App, job: m.Job) !updater.Prepared {
    const manifest = try crs.artifact_manifest.decode(job.manifest.slice());
    var prepared = try read(app, job.id, manifest);
    errdefer prepared.deinit();
    prepared.package = try crs.release_package.prepare(app.gpa, .{
        .archive = prepared.archive.value,
        .signature = prepared.signature.value,
        .configuration = prepared.configuration.value,
        .version = manifest.version,
        .now = app.now(),
    });
    try manifest.bind(prepared.package.?);
    if (app.stopping.load(.acquire)) return error.Canceled;
    return prepared;
}

fn read(app: *App, id: m.Id, manifest: crs.artifact_manifest.Manifest) !updater.Prepared {
    const archive = try readBytes(app, id, .archive, manifest.archive_bytes);
    errdefer app.gpa.free(archive);
    const signature = try readBytes(app, id, .signature, manifest.signature_bytes);
    errdefer app.gpa.free(signature);
    const configuration = try readBytes(app, id, .configuration, manifest.configuration_bytes);
    return .{
        .allocator = app.gpa,
        .archive = .{ .buffer = archive, .value = archive },
        .signature = .{ .buffer = signature, .value = signature },
        .configuration = .{ .buffer = configuration, .value = configuration },
        .package = null,
    };
}

fn readBytes(app: *App, id: m.Id, file: m.File, length: usize) ![]u8 {
    if (length > m.fileLimit(file)) return error.InvalidCrsSource;
    const output = try app.gpa.alloc(u8, length);
    errdefer {
        std.crypto.secureZero(u8, output);
        app.gpa.free(output);
    }
    var offset: usize = 0;
    var ordinal: u32 = 0;
    while (offset < length) : (ordinal += 1) {
        if (app.stopping.load(.acquire)) return error.Canceled;
        var result = try app.background(.{ .crs_management = .{ .source = .{
            .id = id,
            .file = file,
            .ordinal = ordinal,
        } } });
        defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
        if (result != .crs_source) return error.CrsSourceUnavailable;
        const chunk = result.crs_source.slice();
        const count = @min(m.chunk_bytes, length - offset);
        if (chunk.len != count) return error.InvalidCrsSource;
        @memcpy(output[offset..][0..count], chunk);
        offset += count;
    }
    return output;
}

/// A service may expose the operator's editor text after fresh administrator
/// authorization. Neither the signed archive nor its signature can be exposed.
pub fn readConfiguration(app: *App, job: m.Job) ![]u8 {
    const manifest = try crs.artifact_manifest.decode(job.manifest.slice());
    const output = try readBytes(app, job.id, .configuration, manifest.configuration_bytes);
    errdefer {
        std.crypto.secureZero(u8, output);
        app.gpa.free(output);
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(output, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, manifest.operator_digest))
        return error.InvalidCrsSource;
    if (!std.unicode.utf8ValidateSlice(output)) return error.InvalidCrsSource;
    return output;
}
