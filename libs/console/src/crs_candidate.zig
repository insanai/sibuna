//! Private preparation owns all allocation and signature verification. A candidate
//! is not durable or applied until the storage ledger and publisher confirm it.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
const p = @import("console_protocol");
const m = p.crs_management;
const App = @import("app.zig").App;
const sources = @import("crs_sources.zig");
pub const Configuration = p.Bytes(64 * 1024);
pub const Input = struct {
    auth: p.users.Auth,
    id: m.Id,
    kind: m.Kind,
    expected_revision: u64,
    clone: ?m.Job = null,
    version: ?crs.release_version.Version = null,
    settings: m.Settings = .{},
    /// Successful enqueue transfers this owned editor buffer to the joined job.
    configuration: ?*Configuration = null,

    pub fn deinit(self: *Input, gpa: std.mem.Allocator) void {
        if (self.configuration) |configuration| {
            std.crypto.secureZero(u8, std.mem.asBytes(configuration));
            gpa.destroy(configuration);
        }
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub fn observation(app: *const App) crs.config.Observation {
    return if (app.config.proxy_mode == .forward_auth) .request_metadata else .request_response;
}

pub fn options(input: Input, observed: crs.config.Observation) !crs.generation.Options {
    try input.settings.validate();
    if (input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
    const settings = input.settings;
    const activation: crs.config.Activation = .{
        .mode = switch (settings.mode) {
            .off => .off,
            .audit => .audit,
            .enforce => .enforce,
        },
        .profile = if (settings.profile == .full) .full else .headers,
        .blocking_paranoia = settings.blocking_paranoia,
        .detection_paranoia = settings.detection_paranoia,
    };
    try activation.validate(observed, .executable);
    return .{
        .revision = input.expected_revision + 1,
        .activation = activation,
        .thresholds = .{
            .inbound = settings.inbound_threshold,
            .outbound = settings.outbound_threshold,
        },
        .observation = observed,
        .limits = .{
            .request = settings.request_bytes,
            .response = settings.response_bytes,
            .work = settings.work_budget,
        },
        .slots = settings.slots,
        .reservation = std.math.cast(usize, settings.reservation) orelse return error.InvalidLimit,
    };
}

pub fn prepare(app: *App, input: Input, diagnostic: *?m.Diagnostic) !updater.Prepared {
    if (input.clone) |original| {
        var job = original;
        job.id = input.id;
        return sources.loadDiagnosed(app, job, diagnostic);
    }
    return updater.prepare(.{
        .allocator = app.gpa,
        .io = app.io,
        .stopping = &app.stopping,
        .diagnostic = diagnostic,
        .configuration = if (input.configuration) |value| value.slice() else "",
    }, input.version);
}

pub fn verify(app: *App, input: Input, prepared: *updater.Prepared) !m.Manifest {
    const selected = try options(input, observation(app));
    try crs.http_policy.validate(&prepared.package.?.program, selected.activation);
    const manifest = try crs.artifact_manifest.Manifest.create(prepared.package.?, selected, .{
        .previous_revision = input.expected_revision,
        .signature_bytes = prepared.signature.value.len,
        .configuration_bytes = prepared.configuration.value.len,
    });
    // Reserve the complete pool before promising that these settings fit. Source
    // is retained; the unused private generation releases its transferred package.
    const generation = try crs.generation.Generation.create(app.gpa, prepared.package.?, selected);
    _ = prepared.takePackage();
    defer generation.deinit();
    var output: [crs.artifact_manifest.capacity]u8 = undefined;
    return m.Manifest.init(try manifest.encode(&output));
}
