const std = @import("std");
const manifests = @import("artifact_manifest.zig");
const config = @import("config.zig");
const packages = @import("release_package.zig");
const rules = @import("rule_program.zig");
const condition = @import("condition.zig");
const t = std.testing;

fn fixture() manifests.Manifest {
    return .{
        .revision = 2,
        .previous_revision = 1,
        .version = .{ .major = 4, .minor = 30, .patch = 0 },
        .archive_digest = @splat(7),
        .operator_digest = @splat(8),
        .signed_at = 1791049738,
        .archive_bytes = 300000,
        .signature_bytes = 833,
        .configuration_bytes = 20,
        .conditions = 701,
        .compiled_peak = 22 * 1024 * 1024,
        .activation = .{ .mode = .audit },
        .thresholds = .{},
        .limits = .{},
        .slots = 8,
        .reservation = 1024 * 1024 * 1024,
    };
}

test "restart manifest has exact portable framing and rejects every incomplete prefix" {
    const original = fixture();
    var bytes: [manifests.capacity]u8 = undefined;
    const encoded = try original.encode(&bytes);
    try t.expectEqual(@as(usize, 251), encoded.len);
    try t.expect(std.mem.eql(u8, encoded[0..8], "SIBCRS\x00\x01"));
    try t.expectEqual(@as(u64, 2), std.mem.readInt(u64, encoded[32..40], .big));
    try t.expect(std.meta.eql(original, try manifests.decode(encoded)));
    for (0..encoded.len) |length|
        try t.expectError(error.InvalidManifest, manifests.decode(encoded[0..length]));
    bytes[encoded.len] = 0;
    try t.expectError(error.InvalidManifest, manifests.decode(bytes[0 .. encoded.len + 1]));
    try t.expectError(error.ManifestBufferLimit, original.encode(bytes[0 .. encoded.len - 1]));
    bytes[11] = 2;
    try t.expectError(error.IncompatibleManifest, manifests.decode(encoded));
    bytes[11] = 1;
    bytes[12] ^= 1;
    try t.expectError(error.IncompatibleManifest, manifests.decode(encoded));
    bytes[12] ^= 1;
    bytes[146] = 255;
    try t.expectError(error.InvalidMode, manifests.decode(encoded));
}

test "manifest cannot authorize phases the composition layer cannot observe" {
    var manifest = fixture();
    try t.expectError(error.UnobservableProfile, manifest.options(.request_metadata));
    manifest.activation.profile = .headers;
    const selected = try manifest.options(.request_metadata);
    try t.expectEqual(config.Observation.request_metadata, selected.observation);
    try t.expectEqual(config.Profile.headers, selected.activation.profile);
    manifest.activation.mode = .off;
    manifest.activation.profile = .full;
    _ = try manifest.options(.request_metadata);
    manifest.activation.blocking_paranoia = 4;
    try t.expectError(error.DetectionBelowBlocking, manifest.validate());
}

test "manifest refuses unsafe revisions and bounds before any generation allocation" {
    var manifest = fixture();
    manifest.revision = 0;
    try t.expectError(error.InvalidManifestRevision, manifest.validate());
    manifest.revision = 1;
    try t.expectError(error.InvalidManifestRevision, manifest.validate());
    manifest.previous_revision = 0;
    try manifest.validate();
    manifest.revision = 2;
    try t.expectError(error.InvalidManifestRevision, manifest.validate());
    manifest = fixture();
    manifest.slots = 32;
    try t.expectError(error.InvalidManifestBounds, manifest.validate());
    manifest = fixture();
    manifest.configuration_bytes = 65537;
    try t.expectError(error.InvalidManifestBounds, manifest.validate());
    manifest = fixture();
    manifest.limits.request = 64 * 1024 * 1024 + 1;
    try t.expectError(error.InvalidSlotLimits, manifest.validate());
    manifest = fixture();
    manifest.thresholds.inbound = 0;
    try t.expectError(error.InvalidThreshold, manifest.validate());
}

test "binding requires the prepared artifact identity but permits architecture-specific peaks" {
    const manifest = fixture();
    var conditions: [701]condition.Program = undefined;
    // Binding reads metadata only. This fixture makes no claim to signed bytes or
    // executable rules; the production loader must supply an authenticated Package.
    var program: rules.Program = undefined;
    program.conditions = &conditions;
    var package: packages.Package = .{
        .allocator = t.allocator,
        .bounded = .{ .parent = t.allocator, .limit = packages.compiled_capacity },
        .program = program,
        .receipt = .{
            .digest = manifest.archive_digest,
            .created = manifest.signed_at,
            .archive_bytes = manifest.archive_bytes,
        },
        .version = manifest.version,
        .operator_digest = manifest.operator_digest,
    };
    try manifest.bind(&package);
    package.bounded.peak = 12345;
    const options = try manifest.options(.request_response);
    const created = try manifests.Manifest.create(&package, options, .{
        .previous_revision = 1,
        .signature_bytes = manifest.signature_bytes,
        .configuration_bytes = manifest.configuration_bytes,
    });
    try t.expectEqual(@as(u64, 12345), created.compiled_peak);
    try created.bind(&package);
    package.operator_digest[0] ^= 1;
    try t.expectError(error.ManifestPackageMismatch, manifest.bind(&package));
    package.operator_digest = manifest.operator_digest;
    package.version.patch += 1;
    try t.expectError(error.ManifestPackageMismatch, manifest.bind(&package));
    package.version = manifest.version;
    package.receipt.archive_bytes -= 1;
    try t.expectError(error.ManifestPackageMismatch, manifest.bind(&package));
}
