//! A portable, bounded restart contract. Metadata is not authenticity: the loader
//! must verify and compile the signed bytes again, then bind the prepared package.
const std = @import("std");
const config = @import("config.zig");
const generations = @import("generation.zig");
const slots = @import("transaction_slot.zig");
const packages = @import("release_package.zig");
const versions = @import("release_version.zig");
const trust = @import("crs-trust");
pub const compiler_abi: u32 = 1;
pub const capacity = 512;
const magic = "SIBCRS\x00\x01";
// Keep wire order independent of declaration order. Adding a bound requires an
// explicit schema review rather than silently changing a persisted layout.
const limit_fields = .{
    "entries", "depth",      "bytes",  "request", "response",    "events",
    "tags",    "exclusions", "pieces", "work",    "reservation",
};
const count_fields = .{
    "signed_at", "archive_bytes", "signature_bytes", "configuration_bytes", "conditions",
};
comptime {
    std.debug.assert(limit_fields.len == @typeInfo(slots.Limits).@"struct".field_names.len);
}
pub const Error = config.Error || versions.Error || error{
    InvalidSlotLimits,
    InvalidManifest,
    IncompatibleManifest,
    InvalidManifestRevision,
    InvalidManifestBounds,
    ManifestPackageMismatch,
    ManifestBufferLimit,
};
pub const Files = struct {
    previous_revision: u64,
    signature_bytes: usize,
    configuration_bytes: usize,
};
pub const Manifest = struct {
    revision: u64,
    previous_revision: u64,
    version: versions.Version,
    archive_digest: [32]u8,
    operator_digest: [32]u8,
    signed_at: u32,
    archive_bytes: u32,
    signature_bytes: u32,
    configuration_bytes: u32,
    conditions: u32,
    compiled_peak: u64,
    activation: config.Activation,
    thresholds: config.Thresholds,
    limits: slots.Limits,
    slots: u8,
    reservation: u64,

    pub fn create(
        package: *const packages.Package,
        selected: generations.Options,
        files: Files,
    ) Error!Manifest {
        const result: Manifest = .{
            .revision = selected.revision,
            .previous_revision = files.previous_revision,
            .version = package.version,
            .archive_digest = package.receipt.digest,
            .operator_digest = package.operator_digest,
            .signed_at = package.receipt.created,
            .archive_bytes = std.math.cast(u32, package.receipt.archive_bytes) orelse
                return error.InvalidManifestBounds,
            .signature_bytes = std.math.cast(u32, files.signature_bytes) orelse
                return error.InvalidManifestBounds,
            .configuration_bytes = std.math.cast(u32, files.configuration_bytes) orelse
                return error.InvalidManifestBounds,
            .conditions = std.math.cast(u32, package.program.conditions.len) orelse
                return error.InvalidManifestBounds,
            .compiled_peak = package.bounded.peak,
            .activation = selected.activation,
            .thresholds = selected.thresholds,
            .limits = selected.limits,
            .slots = std.math.cast(u8, selected.slots) orelse
                return error.InvalidManifestBounds,
            .reservation = selected.reservation,
        };
        _ = try result.options(selected.observation);
        return result;
    }

    pub fn validate(self: Manifest) Error!void {
        if (self.revision == 0 or self.previous_revision >= self.revision or
            (self.revision > 1 and self.previous_revision == 0))
            return error.InvalidManifestRevision;
        if (self.archive_bytes == 0 or self.archive_bytes > 8 * 1024 * 1024 or
            self.signature_bytes == 0 or self.signature_bytes > 16 * 1024 or
            self.configuration_bytes > 64 * 1024 or self.conditions == 0 or
            self.conditions > 4096 or self.compiled_peak == 0 or
            self.compiled_peak > packages.compiled_capacity or self.slots == 0 or
            self.slots > 31 or self.reservation == 0 or
            self.reservation > std.math.maxInt(usize)) return error.InvalidManifestBounds;
        try self.limits.validate();
        try self.thresholds.validate();
        try self.activation.validate(.request_response, .executable);
    }

    /// Node observation is supplied by composition, never inferred from a manifest.
    pub fn options(self: Manifest, observation: config.Observation) Error!generations.Options {
        try self.validate();
        try self.activation.validate(observation, .executable);
        return .{
            .revision = self.revision,
            .activation = self.activation,
            .thresholds = self.thresholds,
            .observation = observation,
            .limits = self.limits,
            .slots = self.slots,
            .reservation = @intCast(self.reservation),
        };
    }

    /// Compilation payload may differ between architectures. The new node applies
    /// its own allocator ceiling; only authenticated identity and rule counts bind.
    pub fn bind(self: Manifest, package: *const packages.Package) Error!void {
        try self.validate();
        if (!std.meta.eql(self.version, package.version) or
            !std.mem.eql(u8, &self.archive_digest, &package.receipt.digest) or
            !std.mem.eql(u8, &self.operator_digest, &package.operator_digest) or
            self.signed_at != package.receipt.created or
            self.archive_bytes != package.receipt.archive_bytes or
            self.conditions != package.program.conditions.len)
            return error.ManifestPackageMismatch;
    }

    /// Fixed big-endian widths avoid host padding, enum layout and usize changes.
    /// A caller-owned cursor also makes truncation and trailing-byte refusal exact.
    pub fn encode(self: Manifest, output: []u8) Error![]const u8 {
        try self.validate();
        var cursor: Encoder = .{ .output = output };
        try cursor.bytes(magic);
        try cursor.integer(u32, compiler_abi);
        try cursor.bytes(&fingerprint());
        try cursor.integer(u64, self.revision);
        try cursor.integer(u64, self.previous_revision);
        inline for (.{ "major", "minor", "patch" }) |name|
            try cursor.integer(u16, @field(self.version, name));
        try cursor.bytes(&self.archive_digest);
        try cursor.bytes(&self.operator_digest);
        inline for (count_fields) |name|
            try cursor.integer(u32, @field(self, name));
        try cursor.integer(u64, self.compiled_peak);
        try cursor.integer(u8, @backingInt(self.activation.mode));
        try cursor.integer(u8, if (self.activation.profile == .full) 1 else 0);
        try cursor.integer(u8, self.activation.blocking_paranoia);
        try cursor.integer(u8, self.activation.detection_paranoia);
        try cursor.integer(u16, self.thresholds.inbound);
        try cursor.integer(u16, self.thresholds.outbound);
        inline for (limit_fields) |name|
            try cursor.integer(u64, @field(self.limits, name));
        try cursor.integer(u8, self.slots);
        try cursor.integer(u64, self.reservation);
        return output[0..cursor.used];
    }
};

pub fn decode(input: []const u8) Error!Manifest {
    if (input.len > capacity) return error.ManifestBufferLimit;
    var cursor: Decoder = .{ .input = input };
    if (!std.mem.eql(u8, try cursor.bytes(magic.len), magic)) return error.InvalidManifest;
    if (try cursor.integer(u32) != compiler_abi) return error.IncompatibleManifest;
    if (!std.mem.eql(u8, try cursor.bytes(20), &fingerprint()))
        return error.IncompatibleManifest;
    var result: Manifest = undefined;
    result.revision = try cursor.integer(u64);
    result.previous_revision = try cursor.integer(u64);
    inline for (.{ "major", "minor", "patch" }) |name|
        @field(result.version, name) = try cursor.integer(u16);
    @memcpy(&result.archive_digest, try cursor.bytes(32));
    @memcpy(&result.operator_digest, try cursor.bytes(32));
    inline for (count_fields) |name|
        @field(result, name) = try cursor.integer(u32);
    result.compiled_peak = try cursor.integer(u64);
    result.activation.mode = switch (try cursor.integer(u8)) {
        0 => .off,
        1 => .audit,
        2 => .enforce,
        else => return error.InvalidMode,
    };
    result.activation.profile = switch (try cursor.integer(u8)) {
        0 => .headers,
        1 => .full,
        else => return error.InvalidManifest,
    };
    result.activation.blocking_paranoia = try cursor.integer(u8);
    result.activation.detection_paranoia = try cursor.integer(u8);
    result.thresholds.inbound = try cursor.integer(u16);
    result.thresholds.outbound = try cursor.integer(u16);
    inline for (limit_fields) |name| {
        const value = try cursor.integer(u64);
        @field(result.limits, name) = std.math.cast(@FieldType(slots.Limits, name), value) orelse
            return error.InvalidManifestBounds;
    }
    result.slots = try cursor.integer(u8);
    result.reservation = try cursor.integer(u64);
    if (cursor.used != input.len) return error.InvalidManifest;
    try result.validate();
    return result;
}

fn fingerprint() [20]u8 {
    var result: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, trust.fingerprint) catch unreachable;
    return result;
}

const Encoder = struct {
    output: []u8,
    used: usize = 0,

    fn bytes(self: *Encoder, value: []const u8) Error!void {
        if (value.len > self.output.len - self.used) return error.ManifestBufferLimit;
        @memcpy(self.output[self.used..][0..value.len], value);
        self.used += value.len;
    }

    fn integer(self: *Encoder, comptime T: type, value: T) Error!void {
        var buffer: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buffer, value, .big);
        try self.bytes(&buffer);
    }
};
const Decoder = struct {
    input: []const u8,
    used: usize = 0,

    fn bytes(self: *Decoder, count: usize) Error![]const u8 {
        if (count > self.input.len - self.used) return error.InvalidManifest;
        const result = self.input[self.used..][0..count];
        self.used += count;
        return result;
    }

    fn integer(self: *Decoder, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.bytes(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
};

test {
    _ = @import("artifact_manifest_test.zig");
}
