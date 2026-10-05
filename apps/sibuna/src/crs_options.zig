//! Daemon composition options. Argument slices remain owned by the main arena.
//! Parsing does not load artifacts or allocate transaction workspaces.
const std = @import("std");
const crs = @import("crs");
pub const Error = crs.config.Error || error{
    MissingCrsValue,
    DuplicateCrsOption,
    UnknownCrsOption,
    InvalidCrsDirectory,
    InvalidCrsProfile,
    InvalidCrsLimit,
    CrsArgumentBufferLimit,
};
pub const Config = struct {
    choice: crs.config.Choice = .{},
    directory: ?[]const u8 = null,
    profile: ?crs.config.Profile = null,
    blocking: ?u8 = null,
    detection: ?u8 = null,
    inbound: ?u16 = null,
    outbound: ?u16 = null,
    request: ?usize = null,
    response: ?usize = null,
    work: ?u64 = null,
    slots: ?usize = null,
    timeout: ?u16 = null,

    pub fn validate(self: Config, observation: crs.config.Observation) Error!void {
        const activation: crs.config.Activation = .{
            .mode = self.choice.resolved(),
            .profile = self.profile orelse .full,
            .blocking_paranoia = self.blocking orelse 1,
            .detection_paranoia = self.detection orelse self.blocking orelse 1,
        };
        // Off validates operator input without opening even an invalid directory.
        const artifact: crs.config.Artifact = if (self.directory != null) .executable else .absent;
        try activation.validate(observation, artifact);
        try (crs.config.Thresholds{
            .inbound = self.inbound orelse 5,
            .outbound = self.outbound orelse 4,
        }).validate();
    }

    /// Startup overrides are explicit process configuration, not stored edits.
    /// The manifest revision still identifies the authenticated source artifact.
    pub fn apply(self: Config, selected: *crs.generation.Options) Error!void {
        selected.activation.mode = self.choice.resolved();
        if (self.profile) |value| selected.activation.profile = value;
        if (self.blocking) |value| selected.activation.blocking_paranoia = value;
        if (self.detection) |value| selected.activation.detection_paranoia = value;
        if (self.blocking != null and self.detection == null)
            selected.activation.detection_paranoia = @max(
                selected.activation.blocking_paranoia,
                selected.activation.detection_paranoia,
            );
        if (self.request) |value| selected.limits.request = value;
        if (self.response) |value| selected.limits.response = value;
        if (self.work) |value| selected.limits.work = value;
        if (self.slots) |value| selected.slots = value;
        if (self.inbound) |value| selected.thresholds.inbound = value;
        if (self.outbound) |value| selected.thresholds.outbound = value;
        try selected.thresholds.validate();
        try selected.activation.validate(selected.observation, .executable);
    }
};
pub const Parsed = struct { config: Config, remaining: []const []const u8 };

/// The output is caller-owned, with capacity for the complete original argv.
pub fn parse(argv: []const []const u8, output: [][]const u8) Error!Parsed {
    if (output.len < argv.len) return error.CrsArgumentBufferLimit;
    var config: Config = .{};
    var count: usize = 0;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const flag = argv[index];
        if (std.mem.eql(u8, flag, "--crs")) {
            try config.choice.select(.enforce);
        } else if (std.mem.eql(u8, flag, "--no-crs")) {
            try config.choice.select(.off);
        } else if (std.mem.startsWith(u8, flag, "--crs-")) {
            if (index + 1 == argv.len) return error.MissingCrsValue;
            index += 1;
            try option(&config, flag, argv[index]);
        } else {
            output[count] = flag;
            count += 1;
        }
    }
    return .{ .config = config, .remaining = output[0..count] };
}

fn option(config: *Config, flag: []const u8, value: []const u8) Error!void {
    if (std.mem.eql(u8, flag, "--crs-mode")) {
        try config.choice.select(try crs.config.Mode.parse(value));
    } else if (std.mem.eql(u8, flag, "--crs-dir")) {
        if (config.directory != null) return error.DuplicateCrsOption;
        if (value.len == 0 or value.len > 1024 or std.mem.indexOfScalar(u8, value, 0) != null)
            return error.InvalidCrsDirectory;
        config.directory = value;
    } else if (std.mem.eql(u8, flag, "--crs-profile")) {
        if (config.profile != null) return error.DuplicateCrsOption;
        config.profile = try profile(value);
    } else if (std.mem.eql(u8, flag, "--crs-paranoia")) {
        try number(u8, &config.blocking, value, 1, 4);
    } else if (std.mem.eql(u8, flag, "--crs-detection-paranoia")) {
        try number(u8, &config.detection, value, 1, 4);
    } else if (std.mem.eql(u8, flag, "--crs-inbound-threshold")) {
        try number(u16, &config.inbound, value, 1, std.math.maxInt(u16));
    } else if (std.mem.eql(u8, flag, "--crs-outbound-threshold")) {
        try number(u16, &config.outbound, value, 1, std.math.maxInt(u16));
    } else if (std.mem.eql(u8, flag, "--crs-request-limit")) {
        try number(usize, &config.request, value, 1, 64 * 1024 * 1024);
    } else if (std.mem.eql(u8, flag, "--crs-response-limit")) {
        try number(usize, &config.response, value, 1, 64 * 1024 * 1024);
    } else if (std.mem.eql(u8, flag, "--crs-work-budget")) {
        try number(u64, &config.work, value, 1, 1_000_000_000);
    } else if (std.mem.eql(u8, flag, "--crs-timeout")) {
        try number(u16, &config.timeout, value, 1, 300);
    } else if (std.mem.eql(u8, flag, "--crs-slots")) {
        try number(usize, &config.slots, value, 1, 31);
    } else return error.UnknownCrsOption;
}

fn profile(value: []const u8) Error!crs.config.Profile {
    if (std.mem.eql(u8, value, "headers")) return .headers;
    if (std.mem.eql(u8, value, "full")) return .full;
    return error.InvalidCrsProfile;
}

fn number(comptime T: type, out: *?T, value: []const u8, low: T, high: T) Error!void {
    if (out.* != null) return error.DuplicateCrsOption;
    if (value.len == 0) return error.InvalidCrsLimit;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidCrsLimit;
    const parsed = std.fmt.parseInt(T, value, 10) catch return error.InvalidCrsLimit;
    if (parsed < low or parsed > high) return error.InvalidCrsLimit;
    out.* = parsed;
}

test {
    _ = @import("crs_options_test.zig");
}
