//! Shared activation contract for startup and authorized management revisions.
//! Source recognition is not enough to activate protection. The generation publisher
//! must separately establish executable compatibility before selecting Audit or Enforce.
const std = @import("std");
const model = @import("model.zig");

pub const Error = error{
    InvalidMode,
    ConflictingMode,
    InvalidParanoia,
    DetectionBelowBlocking,
    MissingArtifact,
    NotExecutable,
    UnobservableProfile,
};

pub const Mode = enum(u8) {
    off = 0,
    audit = 1,
    enforce = 2,

    pub fn parse(bytes: []const u8) Error!Mode {
        return modes.get(bytes) orelse error.InvalidMode;
    }
};
const modes = std.StaticStringMap(Mode).initComptime(.{
    .{ "off", .off }, .{ "audit", .audit }, .{ "enforce", .enforce },
});

pub const Profile = enum { headers, full };
pub const Observation = enum { request_metadata, request_response };
pub const Artifact = enum { absent, source_only, executable };

pub const Activation = struct {
    mode: Mode = .off,
    profile: Profile = .full,
    blocking_paranoia: u8 = 1,
    detection_paranoia: u8 = 1,

    pub fn validate(self: Activation, observation: Observation, artifact: Artifact) Error!void {
        if (self.blocking_paranoia < 1 or self.blocking_paranoia > 4 or
            self.detection_paranoia < 1 or self.detection_paranoia > 4)
        {
            return error.InvalidParanoia;
        }
        if (self.detection_paranoia < self.blocking_paranoia) {
            return error.DetectionBelowBlocking;
        }
        if (self.mode == .off) return;
        switch (artifact) {
            .absent => return error.MissingArtifact,
            .source_only => return error.NotExecutable,
            .executable => {},
        }
        if (observation == .request_metadata and self.profile == .full) {
            return error.UnobservableProfile;
        }
    }

    /// Callers can check this before acquiring a slot, holding a body or emitting CRS
    /// telemetry. Gate/Shield decisions remain outside this independent contract.
    pub fn observes(self: Activation, phase: model.Phase) bool {
        if (self.mode == .off) return false;
        return self.profile == .full or phase == .request_headers or phase == .logging;
    }
};

pub const Choice = struct {
    explicit: ?Mode = null,

    /// --crs selects Enforce, --no-crs selects Off and --crs-mode parses a Mode.
    /// Agreeing repeated options are harmless; conflicting ones cannot depend on order.
    pub fn select(self: *Choice, mode: Mode) Error!void {
        if (self.explicit) |previous| {
            if (previous != mode) return error.ConflictingMode;
        }
        self.explicit = mode;
    }

    pub fn resolved(self: Choice) Mode {
        return self.explicit orelse .off;
    }
};

test "enable disable and explicit modes cannot depend on argument order" {
    var choice: Choice = .{};
    try std.testing.expectEqual(Mode.off, choice.resolved());
    try choice.select(try Mode.parse("audit"));
    try choice.select(.audit);
    try std.testing.expectEqual(Mode.audit, choice.resolved());
    try std.testing.expectError(error.ConflictingMode, choice.select(.enforce));
    try std.testing.expectEqual(Mode.audit, choice.resolved());
    for ([_]Mode{ .off, .audit, .enforce }) |first| {
        for ([_]Mode{ .off, .audit, .enforce }) |second| {
            if (first == second) continue;
            var pair: Choice = .{};
            try pair.select(first);
            try std.testing.expectError(error.ConflictingMode, pair.select(second));
        }
    }
    try std.testing.expectError(error.InvalidMode, Mode.parse("enabled"));
}

test "source-only plans and unobserved phases cannot be activated" {
    var activation: Activation = .{};
    try activation.validate(.request_metadata, .absent);
    for ([_]model.Phase{
        .request_headers, .request_body, .response_headers, .response_body, .logging,
    }) |phase| try std.testing.expect(!activation.observes(phase));
    for ([_]Mode{ .audit, .enforce }) |mode| {
        activation.mode = mode;
        try std.testing.expectError(
            error.MissingArtifact,
            activation.validate(.request_response, .absent),
        );
        try std.testing.expectError(
            error.NotExecutable,
            activation.validate(.request_response, .source_only),
        );
        try std.testing.expectError(
            error.UnobservableProfile,
            activation.validate(.request_metadata, .executable),
        );
        activation.profile = .headers;
        try activation.validate(.request_metadata, .executable);
        try std.testing.expect(activation.observes(.request_headers));
        try std.testing.expect(activation.observes(.logging));
        try std.testing.expect(!activation.observes(.request_body));
        activation.profile = .full;
    }
    activation.blocking_paranoia = 3;
    try std.testing.expectError(
        error.DetectionBelowBlocking,
        activation.validate(.request_response, .executable),
    );
    activation.detection_paranoia = 5;
    try std.testing.expectError(
        error.InvalidParanoia,
        activation.validate(.request_response, .executable),
    );
}
