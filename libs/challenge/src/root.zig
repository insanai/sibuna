//! Sibuna Challenge Library
//!
//! Coordinates proof-of-work challenge generation, verification, and
//! dynamic load-based difficulty adjustment.

const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");

pub const coordinator = @import("coordinator.zig");
pub const Coordinator = coordinator.Coordinator;
pub const ChallengePayload = coordinator.ChallengePayload;
pub const VerifiedResult = coordinator.VerifiedResult;

pub const Algorithm = enum {
    fast_sha256,
    slow_sha256,
    hashx,
    argon2id,
};

test {
    _ = @import("coordinator.zig");
}
