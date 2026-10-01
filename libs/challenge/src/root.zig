//! Sibuna Challenge Library
//!
//! Stateless challenge issuance, native verification of both proof-of-work
//! tiers, single-use enforcement, token minting, and load-adaptive
//! difficulty control.

const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");

pub const coordinator = @import("coordinator.zig");
pub const adaptive = @import("adaptive.zig");
pub const Coordinator = coordinator.Coordinator;
pub const ChallengePayload = coordinator.ChallengePayload;
pub const ChallengeSpec = coordinator.ChallengeSpec;
pub const Algorithm = coordinator.Algorithm;
pub const TokenScheme = coordinator.TokenScheme;
pub const WorkLevel = coordinator.WorkLevel;
pub const requiredWork = coordinator.requiredWork;
pub const Solution = coordinator.Solution;
pub const VerifiedResult = coordinator.VerifiedResult;
pub const VerifyError = coordinator.VerifyError;
pub const Adaptive = adaptive.Adaptive;

test {
    _ = @import("coordinator.zig");
    _ = @import("adaptive.zig");
}
