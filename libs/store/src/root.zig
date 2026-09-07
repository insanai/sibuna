//! Sibuna Store Library
//!
//! In-memory, zero-allocation state: the Robin Hood spent-challenge set and
//! the GCRA rate limiter. Durable and replicated state (dynamic policies,
//! IP reputation, incident forensics) lives in `persistent.zig` on top of
//! Zaxonlite when the daemon is built with storage enabled.

const std = @import("std");
const core = @import("core");

pub const challenge_store = @import("challenge_store.zig");
pub const ChallengeStore = challenge_store.ChallengeStore;
pub const ChallengeTag = challenge_store.Tag;
pub const StoreError = challenge_store.StoreError;

pub const ring = @import("ring.zig");
pub const BoundedQueue = ring.BoundedQueue;

pub const ban_list = @import("ban_list.zig");
pub const BanList = ban_list.BanList;

pub const rate_limiter = @import("rate_limiter.zig");
pub const RateLimiter = rate_limiter.RateLimiter;
pub const RateLimits = rate_limiter.Limits;
pub const RateDecision = rate_limiter.Decision;

test {
    _ = @import("challenge_store.zig");
    _ = @import("rate_limiter.zig");
    _ = @import("ban_list.zig");
    _ = @import("ring.zig");
}

pub const telemetry = @import("telemetry.zig");
pub const ConsoleTelemetry = telemetry.ConsoleTelemetry;
test {
    _ = @import("telemetry.zig");
}
