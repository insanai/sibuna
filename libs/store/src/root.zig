//! Sibuna Store Library
//!
//! Provides a lockless / sharded Robin Hood hash map with atomic decay,
//! in-memory challenge caching, and optional Valkey/Redis integration.

const std = @import("std");
const core = @import("core");

pub const challenge_store = @import("challenge_store.zig");
pub const ChallengeStore = challenge_store.ChallengeStore;
pub const ChallengeRecord = challenge_store.ChallengeRecord;
pub const StoreError = challenge_store.StoreError;

pub const rate_limiter = @import("rate_limiter.zig");
pub const RateLimiter = rate_limiter.RateLimiter;

test {
    _ = @import("challenge_store.zig");
    _ = @import("rate_limiter.zig");
}
