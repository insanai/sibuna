//! Sibuna Store Library
//!
//! Provides a lockless / sharded Robin Hood hash map with atomic decay,
//! in-memory challenge caching, and optional Valkey/Redis integration.

const std = @import("std");
const core = @import("core");

pub const StoreError = error{
    KeyNotFound,
    Expired,
    StoreFull,
};
