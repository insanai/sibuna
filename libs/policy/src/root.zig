//! Sibuna Policy Library
//!
//! Provides SIMD Aho-Corasick multi-string pattern matching, Radix CIDR
//! routing tries for IPv4/IPv6, and JA4H HTTP fingerprinting.

const std = @import("std");
const core = @import("core");

pub const Action = enum {
    allow,
    deny,
    weigh,
    challenge,
};
