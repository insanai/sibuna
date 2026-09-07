//! Sibuna Policy Library
//!
//! Provides SIMD Aho-Corasick multi-string pattern matching, Radix CIDR
//! routing tries for IPv4/IPv6, and JA4H HTTP fingerprinting.

const std = @import("std");
const core = @import("core");

pub const aho_corasick = @import("aho_corasick.zig");
pub const radix_trie = @import("radix_trie.zig");
pub const bot_signatures = @import("bot_signatures.zig");
pub const rule = @import("rule.zig");
pub const loader = @import("loader.zig");
pub const engine = @import("engine.zig");
pub const waf = @import("waf.zig");
pub const normalizer = @import("normalizer.zig");
pub const embedding = @import("embedding.zig");

pub const Action = engine.Action;
pub const Header = engine.Header;
pub const PolicyRule = engine.PolicyRule;
pub const Decision = engine.Decision;
pub const Engine = engine.Engine;

test {
    _ = @import("aho_corasick.zig");
    _ = @import("radix_trie.zig");
    _ = @import("rule.zig");
    _ = @import("loader.zig");
    _ = @import("engine.zig");
    _ = @import("waf.zig");
    _ = @import("normalizer.zig");
    _ = @import("embedding.zig");
}
