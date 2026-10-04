//! Native Core Rule Set support. Source recognition is separate from executable
//! compatibility: no runtime protection is implied by a successfully parsed file.
pub const regex = @import("regex.zig");
pub const work = @import("work.zig");
pub const compiler = @import("compiler.zig");
pub const model = @import("model.zig");
pub const source = @import("source.zig");
pub const inventory = @import("inventory.zig");
pub const syntax = @import("syntax.zig");
pub const selectors = @import("selectors.zig");
pub const collections = @import("collections.zig");
pub const config = @import("config.zig");
pub const transforms = @import("transforms.zig");
pub const substring = @import("substring.zig");
pub const primitives = @import("primitives.zig");
pub const pipeline = @import("pipeline.zig");
pub const byte_range = @import("byte_range.zig");
pub const utf8_profile = @import("utf8_profile.zig");
pub const phrases = @import("phrases.zig");
pub const phrases_source = @import("phrases_source.zig");
pub const address_set = @import("address_set.zig");

test {
    _ = @import("release_test.zig");
    _ = regex;
    _ = work;
    _ = compiler;
    _ = source;
    _ = syntax;
    _ = inventory;
    _ = selectors;
    _ = config;
    _ = transforms;
    _ = substring;
    _ = primitives;
    _ = pipeline;
    _ = byte_range;
    _ = utf8_profile;
    _ = phrases;
    _ = phrases_source;
    _ = address_set;
}
