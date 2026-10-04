//! Complete request entities. Transfer/content decoding belongs to the transport;
//! the borrowed entity remains immutable through evaluation and origin replay.
const std = @import("std");
const mime = @import("text").mime;
const controls = @import("controls.zig");
const slots = @import("transaction_slot.zig");
const values = @import("acquired_values.zig");
const form = @import("form_acquisition.zig");
const json = @import("json_acquisition.zig");
const xml = @import("xml_acquisition.zig");
const multipart = @import("multipart_acquisition.zig");
const decimal = @import("decimal_format.zig");
const work = @import("work.zig");
pub const Error = form.Error || json.Error || xml.Error || multipart.Error || mime.Error || error{
    InvalidEntityPhase,
    RequestEntityLimit,
    AmbiguousBodyParameter,
    MissingMultipartBoundary,
    UnsupportedBodyCharset,
};
pub const Kind = enum {
    raw,
    urlencoded,
    multipart,
    json,
    xml,

    pub fn label(self: Kind) []const u8 {
        return switch (self) {
            .raw => "",
            .urlencoded => "URLENCODED",
            .multipart => "MULTIPART",
            .json => "JSON",
            .xml => "XML",
        };
    }
};
pub const Descriptor = struct {
    kind: Kind,
    boundary: []const u8 = "",

    pub fn parse(
        content_type: ?[]const u8,
        processor: controls.Processor,
        budget: *work.Budget,
    ) Error!Descriptor {
        var result: Descriptor = .{ .kind = switch (processor) {
            .automatic => .raw,
            .urlencoded => .urlencoded,
            .json => .json,
            .xml => .xml,
        } };
        const text = content_type orelse return result;
        try budget.debitLinear(text.len, 8, 1);
        var parsed = try mime.Value.init(text);
        if (!mime.mediaType(parsed.media)) return error.InvalidMime;
        if (processor == .automatic) {
            if (std.ascii.eqlIgnoreCase(parsed.media, "application/x-www-form-urlencoded"))
                result.kind = .urlencoded;
            if (std.ascii.eqlIgnoreCase(parsed.media, "multipart/form-data"))
                result.kind = .multipart;
        }
        var boundary: ?[]const u8 = null;
        var charset: ?[]const u8 = null;
        while (try parsed.next()) |parameter| {
            if (std.ascii.eqlIgnoreCase(parameter.name, "boundary")) {
                if (boundary != null) return error.AmbiguousBodyParameter;
                boundary = parameter.value;
            }
            if (std.ascii.eqlIgnoreCase(parameter.name, "charset")) {
                if (charset != null) return error.AmbiguousBodyParameter;
                charset = parameter.value;
            }
        }
        if (result.kind == .multipart)
            result.boundary = boundary orelse return error.MissingMultipartBoundary;
        if (result.kind == .json or result.kind == .xml) {
            if (charset) |name| {
                if (!std.ascii.eqlIgnoreCase(name, "utf-8")) return error.UnsupportedBodyCharset;
            }
        }
        return result;
    }
};

/// Begin the slot and acquire phase-one metadata before invoking this function.
/// A failure poisons all evaluation state; a caller cannot run a previous view.
pub fn request(slot: *slots.Slot, entity: []const u8, descriptor: Descriptor) Error!void {
    std.debug.assert(slot.active);
    errdefer {
        slot.input.poison();
        slot.context.poison();
        slot.state.poison();
    }
    if (slot.input.coverage[@backingInt(@import("variables.zig").Collection.request_body)] !=
        .unavailable) return error.InvalidEntityPhase;
    if (entity.len > slot.limits.request) return error.RequestEntityLimit;
    const builder = &slot.input;
    const budget = &slot.budget;
    try builder.scalar(.reqbody_processor, descriptor.kind.label(), budget);
    // An empty HTTP entity is not a malformed empty JSON/XML document. Do not
    // invent a body occurrence: collection counts must agree with the connector.
    if (entity.len != 0) {
        try builder.borrow(.{ .collection = .request_body, .value = entity }, budget);
        var digits: [decimal.capacity(u64)]u8 = undefined;
        try builder.scalar(.request_body_length, try decimal.write(
            u64,
            entity.len,
            &digits,
            budget,
        ), budget);
        switch (descriptor.kind) {
            .raw => {},
            .urlencoded => try form.parse(entity, .form, builder, slot.formScratch(), budget),
            .json => try json.parse(entity, builder, slot.jsonScratch(), budget),
            .xml => try xml.parse(entity, builder, slot.xmlScratch(), budget),
            .multipart => try multipart.parse(
                entity,
                descriptor.boundary,
                builder,
                slot.multipartScratch(),
                .{},
                budget,
            ),
        }
    }
    if (descriptor.kind != .multipart or entity.len == 0)
        try builder.scalar(.files_combined_size, "0", budget);
    try builder.sizes(budget);
    try builder.complete(&.{
        .args,  .args_names,   .args_post,           .args_post_names,
        .files, .files_names,  .files_combined_size, .multipart_part_headers,
        .xml,   .request_body, .request_body_length, .reqbody_processor,
    });
}

test {
    _ = @import("entity_acquisition_test.zig");
}
