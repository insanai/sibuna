//! Complete XML for /* and //@*: concatenate root descendant text and publish all
//! ordinary attributes. Namespace declarations validate scope but are not attributes.
const std = @import("std");
const syntax = @import("xml_syntax.zig");
const text = @import("xml_text.zig");
const names = @import("xml_names.zig");
const namespaces = @import("xml_namespaces.zig");
const values = @import("acquired_values.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = syntax.Error || namespaces.Error || values.Error || error{
    XmlDepthLimit,
    XmlAttributeLimit,
    ForbiddenXmlDeclaration,
    InvalidXmlScratch,
};
pub const Binding = namespaces.Binding;
pub const Frame = struct { name: []const u8, namespace_start: usize };
pub const Attribute = struct {
    name: []const u8,
    value: []const u8,
    expanded: namespaces.Expanded = undefined,
    declaration: bool,
};
pub const Scratch = struct {
    text: []u8,
    value: []u8,
    frames: []Frame,
    attributes: []Attribute,
    bindings: []namespaces.Binding,
};
const Parser = struct {
    reader: syntax.Reader,
    builder: *values.Builder,
    scratch: Scratch,
    scope: namespaces.Scope,
    budget: *work.Budget,
    depth: usize = 0,
    text_used: usize = 0,
    saw_root: bool = false,

    fn run(self: *Parser) Error!void {
        const beginning = self.reader.input[self.reader.cursor..];
        if (beginning.len > 5 and std.mem.startsWith(u8, beginning, "<?xml") and
            syntax.whitespace(beginning[5]))
        {
            const consumed = self.reader.take("<?xml");
            std.debug.assert(consumed);
            try syntax.declaration(&self.reader);
        }
        while (self.reader.cursor < self.reader.input.len) {
            if (self.reader.take("<!--")) {
                const comment = try self.reader.through("-->");
                if (std.mem.indexOf(u8, comment, "--") != null or
                    (comment.len != 0 and comment[comment.len - 1] == '-'))
                {
                    return error.InvalidXml;
                }
            } else if (self.reader.take("<?")) {
                const target = try self.reader.name();
                if (std.ascii.eqlIgnoreCase(target, "xml")) {
                    return error.InvalidXml;
                }
                if (!self.reader.take("?>")) {
                    if (!self.reader.space()) return error.InvalidXml;
                    _ = try self.reader.through("?>");
                }
            } else if (self.reader.take("<![CDATA[")) {
                if (self.depth == 0) return error.InvalidXml;
                try self.characters(try self.reader.through("]]>"), .cdata);
            } else if (self.reader.take("<!")) {
                return error.ForbiddenXmlDeclaration;
            } else if (self.reader.take("</")) {
                try self.close();
            } else if (self.reader.take("<")) {
                try self.open();
            } else {
                const remaining = self.reader.input[self.reader.cursor..];
                const end = std.mem.indexOfScalar(u8, remaining, '<') orelse remaining.len;
                self.reader.cursor += end;
                if (self.depth != 0) {
                    try self.characters(remaining[0..end], .text);
                } else for (remaining[0..end]) |byte| {
                    if (!syntax.whitespace(byte)) return error.InvalidXml;
                }
            }
        }
        if (!self.saw_root or self.depth != 0) return error.InvalidXml;
        try self.builder.xml(.element, self.scratch.text[0..self.text_used], self.budget);
        try self.builder.complete(&.{.xml});
    }

    fn characters(self: *Parser, input: []const u8, kind: text.Kind) Error!void {
        const decoded = try text.decode(
            input,
            self.scratch.text[self.text_used..],
            kind,
            self.budget,
        );
        self.text_used += decoded.len;
    }

    fn open(self: *Parser) Error!void {
        if (self.depth == self.scratch.frames.len) return error.XmlDepthLimit;
        if (self.depth == 0 and self.saw_root) return error.InvalidXml;
        const name = try self.reader.name();
        const start = self.scope.used;
        var count: usize = 0;
        while (true) {
            const separated = self.reader.space();
            if (self.reader.take(">")) break;
            if (self.reader.take("/>")) {
                try self.attributes(name, count);
                self.scope.used = start;
                if (self.depth == 0) self.saw_root = true;
                return;
            }
            if (!separated) return error.InvalidXml;
            if (count == self.scratch.attributes.len) return error.XmlAttributeLimit;
            const attribute = try self.readAttribute(start);
            for (self.scratch.attributes[0..count]) |existing| {
                if (try namespaces.equal(existing.name, attribute.name, self.budget))
                    return error.InvalidXml;
            }
            self.scratch.attributes[count] = attribute;
            count += 1;
        }
        try self.attributes(name, count);
        self.scratch.frames[self.depth] = .{ .name = name, .namespace_start = start };
        self.depth += 1;
        self.saw_root = true;
    }

    fn readAttribute(self: *Parser, start: usize) Error!Attribute {
        const name = try self.reader.name();
        _ = self.reader.space();
        if (!self.reader.take("=")) return error.InvalidXml;
        _ = self.reader.space();
        const raw = try self.reader.quoted();
        const value = try text.decode(raw, self.scratch.value, .attribute, self.budget);
        const owned = try self.builder.own(.{ .value = value }, self.budget);
        const qualified = try names.split(name);
        const declaration = std.mem.eql(u8, name, "xmlns") or
            std.mem.eql(u8, qualified.prefix, "xmlns");
        if (declaration) try self.scope.bind(.{
            .prefix = if (qualified.prefix.len == 0) "" else qualified.local,
            .uri = owned.value,
        }, start);
        return .{ .name = name, .value = owned.value, .declaration = declaration };
    }

    fn attributes(self: *Parser, name: []const u8, count: usize) Error!void {
        _ = try self.scope.expand(name, false);
        for (self.scratch.attributes[0..count], 0..) |*attribute, index| {
            if (attribute.declaration) continue;
            attribute.expanded = try self.scope.expand(attribute.name, true);
            for (self.scratch.attributes[0..index]) |existing| {
                if (existing.declaration) continue;
                const same_uri = try namespaces.equal(
                    existing.expanded.uri,
                    attribute.expanded.uri,
                    self.budget,
                );
                if (same_uri and try namespaces.equal(
                    existing.expanded.local,
                    attribute.expanded.local,
                    self.budget,
                ))
                    return error.InvalidXml;
            }
            try self.builder.borrow(.{
                .collection = .xml,
                .key = "//@*",
                .value = attribute.value,
                .xml = .attribute,
            }, self.budget);
        }
    }

    fn close(self: *Parser) Error!void {
        if (self.depth == 0) return error.InvalidXml;
        const name = try self.reader.name();
        _ = self.reader.space();
        if (!self.reader.take(">")) return error.InvalidXml;
        const top = self.scratch.frames[self.depth - 1];
        if (!try namespaces.equal(top.name, name, self.budget)) return error.InvalidXml;
        self.depth -= 1;
        self.scope.used = top.namespace_start;
    }
};

pub fn parse(
    input: []const u8,
    builder: *values.Builder,
    scratch: Scratch,
    budget: *work.Budget,
) Error!void {
    errdefer builder.poison();
    if (scratch.frames.len == 0 or scratch.frames.len > 256) return error.InvalidXmlScratch;
    buffers.assertExclusive(&.{
        input,
        builder.bytes,
        scratch.text,
        scratch.value,
        std.mem.sliceAsBytes(scratch.frames),
        std.mem.sliceAsBytes(scratch.attributes),
        std.mem.sliceAsBytes(scratch.bindings),
        std.mem.sliceAsBytes(builder.entries),
    });
    var parser: Parser = .{
        .reader = try syntax.Reader.init(input, budget),
        .builder = builder,
        .scratch = scratch,
        .scope = .{ .bindings = scratch.bindings, .budget = budget },
        .budget = budget,
    };
    try parser.run();
}

test {
    _ = @import("xml_acquisition_test.zig");
}
