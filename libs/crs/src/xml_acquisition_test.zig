const std = @import("std");
const xml = @import("xml_acquisition.zig");
const bindings = @import("xml_namespaces.zig");
const values = @import("acquired_values.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");
const State = struct {
    entries: [64]variables.Entry = undefined,
    bytes: [2048]u8 = undefined,
    text: [512]u8 = undefined,
    value: [128]u8 = undefined,
    frames: [8]xml.Frame = undefined,
    attributes: [16]xml.Attribute = undefined,
    namespaces: [16]bindings.Binding = undefined,
    builder: values.Builder = undefined,
    budget: work.Budget = .{ .remaining = 100000 },

    fn init(self: *State) void {
        self.builder = values.Builder.init(&self.entries, &self.bytes);
        self.budget.remaining = 100000;
    }

    fn scratch(self: *State) xml.Scratch {
        return .{
            .text = &self.text,
            .value = &self.value,
            .frames = &self.frames,
            .attributes = &self.attributes,
            .bindings = &self.namespaces,
        };
    }

    fn parse(self: *State, input: []const u8) !void {
        try xml.parse(input, &self.builder, self.scratch(), &self.budget);
    }
};

test "XML wildcard views contain root descendant text and all ordinary attributes" {
    var state: State = .{};
    state.init();
    try state.parse(
        "<?xml version='1.0' encoding='UTF-8'?>" ++
            "<root xmlns:p='urn:one' a='x&amp;y'>before" ++
            "<p:child p:b='é'>inside<![CDATA[&raw<]]></p:child>" ++
            "<!--hidden--><?instruction ignored?>after</root>",
    );
    const view = try state.builder.view();
    try view.require(.xml);
    try std.testing.expectEqual(@as(usize, 3), view.entries.len);
    try std.testing.expectEqual(variables.Xml.attribute, view.entries[0].xml.?);
    try std.testing.expectEqualStrings("//@*", view.entries[0].key);
    try std.testing.expectEqualStrings("x&y", view.entries[0].value);
    try std.testing.expectEqualStrings("é", view.entries[1].value);
    try std.testing.expectEqual(variables.Xml.element, view.entries[2].xml.?);
    try std.testing.expectEqualStrings("/*", view.entries[2].key);
    try std.testing.expectEqualStrings("beforeinside&raw<after", view.entries[2].value);
}

test "XML namespace scopes, empty roots and XML stylesheet instructions are preserved" {
    var state: State = .{};
    state.init();
    try state.parse(
        "<?xml-stylesheet href='style.css'?>" ++
            "<root xmlns='urn:default' xmlns:p='urn:one'>" ++
            "<p:child xmlns:p='urn:two' p:a='two'/><p:child p:a='one'/></root>",
    );
    try std.testing.expectEqualStrings("two", state.entries[0].value);
    try std.testing.expectEqualStrings("one", state.entries[1].value);
    state.init();
    try state.parse("\xef\xbb\xbf<root/>");
    try std.testing.expectEqual(@as(usize, 1), state.builder.used);
    try std.testing.expectEqualStrings("", state.entries[0].value);
    state.init();
    try state.parse("<root xml:lang='en' xmlns='urn:one'><child xmlns=''/></root>");
}

test "XML refuses DTDs, unknown entities, malformed trees and namespace ambiguities" {
    var state: State = .{};
    for ([_][]const u8{
        "",
        "<a>",
        "<a></b>",
        "<a/><b/>",
        "text<a/>",
        "<a>]]></a>",
        "<a>&custom;</a>",
        "<a>&#0;</a>",
        "<a x='<bad'/>",
        "<a x='1' x='2'/>",
        "<p:a/>",
        "<a p:x='1'/>",
        "<a xmlns:p=''/>",
        "<a xmlns:xml='urn:fake'/>",
        "<a xmlns:p='urn:same' xmlns:q='urn:same' p:x='1' q:x='2'/>",
        "<!--bad--comment--><a/>",
        "<a/>\xff",
        "<?XML version='1.0'?><a/>",
    }) |input| {
        state.init();
        try std.testing.expectError(error.InvalidXml, state.parse(input));
        try std.testing.expectError(error.AcquisitionFailed, state.builder.view());
    }
    state.init();
    try std.testing.expectError(error.ForbiddenXmlDeclaration, state.parse(
        "<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><a>&e;</a>",
    ));
    state.init();
    try std.testing.expectError(error.UnsupportedXmlEncoding, state.parse(
        "<?xml version='1.0' encoding='UTF-16'?><a/>",
    ));
}

test "XML scratch bounds and work exhaustion cannot produce complete coverage" {
    var state: State = .{};
    state.init();
    try std.testing.expectError(error.XmlDepthLimit, state.parse(
        "<a><a><a><a><a><a><a><a><a/></a></a></a></a></a></a></a></a>",
    ));
    state.init();
    var tiny_text: [1]u8 = undefined;
    var scratch = state.scratch();
    scratch.text = &tiny_text;
    try std.testing.expectError(
        error.XmlTextLimit,
        xml.parse("<a>long</a>", &state.builder, scratch, &state.budget),
    );
    state.init();
    state.budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, state.parse("<a/>"));
    try std.testing.expectError(error.AcquisitionFailed, state.builder.view());
}
