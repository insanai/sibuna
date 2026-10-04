//! Scoped namespace bindings for the two supported wildcard XPath selectors.
//! URI bytes are identifiers, never resource locations to fetch.
const std = @import("std");
const work = @import("work.zig");
const names = @import("xml_names.zig");
pub const Error = work.Error || names.Error || error{XmlNamespaceLimit};
pub const Binding = struct { prefix: []const u8, uri: []const u8 };
pub const Expanded = struct { uri: []const u8, local: []const u8 };
const xml_uri = "http://www.w3.org/XML/1998/namespace";
const xmlns_uri = "http://www.w3.org/2000/xmlns/";
pub const Scope = struct {
    bindings: []Binding,
    used: usize = 0,
    budget: *work.Budget,

    pub fn bind(self: *Scope, binding: Binding, start: usize) Error!void {
        if (self.used == self.bindings.len) return error.XmlNamespaceLimit;
        if (try equal(binding.prefix, "xmlns", self.budget) or
            try equal(binding.uri, xmlns_uri, self.budget)) return error.InvalidXml;
        const reserved = try equal(binding.prefix, "xml", self.budget);
        if (reserved != try equal(binding.uri, xml_uri, self.budget)) return error.InvalidXml;
        if (binding.prefix.len != 0 and binding.uri.len == 0) return error.InvalidXml;
        for (self.bindings[start..self.used]) |existing| {
            if (try equal(existing.prefix, binding.prefix, self.budget)) return error.InvalidXml;
        }
        try self.budget.debit(1);
        self.bindings[self.used] = binding;
        self.used += 1;
    }

    pub fn expand(self: *Scope, qualified: []const u8, attribute: bool) Error!Expanded {
        const name = try names.split(qualified);
        if (try equal(name.prefix, "xmlns", self.budget)) return error.InvalidXml;
        if (name.prefix.len == 0 and attribute) return .{ .uri = "", .local = name.local };
        if (try equal(name.prefix, "xml", self.budget)) return .{
            .uri = xml_uri,
            .local = name.local,
        };
        var index = self.used;
        while (index != 0) {
            index -= 1;
            try self.budget.debit(1);
            const binding = self.bindings[index];
            if (try equal(name.prefix, binding.prefix, self.budget)) return .{
                .uri = binding.uri,
                .local = name.local,
            };
        }
        if (name.prefix.len != 0) return error.InvalidXml;
        return .{ .uri = "", .local = name.local };
    }
};

pub fn equal(left: []const u8, right: []const u8, budget: *work.Budget) work.Error!bool {
    try budget.debit(1);
    if (left.len != right.len) return false;
    try budget.debit(left.len);
    return std.mem.eql(u8, left, right);
}
