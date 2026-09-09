//! Strict HTML subset for operator response pages. Parse names and quoted attributes rather
//! than guessing browser token boundaries. No recovery, foreign-content integration points,
//! executable attributes, encoded URLs or CSS escapes are accepted. Storage-time only.
const std = @import("std");
pub const Error = error{
    ForbiddenContent,
    ForbiddenAttribute,
    ExternalReference,
    PlaceholderInTag,
};
const tags = " html head body title meta style div span p a img br hr h1 h2 h3 h4 h5 h6 " ++
    "main header footer section article aside nav strong em b i small code pre ul ol li " ++
    "table thead tbody tfoot tr th td caption colgroup col blockquote details summary " ++
    "button progress svg path ";
const attributes = " id class title lang dir role tabindex hidden open disabled type " ++
    "charset name content alt width height loading rel colspan rowspan headers scope " ++
    "value max viewbox fill stroke stroke-width d ";

pub fn validate(source: []const u8) Error!void {
    // Retain clear diagnostics for schemes even when nested inside another attribute.
    for ([_][]const u8{ "javascript:", "vbscript:", "data:", "<!--" }) |token|
        if (std.ascii.indexOfIgnoreCase(source, token) != null) return error.ForbiddenContent;
    var parser: Parser = .{ .source = source };
    while (std.mem.indexOfScalarPos(u8, source, parser.at, '<')) |open| {
        parser.at = open;
        if (std.ascii.startsWithIgnoreCase(source[open..], "<!doctype html>")) {
            parser.at += "<!doctype html>".len;
            continue;
        }
        try parser.tag();
    }
}

const Parser = struct {
    source: []const u8,
    at: usize = 0,

    fn tag(self: *Parser) Error!void {
        self.at += 1;
        const closing = self.take('/');
        const name = self.readName();
        if (!listed(tags, name)) return error.ForbiddenContent;
        if (closing) {
            self.space();
            if (!self.take('>')) return error.ForbiddenContent;
            return;
        }
        while (self.at < self.source.len) {
            const before = self.at;
            self.space();
            if (self.take('>')) {
                if (equal(name, "style") or equal(name, "title")) try self.raw(name);
                return;
            }
            if (self.take('/')) {
                if (!self.take('>') or equal(name, "style") or equal(name, "title"))
                    return error.ForbiddenContent;
                return;
            }
            if (before == self.at) return error.ForbiddenAttribute;
            try self.attribute();
        }
        return error.ForbiddenContent;
    }

    fn attribute(self: *Parser) Error!void {
        const name = self.readName();
        if (name.len == 0) return error.ForbiddenAttribute;
        const url = equal(name, "href") or equal(name, "src");
        const style = equal(name, "style");
        if (!url and !style and !listed(attributes, name) and
            !std.ascii.startsWithIgnoreCase(name, "aria-") and
            !std.ascii.startsWithIgnoreCase(name, "data-")) return error.ForbiddenAttribute;
        const after_name = self.at;
        self.space();
        if (!self.take('=')) {
            if (!listed(" hidden open disabled ", name)) return error.ForbiddenAttribute;
            self.at = after_name;
            return;
        }
        self.space();
        if (self.at == self.source.len) return error.ForbiddenAttribute;
        const quote = self.source[self.at];
        if (quote != '\'' and quote != '"') return error.ForbiddenAttribute;
        self.at += 1;
        const start = self.at;
        const end = std.mem.indexOfScalarPos(u8, self.source, start, quote) orelse
            return error.ForbiddenAttribute;
        const value = self.source[start..end];
        self.at = end + 1;
        if (std.mem.indexOf(u8, value, "{{") != null) return error.PlaceholderInTag;
        if (std.mem.indexOfScalar(u8, value, '<') != null) return error.ForbiddenAttribute;
        if (url) try validateUrl(value);
        if (style) try validateCss(value);
    }

    /// Raw-text elements cannot contain template slots or markup. In particular, the fixed
    /// solver slot must never be swallowed by a style/title element in the browser parser.
    fn raw(self: *Parser, name: []const u8) Error!void {
        const end = std.mem.indexOfScalarPos(u8, self.source, self.at, '<') orelse
            return error.ForbiddenContent;
        const value = self.source[self.at..end];
        if (std.mem.indexOf(u8, value, "{{") != null) return error.PlaceholderInTag;
        if (equal(name, "style")) try validateCss(value);
        self.at = end + 1;
        if (!self.take('/') or !equal(self.readName(), name)) return error.ForbiddenContent;
        self.space();
        if (!self.take('>')) return error.ForbiddenContent;
    }

    fn readName(self: *Parser) []const u8 {
        const start = self.at;
        while (self.at < self.source.len) : (self.at += 1) {
            const byte = self.source[self.at];
            if (!std.ascii.isAlphanumeric(byte) and byte != '-') break;
        }
        return self.source[start..self.at];
    }

    fn space(self: *Parser) void {
        while (self.at < self.source.len and whitespace(self.source[self.at])) self.at += 1;
    }

    fn take(self: *Parser, byte: u8) bool {
        if (self.at == self.source.len or self.source[self.at] != byte) return false;
        self.at += 1;
        return true;
    }
};

fn validateUrl(value: []const u8) Error!void {
    if (value.len == 0 or (value[0] != '/' and value[0] != '#') or
        std.mem.startsWith(u8, value, "//")) return error.ExternalReference;
    // Entity decoding and backslash normalization can turn an apparent path into //host.
    for (value) |byte| if (byte <= 32 or byte == 127 or byte == '&' or byte == '\\')
        return error.ExternalReference;
}

fn validateCss(value: []const u8) Error!void {
    for ([_][]const u8{ "\\", "&", "/*", "url", "@import", "expression", "{{" }) |token|
        if (std.ascii.indexOfIgnoreCase(value, token) != null) return error.ForbiddenContent;
}

fn whitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n' or byte == 12;
}

fn equal(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn listed(list: []const u8, name: []const u8) bool {
    if (name.len == 0) return false;
    var words = std.mem.tokenizeScalar(u8, list, ' ');
    while (words.next()) |word| if (equal(word, name)) return true;
    return false;
}

test "strict markup rejects browser recovery, encoded URLs and foreign content" {
    const bad = [_][]const u8{
        "<img/src=\"/missing\"onerror=\"alert(1)\">",
        "<img src=\"/missing\"onerror=\"alert(1)\">",
        "<img\x0conerror=\"alert(1)\">",
        "<a href=\"/&#47;example.com\">x</a>",
        "<img src=\"/\\example.com/x\">",
        "<svg><foreignObject><p>foreign</p></foreignObject></svg>",
        "<style>{{ challenge }}</style>",
        "<p style=\"background:u\\72l(x)\">x</p>",
        "<p style=\"background:u&#114;l(x)\">x</p>",
        "<style>@im/**/port 'x';</style>",
        "<img srcset=\"/ok,https://example.com/x 2x\">",
        "<a href=\"/ok\" ping=\"/tracking\">x</a>",
        "<img src=\"/ok\"/onerror=\"alert(1)\">",
    };
    for (bad) |source| {
        if (validate(source)) |_| return error.UnsafeMarkupAccepted else |_| {}
    }
    try validate("<!doctype html><p title=\"a > b\" aria-label=\"Message\">Hello</p>");
    try validate("<button disabled class=\"btn\">Wait</button>");
    try validate("<style>@keyframes fade {from {opacity:0} to {opacity:1}}</style>");
}
