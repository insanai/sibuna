//! Native libinjection XSS decision. No allocation and no policy side effects.
//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const std = @import("std");
const lexical = @import("html_tokens.zig");
const profile = @import("xss_profile.zig");
const work = @import("work.zig");
pub const Error = work.Error;
pub const Context = struct {
    input: []const u8,
    budget: *work.Budget,
    failed: bool = false,
};

pub fn detect(context: *Context) Error!bool {
    if (context.failed) return error.WorkLimit;
    errdefer context.failed = true;
    for (std.enums.values(lexical.Initial)) |initial| {
        try context.budget.debit(1);
        if (try pass(context, initial)) return true;
    }
    return false;
}

fn pass(context: *Context, initial: lexical.Initial) Error!bool {
    var tokens = lexical.Context.init(context.input, context.budget, initial);
    var attribute: profile.Attribute = .none;
    while (try lexical.next(&tokens)) |token| {
        try context.budget.debit(1);
        const input = token.bytes(context.input);
        if (token.kind != .attribute_value) attribute = .none;
        switch (token.kind) {
            .doctype => return true,
            .tag_open => if (try profile.tag(input, context.budget)) return true,
            .attribute_name => attribute = try profile.attribute(input, context.budget),
            .attribute_value => {
                const matched = switch (attribute) {
                    .none => false,
                    .black, .style => true,
                    .url => try profile.url(input, context.budget),
                    .indirect => try profile.attribute(input, context.budget) != .none,
                };
                if (matched) return true;
                attribute = .none;
            },
            .comment => if (try profile.comment(input, context.budget)) return true,
            else => {},
        }
    }
    return false;
}

test {
    _ = @import("xss_detector_test.zig");
}
