//! Iterative HTML tokenizer; the reference callbacks never reach the request stack.
//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const lexical = @import("html_context.zig");
const tags = @import("html_tags.zig");
const comments = @import("html_comments.zig");
pub const Context = lexical.Context;
pub const Token = lexical.Token;
pub const Initial = lexical.Initial;
pub const Kind = lexical.Kind;
pub const Error = lexical.Error;

pub fn next(context: *Context) Error!?Token {
    if (context.failed) return error.WorkLimit;
    errdefer context.failed = true;
    while (true) {
        try context.budget.debit(1);
        const result = try step(context);
        switch (result) {
            .transition => continue,
            .token => return context.token,
            .end => {
                context.state = .eof;
                return null;
            },
        }
    }
}

fn step(context: *Context) Error!lexical.Step {
    return switch (context.state) {
        .eof => .end,
        .data => tags.data(context),
        .tag_open => tags.open(context),
        .tag_name => tags.name(context),
        .end_tag => tags.endOpen(context),
        .name_close => tags.nameClose(context),
        .self_close => tags.selfClose(context),
        .before_name => tags.beforeName(context),
        .name => tags.attribute(context),
        .after_name => tags.afterName(context),
        .before_value => tags.beforeValue(context),
        .single => tags.quoted(context, '\''),
        .double => tags.quoted(context, '"'),
        .backtick => tags.quoted(context, '`'),
        .unquoted => tags.unquoted(context),
        .after_value => tags.afterValue(context),
        .bogus => comments.untilGreater(context, .comment),
        .percent_comment => comments.percent(context),
        .declaration => comments.declaration(context),
        .comment => comments.comment(context),
        .cdata => comments.cdata(context),
        .doctype => comments.untilGreater(context, .doctype),
    };
}

test {
    _ = @import("html_tokens_test.zig");
}
