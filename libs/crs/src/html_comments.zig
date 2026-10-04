//! Length-aware declaration and comment scans for libinjection's HTML grammar.
//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const std = @import("std");
const lexical = @import("html_context.zig");
const Context = lexical.Context;
const Step = lexical.Step;
const Error = lexical.Error;

pub fn untilGreater(context: *Context, kind: lexical.Kind) Error!Step {
    const start = context.position;
    if (try context.find(start, '>')) |end| {
        context.position = end + 1;
        context.state = .data;
        return context.emit(kind, start, end);
    }
    if (kind == .comment) context.position = context.input.len;
    context.state = .eof;
    return context.emit(kind, start, context.input.len);
}

pub fn percent(context: *Context) Error!Step {
    const start = context.position;
    var position = start;
    while (try context.find(position, '%')) |candidate| {
        if (context.input.len - candidate < 2) break;
        if (try context.byte(candidate + 1) == '>') {
            context.position = candidate + 2;
            context.state = .data;
            return context.emit(.comment, start, candidate);
        }
        position = candidate + 1;
    }
    context.position = context.input.len;
    context.state = .eof;
    return context.emit(.comment, start, context.input.len);
}

pub fn declaration(context: *Context) Error!Step {
    const start = context.position;
    if (try prefix(context, "DOCTYPE", true)) {
        context.state = .doctype;
    } else if (try prefix(context, "[CDATA[", false)) {
        context.position = start + 7;
        context.state = .cdata;
    } else if (try prefix(context, "--", false)) {
        context.position = start + 2;
        context.state = .comment;
    } else context.state = .bogus;
    return .transition;
}

fn prefix(context: *Context, expected: []const u8, insensitive: bool) Error!bool {
    if (context.input.len - context.position < expected.len) return false;
    for (expected, 0..) |byte, index| {
        const value = try context.byte(context.position + index);
        if (value != byte and (!insensitive or std.ascii.toUpper(value) != byte)) return false;
    }
    return true;
}

pub fn comment(context: *Context) Error!Step {
    const start = context.position;
    var position = start;
    while (try context.find(position, '-')) |candidate| {
        if (context.input.len - candidate < 3) break;
        var after = candidate + 1;
        while (after < context.input.len) : (after += 1) {
            if (try context.byte(after) != 0) break;
        }
        if (after == context.input.len) break;
        const byte = try context.byte(after);
        if (byte != '-' and byte != '!') {
            position = candidate + 1;
            continue;
        }
        after += 1;
        if (after == context.input.len) break;
        if (try context.byte(after) != '>') {
            position = candidate + 1;
            continue;
        }
        context.position = after + 1;
        context.state = .data;
        return context.emit(.comment, start, candidate);
    }
    context.state = .eof;
    return context.emit(.comment, start, context.input.len);
}

pub fn cdata(context: *Context) Error!Step {
    const start = context.position;
    var position = start;
    while (try context.find(position, ']')) |candidate| {
        if (context.input.len - candidate < 3) break;
        if (try context.byte(candidate + 1) == ']' and
            try context.byte(candidate + 2) == '>')
        {
            context.position = candidate + 3;
            context.state = .data;
            return context.emit(.data, start, candidate);
        }
        position = candidate + 1;
    }
    context.state = .eof;
    return context.emit(.data, start, context.input.len);
}
