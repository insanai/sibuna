//! Iterative tag and attribute transitions for the pinned libinjection grammar.
//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSES.
const std = @import("std");
const lexical = @import("html_context.zig");
const Context = lexical.Context;
const Step = lexical.Step;
const Error = lexical.Error;

pub fn data(context: *Context) Error!Step {
    const start = context.position;
    if (try context.find(start, '<')) |end| {
        context.position = end + 1;
        context.state = .tag_open;
        if (end == start) return .transition;
        return context.emit(.data, start, end);
    }
    context.state = .eof;
    if (start == context.input.len) return .end;
    return context.emit(.data, start, context.input.len);
}

pub fn open(context: *Context) Error!Step {
    if (context.position == context.input.len) return .end;
    const byte = try context.byte(context.position);
    context.state = switch (byte) {
        '!' => .declaration,
        '/' => .end_tag,
        '?' => .bogus,
        '%' => .percent_comment,
        else => .tag_name,
    };
    if (byte == '!' or byte == '/' or byte == '?' or byte == '%') {
        context.position += 1;
        if (byte == '/') context.closing = true;
        return .transition;
    }
    if (byte == 0 or std.ascii.isAlphabetic(byte)) return .transition;
    context.state = .data;
    if (context.position == 0) return .transition;
    return context.emit(.data, context.position - 1, context.position);
}

pub fn endOpen(context: *Context) Error!Step {
    if (context.position == context.input.len) return .end;
    const byte = try context.byte(context.position);
    if (byte == '>') {
        context.state = .data;
    } else if (std.ascii.isAlphabetic(byte)) {
        context.state = .tag_name;
    } else {
        context.closing = false;
        context.state = .bogus;
    }
    return .transition;
}

pub fn nameClose(context: *Context) Step {
    std.debug.assert(context.position < context.input.len);
    const start = context.position;
    context.closing = false;
    context.position += 1;
    context.state = if (context.position == context.input.len) .eof else .data;
    return context.emit(.tag_name_close, start, start + 1);
}

pub fn name(context: *Context) Error!Step {
    const start = context.position;
    var position = start;
    while (position < context.input.len) : (position += 1) {
        const byte = try context.byte(position);
        if (byte == 0) continue;
        if (lexical.isWhite(byte) or byte == '/') {
            context.position = position + 1;
            context.state = if (byte == '/') .self_close else .before_name;
            return context.emit(.tag_open, start, position);
        }
        if (byte == '>') {
            if (context.closing) {
                context.position = position + 1;
                context.closing = false;
                context.state = .data;
                return context.emit(.tag_close, start, position);
            }
            context.position = position;
            context.state = .name_close;
            return context.emit(.tag_open, start, position);
        }
    }
    context.state = .eof;
    return context.emit(.tag_open, start, context.input.len);
}

pub fn beforeName(context: *Context) Error!Step {
    const byte = try context.white() orelse return .end;
    if (byte == '/') {
        context.position += 1;
        context.state = .self_close;
    } else if (byte == '>') {
        const start = context.position;
        context.position += 1;
        context.state = .data;
        return context.emit(.tag_name_close, start, start + 1);
    } else context.state = .name;
    return .transition;
}

pub fn selfClose(context: *Context) Error!Step {
    if (context.position == context.input.len) return .end;
    if (try context.byte(context.position) != '>') {
        context.state = .before_name;
        return .transition;
    }
    std.debug.assert(context.position > 0);
    const start = context.position - 1;
    context.position += 1;
    context.state = .data;
    return context.emit(.tag_self_close, start, context.position);
}

pub fn attribute(context: *Context) Error!Step {
    const start = context.position;
    std.debug.assert(start < context.input.len);
    var position = start + 1;
    while (position < context.input.len) : (position += 1) {
        const byte = try context.byte(position);
        if (lexical.isWhite(byte) or byte == '/' or byte == '=' or byte == '>') {
            context.state = if (lexical.isWhite(byte)) .after_name else switch (byte) {
                '/' => .self_close,
                '=' => .before_value,
                else => .name_close,
            };
            context.position = position + @intFromBool(byte != '>');
            return context.emit(.attribute_name, start, position);
        }
    }
    context.state = .eof;
    context.position = context.input.len;
    return context.emit(.attribute_name, start, context.input.len);
}

pub fn afterName(context: *Context) Error!Step {
    const byte = try context.white() orelse return .end;
    context.state = switch (byte) {
        '/' => .self_close,
        '=' => .before_value,
        '>' => .name_close,
        else => .name,
    };
    if (byte == '/' or byte == '=') context.position += 1;
    return .transition;
}

pub fn beforeValue(context: *Context) Error!Step {
    const byte = try context.white() orelse {
        context.state = .eof;
        return .end;
    };
    context.state = switch (byte) {
        '\'' => .single,
        '"' => .double,
        '`' => .backtick,
        else => .unquoted,
    };
    return .transition;
}

pub fn quoted(context: *Context, quote: u8) Error!Step {
    // A quote-context start at zero represents a value whose opener was external.
    if (context.position > 0) context.position += 1;
    const start = context.position;
    if (try context.find(start, quote)) |finish| {
        context.position = finish + 1;
        context.state = .after_value;
        return context.emit(.attribute_value, start, finish);
    }
    context.state = .eof;
    return context.emit(.attribute_value, start, context.input.len);
}

pub fn unquoted(context: *Context) Error!Step {
    const start = context.position;
    var position = start;
    while (position < context.input.len) : (position += 1) {
        const byte = try context.byte(position);
        if (lexical.isWhite(byte) or byte == '>') {
            context.position = position + @intFromBool(byte != '>');
            context.state = if (byte == '>') .name_close else .before_name;
            return context.emit(.attribute_value, start, position);
        }
    }
    context.state = .eof;
    return context.emit(.attribute_value, start, context.input.len);
}

pub fn afterValue(context: *Context) Error!Step {
    if (context.position == context.input.len) return .end;
    const byte = try context.byte(context.position);
    if (byte == '>') {
        const start = context.position;
        context.position += 1;
        context.state = .data;
        return context.emit(.tag_name_close, start, start + 1);
    }
    context.state = if (byte == '/') .self_close else .before_name;
    if (byte == '/' or lexical.isWhite(byte)) context.position += 1;
    return .transition;
}
