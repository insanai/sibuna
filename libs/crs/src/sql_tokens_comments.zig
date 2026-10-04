//! Ported from libinjection b9fcaaf; Copyright 2012-2016 Nick Galbreath, BSD-3-Clause.
const context = @import("sql_token_context.zig");
const Frame = context.Frame;
const Error = context.Error;
const Kind = context.Kind;

pub fn symbol(frame: Frame, kind: Kind) Error!usize {
    const start = frame.state.position;
    try frame.assign(kind, start, 1);
    return start + 1;
}

pub fn eol(frame: Frame) Error!usize {
    const start = frame.state.position;
    const end = try frame.find(start, '\n') orelse frame.state.input.len;
    try frame.assign(.comment, start, end - start);
    return if (end < frame.state.input.len) end + 1 else end;
}

pub fn hash(frame: Frame) Error!usize {
    frame.state.stats.hash += 1;
    if (frame.state.options.dialect == .mysql) {
        frame.state.stats.hash += 1;
        return eol(frame);
    }
    return symbol(frame, .operator);
}

pub fn dash(frame: Frame) Error!usize {
    const start = frame.state.position;
    const length = frame.state.input.len;
    if (length - start >= 2 and try frame.byte(start + 1) == '-') {
        if (length - start == 2 or context.white(try frame.byte(start + 2))) {
            return eol(frame);
        }
        if (frame.state.options.dialect == .ansi) {
            frame.state.stats.dash_comment += 1;
            return eol(frame);
        }
    }
    return symbol(frame, .operator);
}

pub fn slash(frame: Frame) Error!usize {
    const start = frame.state.position;
    const length = frame.state.input.len;
    if (length - start == 1 or try frame.byte(start + 1) != '*') {
        return symbol(frame, .operator);
    }
    const close = try frame.pair(start + 2, length, '*', '/');
    const end = if (close) |position| position + 2 else length;
    var kind: Kind = .comment;
    if (close) |position| {
        if (try frame.pair(start + 2, position + 1, '/', '*') != null) kind = .evil;
    }
    if (length - start > 2 and try frame.byte(start + 2) == '!') kind = .evil;
    try frame.assign(kind, start, end - start);
    return end;
}

pub fn backslash(frame: Frame) Error!usize {
    const start = frame.state.position;
    if (frame.state.input.len - start >= 2 and try frame.byte(start + 1) == 'N') {
        try frame.assign(.number, start, 2);
        return start + 2;
    }
    return symbol(frame, .backslash);
}

pub fn operator(frame: Frame) Error!usize {
    const start = frame.state.position;
    const length = frame.state.input.len;
    if (length - start == 1) return symbol(frame, .operator);
    if (length - start >= 3 and try frame.byte(start) == '<' and
        try frame.byte(start + 1) == '=' and try frame.byte(start + 2) == '>')
    {
        try frame.assign(.operator, start, 3);
        return start + 3;
    }
    const kind = try frame.lookup(frame.state.input[start..][0..2]);
    if (kind != .none) {
        try frame.assign(kind, start, 2);
        return start + 2;
    }
    return symbol(frame, if (try frame.byte(start) == ':') .colon else .operator);
}
