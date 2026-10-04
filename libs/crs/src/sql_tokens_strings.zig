//! Ported from libinjection b9fcaaf; Copyright 2012-2016 Nick Galbreath, BSD-3-Clause.
const context = @import("sql_token_context.zig");
const words = @import("sql_tokens_words.zig");
const Frame = context.Frame;
const Error = context.Error;

pub fn quoted(frame: Frame, start: usize, delimiter: u8, offset: usize) Error!usize {
    const content = start + offset;
    const length = frame.state.input.len;
    frame.token.open = if (offset > 0) delimiter else 0;
    var position = content;
    while (try frame.find(position, delimiter)) |close| {
        var slash = close;
        while (slash > content and try frame.byte(slash - 1) == '\\') slash -= 1;
        if ((close - slash) % 2 != 0) {
            position = close + 1;
            continue;
        }
        if (close + 1 < length and try frame.byte(close + 1) == delimiter) {
            position = close + 2;
            continue;
        }
        try frame.assign(.string, content, close - content);
        frame.token.close = delimiter;
        return close + 1;
    }
    try frame.assign(.string, content, length - content);
    frame.token.close = 0;
    return length;
}

pub fn tick(frame: Frame) Error!usize {
    const end = try quoted(frame, frame.state.position, '`', 1);
    frame.token.kind = if (try frame.lookup(frame.token.bytes()) == .function)
        .function
    else
        .bareword;
    return end;
}

pub fn escaped(frame: Frame) Error!usize {
    const start = frame.state.position;
    if (frame.state.input.len - start <= 2 or try frame.byte(start + 1) != '\'') {
        return words.word(frame);
    }
    return quoted(frame, start, '\'', 2);
}

pub fn unicode(frame: Frame) Error!usize {
    const start = frame.state.position;
    if (frame.state.input.len - start <= 2 or try frame.byte(start + 1) != '&' or
        try frame.byte(start + 2) != '\'') return words.word(frame);
    const end = try quoted(frame, start + 2, '\'', 1);
    frame.token.open = 'u';
    if (frame.token.close == '\'') frame.token.close = 'u';
    return end;
}

pub fn alternate(frame: Frame, offset: usize) Error!usize {
    const start = frame.state.position + offset;
    const length = frame.state.input.len;
    if (start >= length or length - start <= 2) return words.word(frame);
    const first = try frame.byte(start);
    if ((first != 'q' and first != 'Q') or try frame.byte(start + 1) != '\'') {
        return words.word(frame);
    }
    const opening = try frame.byte(start + 2);
    // The pinned C implementation treats char as signed in this predicate.
    if (opening < 33 or opening >= 128) return words.word(frame);
    const closing: u8 = switch (opening) {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        else => opening,
    };
    const end = try frame.pair(start + 3, length, closing, '\'');
    const content_end = end orelse length;
    try frame.assign(.string, start + 3, content_end - start - 3);
    frame.token.open = 'q';
    frame.token.close = if (end != null) 'q' else 0;
    return if (end) |position| position + 2 else length;
}

pub fn national(frame: Frame) Error!usize {
    const start = frame.state.position;
    if (frame.state.input.len - start > 2 and try frame.byte(start + 1) == '\'') {
        return escaped(frame);
    }
    return alternate(frame, 1);
}

pub fn numeric(frame: Frame, mode: context.Span) Error!usize {
    const start = frame.state.position;
    const length = frame.state.input.len;
    if (length - start <= 2 or try frame.byte(start + 1) != '\'') return words.word(frame);
    const end = try frame.span(start + 2, mode);
    if (end == length or try frame.byte(end) != '\'') return words.word(frame);
    try frame.assign(.number, start, end + 1 - start);
    return end + 1;
}
