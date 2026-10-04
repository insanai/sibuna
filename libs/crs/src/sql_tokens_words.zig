//! Ported from libinjection b9fcaaf; Copyright 2012-2016 Nick Galbreath, BSD-3-Clause.
const context = @import("sql_token_context.zig");
const strings = @import("sql_tokens_strings.zig");
const Frame = context.Frame;
const Error = context.Error;

pub fn word(frame: Frame) Error!usize {
    const start = frame.state.position;
    const end = try frame.span(start, .word);
    try frame.assign(.bareword, start, end - start);
    for (0..frame.token.length) |index| {
        try frame.state.budget.debit(1);
        const byte = frame.token.value[index];
        if (byte != '.' and byte != '`') continue;
        const kind = try frame.lookup(frame.token.value[0..index]);
        if (kind == .none or kind == .bareword) continue;
        try frame.assign(kind, start, index);
        return start + index;
    }
    if (end - start < 32) {
        const kind = try frame.lookup(frame.token.bytes());
        frame.token.kind = if (kind == .none) .bareword else kind;
    }
    return end;
}

pub fn bracket(frame: Frame) Error!usize {
    const start = frame.state.position;
    const end = if (try frame.find(start, ']')) |close| close + 1 else frame.state.input.len;
    try frame.assign(.bareword, start, end - start);
    return end;
}

pub fn variable(frame: Frame) Error!usize {
    var position = frame.state.position + 1;
    const length = frame.state.input.len;
    frame.token.count = 1;
    if (position < length and try frame.byte(position) == '@') {
        position += 1;
        frame.token.count = 2;
    }
    if (position < length) {
        const byte = try frame.byte(position);
        if (byte == '`' or byte == '\'' or byte == '"') {
            frame.state.position = position;
            const end = if (byte == '`')
                try strings.tick(frame)
            else
                try strings.quoted(frame, position, byte, 1);
            frame.token.kind = .variable;
            return end;
        }
    }
    const end = try frame.span(position, .variable);
    try frame.assign(.variable, position, end - position);
    return end;
}

fn dollarString(frame: Frame, start: usize, content: usize, end: ?usize) Error!usize {
    const length = frame.state.input.len;
    try frame.assign(.string, content, (end orelse length) - content);
    frame.token.open = '$';
    frame.token.close = if (end != null) '$' else 0;
    return if (end) |position| position + content - start else length;
}

pub fn money(frame: Frame) Error!usize {
    const start = frame.state.position;
    const length = frame.state.input.len;
    if (length - start == 1) {
        try frame.assign(.bareword, start, 1);
        return length;
    }
    const number_end = try frame.span(start + 1, .money);
    if (number_end > start + 1) {
        if (number_end == start + 2 and try frame.byte(start + 1) == '.') return word(frame);
        try frame.assign(.number, start, number_end - start);
        return number_end;
    }
    if (try frame.byte(start + 1) == '$') {
        const end = try frame.pair(start + 2, length, '$', '$');
        return dollarString(frame, start, start + 2, end);
    }
    const tag_end = try frame.span(start + 1, .letters);
    if (tag_end == start + 1 or tag_end == length or try frame.byte(tag_end) != '$') {
        try frame.assign(.bareword, start, 1);
        return start + 1;
    }
    const content = tag_end + 1;
    const delimiter = frame.state.input[start..content];
    return dollarString(frame, start, content, try frame.delimiter(content, delimiter));
}
