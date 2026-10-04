//! Ported from libinjection b9fcaaf; Copyright 2012-2016 Nick Galbreath, BSD-3-Clause.
const context = @import("sql_token_context.zig");
const Frame = context.Frame;
const Error = context.Error;

fn floatSuffix(frame: Frame, start: usize) Error!usize {
    const length = frame.state.input.len;
    if (start == length) return start;
    const byte = try frame.byte(start);
    if (byte != 'd' and byte != 'D' and byte != 'f' and byte != 'F') return start;
    if (start + 1 == length) return start + 1;
    const next = try frame.byte(start + 1);
    return if (context.white(next) or next == ';' or next == 'u' or next == 'U')
        start + 1
    else
        start;
}

pub fn number(frame: Frame) Error!usize {
    const start = frame.state.position;
    const length = frame.state.input.len;
    if (try frame.byte(start) == '0' and length - start >= 2) {
        const next = try frame.byte(start + 1);
        const mode: ?context.Span = switch (next) {
            'x', 'X' => .hexadecimal,
            'b', 'B' => .binary,
            else => null,
        };
        if (mode) |base| {
            const end = try frame.span(start + 2, base);
            try frame.assign(if (end == start + 2) .bareword else .number, start, end - start);
            return end;
        }
    }
    var position = try frame.span(start, .digits);
    if (position < length and try frame.byte(position) == '.') {
        position = try frame.span(position + 1, .digits);
        if (position == start + 1) {
            try frame.assign(.dot, start, 1);
            return position;
        }
    }
    var incomplete_exponent = false;
    if (position < length) {
        const next = try frame.byte(position);
        if (next == 'e' or next == 'E') {
            position += 1;
            if (position < length) {
                const sign = try frame.byte(position);
                if (sign == '+' or sign == '-') position += 1;
            }
            const end = try frame.span(position, .digits);
            incomplete_exponent = end == position;
            position = end;
        }
    }
    position = try floatSuffix(frame, position);
    try frame.assign(if (incomplete_exponent) .bareword else .number, start, position - start);
    return position;
}
