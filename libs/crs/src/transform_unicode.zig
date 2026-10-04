//! Permissive UTF-8-to-%u byte transformation, never strict Unicode validation.
// Compatibility algorithm adapted from ModSecurity 3.0.14 under Apache-2.0.
// Copyright (c) 2015-2021 Trustwave Holdings, Inc. See NOTICE and LICENSES/.
const types = @import("transform_types.zig");
const utf8 = @import("utf8_profile.zig");

fn format(value: u21, output: []u8) usize {
    const digits: usize = if (value <= 0xffff) 4 else if (value <= 0xfffff) 5 else 6;
    const alphabet = "0123456789abcdef";
    output[0] = '%';
    output[1] = 'u';
    for (0..digits) |index| {
        const shift: u5 = @intCast((digits - index - 1) * 4);
        output[index + 2] = alphabet[(@as(u32, value) >> shift) & 15];
    }
    return digits + 2;
}

fn overlong(character: utf8.Character) bool {
    return switch (character.length) {
        2 => character.value < 0x80,
        3 => character.value < 0x800,
        4 => character.value < 0x10000,
        else => false,
    };
}

pub fn encode(buffer: types.Buffer) types.Write {
    var position: usize = 0;
    var written: usize = 0;
    var changed = false;
    while (position < buffer.input.len) {
        const first = buffer.input[position];
        if (first < 0xc0 or first >= 0xf8) {
            // The reference's nonfinal NUL writes without advancing its output
            // pointer, so a later write or the terminator overwrites that byte.
            if (first != 0 or position + 1 == buffer.input.len) {
                buffer.output[written] = first;
                written += 1;
            }
            position += 1;
            continue;
        }
        if (first >= 0xf5) {
            buffer.output[written] = first;
            written += 1;
        }
        const character = utf8.structural(buffer.input[position..]) catch {
            position += 1;
            continue;
        };
        written += format(character.value, buffer.output[written..]);
        changed = true;
        const surrogate = character.value >= 0xd800 and character.value <= 0xdfff;
        const copies: usize = @as(usize, @intFromBool(surrogate)) +
            @intFromBool(overlong(character));
        for (0..copies) |_| {
            buffer.output[written] = first;
            written += 1;
        }
        position += character.length;
    }
    return .{ .length = written, .changed = changed };
}
