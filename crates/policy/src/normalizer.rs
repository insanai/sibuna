//! Canonicalisation of inspected text: percent decoding, SQL comment stripping, whitespace
//! folding and ASCII lower-casing, so that `%2527/**/UnIoN` style evasion collapses onto the
//! raw signatures.
//!
//! Every stage only shrinks its input (an output byte never runs ahead of the input byte it
//! comes from), so the whole pipeline shares the caller's buffer and allocates nothing.
//! Each stage writes at most `out.len()` bytes and stops there; the result is then a prefix
//! of the full transform.

/// Where a stage reads and writes: two separate buffers, or one buffer in place.
trait Buffers {
    fn input_len(&self) -> usize;
    fn input(&self, index: usize) -> u8;
    fn output_len(&self) -> usize;
    fn write(&mut self, index: usize, byte: u8);
}

struct Split<'i, 'o> {
    input: &'i [u8],
    output: &'o mut [u8],
}

impl Buffers for Split<'_, '_> {
    fn input_len(&self) -> usize {
        self.input.len()
    }
    // Stages read only below `input_len`.
    fn input(&self, index: usize) -> u8 {
        self.input[index]
    }
    fn output_len(&self) -> usize {
        self.output.len()
    }
    // Stages write only below `output_len`.
    fn write(&mut self, index: usize, byte: u8) {
        self.output[index] = byte;
    }
}

/// A buffer whose first `len` bytes are the input, overwritten from the front. Stages write
/// index `o` only after reading every index below `o + 1`, so no input byte is lost.
struct InPlace<'b> {
    buffer: &'b mut [u8],
    len: usize,
}

impl Buffers for InPlace<'_> {
    fn input_len(&self) -> usize {
        self.len
    }
    // `len` never exceeds the buffer length.
    fn input(&self, index: usize) -> u8 {
        self.buffer[index]
    }
    fn output_len(&self) -> usize {
        self.buffer.len()
    }
    fn write(&mut self, index: usize, byte: u8) {
        self.buffer[index] = byte;
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent decoding: `%HH` becomes the byte, `+` a space; a `%` without two hex digits
/// after it stays as it is. Returns the output length.
fn percent_decode_with(io: &mut impl Buffers) -> usize {
    let (mut input, mut output) = (0, 0);
    let len = io.input_len();
    while input < len && output < io.output_len() {
        let byte = io.input(input);
        if byte == b'%'
            && input + 2 < len
            && let (Some(high), Some(low)) =
                (hex_value(io.input(input + 1)), hex_value(io.input(input + 2)))
        {
            io.write(output, (high << 4) | low);
            output += 1;
            input += 3;
            continue;
        }
        io.write(output, if byte == b'+' { b' ' } else { byte });
        output += 1;
        input += 1;
    }
    output
}

/// Replaces each `/* ... */` with one space. An unterminated comment swallows all but the
/// last input byte, which is then copied (the Zig loop's behaviour, kept for parity).
fn strip_sql_comments_with(io: &mut impl Buffers) -> usize {
    let (mut input, mut output) = (0, 0);
    let len = io.input_len();
    while input < len && output < io.output_len() {
        if input + 1 < len && io.input(input) == b'/' && io.input(input + 1) == b'*' {
            input += 2;
            while input + 1 < len && !(io.input(input) == b'*' && io.input(input + 1) == b'/') {
                crate::steps::count(1);
                input += 1;
            }
            if input + 1 < len {
                input += 2;
            }
            io.write(output, b' ');
            output += 1;
            continue;
        }
        io.write(output, io.input(input));
        output += 1;
        input += 1;
    }
    output
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)
}

/// Folds every run of spaces, tabs, CR, LF, VT and FF into one space.
fn collapse_whitespace_with(io: &mut impl Buffers) -> usize {
    let (mut input, mut output) = (0, 0);
    let mut in_space = false;
    while input < io.input_len() && output < io.output_len() {
        let byte = io.input(input);
        if is_space(byte) {
            if !in_space {
                io.write(output, b' ');
                output += 1;
                in_space = true;
            }
        } else {
            io.write(output, byte);
            output += 1;
            in_space = false;
        }
        input += 1;
    }
    output
}

/// Percent-decodes `input` into `out` (`%20` is a space, `+` is a space) and returns the
/// decoded prefix of `out`. Writes at most `out.len()` bytes.
pub fn percent_decode<'o>(input: &[u8], out: &'o mut [u8]) -> &'o [u8] {
    let len = percent_decode_with(&mut Split { input, output: out });
    &out[..len]
}

/// Copies `input` into `out` with each C-style comment replaced by one space, and returns the
/// written prefix of `out`.
pub fn strip_sql_comments<'o>(input: &[u8], out: &'o mut [u8]) -> &'o [u8] {
    let len = strip_sql_comments_with(&mut Split { input, output: out });
    &out[..len]
}

/// Copies `input` into `out` with whitespace runs folded into one space, and returns the
/// written prefix of `out`.
pub fn collapse_whitespace<'o>(input: &[u8], out: &'o mut [u8]) -> &'o [u8] {
    let len = collapse_whitespace_with(&mut Split { input, output: out });
    &out[..len]
}

/// The full pipeline into `out`: percent decoding (a second round when the first leaves a
/// `%`), comment stripping, whitespace folding and ASCII lower-casing. Returns the written
/// prefix of `out`; when `out` is at least as long as `input` nothing is truncated.
pub fn canonicalize<'o>(input: &[u8], out: &'o mut [u8]) -> &'o [u8] {
    let mut len = percent_decode_with(&mut Split { input, output: &mut *out });
    if out[..len].contains(&b'%') {
        len = percent_decode_with(&mut InPlace { buffer: &mut *out, len });
    }
    len = strip_sql_comments_with(&mut InPlace { buffer: &mut *out, len });
    len = collapse_whitespace_with(&mut InPlace { buffer: &mut *out, len });
    let result = &mut out[..len];
    result.make_ascii_lowercase();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_decodes_standard_and_plus_encodings() {
        let mut buf = [0u8; 128];
        assert_eq!(percent_decode(b"hello%20world%27+test", &mut buf), b"hello world' test");
        assert_eq!(percent_decode(b"%4", &mut buf), b"%4");
        assert_eq!(percent_decode(b"%zz%41", &mut buf), b"%zzA");
        assert_eq!(percent_decode(b"%41BC", &mut buf[..2]), b"AB");
    }

    #[test]
    fn strip_sql_comments_replaces_comments_with_single_space() {
        let mut buf = [0u8; 128];
        assert_eq!(strip_sql_comments(b"UNION/**/SELECT/**/1", &mut buf), b"UNION SELECT 1");
        assert_eq!(strip_sql_comments(b"a/*bc", &mut buf), b"a c");
        assert_eq!(strip_sql_comments(b"a/*", &mut buf), b"a ");
        assert_eq!(strip_sql_comments(b"/*/", &mut buf), b" /");
    }

    #[test]
    fn collapse_whitespace_collapses_whitespace_variations() {
        let mut buf = [0u8; 128];
        assert_eq!(
            collapse_whitespace(b"SELECT  \t\r\n  FROM   users", &mut buf),
            b"SELECT FROM users"
        );
    }

    #[test]
    fn canonicalize_normalizes_obfuscated_sql_injection() {
        let mut buf = [0u8; 256];
        assert_eq!(canonicalize(b"1%27/**/UnIoN/**/SeLeCt/**/1", &mut buf), b"1' union select 1");
    }

    #[test]
    fn canonicalize_decodes_double_encoded_path_traversal() {
        let mut buf = [0u8; 256];
        let result = canonicalize(b"/api/%252e%252e/%252e%252e/etc/passwd", &mut buf);
        assert_eq!(result, b"/api/../../etc/passwd");
    }

    #[test]
    fn in_place_stages_agree_with_split_stages() {
        let samples: [&[u8]; 6] =
            [b"%2541%41+x", b"a/**/b/*c", b"  a \t\n b ", b"%", b"/*", b"%%41%4"];
        for sample in samples {
            let mut split = [0u8; 32];
            let mut place = [0u8; 32];
            place[..sample.len()].copy_from_slice(sample);
            let expected = percent_decode(sample, &mut split).to_vec();
            let len = percent_decode_with(&mut InPlace { buffer: &mut place, len: sample.len() });
            assert_eq!(&place[..len], &expected[..]);
        }
    }
}
