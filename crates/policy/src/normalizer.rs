//! Canonicalisation of inspected text: percent decoding, JSON string escapes, HTML
//! character references, SQL comment stripping, whitespace folding and ASCII lower-casing,
//! so that `%2527/**/UnIoN`, `\u0027` and `&lt;script` style evasion collapses onto the raw
//! signatures.
//!
//! The pipeline has two halves. [`decode`] undoes the encodings (percent escapes, JSON
//! escapes, character references) and keeps every byte the encodings produced, including
//! line feeds and tabs; the WAF inspects that decoded form for what folding would destroy
//! (a line feed that separates shell commands, a `javascript:` scheme split by tabs).
//! [`finish`] then strips comments, folds whitespace and lower-cases in place.
//!
//! Every stage only shrinks its input (an output byte never runs ahead of the input byte it
//! comes from), so the whole pipeline shares the caller's buffer and allocates nothing.
//! Each stage writes at most `out.len()` bytes and stops there; the result is then a prefix
//! of the full transform.

mod escapes;

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

/// Returns the index just past the opening of a MySQL or MariaDB executable comment whose
/// `/*` ends before `at`: `!` or `M!`, then an optional version number. MySQL runs the text
/// of such a comment, so it must survive canonicalisation.
fn executable_comment(io: &impl Buffers, at: usize) -> Option<usize> {
    let len = io.input_len();
    let mut index = match (at < len).then(|| io.input(at))? {
        b'!' => at + 1,
        b'M' | b'm' if at + 1 < len && io.input(at + 1) == b'!' => at + 2,
        _ => return None,
    };
    while index < len && io.input(index).is_ascii_digit() {
        crate::steps::count(1);
        index += 1;
    }
    Some(index)
}

/// Replaces each `/* ... */` with one space. An unterminated comment swallows all but the
/// last input byte, which is then copied (the Zig loop's behaviour, kept for parity).
///
/// An executable comment (`/*!50000select*/`) keeps its text: its opening and its closing
/// `*/` each become one space, as if the comment markers were not there. Zig dropped the
/// text, so `union/*!50000select*/` lost its `select`.
fn strip_sql_comments_with(io: &mut impl Buffers) -> usize {
    let (mut input, mut output) = (0, 0);
    let len = io.input_len();
    let mut executable = false;
    while input < len && output < io.output_len() {
        if executable && pair_at(io, input, b'*', b'/') {
            executable = false;
            input += 2;
            io.write(output, b' ');
            output += 1;
            continue;
        }
        if pair_at(io, input, b'/', b'*') {
            input += 2;
            if let Some(after) = executable_comment(io, input) {
                executable = true;
                input = after;
                io.write(output, b' ');
                output += 1;
                continue;
            }
            while input + 1 < len && !pair_at(io, input, b'*', b'/') {
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

/// True when the input holds `first` at `index` and `second` right after it.
fn pair_at(io: &impl Buffers, index: usize, first: u8, second: u8) -> bool {
    index + 1 < io.input_len() && io.input(index) == first && io.input(index + 1) == second
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

/// The decoding half of the pipeline into `out`: percent decoding (a second round when the
/// first leaves a `%`), then JSON string escapes when a backslash remains and HTML
/// character references when an ampersand remains. Returns the written prefix of `out`;
/// when `out` is at least as long as `input` nothing is truncated.
pub fn decode<'o>(input: &[u8], out: &'o mut [u8]) -> &'o [u8] {
    let len = decode_len(input, out);
    &out[..len]
}

fn decode_len(input: &[u8], out: &mut [u8]) -> usize {
    let mut len = percent_decode_with(&mut Split { input, output: &mut *out });
    if out[..len].contains(&b'%') {
        len = percent_decode_with(&mut InPlace { buffer: &mut *out, len });
    }
    if out[..len].contains(&b'\\') {
        len = escapes::json_unescape_with(&mut InPlace { buffer: &mut *out, len });
    }
    if out[..len].contains(&b'&') {
        len = escapes::html_unescape_with(&mut InPlace { buffer: &mut *out, len });
    }
    len
}

/// The second half of the pipeline, in place on the first `len` bytes of `buffer` (a
/// decoded form): comment stripping, whitespace folding and ASCII lower-casing. Returns
/// the canonical prefix of `buffer`.
pub fn finish(buffer: &mut [u8], len: usize) -> &[u8] {
    let len = len.min(buffer.len());
    let len = strip_sql_comments_with(&mut InPlace { buffer: &mut *buffer, len });
    let len = collapse_whitespace_with(&mut InPlace { buffer: &mut *buffer, len });
    let result = &mut buffer[..len];
    result.make_ascii_lowercase();
    result
}

/// The full pipeline into `out`: [`decode`], then [`finish`]. Returns the written prefix
/// of `out`; when `out` is at least as long as `input` nothing is truncated.
pub fn canonicalize<'o>(input: &[u8], out: &'o mut [u8]) -> &'o [u8] {
    let len = decode_len(input, out);
    finish(out, len)
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

    #[test]
    fn executable_comments_keep_their_text() {
        let mut buf = [0u8; 128];
        let text = b"1 UNION/*!50000SELECT*/ password/*M!100000,*/x/*plain*/y";
        assert_eq!(canonicalize(text, &mut buf), b"1 union select password , x y");
        assert_eq!(strip_sql_comments(b"/*!", &mut buf), b" ");
        assert_eq!(strip_sql_comments(b"a/*!1*/*/b", &mut buf), b"a  */b");
    }

    #[test]
    fn decode_keeps_line_feeds_that_finish_folds() {
        let mut buf = [0u8; 64];
        assert_eq!(decode(b"a%0Ab&#x09;c\\nd", &mut buf), b"a\nb\tc\nd");
        let len = decode(b"a%0Ab&#x09;c", &mut buf).len();
        assert_eq!(finish(&mut buf, len), b"a b c");
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// Every stage, split or in place, shrinks its input, and in-place decoding agrees with
    /// decoding into a second buffer, within a linear work budget.
    #[test]
    fn decoding_stages_survive_random_inputs() {
        let alphabet = b"%&#;xX0123456789aAfFuUlt/*!M' \n\\u";
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..100_000 {
            let len = (xorshift(&mut state) % 48) as usize;
            let text: Vec<u8> = (0..len)
                .map(|_| alphabet[(xorshift(&mut state) % alphabet.len() as u64) as usize])
                .collect();
            crate::steps::take();
            let mut split = [0u8; 48];
            let mut place = [0u8; 48];
            let canonical = canonicalize(&text, &mut split).to_vec();
            assert!(canonical.len() <= text.len());
            place[..len].copy_from_slice(&text);
            let json = escapes::json_unescape_with(&mut InPlace { buffer: &mut place, len });
            let mut expected = [0u8; 48];
            let split_json =
                escapes::json_unescape_with(&mut Split { input: &text, output: &mut expected });
            assert_eq!(&place[..json], &expected[..split_json], "{text:?}");
            place[..len].copy_from_slice(&text);
            let html = escapes::html_unescape_with(&mut InPlace { buffer: &mut place, len });
            let split_html =
                escapes::html_unescape_with(&mut Split { input: &text, output: &mut expected });
            assert_eq!(&place[..html], &expected[..split_html], "{text:?}");
            assert!(json <= len && html <= len);
            assert!(crate::steps::take() <= 8 * (len as u64 + 1), "{text:?}");
        }
    }
}
