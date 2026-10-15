//! Elm-style diagnostics for operators.
//!
//! A diagnostic is a title rule, a plain explanation and a hint that says what to do
//! instead:
//!
//! ```text
//! -- INVALID CHALLENGE -------------------------------------------------------
//!
//! The submitted nonce does not satisfy the difficulty threshold.
//!
//! Hint: Ensure the client Web Worker completes all hashing iterations.
//! ```
//!
//! The output is byte for byte the output of the Zig daemon's `diagnostic.write`.

use std::fmt;

/// The width of the title rule: `-- `, the title, a space and the dashes fill 76 columns.
const RULE_WIDTH: usize = 76;

/// One diagnostic, borrowed from its caller. `Display` renders it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Diagnostic<'a> {
    /// The title; it is shown in ASCII upper case in the rule.
    pub title: &'a str,
    /// The explanation, shown verbatim between the rule and the hint.
    pub message: &'a str,
    /// What the reader can do instead, shown after `Hint: `.
    pub hint: &'a str,
}

impl fmt::Display for Diagnostic<'_> {
    /// Writes the rule, the message and the hint, ending with one newline. A title of 72
    /// bytes or more gets no dashes; the rule then ends with the space after the title.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        render(out, self.title, self.message, self.hint)
    }
}

/// Writes the diagnostic for `title`, `message` and `hint` into `out`.
///
/// It borrows its inputs only for the call and allocates nothing. It fails only when `out`
/// fails.
pub fn render(out: &mut impl fmt::Write, title: &str, message: &str, hint: &str) -> fmt::Result {
    out.write_str("-- ")?;
    // Byte-wise ASCII upper case, as Zig's `std.ascii.toUpper`: other characters stay.
    for character in title.chars() {
        out.write_char(character.to_ascii_uppercase())?;
    }
    out.write_char(' ')?;
    let dashes = RULE_WIDTH.saturating_sub(title.len() + 4);
    for _ in 0..dashes {
        out.write_char('-')?;
    }
    out.write_str("\n\n")?;
    out.write_str(message)?;
    out.write_str("\n\nHint: ")?;
    out.write_str(hint)?;
    out.write_char('\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_format_has_boundary_explanation_and_hint() {
        let mut text = String::new();
        render(
            &mut text,
            "invalid challenge",
            "The submitted nonce does not satisfy the difficulty threshold.",
            "Ensure the client Web Worker completes all hashing iterations.",
        )
        .unwrap();
        assert!(text.contains("-- INVALID CHALLENGE --"));
        assert!(text.contains("Hint: Ensure the client"));
    }

    #[test]
    fn the_rule_fills_seventy_six_columns_until_the_title_is_too_long() {
        for length in [0, 1, 40, 71, 72, 73, 200] {
            let title = "t".repeat(length);
            let text = Diagnostic { title: &title, message: "m", hint: "h" }.to_string();
            let rule = text.lines().next().unwrap();
            assert_eq!(rule.len(), RULE_WIDTH.max(length + 4));
            assert!(text.ends_with("\n\nm\n\nHint: h\n"));
        }
    }

    #[test]
    fn non_ascii_titles_keep_their_characters() {
        let text = Diagnostic { title: "caf\u{e9} \u{fc}ber", message: "", hint: "" }.to_string();
        assert!(text.starts_with("-- CAF\u{e9} \u{fc}BER "));
        // The dash count follows the byte length, as in Zig.
        assert_eq!(text.lines().next().unwrap().len(), RULE_WIDTH);
    }
}
