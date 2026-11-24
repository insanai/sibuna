//! The one JLV lexer and parser (JDD 0004, JDD 0013 and JDD 0016; tier `kernel` of JDD 0002).
//!
//! [`Syntax::parse`] turns one `.jlv` source into a token table and a flat postorder
//! tree, or a located diagnostic of class `invalid_source`, `unsupported_syntax`,
//! `integer_overflow`, `argument_error` or `budget_exhausted`. The passes read the tree
//! through the typed views of [`view`]; a [`Workspace`] reuses its columns from one
//! module to the next. Nothing recurses, so no input exhausts the native stack. The
//! tree has no semantics of its own; `jlv-compiler` resolves, checks and lowers it.

#![forbid(unsafe_code)]

mod expr;
mod guide;
mod lexer;
mod parse;
pub mod token;
pub mod tree;
pub mod view;

pub use lexer::{Comment, text_block_end};

/// Whether `word` can be a segment of a dotted module path, and so a package alias:
/// lower-case letters, digits and `_`, starting with a letter, and neither a keyword
/// nor a reserved word (JDD 0016, "Modules and imports").
pub fn is_segment(word: &str) -> bool {
    let mut bytes = word.bytes();
    let lower = bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    let keyword = token::KEYWORDS.iter().any(|(k, _)| *k == word);
    lower && !keyword && !lexer::RESERVED.contains(&word)
}
pub use parse::Workspace;
pub use view::{Source, Syntax};
