//! Finds function bodies in a token stream and counts their logical lines.
//!
//! A function is the keyword `fn` followed by a name and, eventually, a body in braces.
//! Free functions, methods, trait default methods and functions nested in other functions
//! are all found. A closure is not a function here: its lines belong to the function that
//! contains it. A nested function is checked on its own and its lines also count toward the
//! function around it, because they make that function longer to read.

use super::lexer::{Lexed, Token, TokenKind};

/// One function body found in a source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function<'a> {
    /// The function's name, borrowed from the source.
    pub name: &'a str,
    /// The 1-based line of the name.
    pub line: usize,
    /// The 0-based byte column of the name within its line.
    pub column: usize,
    /// The 1-based line of the `fn` keyword.
    pub keyword_line: usize,
    /// The 1-based line of the brace that opens the body.
    pub open_line: usize,
    /// The 1-based line of the brace that closes the body.
    pub close_line: usize,
    /// The number of lines after the opening brace, up to and including the closing brace,
    /// that hold code.
    pub logical_lines: usize,
}

/// Finds every function with a body in `lexed`, a lexing of `source`.
///
/// Returns them in source order. Declarations without a body (trait methods, foreign
/// functions) and function pointer types such as `fn(u8) -> u8` are skipped.
pub fn find_functions<'a>(source: &'a str, lexed: &Lexed) -> Vec<Function<'a>> {
    let tokens = &lexed.tokens;
    let closes = match_braces(tokens);
    let mut functions = Vec::new();
    for (index, window) in tokens.windows(2).enumerate() {
        let (keyword, name) = (window[0], window[1]);
        let is_fn =
            keyword.kind == TokenKind::Ident && &source[keyword.start..keyword.end] == "fn";
        if !is_fn || name.kind != TokenKind::Ident {
            continue;
        }
        let Some(open) = body_open(tokens, index + 2) else {
            continue;
        };
        // An unmatched brace only occurs in code that does not compile; let the body run to
        // the end of the file.
        let close = closes[open].unwrap_or(tokens.len() - 1);
        let open_line = tokens[open].line;
        let close_line = tokens[close].line;
        let logical_lines =
            (open_line + 1..=close_line).filter(|&line| lexed.is_code_line(line)).count();
        functions.push(Function {
            name: &source[name.start..name.end],
            line: name.line,
            column: name.column,
            keyword_line: keyword.line,
            open_line,
            close_line,
            logical_lines,
        });
    }
    functions
}

/// Pairs each `{` token with the index of its `}`.
///
/// Returns a table indexed by token: `Some(close)` for a matched opening brace, `None` for
/// every other token.
fn match_braces(tokens: &[Token]) -> Vec<Option<usize>> {
    let mut closes = vec![None; tokens.len()];
    let mut open = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match token.kind {
            TokenKind::Punct(b'{') => open.push(index),
            TokenKind::Punct(b'}') => {
                if let Some(start) = open.pop() {
                    closes[start] = Some(index);
                }
            }
            _ => {}
        }
    }
    closes
}

/// Finds the brace that opens a function body, scanning the signature from token `from`.
///
/// Returns `None` when the signature ends in `;` (no body). Braces and semicolons inside
/// parentheses or brackets, such as `[u8; 4]`, belong to the signature.
fn body_open(tokens: &[Token], from: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, token) in tokens.get(from..)?.iter().enumerate() {
        match token.kind {
            TokenKind::Punct(b'(' | b'[') => depth += 1,
            TokenKind::Punct(b')' | b']') => depth = depth.saturating_sub(1),
            TokenKind::Punct(b'{') if depth == 0 => return Some(from + offset),
            TokenKind::Punct(b';') if depth == 0 => return None,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::lexer::lex;

    fn functions(source: &str) -> Vec<Function<'_>> {
        find_functions(source, &lex(source).unwrap())
    }

    fn names_and_lines(source: &str) -> Vec<(&str, usize)> {
        functions(source).iter().map(|f| (f.name, f.logical_lines)).collect()
    }

    #[test]
    fn finds_free_functions_methods_and_nested_functions() {
        let source = "\
pub fn outer() {
    fn inner() {
        a();
    }
    inner();
}
impl S {
    pub(crate) async fn method(&self) -> u8 { 1 }
}";
        assert_eq!(names_and_lines(source), [("outer", 3), ("inner", 1), ("method", 0)]);
    }

    #[test]
    fn skips_declarations_and_function_pointers() {
        let source = "\
trait T {
    fn required(&self) -> [u8; 4];
    fn provided(&self) { self.required(); }
}
extern \"C\" { fn foreign(x: u8); }
type Callback = fn(u8) -> u8;
fn takes(f: fn(u8) -> u8, g: impl Fn() -> u8) -> u8 {
    f(g())
}";
        assert_eq!(names_and_lines(source), [("provided", 0), ("takes", 1)]);
    }

    #[test]
    fn closures_count_toward_the_enclosing_function() {
        let source = "\
fn f() {
    let add = |a: u8, b: u8| {
        a + b
    };
    add(1, 2);
}";
        assert_eq!(names_and_lines(source), [("f", 3)]);
    }

    #[test]
    fn where_clauses_spanning_lines_are_signature() {
        let source = "\
fn f<T, const N: usize>(
    items: [T; N],
) -> [T; N]
where
    T: Clone + Default,
{
    items
}";
        let found = functions(source);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].keyword_line, found[0].open_line), (1, 6));
        assert_eq!((found[0].close_line, found[0].logical_lines), (8, 1));
    }

    #[test]
    fn attributes_and_test_modules_are_handled() {
        let source = "\
#[cfg(test)]
mod tests {
    #[test]
    #[allow(clippy::needless_range_loop)]
    fn checks() {
        #[rustfmt::skip]
        let table = [1, 2];
        assert_eq!(table.len(), 2);
    }
}";
        assert_eq!(names_and_lines(source), [("checks", 3)]);
    }

    #[test]
    fn braces_in_literals_and_comments_do_not_end_the_body() {
        let source = "\
fn f<'a>(x: &'a str) -> char {
    let open = '{';
    let raw = r#\"}\"#; // }
    /* } */
    open
}
fn g() {}";
        let found = functions(source);
        assert_eq!(names_and_lines(source), [("f", 3), ("g", 0)]);
        assert_eq!(found[0].close_line, 6);
    }

    #[test]
    fn raw_identifier_names_are_kept() {
        assert_eq!(names_and_lines("fn r#match() {}"), [("r#match", 0)]);
    }
}
