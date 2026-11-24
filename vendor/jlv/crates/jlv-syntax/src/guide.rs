//! What a person should write next, when the parser expected one thing and found
//! another (JDD 0001, "Elm-style messages"; JDD 0016).
//!
//! A message says what the parser expected and what it found; the hint says how to go
//! on. The common mistakes each have a hint of their own: `=` where `==` compares, a
//! missing `,`, a statement outside a function, a quoted name. The parser adds what
//! only it knows, such as where an unclosed bracket was opened, at the call site.

use crate::token::Kind;

/// What the parser was looking for, by the words of its message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wanted<'a> {
    /// A name of a binding, a parameter or a function.
    Name,
    /// An operand: a literal, a name, a call, `(`, `[` or `{`.
    Expression,
    /// The end of a statement.
    EndOfLine,
    /// The `{` that opens a block.
    Block,
    /// A record's key.
    RecordKey,
    /// What a module holds: an import, a function or a constant.
    ModuleItem,
    /// One token, spelled as written, such as `)` or `in`.
    Token(&'a str),
}

/// The hint for having found `found`, spelled `text`, where `wanted` belongs.
pub(crate) fn hint(wanted: Wanted<'_>, found: Kind, text: &str) -> String {
    if let Some(specific) = common_mistake(wanted, found, text) {
        return specific;
    }
    match wanted {
        Wanted::Name => "Write a name: a letter or `_`, then letters, digits or `_`.".into(),
        Wanted::Expression => {
            "Write a value here: a literal, a name, a call, or a `(`, `[` or `{`.".into()
        }
        Wanted::EndOfLine => "Start the next statement on its own line.".into(),
        Wanted::Block => "Open the block with `{` at the end of this line.".into(),
        Wanted::RecordKey => {
            "A record key is a name or a string, as in `{ port: 80 }` or `{ \"a.b\": 1 }`.".into()
        }
        Wanted::ModuleItem => {
            "A module holds imports, functions and constants: write `import`, `fn` or `let`."
                .into()
        }
        Wanted::Token(token) => token_hint(token),
    }
}

/// The hint for a mistake common enough to name, or `None`.
pub(crate) fn common_mistake(wanted: Wanted<'_>, found: Kind, text: &str) -> Option<String> {
    let keyword = found.is_keyword() || found == Kind::Reserved;
    Some(match (wanted, found) {
        (Wanted::Expression, Kind::If) => {
            "`if` is a statement, not a value: declare `var x = ...` with one value and \
             assign the other in the `if`, as in `var mode = \"0600\"` and \
             `if public { mode = \"0644\" }`."
                .into()
        }
        (Wanted::Expression, Kind::For) => {
            "A loop is a statement; to build a list, write a comprehension, as in \
             `[for t in ctx.targets(): t.name()]`."
                .into()
        }
        (Wanted::Expression, Kind::Fn) => {
            "JLV has no function values; define a function with `fn` at module level and \
             call it, or build the list with a comprehension."
                .into()
        }
        (Wanted::RecordKey, Kind::StrHead) => {
            "A record key is a name or a plain string; for a key computed from values, build \
             a map with `map.set(m, key, value)` from `jlv.std.foundation`."
                .into()
        }
        (Wanted::Expression, Kind::StrTail) => {
            "Write an expression inside `${...}`, or `$${` for the text `${`.".into()
        }
        (Wanted::Block, Kind::Equals) => {
            "Compare with `==`; a single `=` assigns, and only as a statement of its own.".into()
        }
        (Wanted::Name | Wanted::Token("=" | ":"), Kind::Str) => {
            "A name is written without quotes.".into()
        }
        (Wanted::Name, _) if keyword => {
            format!("`{text}` is a keyword; choose another name, such as `{text}_name`.")
        }
        (Wanted::Token(")" | "]" | "}"), kind) if starts_operand(kind) => {
            "Separate the elements with `,`.".into()
        }
        (Wanted::EndOfLine, _) => {
            format!("Start `{text}` on a line of its own; a statement ends at its line's end.")
        }
        (Wanted::ModuleItem, Kind::Return | Kind::If | Kind::For | Kind::Ident) => {
            "Statements belong inside a function; a module holds imports, `fn` and `let`.".into()
        }
        (_, Kind::End) => match wanted {
            Wanted::Token(token) => format!("The module ends too early; write `{token}`."),
            _ => "The module ends in the middle of a construct; finish it.".into(),
        },
        _ => return None,
    })
}

/// The hint for a missing token, by the token.
fn token_hint(token: &str) -> String {
    match token {
        "=" => "Write `=` and the value, as in `let port = 80`.".into(),
        ":" => "Give each parameter a type, as in `fn f(port: Int)`.".into(),
        "(" => {
            "Write the parameters in parentheses, as in `fn deploy(ctx: DeployContext) {`.".into()
        }
        "in" => "Write `in` and what the loop runs over, as in `for t in ctx.targets() {`.".into(),
        "from" => "Write `from` and the module's path, as in `import { host } from host`.".into(),
        "{" => {
            "Open the list of imported names with `{`, as in `import { a, b } from lib.x`.".into()
        }
        ">" => "Close the type's arguments with `>`, as in `Map<Text>`.".into(),
        token => format!("Write `{token}` here."),
    }
}

/// Whether a token of `kind` can begin an operand, so that it shows a missing `,`.
fn starts_operand(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Ident
            | Kind::Int
            | Kind::Str
            | Kind::StrHead
            | Kind::True
            | Kind::False
            | Kind::Null
            | Kind::LeftParen
            | Kind::LeftBracket
            | Kind::LeftBrace
            | Kind::Bang
            | Kind::Minus
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_mistakes_have_their_own_hints() {
        assert!(hint(Wanted::Block, Kind::Equals, "=").contains("`==`"));
        assert!(hint(Wanted::Token("]"), Kind::Int, "2").contains("`,`"));
        assert!(hint(Wanted::Name, Kind::For, "for").contains("choose another name"));
        assert!(hint(Wanted::ModuleItem, Kind::Return, "return").contains("inside a function"));
        assert!(hint(Wanted::Token("}"), Kind::End, "").contains("ends too early"));
        assert!(hint(Wanted::Token("in"), Kind::Ident, "x").contains("for t in"));
        assert!(hint(Wanted::Expression, Kind::If, "if").contains("`var"));
        assert!(hint(Wanted::Expression, Kind::For, "for").contains("comprehension"));
    }
}
