//! The JLV/2 parser as machines over explicit stacks (JDD 0013, "Construction"; JDD
//! 0016, "Statements and lines").
//!
//! The statement machine keeps one frame per open function, block, `if` and `for`; the
//! type machine one per open `<`; the expression machine is the shunting-yard
//! algorithm with groups for brackets, in [`crate::expr`]. Nothing recurses, so no
//! input exhausts the native stack. Each node is emitted after its children, with the
//! size of its subtree, and its height is checked against [`Limits::depth`] when it is
//! emitted; every open bracket and block is also counted as it opens, so a long run of
//! opening brackets is refused before the parser reads on.

use jlv_core::{Diagnostic, Limits, SourceId, Span};
use jlv_lang::codes;

use crate::expr::Operator;
use crate::guide::{self, Wanted};
use crate::lexer::lex;
use crate::token::{Kind, TokenId, TokenTable};
use crate::tree::{NodeId, NodeKind, SyntaxTree};

/// A token table, a tree and the parser's stacks, reused from one module to the next
/// so that parsing allocates nothing once the columns are large enough. The tree is
/// empty after a parse that failed.
#[derive(Debug, Default)]
pub struct Workspace {
    /// The tokens of the last module parsed.
    pub tokens: TokenTable,
    /// Its syntax tree.
    pub tree: SyntaxTree,
    stacks: Stacks,
}

/// The parser's transient state, kept for reuse.
#[derive(Debug, Default)]
pub(crate) struct Stacks {
    /// The height of each emitted node.
    pub heights: Vec<u32>,
    pub frames: Vec<Frame>,
    pub types: Vec<TypeFrame>,
    pub operators: Vec<Operator>,
    pub operands: Vec<NodeId>,
}

impl Stacks {
    /// Empties the stacks and reserves what a module of `nodes` nodes under the depth
    /// limit `depth` can need, so that none grows while parsing. The frames and type
    /// frames are open constructs, at most `depth`; each open group holds at most a
    /// prefix and one pending operator of each of five powers, and as many operands.
    fn reset(&mut self, nodes: usize, depth: usize) {
        let bound = 8 * (depth + 1);
        self.heights.clear();
        self.heights.reserve(nodes);
        self.frames.clear();
        self.frames.reserve(bound);
        self.types.clear();
        self.types.reserve(bound);
        self.operators.clear();
        self.operators.reserve(bound);
        self.operands.clear();
        self.operands.reserve(bound);
    }
}

impl Workspace {
    /// Lexes and parses `text` into [`Workspace::tokens`] and [`Workspace::tree`].
    pub fn parse(
        &mut self,
        source: SourceId,
        text: &str,
        limits: &Limits,
    ) -> Result<(), Diagnostic> {
        if text.len() > limits.module_bytes {
            self.tree.reset(0);
            let message = format!("The module is larger than {} bytes.", limits.module_bytes);
            let hint = "Split the module, or raise `[limits] module_bytes` in jlv.toml.";
            return Err(Diagnostic::at(
                codes::problem(codes::BUDGET_EXHAUSTED, &message, hint),
                Span::new(source, 0, 0),
            ));
        }
        if let Err(error) = lex(&mut self.tokens, source, text, limits.depth) {
            // The last module's tree does not describe the new tokens.
            self.tree.reset(0);
            return Err(error);
        }
        // Distinct nodes have distinct tokens (JDD 0013, Lemma 0).
        self.tree.reset(self.tokens.len());
        self.stacks.reset(self.tokens.len(), limits.depth);
        let mut parser = Parser {
            text,
            tokens: &self.tokens,
            tree: &mut self.tree,
            stacks: &mut self.stacks,
            at: 0,
            open: 0,
            limit: limits.depth,
        };
        let parsed = parser.module();
        if parsed.is_err() {
            // A partial tree has no module node; views must never see one.
            self.tree.reset(0);
        }
        parsed
    }
}

/// An open construct of the statement machine.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Frame {
    /// A function whose body is open.
    Function { start: u32, first: TokenId },
    /// A block.
    Block { start: u32, first: TokenId },
    /// An `if` whose latest block is open; `last_arm` once its `else` block is.
    If { start: u32, first: TokenId, last_arm: bool },
    /// A `for` whose body is open.
    For { start: u32, first: TokenId },
}

/// An open `<` of the type machine: the type whose arguments follow.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TypeFrame {
    start: u32,
    first: TokenId,
    name: TokenId,
}

pub(crate) type Parsed<T> = Result<T, Diagnostic>;

/// One parse in progress.
pub(crate) struct Parser<'w> {
    pub text: &'w str,
    pub tokens: &'w TokenTable,
    pub tree: &'w mut SyntaxTree,
    pub stacks: &'w mut Stacks,
    /// The next token.
    pub at: u32,
    /// The brackets, blocks and type arguments open now.
    pub open: usize,
    pub limit: usize,
}

impl Parser<'_> {
    pub fn peek(&self) -> Kind {
        self.tokens.kind(TokenId(self.at))
    }

    pub fn peek_at(&self, offset: u32) -> Kind {
        let last = self.tokens.len() as u32 - 1;
        self.tokens.kind(TokenId((self.at + offset).min(last)))
    }

    pub fn here(&self) -> TokenId {
        TokenId(self.at)
    }

    /// Moves past the next token, never past the end token, and returns it.
    pub fn bump(&mut self) -> TokenId {
        let token = self.here();
        if (self.at as usize) + 1 < self.tokens.len() {
            self.at += 1;
        }
        token
    }

    pub fn eat(&mut self, kind: Kind) -> bool {
        let found = self.peek() == kind;
        if found {
            self.bump();
        }
        found
    }

    /// The next token when it is `kind`; "Expected `kind`" otherwise.
    pub fn expect(&mut self, kind: Kind) -> Parsed<TokenId> {
        if self.peek() == kind {
            return Ok(self.bump());
        }
        Err(self.unexpected(Wanted::Token(kind.spelling().unwrap_or("?"))))
    }

    pub fn name(&mut self) -> Parsed<TokenId> {
        if self.peek() == Kind::Ident {
            return Ok(self.bump());
        }
        Err(self.unexpected(Wanted::Name))
    }

    /// The refusal of a reserved word where `wanted` belongs: a form a later version may
    /// add, or a name that must be another.
    fn reserved(&self, wanted: Wanted<'_>) -> Diagnostic {
        let here = self.here();
        let word = self.tokens.text(here, self.text);
        let message = format!("`{word}` is reserved; JLV excludes the form it would introduce.");
        let hint = match wanted {
            Wanted::Name => guide::hint(wanted, Kind::Reserved, word),
            _ => "Use a bounded `for` over a finite list, `if`/`else`, or a library function."
                .to_string(),
        };
        Diagnostic::at(codes::problem(codes::UNSUPPORTED_SYNTAX, &message, &hint), self.span(here))
    }

    /// "Expected `wanted`, but found" the next token, with what to write instead.
    pub fn unexpected(&self, wanted: Wanted<'_>) -> Diagnostic {
        if self.peek() == Kind::Reserved {
            return self.reserved(wanted);
        }
        let here = self.here();
        let text = self.tokens.text(here, self.text);
        let hint = guide::hint(wanted, self.peek(), text);
        self.unexpected_hint(wanted, &hint)
    }

    /// As [`Parser::unexpected`], with a hint that only the caller knows.
    pub fn unexpected_hint(&self, wanted: Wanted<'_>, hint: &str) -> Diagnostic {
        let here = self.here();
        let found = match self.peek() {
            Kind::Ident => format!("the name `{}`", self.tokens.text(here, self.text)),
            Kind::Int => "an integer".to_string(),
            Kind::Str => "a string".to_string(),
            Kind::StrHead | Kind::StrMid | Kind::StrTail => "an interpolated string".to_string(),
            Kind::End => "the end of the module".to_string(),
            kind if kind.is_keyword() => format!("the keyword `{}`", spelled(kind)),
            kind => format!("`{}`", spelled(kind)),
        };
        let wanted = match wanted {
            Wanted::Name => "a name".to_string(),
            Wanted::Expression => "an expression".to_string(),
            Wanted::EndOfLine => "the end of the line".to_string(),
            Wanted::Block => "`{`".to_string(),
            Wanted::RecordKey => "a record key".to_string(),
            Wanted::ModuleItem => "`import`, `fn` or `let`".to_string(),
            Wanted::Token(token) => format!("`{token}`"),
        };
        let message = format!("Expected {wanted}, but found {found}.");
        Diagnostic::at(codes::problem(codes::INVALID_SOURCE, &message, hint), self.span(here))
    }

    /// As [`Parser::unexpected`] inside a bracket or a block that `opener` opened: the
    /// diagnostic also points at the opener and says on which line it is.
    ///
    /// A token that begins a line, or the end of the module, shows that the opener was
    /// left open, so the hint says where to close it; a mistake in the middle of a line,
    /// such as a missing `,`, keeps its own hint.
    pub fn unclosed(&self, wanted: Wanted<'_>, opener: TokenId) -> Diagnostic {
        let span = self.span(opener);
        let line = self.text[..span.start as usize].matches('\n').count() + 1;
        let open = self.tokens.text(opener, self.text);
        let what = if open == "{" { "block" } else { "bracket" };
        let close = match wanted {
            Wanted::Token(token) => {
                format!("Close the {what} `{open}` on line {line} with `{token}`.")
            }
            _ => format!("Close the {what} `{open}` on line {line}."),
        };
        let left_open = self.peek() == Kind::End || self.starts_line();
        let text = self.tokens.text(self.here(), self.text);
        let mut diagnostic = match guide::common_mistake(wanted, self.peek(), text) {
            Some(hint) if !left_open => {
                let mut d = self.unexpected_hint(wanted, &hint);
                let here = self.span(self.here()).start as usize;
                // A note about the opener helps only when it is on another line.
                if self.text[..here].matches('\n').count() + 1 != line {
                    d.problem
                        .hints
                        .push(format!("The {what} `{open}` on line {line} is still open."));
                }
                d
            }
            _ => self.unexpected_hint(wanted, &close),
        };
        if self.peek() == Kind::Reserved {
            diagnostic = self.reserved(wanted);
        }
        diagnostic.related(span)
    }

    pub fn span(&self, token: TokenId) -> Span {
        self.tokens.span(token)
    }

    /// The number of nodes emitted so far, which is where the next subtree starts.
    pub fn count(&self) -> u32 {
        self.tree.len() as u32
    }

    /// Emits a node whose subtree starts at `start`, after checking its height.
    pub fn emit(
        &mut self,
        kind: NodeKind,
        token: TokenId,
        start: u32,
        first: TokenId,
        last: TokenId,
    ) -> Parsed<NodeId> {
        let id = self.tree.push(kind, token, start, first, last);
        let tallest = self.tree.children_rev(id).map(|c| self.stacks.heights[c.0 as usize]).max();
        let height = u32::from(kind.nests()).saturating_add(tallest.unwrap_or(0));
        self.stacks.heights.push(height);
        if (height as usize) > self.limit {
            return Err(self.too_deep(self.tree.span(id, self.tokens)));
        }
        Ok(id)
    }

    /// Counts one more open bracket, block or type argument list, a lower bound of the
    /// height of the node that will close it.
    pub fn open_one(&mut self) -> Parsed<()> {
        self.open += 1;
        if self.open > self.limit {
            return Err(self.too_deep(self.span(self.here())));
        }
        Ok(())
    }

    pub fn close_one(&mut self) {
        self.open -= 1;
    }

    fn too_deep(&self, span: Span) -> Diagnostic {
        let message = format!("The source nests deeper than {} levels.", self.limit);
        let hint = "Bind intermediate values with `let` to flatten the expression.";
        Diagnostic::at(codes::problem(codes::BUDGET_EXHAUSTED, &message, hint), span)
    }

    fn module(&mut self) -> Parsed<()> {
        while self.peek() == Kind::Import {
            self.import()?;
        }
        loop {
            match self.peek() {
                Kind::Fn => self.function()?,
                Kind::Let => self.constant()?,
                Kind::Var => {
                    let message = "A module's top-level bindings are constants.";
                    let hint = "Write `let`; `var` is for a function's own variables.";
                    let problem = codes::problem(codes::INVALID_SOURCE, message, hint);
                    return Err(Diagnostic::at(problem, self.span(self.here())));
                }
                Kind::Import => {
                    let message = "Imports must precede every function and constant.";
                    let hint = "Move this import to the top of the module.";
                    let problem = codes::problem(codes::INVALID_SOURCE, message, hint);
                    return Err(Diagnostic::at(problem, self.span(self.here())));
                }
                Kind::End => {
                    let end = self.here();
                    self.emit(NodeKind::Module, end, 0, TokenId(0), end)?;
                    return Ok(());
                }
                _ => return Err(self.unexpected(Wanted::ModuleItem)),
            }
        }
    }

    fn import(&mut self) -> Parsed<()> {
        let start = self.count();
        let first = self.expect(Kind::Import)?;
        self.same_line()?;
        self.expect(Kind::LeftBrace)?;
        let name = self.name()?;
        self.emit(NodeKind::ImportName, name, self.count(), name, name)?;
        while self.eat(Kind::Comma) {
            if self.peek() == Kind::RightBrace {
                break;
            }
            let name = self.name()?;
            self.emit(NodeKind::ImportName, name, self.count(), name, name)?;
        }
        self.expect(Kind::RightBrace)?;
        self.on_this_line()?;
        self.expect(Kind::From)?;
        self.on_this_line()?;
        let mut last = self.segment()?;
        while self.peek() == Kind::Dot && !self.starts_line() {
            self.bump();
            self.same_line()?;
            last = self.segment()?;
        }
        self.end_line()?;
        self.emit(NodeKind::Import, first, start, first, last)?;
        Ok(())
    }

    /// One segment of a module path: a name, never a keyword (JDD 0016, "Modules and
    /// imports").
    fn segment(&mut self) -> Parsed<TokenId> {
        if self.peek().is_keyword() || self.peek() == Kind::Reserved {
            let word = self.tokens.text(self.here(), self.text);
            let message = format!("`{word}` is a keyword, so it cannot name a module.");
            let hint = "Rename the module or its directory.";
            let problem = codes::problem(codes::INVALID_SOURCE, &message, hint);
            return Err(Diagnostic::at(problem, self.span(self.here())));
        }
        if self.peek() == Kind::Str {
            let message = "A module is named by a dotted path, not a label.";
            let hint = "Write the path without quotes, such as `jlv.std.deploy` or `lib.app`.";
            let problem = codes::problem(codes::INVALID_SOURCE, message, hint);
            return Err(Diagnostic::at(problem, self.span(self.here())));
        }
        let name = self.name()?;
        let written = self.tokens.text(name, self.text);
        let mut bytes = written.bytes();
        let lower = bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !lower {
            let message = format!("`{written}` cannot name a module.");
            let hint = "Name modules and directories with lower-case letters, digits and `_`, \
                        starting with a letter.";
            let problem = codes::problem(codes::INVALID_SOURCE, &message, hint);
            return Err(Diagnostic::at(problem, self.tokens.span(name)));
        }
        Ok(name)
    }

    /// Whether the next token begins a line.
    pub fn starts_line(&self) -> bool {
        self.tokens.starts_line(self.here())
    }

    /// Refuses a next token that begins a line where the line before cannot continue:
    /// a line continues only when it ends with an operator, `,`, `=`, `->` or `:`, or
    /// when the next begins with `.` or an operator other than `+` and `-` (JDD 0016).
    pub(crate) fn on_this_line(&self) -> Parsed<()> {
        // A block's `{` has a rule and a message of its own.
        if self.peek() == Kind::LeftBrace {
            return Ok(());
        }
        self.same_line()
    }

    /// As [`Parser::on_this_line`], for any next token, a `{` too: after a keyword such
    /// as `let`, `fn`, `import`, `if` or `for`, or a prefix operator, the line goes on.
    pub(crate) fn same_line(&self) -> Parsed<()> {
        if !self.starts_line() || self.peek() == Kind::End {
            return Ok(());
        }
        let written = self.tokens.text(self.here(), self.text);
        let message =
            format!("`{written}` begins a line, so it does not continue the one before.");
        let hint = format!("Move `{written}` to the end of the line before.");
        let problem = codes::problem(codes::INVALID_SOURCE, &message, &hint);
        Err(Diagnostic::at(problem, self.span(self.here())))
    }

    /// Ends a statement or an item at the end of its line, or before the `}` that closes
    /// its block; the statement's last token is the one before.
    fn end_line(&mut self) -> Parsed<TokenId> {
        let last = TokenId(self.at.saturating_sub(1));
        if matches!(self.peek(), Kind::RightBrace | Kind::End) || self.starts_line() {
            return Ok(last);
        }
        match self.habit_before_end(last) {
            Some(hint) => Err(self.unexpected_hint(Wanted::EndOfLine, hint)),
            None => Err(self.unexpected(Wanted::EndOfLine)),
        }
    }

    /// The hint for a line that goes on where it should end, when what comes before
    /// shows a habit of another language, such as `x.a = 1`, `a and b`, `const x = 1` or
    /// `f"..."`.
    fn habit_before_end(&self, last: TokenId) -> Option<&'static str> {
        let before = self.tokens.text(last, self.text);
        let adjacent = self.span(last).end == self.span(self.here()).start;
        let found = self.tokens.text(self.here(), self.text);
        Some(match self.peek() {
            Kind::Equals => {
                "Only a name declared with `var` can be assigned, as in `x = 1`; a field or \
                 an element cannot. Build the new value and assign it to the `var`."
            }
            Kind::Ident if matches!(found, "and" | "or" | "not") => {
                "Write `&&` for `and`, `||` for `or` and `!` for `not`."
            }
            Kind::Str | Kind::StrHead if adjacent && matches!(before, "f" | "r" | "b" | "s") => {
                "Every JLV string interpolates: write `\"a${x}\"` without a prefix; a raw text \
                 is a text block between lines of `\"\"\"`."
            }
            Kind::Ident if matches!(before, "const" | "val" | "mut" | "auto") => {
                "Declare a name with `let`, or with `var` to assign it later, as in `let x = 1`."
            }
            Kind::Ident if matches!(before, "def" | "func" | "function" | "fun") => {
                "Define a function with `fn`, as in `fn name(x: Int) -> Int { ... }`."
            }
            _ => return None,
        })
    }

    fn function(&mut self) -> Parsed<()> {
        let start = self.count();
        let first = self.expect(Kind::Fn)?;
        self.same_line()?;
        self.name()?;
        self.on_this_line()?;
        self.expect(Kind::LeftParen)?;
        while self.peek() != Kind::RightParen {
            let param_start = self.count();
            let name = self.name()?;
            self.expect(Kind::Colon)?;
            let ty = self.type_expr()?;
            let last = self.tree.last(ty);
            self.emit(NodeKind::Param, name, param_start, name, last)?;
            if !self.eat(Kind::Comma) {
                break;
            }
        }
        self.expect(Kind::RightParen)?;
        self.on_this_line()?;
        if self.eat(Kind::Arrow) {
            self.type_expr()?;
        } else if self.peek() == Kind::Ident {
            let hint = "Write `->` before the result type, as in `fn main() -> Int {`.";
            return Err(self.unexpected_hint(Wanted::Block, hint));
        }
        self.body(Frame::Function { start, first })
    }

    fn constant(&mut self) -> Parsed<()> {
        let start = self.count();
        let first = self.expect(Kind::Let)?;
        self.same_line()?;
        self.name()?;
        self.on_this_line()?;
        if self.eat(Kind::Colon) {
            self.type_expr()?;
        }
        self.on_this_line()?;
        self.expect(Kind::Equals)?;
        self.expr()?;
        let last = self.end_line()?;
        self.emit(NodeKind::Constant, first, start, first, last)?;
        Ok(())
    }

    /// The type machine: a path with optional arguments, one frame per open `<`.
    pub fn type_expr(&mut self) -> Parsed<NodeId> {
        let base = self.stacks.types.len();
        loop {
            let start = self.count();
            self.open_one()?;
            let first = self.name()?;
            let mut name = first;
            while self.eat(Kind::Dot) {
                name = self.name()?;
            }
            if self.eat(Kind::Less) {
                self.stacks.types.push(TypeFrame { start, first, name });
                continue;
            }
            self.close_one();
            let mut done = self.emit(NodeKind::Type, name, start, first, name)?;
            // Close every type whose last argument this was, until a `,` starts another.
            loop {
                if self.stacks.types.len() == base {
                    return Ok(done);
                }
                if self.eat(Kind::Comma) {
                    break;
                }
                let close = self.expect(Kind::Greater)?;
                let Some(frame) = self.stacks.types.pop() else { return Ok(done) };
                self.close_one();
                done = self.emit(NodeKind::Type, frame.name, frame.start, frame.first, close)?;
            }
        }
    }

    /// The statement machine: the body of a function, from its `{` to the `}` that
    /// closes it, with every `if`, `for` and block inside it on the frame stack.
    fn body(&mut self, outer: Frame) -> Parsed<()> {
        let base = self.stacks.frames.len();
        self.stacks.frames.push(outer);
        self.open_block()?;
        while self.stacks.frames.len() > base {
            match self.peek() {
                Kind::RightBrace => self.close_block(base)?,
                Kind::End => {
                    return Err(self.unclosed(Wanted::Token("}"), self.open_block_token()));
                }
                _ => self.statement()?,
            }
        }
        Ok(())
    }

    fn open_block(&mut self) -> Parsed<()> {
        if self.peek() == Kind::LeftBrace && self.starts_line() {
            let message = "A block's `{` begins a line.";
            let hint = "Put the `{` at the end of the line that starts the block.";
            let problem = codes::problem(codes::INVALID_SOURCE, message, hint);
            return Err(Diagnostic::at(problem, self.span(self.here())));
        }
        if self.peek() != Kind::LeftBrace {
            return Err(self.unexpected(Wanted::Block));
        }
        self.open_one()?;
        let start = self.count();
        let first = self.bump();
        self.stacks.frames.push(Frame::Block { start, first });
        Ok(())
    }

    /// The `{` of the innermost open block.
    fn open_block_token(&self) -> TokenId {
        let blocks = self.stacks.frames.iter().rev();
        let mut opened = blocks.filter_map(|f| match f {
            Frame::Block { first, .. } => Some(*first),
            _ => None,
        });
        opened.next().unwrap_or(TokenId(0))
    }

    /// Closes the innermost block and every construct that ends with it.
    fn close_block(&mut self, base: usize) -> Parsed<()> {
        let last = self.bump();
        let Some(Frame::Block { start, first }) = self.stacks.frames.pop() else {
            return Err(self.unexpected(Wanted::Expression));
        };
        self.close_one();
        self.emit(NodeKind::Block, first, start, first, last)?;
        if self.stacks.frames.len() == base {
            return Ok(());
        }
        let Some(parent) = self.stacks.frames.pop() else { return Ok(()) };
        match parent {
            Frame::Function { start, first } | Frame::For { start, first } => {
                let kind = if matches!(parent, Frame::For { .. }) {
                    NodeKind::For
                } else {
                    NodeKind::Function
                };
                self.emit(kind, first, start, first, last)?;
                // What follows a block statement or a function begins its own line.
                self.end_line()?;
            }
            Frame::If { start, first, last_arm } => {
                self.after_arm(start, first, last_arm, last)?
            }
            Frame::Block { .. } => self.stacks.frames.push(parent),
        }
        Ok(())
    }

    /// Continues an `if` after the block of an arm: another arm, an `else`, or its end.
    fn after_arm(
        &mut self,
        start: u32,
        first: TokenId,
        last_arm: bool,
        last: TokenId,
    ) -> Parsed<()> {
        if !last_arm && self.peek() == Kind::Else && self.starts_line() {
            let message = "An `else` begins a line.";
            let hint = "Write `} else {` on one line.";
            let problem = codes::problem(codes::INVALID_SOURCE, message, hint);
            return Err(Diagnostic::at(problem, self.span(self.here())));
        }
        if !last_arm && self.eat(Kind::Else) {
            self.on_this_line()?;
            let else_if = self.eat(Kind::If);
            self.stacks.frames.push(Frame::If { start, first, last_arm: !else_if });
            if else_if {
                self.same_line()?;
                self.expr()?;
            }
            return self.open_block();
        }
        self.emit(NodeKind::If, first, start, first, last)?;
        self.end_line()?;
        Ok(())
    }

    fn statement(&mut self) -> Parsed<()> {
        let start = self.count();
        let first = self.here();
        match self.peek() {
            Kind::Let | Kind::Var => {
                let kind = if self.peek() == Kind::Var { NodeKind::Var } else { NodeKind::Let };
                self.bump();
                self.same_line()?;
                self.name()?;
                self.on_this_line()?;
                if self.eat(Kind::Colon) {
                    self.type_expr()?;
                }
                self.on_this_line()?;
                self.expect(Kind::Equals)?;
                self.expr()?;
                let last = self.end_line()?;
                self.emit(kind, first, start, first, last)?;
            }
            Kind::Return => {
                self.bump();
                let ends = matches!(self.peek(), Kind::RightBrace | Kind::End);
                if !ends && !self.starts_line() {
                    self.expr()?;
                }
                let last = self.end_line()?;
                self.emit(NodeKind::Return, first, start, first, last)?;
            }
            Kind::If => {
                self.bump();
                self.stacks.frames.push(Frame::If { start, first, last_arm: false });
                self.same_line()?;
                self.expr()?;
                self.open_block()?;
            }
            Kind::For => {
                self.bump();
                self.stacks.frames.push(Frame::For { start, first });
                self.same_line()?;
                self.name()?;
                self.on_this_line()?;
                if self.eat(Kind::Comma) {
                    self.name()?;
                }
                self.on_this_line()?;
                self.expect(Kind::In)?;
                self.same_line()?;
                self.expr()?;
                self.open_block()?;
            }
            Kind::Ident
                if self.peek_at(1) == Kind::Equals
                    && self.tokens.starts_line(TokenId(self.at + 1)) =>
            {
                self.bump();
                return self.on_this_line();
            }
            Kind::Ident if self.peek_at(1) == Kind::Equals => {
                self.bump();
                let equals = self.bump();
                self.expr()?;
                let last = self.end_line()?;
                self.emit(NodeKind::Assign, equals, start, first, last)?;
            }
            kind if kind.continues_line() => return Err(self.leading_operator()),
            _ => self.call_statement()?,
        }
        Ok(())
    }

    /// An expression statement, which must be a call; it is its call node, with no node
    /// of its own (JDD 0016, "Statements and lines").
    fn call_statement(&mut self) -> Parsed<()> {
        let value = self.expr()?;
        self.end_line()?;
        if self.tree.kind(value) != NodeKind::Call {
            let message = "This value is computed and left unused.";
            let hint = "Bind it with `let`, return it, or remove it; only a call is a statement.";
            let problem = codes::problem(codes::INVALID_SOURCE, message, hint);
            return Err(Diagnostic::at(problem, self.tree.span(value, self.tokens)));
        }
        Ok(())
    }

    /// The refusal of a statement that begins with an operator, which would have
    /// continued the line before.
    fn leading_operator(&self) -> Diagnostic {
        let operator = spelled(self.peek());
        let message = format!("A line begins with `{operator}`, which continues nothing.");
        let hint = format!(
            "End the previous line with `{operator}`, or wrap the expression in parentheses."
        );
        let problem = codes::problem(codes::INVALID_SOURCE, &message, &hint);
        Diagnostic::at(problem, self.span(self.here()))
    }
}

/// The spelling of a keyword or punctuation kind.
fn spelled(kind: Kind) -> &'static str {
    kind.spelling().unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use jlv_core::{Diagnostic, Limits, SourceId};

    use crate::view::{ExprKind, Item, Part, Stmt, Syntax};

    fn parse(text: &str) -> Result<Syntax, Diagnostic> {
        Syntax::parse(SourceId(0), text, &Limits::default())
    }

    fn code(text: &str) -> String {
        parse(text).unwrap_err().code().to_string()
    }

    fn message(text: &str) -> String {
        parse(text).unwrap_err().problem.message
    }

    /// The statements of the first function of `text`.
    fn statements(text: &str) -> Vec<String> {
        let syntax = parse(text).unwrap();
        let Item::Function(f) = &syntax.source(text).module().items()[0] else { panic!() };
        f.body
            .statements()
            .iter()
            .map(|s| match s {
                Stmt::Let { mutable: true, .. } => "var".into(),
                Stmt::Let { .. } => "let".into(),
                Stmt::Assign { .. } => "assign".into(),
                Stmt::Return { value, .. } => format!("return {}", value.is_some()),
                Stmt::Expr(_) => "call".into(),
                Stmt::If { .. } => "if".into(),
                Stmt::For { key, .. } => format!("for {}", key.is_some()),
            })
            .collect()
    }

    /// The tree is empty after any failed parse, a lexical error included.
    #[test]
    fn a_failed_parse_leaves_no_tree() {
        let mut workspace = crate::Workspace::default();
        let limits = Limits::default();
        workspace.parse(SourceId(0), "fn f() {}\n", &limits).unwrap();
        assert!(!workspace.tree.is_empty());
        assert!(workspace.parse(SourceId(0), "fn f() { \"open", &limits).is_err());
        assert!(workspace.tree.is_empty(), "a lexical error");
        workspace.parse(SourceId(0), "fn f() {}\n", &limits).unwrap();
        assert!(workspace.parse(SourceId(0), "fn f( {}", &limits).is_err());
        assert!(workspace.tree.is_empty(), "a syntax error");
    }

    /// Runs `test` on a thread of 256 KiB: the parser needs no stack of its own
    /// (JDD 0013, TREE-02).
    fn on_small_stack(test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new().stack_size(256 << 10).spawn(test).unwrap().join().unwrap();
    }

    #[test]
    fn a_deployment_entry_parses() {
        let text = "import { DeployContext, OutputRef } from jlv.std.deploy
            import { incus } from incus

            fn deploy(ctx: DeployContext) -> Map<OutputRef> {
                let web = incus.instance(\"web\", lifecycle: { protect: true })
                return { address: web.output(\"address\") }
            }";
        let syntax = parse(text).unwrap();
        let module = syntax.source(text).module();
        let imports = module.imports();
        assert_eq!(imports[0].names.len(), 2);
        assert_eq!(imports[0].dotted(), "jlv.std.deploy");
        assert_eq!(imports[1].dotted(), "incus");
        let Item::Function(f) = &module.items()[0] else { panic!("a function") };
        assert_eq!(f.body.statements().len(), 2);
    }

    #[test]
    fn precedence_and_assignment() {
        let text = "fn f(x: Int) -> Bool {\n var y = x + 1 * 2\n y = 3\n \
                    return -x < 3 && !false || true\n}";
        assert_eq!(statements(text), ["var", "assign", "return true"]);
        let syntax = parse(text).unwrap();
        let Item::Function(f) = &syntax.source(text).module().items()[0] else { panic!() };
        let Stmt::Return { value: Some(e), .. } = &f.body.statements()[2] else { panic!() };
        assert!(matches!(e.kind(), ExprKind::Or(..)));
    }

    /// LIN-01: lines end statements; brackets, records and leading operators other than
    /// `+` and `-` continue them.
    #[test]
    fn lines_end_statements() {
        let text = "fn f() {\n let a = g(1,\n  2)\n let b = [\n 1,\n 2,\n]\n \
                    let c = a\n  && b\n  .x\n let d = a +\n  1\n g()\n return\n}";
        assert_eq!(statements(text), ["let", "let", "let", "let", "call", "return false"]);
        assert_eq!(statements("fn f() { return 1 }"), ["return true"]);
        assert!(message("fn f() {\n let a = 1\n  + 2\n}").contains("begins with `+`"));
        assert!(message("fn f() {\n let a = 1 let b = 2\n}").contains("end of the line"));
        assert!(message("fn f() {\n for x in xs { g() } g()\n}").contains("end of the line"));
        assert!(message("fn f() {} fn g() {}").contains("end of the line"));
        // A `,` may end a line.
        assert!(parse("fn f() {\n for k,\n v in m {\n }\n}").is_ok());
        for broken in [
            "fn f() {\n var x = 1\n x\n = 3\n}",
            "fn f() {\n let x: Int\n = 1\n}",
            "fn f()\n -> Int {\n return 1\n}",
            "fn f() {\n if a {\n } else\n if b {\n }\n}",
            "import { a }\nfrom m",
            "fn f() {\n for x\n in xs {\n }\n}",
            "fn f() {\n let\n x = 1\n}",
            "fn\n f() {\n}",
            "import\n { a } from m",
            "import { a } from lib.\n a",
            "fn f() {\n if\n a {\n }\n}",
            "fn f() {\n for\n x in xs {\n }\n}",
            "fn f() {\n for x in\n xs {\n }\n}",
            "fn f() {\n if a {\n } else if\n b {\n }\n}",
            "fn f() {\n let x = !\n a\n}",
            "let\n X = 1",
        ] {
            assert!(message(broken).contains("begins a line"), "{broken}");
        }
        assert!(message("fn f()\n{\n}").contains("block's `{` begins a line"));
        assert!(message("fn f() {\n if a {\n }\n else {\n }\n}").contains("`else` begins"));
        assert!(message("fn f() {\n (a)\n}").contains("left unused"));
        assert!(message("fn f() {\n -x\n}").contains("begins with `-`"));
        assert!(message("var x = 1").contains("constants"));
    }

    /// REC-01 and FOR-01: records with keyword keys, comprehensions and map loops.
    #[test]
    fn records_comprehensions_and_loops() {
        let text = "fn f() {\n let r = { type: \"oneshot\", \"a.b\": 1 }\n \
                    let xs = [for t in ts: t.name() if t.ok]\n \
                    let ys = [for k, v in m: k]\n for k, v in m {\n  g(k)\n }\n}";
        assert_eq!(statements(text), ["let", "let", "let", "for true"]);
        let syntax = parse(text).unwrap();
        let Item::Function(f) = &syntax.source(text).module().items()[0] else { panic!() };
        let Stmt::Let { value, .. } = &f.body.statements()[1] else { panic!() };
        let ExprKind::Comprehension { names, filter, .. } = value.kind() else { panic!() };
        assert_eq!(names.len(), 1);
        assert!(filter.is_some());
        assert!(message("fn f() {\n let x = [for t in ts]\n}").contains("`:`"));
        assert!(parse("fn f() {\n g(type: 1)\n}").is_ok(), "a keyword names an argument");
    }

    /// STR-01: an interpolated string is a node of its parts.
    #[test]
    fn strings_interpolate() {
        let text = "fn f() {\n let s = \"a${x + 1}b${g(\"c\")}\"\n}";
        let syntax = parse(text).unwrap();
        let Item::Function(f) = &syntax.source(text).module().items()[0] else { panic!() };
        let Stmt::Let { value, .. } = &f.body.statements()[0] else { panic!() };
        let ExprKind::Interp(parts) = value.kind() else { panic!("an interpolation") };
        let shape: Vec<&str> = parts
            .iter()
            .map(|p| match p {
                Part::Text { text, .. } => *text,
                Part::Expr(_) => "$",
            })
            .collect();
        assert_eq!(shape, ["a", "$", "b", "$", ""]);
        assert!(parse("fn f() {\n let s = \"${}\"\n}").is_err(), "an empty interpolation");
    }

    #[test]
    fn imports_are_dotted_paths() {
        assert!(message("import { a } from \"@jlv//std:deploy.jlv\"").contains("dotted path"));
        assert!(message("import { a } from lib.type.x").contains("keyword"));
        assert!(message("import { a } from lib.App").contains("cannot name a module"));
    }

    #[test]
    fn malformed_programs_are_refused() {
        assert_eq!(code("fn f() -> Int { return 1 < 2 < 3 }"), "invalid_source");
        assert_eq!(code("fn f() -> Int { return g(a: 1, 2) }"), "argument_error");
        assert_eq!(code("fn f() -> Int { while true {} }"), "unsupported_syntax");
        assert_eq!(code("fn f() -> Int { let type = 1 }"), "unsupported_syntax");
        on_small_stack(|| {
            let deep =
                format!("fn f() -> Int {{ return {}1{} }}", "(".repeat(200), ")".repeat(200));
            assert_eq!(code(&deep), "budget_exhausted");
        });
    }

    /// A chain counts its links as nesting, so a long one is refused rather than
    /// letting the passes that recurse over the tree recurse as deep.
    #[test]
    fn long_chains_are_bounded_like_nesting() {
        on_small_stack(|| {
            for link in [".a", " + 1", " && x", " * 2", "[0]", "()"] {
                let short = format!("fn f() {{ let z = x{} }}", link.repeat(40));
                assert!(parse(&short).is_ok(), "40 links of `{link}`");
                let long = format!("fn f() {{ let z = x{} }}", link.repeat(5000));
                assert_eq!(code(&long), "budget_exhausted", "`{link}`");
            }
        });
    }

    /// JDD 0013, TREE-01: what JDD 0004's grammar refuses stays refused.
    #[test]
    fn prefixes_tuples_and_late_positionals_are_refused() {
        assert_eq!(message("fn f() { let z = !!x }"), "Expected an expression, but found `!`.");
        assert_eq!(message("fn f() { let z = - -x }"), "Expected an expression, but found `-`.");
        assert_eq!(message("fn f() { let z = (a, b) }"), "Expected `)`, but found `,`.");
        assert_eq!(message("fn f() { let z = a[1, 2] }"), "Expected `]`, but found `,`.");
        assert_eq!(message("fn f() { g(a: 1, 2) }"), "A positional argument follows a named one.");
        assert_eq!(message("fn f() { let z = a == b != c }"), "Comparisons do not chain.");
        assert!(parse("fn f() { let z = -x.y[0](1) * !a }").is_ok());
    }

    /// JDD 0013, "Limits": the depth limit bounds the height of the tree, so a nested
    /// call counts once per level and a parenthesized prefix twice.
    #[test]
    fn the_depth_limit_is_the_height() {
        on_small_stack(|| {
            // Each call is one level above its argument, and the block one more: a body
            // holds 62 nested calls of `1` (`calls(61)` writes 62).
            let calls = |n: usize| format!("fn f() {{ g({}1{}) }}", "g(".repeat(n), ")".repeat(n));
            assert!(parse(&calls(61)).is_ok(), "62 calls");
            assert_eq!(code(&calls(62)), "budget_exhausted");
            // A negated parenthesis is two levels.
            let negations =
                |n: usize| format!("fn f() {{ let z = {}1{} }}", "-(".repeat(n), ")".repeat(n));
            assert!(parse(&negations(31)).is_ok());
            assert_eq!(code(&negations(32)), "budget_exhausted");
        });
    }

    #[test]
    fn types_keep_their_arguments() {
        let text = "fn f(x: Map<List<SecretRef<Text>>>, y: std.Text) { }";
        let syntax = parse(text).unwrap();
        let Item::Function(f) = &syntax.source(text).module().items()[0] else { panic!() };
        assert_eq!(f.params[0].ty.text(), "Map<List<SecretRef<Text>>>");
        assert_eq!(f.params[0].ty.args()[0].args()[0].path()[0].text, "SecretRef");
        assert_eq!(f.params[1].ty.path().len(), 2);
        let small = Limits { module_bytes: 8, ..Limits::default() };
        let err = Syntax::parse(SourceId(0), text, &small).unwrap_err();
        assert_eq!(err.code(), "budget_exhausted");
    }
}
