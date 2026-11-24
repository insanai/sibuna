//! Typed views of the flat tree, in the shapes of JDD 0004's grammar (JDD 0013).
//!
//! A view is a small value that borrows the module's text, tokens and tree: an
//! [`Expr`], a [`Block`] or a [`TypeExpr`] is a node and its span, and asking for its
//! parts builds one level of views, never more. So the passes read the grammar's names
//! and fields, and no view owns or drops a subtree.

use jlv_core::{Diagnostic, Limits, SourceId, Span};
use jlv_lang::program::{BinaryOp, UnaryOp};

use crate::parse::Workspace;
use crate::token::{Kind, TokenId, TokenTable};
use crate::tree::{NodeId, NodeKind, SyntaxTree};

/// The parsed form of a module: its tokens and its tree, without the source text. Made
/// only by a successful parse, so its tree always ends with the module node the views
/// start from.
#[derive(Debug, Clone)]
pub struct Syntax {
    /// The module's tokens and comments.
    pub tokens: TokenTable,
    /// Its tree.
    pub tree: SyntaxTree,
}

impl Syntax {
    /// Parses one module, or returns the first problem.
    pub fn parse(source: SourceId, text: &str, limits: &Limits) -> Result<Syntax, Diagnostic> {
        let mut workspace = Workspace::default();
        workspace.parse(source, text, limits)?;
        Ok(Syntax { tokens: workspace.tokens, tree: workspace.tree })
    }

    /// The views of this module, whose source is `text`.
    pub fn source<'a>(&'a self, text: &'a str) -> Source<'a> {
        Source { text, tokens: &self.tokens, tree: &self.tree }
    }
}

/// A module's text, tokens and tree, from which views are made.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    /// The module's source.
    pub text: &'a str,
    /// Its tokens.
    pub tokens: &'a TokenTable,
    /// Its tree.
    pub tree: &'a SyntaxTree,
}

impl<'a> Source<'a> {
    /// The module.
    pub fn module(self) -> Module<'a> {
        Module { src: self, id: self.tree.root() }
    }

    fn span(self, id: NodeId) -> Span {
        self.tree.span(id, self.tokens)
    }

    /// The name or the string key that `token` spells.
    fn name(self, token: TokenId) -> Name<'a> {
        let text = match self.tokens.kind(token) {
            Kind::Str => self.tokens.string(token),
            _ => self.tokens.text(token, self.text),
        };
        Name { text, span: self.tokens.span(token) }
    }

    fn children(self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        self.tree.children(id, &mut out);
        out
    }

    fn expr(self, id: NodeId) -> Expr<'a> {
        Expr { src: self, id, span: self.span(id) }
    }

    fn block(self, id: NodeId) -> Block<'a> {
        Block { src: self, id, span: self.span(id) }
    }

    fn type_expr(self, id: NodeId) -> TypeExpr<'a> {
        TypeExpr { src: self, id, span: self.span(id) }
    }

    /// The token after `token`, such as the name after `fn`.
    fn after(token: TokenId) -> TokenId {
        TokenId(token.0 + 1)
    }
}

/// A name, or a record key, as written, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name<'a> {
    /// The text; a string key's decoded value.
    pub text: &'a str,
    /// Its bytes.
    pub span: Span,
}

/// A module: imports, then functions and constants.
#[derive(Debug, Clone, Copy)]
pub struct Module<'a> {
    src: Source<'a>,
    id: NodeId,
}

impl<'a> Module<'a> {
    /// The imports, in order.
    pub fn imports(&self) -> Vec<Import<'a>> {
        let src = self.src;
        if src.tree.is_empty() {
            return Vec::new();
        }
        let imports = src.children(self.id).into_iter();
        imports.filter(|c| src.tree.kind(*c) == NodeKind::Import).map(|c| import(src, c)).collect()
    }

    /// The functions and constants, in order.
    pub fn items(&self) -> Vec<Item<'a>> {
        let src = self.src;
        if src.tree.is_empty() {
            return Vec::new();
        }
        src.children(self.id)
            .into_iter()
            .filter_map(|c| match src.tree.kind(c) {
                NodeKind::Function => Some(Item::Function(function(src, c))),
                NodeKind::Constant => Some(Item::Constant(constant(src, c))),
                _ => None,
            })
            .collect()
    }
}

fn import(src: Source<'_>, id: NodeId) -> Import<'_> {
    let names = src.children(id).into_iter().map(|c| src.name(src.tree.token(c))).collect();
    // The path's segments end the import, separated by dots, after `from`.
    let mut at = src.tree.last(id).0;
    let mut path = vec![src.name(TokenId(at))];
    while at >= 2 && src.tokens.kind(TokenId(at - 1)) == Kind::Dot {
        at -= 2;
        path.push(src.name(TokenId(at)));
    }
    path.reverse();
    let path_span = Span::new(path[0].span.source, path[0].span.start as usize, {
        let last = path[path.len() - 1].span;
        last.end as usize
    });
    Import { names, path, path_span, span: src.span(id) }
}

fn function(src: Source<'_>, id: NodeId) -> Function<'_> {
    let (mut params, mut result, mut body) = (Vec::new(), None, None);
    for child in src.children(id) {
        match src.tree.kind(child) {
            NodeKind::Param => {
                let ty = src.tree.children_rev(child).next().map(|t| src.type_expr(t));
                let name = src.name(src.tree.token(child));
                params.extend(ty.map(|ty| Param { name, ty }));
            }
            NodeKind::Type => result = Some(src.type_expr(child)),
            _ => body = Some(src.block(child)),
        }
    }
    let span = src.span(id);
    let body = body.unwrap_or_else(|| src.block(id));
    Function { name: src.name(Source::after(src.tree.first(id))), params, result, body, span }
}

fn constant(src: Source<'_>, id: NodeId) -> Constant<'_> {
    let (ty, value) = typed_value(src, id);
    let name = src.name(Source::after(src.tree.first(id)));
    Constant { name, ty, value, span: src.span(id) }
}

/// The optional type and the value of a `let` or a constant: its last child is the
/// value, and a child before it the type.
fn typed_value(src: Source<'_>, id: NodeId) -> (Option<TypeExpr<'_>>, Expr<'_>) {
    let mut children = src.tree.children_rev(id);
    let value = children.next().map_or_else(|| src.expr(id), |v| src.expr(v));
    (children.next().map(|t| src.type_expr(t)), value)
}

/// `import { names } from path.of.module`.
#[derive(Debug, Clone)]
pub struct Import<'a> {
    /// The imported names.
    pub names: Vec<Name<'a>>,
    /// The module's dotted path, segment by segment.
    pub path: Vec<Name<'a>>,
    /// The path's bytes.
    pub path_span: Span,
    /// The import's bytes.
    pub span: Span,
}

impl Import<'_> {
    /// The dotted path as written, such as `jlv.std.deploy`.
    pub fn dotted(&self) -> String {
        let segments: Vec<&str> = self.path.iter().map(|n| n.text).collect();
        segments.join(".")
    }
}

/// A function or a constant.
#[derive(Debug, Clone)]
pub enum Item<'a> {
    /// `fn`.
    Function(Function<'a>),
    /// A module constant.
    Constant(Constant<'a>),
}

/// `fn name(params) -> result { body }`.
#[derive(Debug, Clone)]
pub struct Function<'a> {
    /// Its name.
    pub name: Name<'a>,
    /// Its parameters.
    pub params: Vec<Param<'a>>,
    /// The declared result, if any.
    pub result: Option<TypeExpr<'a>>,
    /// Its body.
    pub body: Block<'a>,
    /// Its bytes.
    pub span: Span,
}

/// `name: Type`.
#[derive(Debug, Clone, Copy)]
pub struct Param<'a> {
    /// The parameter's name.
    pub name: Name<'a>,
    /// Its type.
    pub ty: TypeExpr<'a>,
}

/// `let NAME: Type = value;` at module level.
#[derive(Debug, Clone, Copy)]
pub struct Constant<'a> {
    /// Its name.
    pub name: Name<'a>,
    /// The declared type, if any.
    pub ty: Option<TypeExpr<'a>>,
    /// Its initializer.
    pub value: Expr<'a>,
    /// Its bytes.
    pub span: Span,
}

/// A type as written: a dotted path and its arguments.
#[derive(Debug, Clone, Copy)]
pub struct TypeExpr<'a> {
    src: Source<'a>,
    id: NodeId,
    /// Its bytes.
    pub span: Span,
}

impl<'a> TypeExpr<'a> {
    /// The names of the path, such as `std` and `Text` for `std.Text`.
    pub fn path(&self) -> Vec<Name<'a>> {
        let (first, last) = (self.src.tree.first(self.id), self.src.tree.token(self.id));
        (first.0..=last.0).step_by(2).map(|t| self.src.name(TokenId(t))).collect()
    }

    /// The type as written, such as `Map<List<Int>>`, in one spelling: no spaces, and
    /// one after each comma. Read from its tokens, so it needs no recursion.
    pub fn text(&self) -> String {
        let (first, last) = (self.src.tree.first(self.id), self.src.tree.last(self.id));
        let mut out = String::new();
        for token in (first.0..=last.0).map(TokenId) {
            out.push_str(self.src.tokens.text(token, self.src.text));
            if self.src.tokens.kind(token) == Kind::Comma {
                out.push(' ');
            }
        }
        out
    }

    /// The type arguments, such as `Int` for `List<Int>`.
    pub fn args(&self) -> Vec<TypeExpr<'a>> {
        self.src.children(self.id).into_iter().map(|c| self.src.type_expr(c)).collect()
    }
}

/// `{ statements }`.
#[derive(Debug, Clone, Copy)]
pub struct Block<'a> {
    src: Source<'a>,
    id: NodeId,
    /// Its bytes, braces included.
    pub span: Span,
}

impl<'a> Block<'a> {
    /// The statements, in order.
    pub fn statements(&self) -> Vec<Stmt<'a>> {
        self.src.children(self.id).into_iter().map(|c| statement(self.src, c)).collect()
    }
}

/// A statement.
#[derive(Debug, Clone)]
pub enum Stmt<'a> {
    /// `let name: Type = value`, or `var` when `mutable`.
    Let {
        /// Whether it was declared with `var`, so that it may be assigned again.
        mutable: bool,
        /// The bound name.
        name: Name<'a>,
        /// The declared type, if any.
        ty: Option<TypeExpr<'a>>,
        /// The value.
        value: Expr<'a>,
        /// The statement's bytes.
        span: Span,
    },
    /// `name = value`.
    Assign {
        /// The assigned local.
        name: Name<'a>,
        /// The value.
        value: Expr<'a>,
        /// The statement's bytes.
        span: Span,
    },
    /// `return value`.
    Return {
        /// The returned value, if any.
        value: Option<Expr<'a>>,
        /// The statement's bytes.
        span: Span,
    },
    /// An expression statement, which is a call.
    Expr(Expr<'a>),
    /// `if`, its `else if` arms and its `else`.
    If {
        /// Each condition and its block.
        arms: Vec<(Expr<'a>, Block<'a>)>,
        /// The `else` block, if any.
        otherwise: Option<Block<'a>>,
        /// The statement's bytes.
        span: Span,
    },
    /// `for name in items { body }`, or `for key, value in map { body }`.
    For {
        /// The key of a loop over a map's entries.
        key: Option<Name<'a>>,
        /// The loop variable: an item, or an entry's value.
        name: Name<'a>,
        /// The list it runs over.
        items: Expr<'a>,
        /// The body.
        body: Block<'a>,
        /// The statement's bytes.
        span: Span,
    },
}

fn statement(src: Source<'_>, id: NodeId) -> Stmt<'_> {
    let span = src.span(id);
    let first = src.tree.first(id);
    let last_child = src.tree.children_rev(id).next();
    let child = || last_child.map_or_else(|| src.expr(id), |c| src.expr(c));
    match src.tree.kind(id) {
        NodeKind::Let | NodeKind::Var => {
            let (ty, value) = typed_value(src, id);
            let mutable = src.tree.kind(id) == NodeKind::Var;
            Stmt::Let { mutable, name: src.name(Source::after(first)), ty, value, span }
        }
        NodeKind::Assign => Stmt::Assign { name: src.name(first), value: child(), span },
        NodeKind::Return => Stmt::Return { value: last_child.map(|c| src.expr(c)), span },
        NodeKind::If => if_statement(src, id, span),
        NodeKind::For => {
            let children = src.children(id);
            let items = src.expr(children[0]);
            let body = src.block(children[children.len() - 1]);
            let one = Source::after(first);
            let (key, name) = if src.tokens.kind(Source::after(one)) == Kind::Comma {
                (Some(src.name(one)), src.name(TokenId(one.0 + 2)))
            } else {
                (None, src.name(one))
            };
            Stmt::For { key, name, items, body, span }
        }
        // An expression statement is its call node (JDD 0016).
        _ => Stmt::Expr(src.expr(id)),
    }
}

/// An `if`: conditions and blocks alternate, and a block after a block is `else`.
fn if_statement(src: Source<'_>, id: NodeId, span: Span) -> Stmt<'_> {
    let (mut arms, mut otherwise, mut condition) = (Vec::new(), None, None);
    for child in src.children(id) {
        match (src.tree.kind(child), condition.take()) {
            (NodeKind::Block, Some(c)) => arms.push((c, src.block(child))),
            (NodeKind::Block, None) => otherwise = Some(src.block(child)),
            _ => condition = Some(src.expr(child)),
        }
    }
    Stmt::If { arms, otherwise, span }
}

/// An expression.
#[derive(Debug, Clone, Copy)]
pub struct Expr<'a> {
    src: Source<'a>,
    id: NodeId,
    /// Its bytes.
    pub span: Span,
}

/// What an expression is, with its parts as views.
#[derive(Debug, Clone)]
pub enum ExprKind<'a> {
    /// An integer literal's magnitude.
    Int(u64),
    /// A string literal's decoded text.
    Str(&'a str),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// A name.
    Name(&'a str),
    /// `[items]`.
    List(Vec<Expr<'a>>),
    /// `#{ entries }`.
    Record(Vec<Entry<'a>>),
    /// A prefix operator and its operand.
    Unary(UnaryOp, Expr<'a>),
    /// A binary operator and its operands.
    Binary(BinaryOp, Expr<'a>, Expr<'a>),
    /// `a && b`.
    And(Expr<'a>, Expr<'a>),
    /// `a || b`.
    Or(Expr<'a>, Expr<'a>),
    /// `base.name`.
    Field(Expr<'a>, Name<'a>),
    /// `base[index]`.
    Index(Expr<'a>, Expr<'a>),
    /// `callee(args)`.
    Call(Expr<'a>, Vec<Arg<'a>>),
    /// `(expression)`.
    Paren(Expr<'a>),
    /// A string with interpolations: its literal parts and expressions, in order.
    Interp(Vec<Part<'a>>),
    /// `[for names in items: body if filter]`.
    Comprehension {
        /// The one or two names it binds: an item, or an entry's key and value.
        names: Vec<Name<'a>>,
        /// What it runs over.
        items: Expr<'a>,
        /// The value of each element it keeps.
        body: Expr<'a>,
        /// The condition an element must meet.
        filter: Option<Expr<'a>>,
    },
}

/// One part of an interpolated string.
#[derive(Debug, Clone, Copy)]
pub enum Part<'a> {
    /// A literal part, decoded, and its token: the bytes that delimit the part, such
    /// as `"` and `${`, are part of the token, so it is never empty in source.
    Text {
        /// The decoded text, which may be empty.
        text: &'a str,
        /// The token's bytes.
        span: Span,
    },
    /// An interpolated expression.
    Expr(Expr<'a>),
}

/// `key: value` in a record.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// The key.
    pub key: Name<'a>,
    /// The value.
    pub value: Expr<'a>,
}

/// One argument of a call.
#[derive(Debug, Clone, Copy)]
pub struct Arg<'a> {
    /// The name of a named argument.
    pub name: Option<Name<'a>>,
    /// The value.
    pub value: Expr<'a>,
}

impl<'a> Expr<'a> {
    /// What the expression is.
    pub fn kind(&self) -> ExprKind<'a> {
        let (src, id) = (self.src, self.id);
        let token = src.tree.token(id);
        let mut parts = src.tree.children_rev(id).map(|c| src.expr(c));
        let mut one = || parts.next().unwrap_or(*self);
        match src.tree.kind(id) {
            NodeKind::Int => ExprKind::Int(src.tokens.int(token)),
            NodeKind::Str => ExprKind::Str(src.tokens.string(token)),
            NodeKind::Bool => ExprKind::Bool(src.tokens.kind(token) == Kind::True),
            NodeKind::Name => ExprKind::Name(src.tokens.text(token, src.text)),
            NodeKind::Unary => ExprKind::Unary(unary(src.tokens.kind(token)), one()),
            NodeKind::Binary => {
                let (right, left) = (one(), one());
                ExprKind::Binary(binary(src.tokens.kind(token)), left, right)
            }
            NodeKind::And => {
                let (right, left) = (one(), one());
                ExprKind::And(left, right)
            }
            NodeKind::Or => {
                let (right, left) = (one(), one());
                ExprKind::Or(left, right)
            }
            NodeKind::Field => ExprKind::Field(one(), src.name(src.tree.last(id))),
            NodeKind::Index => {
                let (index, base) = (one(), one());
                ExprKind::Index(base, index)
            }
            NodeKind::Paren => ExprKind::Paren(one()),
            NodeKind::List => {
                ExprKind::List(src.children(id).into_iter().map(|c| src.expr(c)).collect())
            }
            NodeKind::Record => ExprKind::Record(
                src.children(id)
                    .into_iter()
                    .map(|c| Entry { key: src.name(src.tree.token(c)), value: child_expr(src, c) })
                    .collect(),
            ),
            NodeKind::Call => {
                let children = src.children(id);
                let callee = src.expr(children[0]);
                ExprKind::Call(callee, children[1..].iter().map(|c| argument(src, *c)).collect())
            }
            NodeKind::Interp => ExprKind::Interp(interpolation(src, id, token)),
            NodeKind::Comprehension => comprehension(src, id),
            _ => ExprKind::Null,
        }
    }
}

/// The parts of the interpolated string `id`, whose own token is its first part.
fn interpolation<'a>(src: Source<'a>, id: NodeId, head: TokenId) -> Vec<Part<'a>> {
    let literal = |token: TokenId| Part::Text {
        text: src.tokens.string(token),
        span: src.tokens.span(token),
    };
    let mut parts = vec![literal(head)];
    for child in src.children(id) {
        parts.push(match src.tree.kind(child) {
            NodeKind::StrPart => literal(src.tree.token(child)),
            _ => Part::Expr(src.expr(child)),
        });
    }
    parts
}

/// The comprehension `id`: its bindings, then its items, body and optional filter.
fn comprehension(src: Source<'_>, id: NodeId) -> ExprKind<'_> {
    let children = src.children(id);
    let bound = children.iter().take_while(|c| src.tree.kind(**c) == NodeKind::Binding);
    let names: Vec<Name<'_>> = bound.map(|c| src.name(src.tree.token(*c))).collect();
    let rest = &children[names.len()..];
    let items = src.expr(rest[0]);
    let body = src.expr(rest[1]);
    let filter = rest.get(2).map(|c| src.expr(*c));
    ExprKind::Comprehension { names, items, body, filter }
}

/// The only child of an entry or an argument.
fn child_expr(src: Source<'_>, id: NodeId) -> Expr<'_> {
    src.tree.children_rev(id).next().map_or_else(|| src.expr(id), |c| src.expr(c))
}

/// An argument, named when its first token is a name followed by `:`.
fn argument(src: Source<'_>, id: NodeId) -> Arg<'_> {
    let first = src.tree.first(id);
    let kind = src.tokens.kind(first);
    let word = matches!(kind, Kind::Ident | Kind::Reserved) || kind.is_keyword();
    let named = word && src.tokens.kind(Source::after(first)) == Kind::Colon;
    Arg { name: named.then(|| src.name(first)), value: child_expr(src, id) }
}

fn unary(kind: Kind) -> UnaryOp {
    match kind {
        Kind::Bang => UnaryOp::Not,
        Kind::Minus => UnaryOp::Neg,
        _ => UnaryOp::Plus,
    }
}

fn binary(kind: Kind) -> BinaryOp {
    match kind {
        Kind::Plus => BinaryOp::Add,
        Kind::Minus => BinaryOp::Sub,
        Kind::Star => BinaryOp::Mul,
        Kind::EqEq => BinaryOp::Eq,
        Kind::NotEq => BinaryOp::Ne,
        Kind::Less => BinaryOp::Lt,
        Kind::LessEq => BinaryOp::Le,
        Kind::Greater => BinaryOp::Gt,
        _ => BinaryOp::Ge,
    }
}
