//! The checked core program the compiler lowers source to and the evaluator runs.
//!
//! Names are resolved: locals are numbered slots of their function, module constants
//! are global slots in initialization order, and every call names a source function
//! or a native by index. Named arguments are resolved to parameter positions while
//! keeping their source order, since call arguments evaluate left to right (JDD 0004).

use std::sync::Arc;

use jlv_core::Span;

use crate::value::Value;

/// An index into [`Program::natives`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NativeId(pub u32);

/// An index into [`Program::functions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionId(pub u32);

/// A whole checked closure: every function, constant and native it uses.
#[derive(Debug, Clone, Default)]
pub struct Program {
    /// Source functions of every module.
    pub functions: Vec<Function>,
    /// Module constants, in module dependency order and then source order.
    pub constants: Vec<Constant>,
    /// The qualified names of the natives the program calls, such as
    /// `@jlv//std:foundation.jlv#math.div_floor`.
    pub natives: Vec<Arc<str>>,
}

/// One module constant and its initializer.
#[derive(Debug, Clone)]
pub struct Constant {
    /// The name, for diagnostics.
    pub name: Arc<str>,
    /// The initializer; it cannot read an entrypoint context.
    pub value: Expr,
    /// The local slots the initializer uses, such as the list a comprehension builds.
    pub locals: u32,
}

/// One source function.
#[derive(Debug, Clone)]
pub struct Function {
    /// The name, for diagnostics.
    pub name: Arc<str>,
    /// The number of parameters; they occupy the first local slots.
    pub params: u32,
    /// The number of local slots, parameters included.
    pub locals: u32,
    /// The body.
    pub body: Block,
    /// Where it is defined.
    pub span: Span,
}

/// A sequence of statements with its own scope.
#[derive(Debug, Clone, Default)]
pub struct Block {
    /// The statements in order.
    pub statements: Vec<Stmt>,
}

/// A statement.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// `let name = value;` into a fresh slot.
    Let {
        /// The slot.
        slot: u32,
        /// The initializer.
        value: Expr,
    },
    /// `name = value;` into an existing local slot.
    Assign {
        /// The slot.
        slot: u32,
        /// The new value.
        value: Expr,
    },
    /// `return value;`, or `return;` for a `Null` result.
    Return {
        /// The value, if any.
        value: Option<Expr>,
        /// The statement.
        span: Span,
    },
    /// An expression evaluated for its effect on the builder, or its failure.
    Expr(Expr),
    /// `if c { } else if c { } else { }`.
    If {
        /// Each condition and its block, in order.
        arms: Vec<(Expr, Block)>,
        /// The `else` block.
        otherwise: Option<Block>,
    },
    /// `for key, value in map { }` over a map's entries in key order.
    ForEntries {
        /// The key's slot.
        key: u32,
        /// The value's slot.
        value: u32,
        /// The map, evaluated once.
        items: Expr,
        /// The body.
        body: Block,
        /// The statement.
        span: Span,
    },
    /// `for name in items { }` over a finite list.
    For {
        /// The loop variable's slot.
        slot: u32,
        /// The list, evaluated once.
        items: Expr,
        /// The body.
        body: Block,
        /// The statement.
        span: Span,
    },
}

/// An expression and its source span.
#[derive(Debug, Clone)]
pub struct Expr {
    /// What it computes.
    pub kind: ExprKind,
    /// Where it is.
    pub span: Span,
}

/// The kinds of expressions.
#[derive(Debug, Clone)]
pub enum ExprKind {
    /// A constant value.
    Literal(Value),
    /// A local slot.
    Local(u32),
    /// A module constant slot.
    Constant(u32),
    /// `[a, b]`.
    List(Vec<Expr>),
    /// `{ key: value }`, entries in source order.
    Map(Vec<MapEntry>),
    /// `!x`, `-x` or `+x`.
    Unary(UnaryOp, Box<Expr>),
    /// A strict binary operator.
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
    /// `a && b`, which does not evaluate `b` when `a` is false.
    And(Box<Expr>, Box<Expr>),
    /// `a || b`, which does not evaluate `b` when `a` is true.
    Or(Box<Expr>, Box<Expr>),
    /// `a[i]` on a list, bytes or map.
    Index(Box<Expr>, Box<Expr>),
    /// `a.name` on a record value.
    Field(Box<Expr>, Arc<str>),
    /// A call of a source function.
    Call(FunctionId, Args),
    /// A call of a library native; a method's receiver is its first source argument.
    Native(NativeId, Args),
    /// A call of a prelude builtin.
    Builtin(Builtin, Args),
    /// An interpolated string: its literal parts and the `Text` or `Int` values between
    /// them, joined (JDD 0016, "Strings").
    Interpolate(Vec<Expr>),
    /// `[for x in xs: body if filter]`.
    Comprehension(Box<Comprehension>),
}

/// A comprehension and the slots it uses.
#[derive(Debug, Clone)]
pub struct Comprehension {
    /// The slot of an entry's key, for a comprehension over a map.
    pub key: Option<u32>,
    /// The slot of the item, or of an entry's value.
    pub slot: u32,
    /// The hidden slot that holds the list being built.
    pub list: u32,
    /// What it runs over.
    pub items: Expr,
    /// The condition an element must meet.
    pub filter: Option<Expr>,
    /// The value of each element it keeps.
    pub body: Expr,
}

/// One entry of a map literal.
#[derive(Debug, Clone)]
pub struct MapEntry {
    /// The key.
    pub key: Arc<str>,
    /// Where the key is, for duplicate-key diagnostics.
    pub key_span: Span,
    /// The value.
    pub value: Expr,
}

/// Call arguments: the expressions in source order and, for each parameter, where its
/// value comes from.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// The argument expressions in the order they are written and evaluated.
    pub exprs: Vec<Expr>,
    /// For each parameter: a source argument, a default value or nothing.
    pub slots: Vec<ArgSlot>,
}

impl Args {
    /// Positional arguments that fill the parameters in order.
    pub fn positional(exprs: Vec<Expr>) -> Args {
        let slots = (0..exprs.len()).map(|i| ArgSlot::Source(i as u32)).collect();
        Args { exprs, slots }
    }
}

/// Where a parameter's value comes from.
#[derive(Debug, Clone)]
pub enum ArgSlot {
    /// The source argument at this index of [`Args::exprs`].
    Source(u32),
    /// The signature's exact default.
    Default(Value),
    /// An optional parameter that was not given; distinct from `null`.
    Absent,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// Boolean negation.
    Not,
    /// Checked integer negation.
    Neg,
    /// Integer identity.
    Plus,
}

/// Strict binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    /// Checked integer addition, or concatenation of texts, bytes or lists.
    Add,
    /// Checked integer subtraction.
    Sub,
    /// Checked integer multiplication.
    Mul,
    /// Structural, tag-sensitive equality.
    Eq,
    /// Its negation.
    Ne,
    /// Integer or byte-wise text ordering.
    Lt,
    /// Less or equal.
    Le,
    /// Greater.
    Gt,
    /// Greater or equal.
    Ge,
}

impl BinaryOp {
    /// The operator as source spells it.
    pub fn symbol(self) -> &'static str {
        match self {
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::Mul => "*",
            BinaryOp::Eq => "==",
            BinaryOp::Ne => "!=",
            BinaryOp::Lt => "<",
            BinaryOp::Le => "<=",
            BinaryOp::Gt => ">",
            BinaryOp::Ge => ">=",
        }
    }
}

/// The implicitly visible prelude (JDD 0004, "Modules, context and foundation").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    /// `len(x)`: UTF-8 bytes of a text, bytes of a byte string, items of a list or map.
    Len,
    /// `keys(m)`: the sorted keys of a map.
    Keys,
    /// `contains(c, x)`: list membership, map key presence or text containment.
    Contains,
    /// `range(n)` or `range(start, end)`: a bounded list of integers.
    Range,
    /// `fail(message)`: stops preparation with `user_error`.
    Fail,
}

impl Builtin {
    /// The builtin named `name`.
    pub fn named(name: &str) -> Option<Builtin> {
        match name {
            "len" => Some(Builtin::Len),
            "keys" => Some(Builtin::Keys),
            "contains" => Some(Builtin::Contains),
            "range" => Some(Builtin::Range),
            "fail" => Some(Builtin::Fail),
            _ => None,
        }
    }
}
