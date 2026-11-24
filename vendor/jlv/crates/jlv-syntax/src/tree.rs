//! The flat syntax tree of one module (JDD 0013, "The syntax tree").
//!
//! Nodes are stored in postorder in five columns. A node's subtree is the interval of
//! nodes that ends at it and has its `size` (Lemma 1), so its last child is the node
//! before it and the child before a child `c` is `c - size(c)` (Lemma 3). The tree
//! holds no pointer: it is a few vectors, freed in a few steps whatever its depth.

use jlv_core::Span;

use crate::token::{TokenId, TokenTable};

/// The index of a node in its tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u32);

/// What a node is; the record's table "Node kinds" gives each one's token and children.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NodeKind {
    /// The module: imports, then functions and constants.
    Module,
    /// `import { names } from path.of.module`.
    Import,
    /// One imported name.
    ImportName,
    /// `fn name(params) -> Type { ... }`.
    Function,
    /// `name: Type`.
    Param,
    /// A module constant, `let NAME: Type = value`.
    Constant,
    /// A type: a dotted path, with its arguments as children.
    Type,
    /// `{ statements }`.
    Block,
    /// `let name: Type = value`.
    Let,
    /// `var name: Type = value`, which may be assigned again.
    Var,
    /// `name = value`.
    Assign,
    /// `return value`.
    Return,
    /// `if` with its arms and an optional `else` block.
    If,
    /// `for name in items { ... }`.
    For,
    /// An integer literal.
    Int,
    /// A string literal or a text block.
    Str,
    /// `true` or `false`.
    Bool,
    /// `null`.
    Null,
    /// A name.
    Name,
    /// `[elements]`.
    List,
    /// `{ entries }`.
    Record,
    /// `key: value` in a record.
    Entry,
    /// `!`, `-` or `+` before an operand.
    Unary,
    /// An arithmetic or comparison operator between two operands.
    Binary,
    /// `&&`.
    And,
    /// `||`.
    Or,
    /// `operand.name`.
    Field,
    /// `operand[index]`.
    Index,
    /// `callee(arguments)`.
    Call,
    /// One argument of a call, positional or named.
    Arg,
    /// `(expression)`.
    Paren,
    /// `[for names in items: body if filter]`: its names, then the items, the body and
    /// the filter.
    Comprehension,
    /// A name that a comprehension binds.
    Binding,
    /// A string with interpolations: its own token is the first literal part, and its
    /// children alternate expressions and the later parts.
    Interp,
    /// A literal part of an interpolated string after an interpolation.
    StrPart,
}

impl NodeKind {
    /// Whether a node of this kind counts as one level of nesting: expressions, types
    /// and blocks do (JDD 0013, "Limits").
    pub fn nests(self) -> bool {
        !matches!(
            self,
            NodeKind::Module
                | NodeKind::Import
                | NodeKind::ImportName
                | NodeKind::Function
                | NodeKind::Param
                | NodeKind::Constant
                | NodeKind::Let
                | NodeKind::Var
                | NodeKind::Assign
                | NodeKind::Return
                | NodeKind::If
                | NodeKind::For
                | NodeKind::Entry
                | NodeKind::Arg
                | NodeKind::Binding
                | NodeKind::StrPart
        )
    }
}

/// The nodes of one module, in postorder, in columns.
#[derive(Debug, Clone, Default)]
pub struct SyntaxTree {
    kinds: Vec<NodeKind>,
    tokens: Vec<u32>,
    sizes: Vec<u32>,
    firsts: Vec<u32>,
    lasts: Vec<u32>,
}

impl SyntaxTree {
    /// Empties the tree, keeping its capacity, and reserves `rows` nodes.
    pub(crate) fn reset(&mut self, rows: usize) {
        for column in [&mut self.tokens, &mut self.sizes, &mut self.firsts, &mut self.lasts] {
            column.clear();
            column.reserve(rows);
        }
        self.kinds.clear();
        self.kinds.reserve(rows);
    }

    /// Appends the node whose subtree starts at node `start`.
    pub(crate) fn push(
        &mut self,
        kind: NodeKind,
        token: TokenId,
        start: u32,
        first: TokenId,
        last: TokenId,
    ) -> NodeId {
        let id = self.kinds.len() as u32;
        self.kinds.push(kind);
        self.tokens.push(token.0);
        self.sizes.push(id - start + 1);
        self.firsts.push(first.0);
        self.lasts.push(last.0);
        NodeId(id)
    }

    /// The number of nodes.
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Whether the tree has no node, which happens only before parsing.
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// The module node, the last of a parsed tree.
    pub fn root(&self) -> NodeId {
        NodeId(self.kinds.len().saturating_sub(1) as u32)
    }

    /// The kind of node `id`.
    pub fn kind(&self, id: NodeId) -> NodeKind {
        self.kinds[id.0 as usize]
    }

    /// The node's own token.
    pub fn token(&self, id: NodeId) -> TokenId {
        TokenId(self.tokens[id.0 as usize])
    }

    /// The number of nodes in the subtree of `id`, itself included.
    pub fn size(&self, id: NodeId) -> u32 {
        self.sizes[id.0 as usize]
    }

    /// The first node of the subtree of `id`.
    pub fn start(&self, id: NodeId) -> u32 {
        (id.0 + 1).saturating_sub(self.size(id))
    }

    /// The first token of the node's text.
    pub fn first(&self, id: NodeId) -> TokenId {
        TokenId(self.firsts[id.0 as usize])
    }

    /// The last token of the node's text.
    pub fn last(&self, id: NodeId) -> TokenId {
        TokenId(self.lasts[id.0 as usize])
    }

    /// The node's bytes.
    pub fn span(&self, id: NodeId, tokens: &TokenTable) -> Span {
        tokens.span(self.first(id)).to(tokens.span(self.last(id)))
    }

    /// The children of `id`, last to first (Lemma 3).
    pub fn children_rev(&self, id: NodeId) -> ChildrenRev<'_> {
        ChildrenRev { tree: self, next: id.0, stop: self.start(id) }
    }

    /// Replaces the contents of `out` with the children of `id`, in source order.
    pub fn children(&self, id: NodeId, out: &mut Vec<NodeId>) {
        out.clear();
        out.extend(self.children_rev(id));
        out.reverse();
    }
}

/// The children of a node, last to first.
#[derive(Debug, Clone)]
pub struct ChildrenRev<'t> {
    tree: &'t SyntaxTree,
    /// One past the next child to yield.
    next: u32,
    /// The first node of the parent's subtree.
    stop: u32,
}

impl Iterator for ChildrenRev<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        if self.next <= self.stop {
            return None;
        }
        let child = NodeId(self.next - 1);
        self.next = child.0 + 1 - self.tree.size(child);
        Some(child)
    }
}
