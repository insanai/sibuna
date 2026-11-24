//! The expression machine: the shunting-yard algorithm with groups (JDD 0013,
//! "Construction").
//!
//! The operand stack holds completed subtrees and the operator stack pending prefix and
//! infix operators and open groups: a parenthesis, a list, a record, a call or an
//! index. An infix operator first reduces the pending operators that bind at least as
//! tightly, which gives left association; a group marker stops every reduction, so a
//! bracket's contents form their own subtrees. A prefix operator binds one postfix
//! operand, so `!!x` is refused as JDD 0004's grammar says.
//!
//! Outside every group, a token that begins a line ends the expression, unless it is
//! `.` or a binary operator other than `+` and `-`, which continue it (JDD 0016,
//! "Statements and lines"). A comprehension and an interpolated string are groups too,
//! with their own separators: `:` and `if`, and the literal parts.

use jlv_core::Diagnostic;
use jlv_lang::codes;

use crate::guide::Wanted;
use crate::parse::{Parsed, Parser};
use crate::token::{Kind, TokenId};
use crate::tree::{NodeId, NodeKind};

/// A pending operator or an open group.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Operator {
    /// `!`, `-` or `+` before an operand.
    Prefix { token: TokenId },
    /// A binary operator and how tightly it binds.
    Infix { kind: NodeKind, token: TokenId, power: u8 },
    /// An open bracket.
    Group(Group),
}

/// An open bracket and the element being parsed inside it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Group {
    kind: GroupKind,
    /// The opening bracket.
    open: TokenId,
    /// The first node of the group's subtree: the callee or operand of a call or an
    /// index, or the first element otherwise.
    start: u32,
    /// The first token of the group's text.
    first: TokenId,
    /// The first node of the element being parsed.
    element: u32,
    /// The element's record key or argument name.
    label: Option<TokenId>,
    /// Whether a call has had a named argument.
    named: bool,
    /// How far a comprehension has come: 0 in its items, 1 in its body, 2 in its filter.
    phase: u8,
}

/// What an open bracket builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupKind {
    Paren,
    List,
    Record,
    Call,
    Index,
    Comprehension,
    Interp,
}

impl GroupKind {
    fn closer(self) -> Kind {
        match self {
            GroupKind::Paren | GroupKind::Call => Kind::RightParen,
            GroupKind::List | GroupKind::Index | GroupKind::Comprehension => Kind::RightBracket,
            GroupKind::Record => Kind::RightBrace,
            GroupKind::Interp => Kind::StrTail,
        }
    }

    fn node(self) -> NodeKind {
        match self {
            GroupKind::Paren => NodeKind::Paren,
            GroupKind::List => NodeKind::List,
            GroupKind::Record => NodeKind::Record,
            GroupKind::Call => NodeKind::Call,
            GroupKind::Index => NodeKind::Index,
            GroupKind::Comprehension => NodeKind::Comprehension,
            GroupKind::Interp => NodeKind::Interp,
        }
    }

    /// Whether the group holds any number of elements, rather than exactly one.
    fn is_sequence(self) -> bool {
        matches!(self, GroupKind::List | GroupKind::Record | GroupKind::Call)
    }
}

/// What the machine expects next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The start of an operand, where a prefix operator may come.
    Operand,
    /// The operand of a prefix operator, where another prefix may not come.
    Prefixed,
    /// An operand has ended; a postfix or infix operator, a separator or the end.
    Operator,
}

/// How tightly a binary operator binds, from JDD 0013's table, and its node.
fn binary(kind: Kind) -> Option<(NodeKind, u8)> {
    Some(match kind {
        Kind::OrOr => (NodeKind::Or, 1),
        Kind::AndAnd => (NodeKind::And, 2),
        Kind::EqEq | Kind::NotEq | Kind::Less | Kind::LessEq | Kind::Greater | Kind::GreaterEq => {
            (NodeKind::Binary, 3)
        }
        Kind::Plus | Kind::Minus => (NodeKind::Binary, 4),
        Kind::Star => (NodeKind::Binary, 5),
        _ => return None,
    })
}

/// The power of comparisons, which do not chain.
const COMPARISON: u8 = 3;

impl Parser<'_> {
    /// Parses one expression and returns its root.
    pub fn expr(&mut self) -> Parsed<NodeId> {
        let base = self.stacks.operators.len();
        let mut state = State::Operand;
        loop {
            state = match state {
                State::Operand | State::Prefixed => self.operand(state)?,
                State::Operator => match self.operator(base)? {
                    Some(next) => next,
                    None => break,
                },
            };
        }
        self.reduce_to(base)?;
        Ok(self.pop_operand())
    }

    fn pop_operand(&mut self) -> NodeId {
        // Every reduction and group finds its operands: the states guarantee them.
        let Some(id) = self.stacks.operands.pop() else { unreachable!("an operand is pending") };
        id
    }

    /// The innermost open group above `base`, if any.
    fn group(&self, base: usize) -> Option<Group> {
        self.stacks.operators[base..].iter().rev().find_map(|op| match op {
            Operator::Group(group) => Some(*group),
            _ => None,
        })
    }

    fn operand(&mut self, state: State) -> Parsed<State> {
        let token = self.here();
        let leaf = match self.peek() {
            Kind::Int => Some(NodeKind::Int),
            Kind::Str => Some(NodeKind::Str),
            Kind::True | Kind::False => Some(NodeKind::Bool),
            Kind::Null => Some(NodeKind::Null),
            Kind::Ident => Some(NodeKind::Name),
            _ => None,
        };
        if let Some(kind) = leaf {
            self.bump();
            let id = self.emit(kind, token, self.count(), token, token)?;
            self.stacks.operands.push(id);
            return Ok(State::Operator);
        }
        match self.peek() {
            Kind::Plus | Kind::Minus
                if state == State::Operand
                    && self.at > 0
                    && self.tokens.kind(TokenId(self.at - 1)) == self.peek() =>
            {
                let hint = "JLV has no `++` or `--`: write `x = x + 1` with `x` a `var`.";
                Err(self.unexpected_hint(Wanted::Expression, hint))
            }
            Kind::Equals
                if state == State::Operand
                    && self.at > 0
                    && matches!(
                        self.tokens.kind(TokenId(self.at - 1)),
                        Kind::Plus | Kind::Minus | Kind::Star
                    ) =>
            {
                let hint = "JLV has no `+=` or the like: write `x = x + 1` with `x` a `var`.";
                Err(self.unexpected_hint(Wanted::Expression, hint))
            }
            Kind::Bang | Kind::Minus | Kind::Plus if state == State::Operand => {
                self.bump();
                // A prefix operator is not a binary one: its operand stays on its line.
                self.same_line()?;
                self.stacks.operators.push(Operator::Prefix { token });
                Ok(State::Prefixed)
            }
            Kind::LeftParen => self.open_group(GroupKind::Paren, self.count(), token),
            Kind::LeftBracket if self.peek_at(1) == Kind::For => self.open_comprehension(token),
            Kind::LeftBracket => self.open_group(GroupKind::List, self.count(), token),
            Kind::LeftBrace => self.open_group(GroupKind::Record, self.count(), token),
            Kind::StrHead => self.open_group(GroupKind::Interp, self.count(), token),
            _ => Err(self.unexpected(Wanted::Expression)),
        }
    }

    /// Returns the next state, or `None` when the expression has ended.
    fn operator(&mut self, base: usize) -> Parsed<Option<State>> {
        let token = self.here();
        let kind = self.peek();
        let outside = self.group(base).is_none();
        if outside && self.starts_line() && (!kind.continues_line() || binary_sign(kind)) {
            return Ok(None);
        }
        if let Some(group) = self.group(base)
            && let Some(next) = self.separator(base, group, kind)?
        {
            return Ok(Some(next));
        }
        if let Some((node, power)) = binary(kind) {
            self.infix(base, node, token, power)?;
            return Ok(Some(State::Operand));
        }
        match kind {
            Kind::Dot => {
                self.bump();
                let name = self.name()?;
                let operand = self.pop_operand();
                let (start, first) = (self.tree.start(operand), self.tree.first(operand));
                let id = self.emit(NodeKind::Field, token, start, first, name)?;
                self.stacks.operands.push(id);
                Ok(Some(State::Operator))
            }
            Kind::LeftBracket | Kind::LeftParen => {
                let operand = self.pop_operand();
                let (start, first) = (self.tree.start(operand), self.tree.first(operand));
                let group =
                    if kind == Kind::LeftParen { GroupKind::Call } else { GroupKind::Index };
                self.open_group(group, start, first).map(Some)
            }
            _ => match self.group(base) {
                None => Ok(None),
                Some(group) if kind == Kind::Comma => self.comma(base, group).map(Some),
                Some(group) if kind == group.kind.closer() => self.close(base, group).map(Some),
                Some(group) if group.kind == GroupKind::Comprehension && group.phase == 0 => {
                    Err(self.missing_colon())
                }
                Some(group) => {
                    self.finish_element(base, group)?;
                    Err(self.unclosed_group(group))
                }
            },
        }
    }

    fn infix(&mut self, base: usize, node: NodeKind, token: TokenId, power: u8) -> Parsed<()> {
        while let Some(&top) = self.stacks.operators[base..].last() {
            match top {
                Operator::Prefix { .. } => self.reduce_top()?,
                Operator::Infix { power: pending, .. } if pending >= power => {
                    if pending == COMPARISON && power == COMPARISON {
                        let message = "Comparisons do not chain.";
                        let hint = "Combine two comparisons with `&&`.";
                        let problem = codes::problem(codes::INVALID_SOURCE, message, hint);
                        return Err(Diagnostic::at(problem, self.span(token)));
                    }
                    self.reduce_top()?;
                }
                _ => break,
            }
        }
        self.bump();
        self.stacks.operators.push(Operator::Infix { kind: node, token, power });
        Ok(())
    }

    /// Reduces the operator on top of the stack, which is not a group.
    fn reduce_top(&mut self) -> Parsed<()> {
        let Some(top) = self.stacks.operators.pop() else { return Ok(()) };
        let id = match top {
            Operator::Prefix { token } => {
                let operand = self.pop_operand();
                let (start, last) = (self.tree.start(operand), self.tree.last(operand));
                self.emit(NodeKind::Unary, token, start, token, last)?
            }
            Operator::Infix { kind, token, .. } => {
                let right = self.pop_operand();
                let left = self.pop_operand();
                let (start, first) = (self.tree.start(left), self.tree.first(left));
                self.emit(kind, token, start, first, self.tree.last(right))?
            }
            Operator::Group(_) => unreachable!("groups are closed, not reduced"),
        };
        self.stacks.operands.push(id);
        Ok(())
    }

    /// Reduces every pending operator above `base` down to the innermost group.
    fn reduce_to(&mut self, base: usize) -> Parsed<()> {
        while let Some(top) = self.stacks.operators[base..].last() {
            if matches!(top, Operator::Group(_)) {
                break;
            }
            self.reduce_top()?;
        }
        Ok(())
    }

    fn open_group(&mut self, kind: GroupKind, start: u32, first: TokenId) -> Parsed<State> {
        self.open_one()?;
        let open = self.bump();
        let element = self.count();
        let group =
            Group { kind, open, start, first, element, label: None, named: false, phase: 0 };
        self.stacks.operators.push(Operator::Group(group));
        self.element_start()
    }

    /// Opens `[for names in`, binding its one or two names, before its items.
    fn open_comprehension(&mut self, open: TokenId) -> Parsed<State> {
        self.open_one()?;
        let start = self.count();
        self.bump();
        self.bump();
        let name = self.name()?;
        self.emit(NodeKind::Binding, name, self.count(), name, name)?;
        if self.eat(Kind::Comma) {
            let name = self.name()?;
            self.emit(NodeKind::Binding, name, self.count(), name, name)?;
        }
        self.expect(Kind::In)?;
        let element = self.count();
        let kind = GroupKind::Comprehension;
        let group =
            Group { kind, open, start, first: open, element, label: None, named: false, phase: 0 };
        self.stacks.operators.push(Operator::Group(group));
        Ok(State::Operand)
    }

    /// The separators of a comprehension, `:` before its body and `if` before its
    /// filter, and the literal parts of an interpolated string; the next state, or
    /// `None` when `kind` is none of them.
    fn separator(&mut self, base: usize, group: Group, kind: Kind) -> Parsed<Option<State>> {
        let next_phase = match (group.kind, group.phase, kind) {
            (GroupKind::Comprehension, 0, Kind::Colon) => 1,
            (GroupKind::Comprehension, 1, Kind::If) => 2,
            (GroupKind::Interp, _, Kind::StrMid) => 1,
            _ => return Ok(None),
        };
        self.finish_element(base, group)?;
        let token = self.bump();
        if group.kind == GroupKind::Interp {
            self.emit(NodeKind::StrPart, token, self.count(), token, token)?;
        }
        let element = self.count();
        if let Some(Operator::Group(open)) = self.stacks.operators.last_mut() {
            open.phase = next_phase;
            open.element = element;
        }
        Ok(Some(State::Operand))
    }

    /// Starts the next element of the innermost group, or closes a sequence that has
    /// none, as after `[`, `#{`, `(` of a call, or a trailing comma.
    fn element_start(&mut self) -> Parsed<State> {
        let Some(Operator::Group(mut group)) = self.stacks.operators.pop() else {
            unreachable!("an element starts in a group")
        };
        group.element = self.count();
        group.label = None;
        if group.kind.is_sequence() && self.peek() == group.kind.closer() {
            self.stacks.operators.push(Operator::Group(group));
            return self.close_empty(group);
        }
        match group.kind {
            GroupKind::Record => {
                let word = matches!(self.peek(), Kind::Ident | Kind::Str | Kind::Reserved);
                if !word && !self.peek().is_keyword() {
                    return Err(self.unexpected(Wanted::RecordKey));
                }
                if self.peek() == Kind::For && self.peek_at(1) != Kind::Colon {
                    let hint = "JLV has list comprehensions but no map comprehensions; build \
                                the map in a loop, `var m: Map<Text> = {}` and \
                                `m = map.set(m, key, value)`, with `map` from \
                                `jlv.std.foundation`.";
                    return Err(self.unexpected_hint(Wanted::RecordKey, hint));
                }
                group.label = Some(self.bump());
                if self.peek() != Kind::Colon {
                    let hint = "Write `:` between a key and its value, as in `{ port: 80 }`.";
                    return Err(self.unexpected_hint(Wanted::Token(":"), hint));
                }
                self.bump();
                group.element = self.count();
            }
            GroupKind::Call
                if (matches!(self.peek(), Kind::Ident | Kind::Reserved)
                    || self.peek().is_keyword())
                    && self.peek_at(1) == Kind::Colon =>
            {
                group.label = Some(self.bump());
                self.bump();
            }
            _ => {}
        }
        self.stacks.operators.push(Operator::Group(group));
        Ok(State::Operand)
    }

    /// Ends the element that has just ended: wraps it as an entry or an argument,
    /// after the rule that positional arguments come first, and takes it off the
    /// operand stack. The group's node finds its elements by their subtree sizes, so
    /// the stack holds only what is pending, however many elements a list has.
    fn finish_element(&mut self, base: usize, group: Group) -> Parsed<()> {
        self.reduce_to(base)?;
        let Some(&value) = self.stacks.operands.last() else { return Ok(()) };
        match group.kind {
            GroupKind::Record => {
                self.pop_operand();
                let key = group.label.unwrap_or(group.open);
                let last = self.tree.last(value);
                self.emit(NodeKind::Entry, key, group.element, key, last)?;
            }
            GroupKind::Call => {
                if group.label.is_none() && group.named {
                    let message = "A positional argument follows a named one.";
                    let hint = "Write positional arguments first, then named ones.";
                    let problem = codes::problem(codes::ARGUMENT_ERROR, message, hint);
                    return Err(Diagnostic::at(problem, self.tree.span(value, self.tokens)));
                }
                self.pop_operand();
                let first = group.label.unwrap_or(self.tree.first(value));
                let (separator, last) = (self.here(), self.tree.last(value));
                self.emit(NodeKind::Arg, separator, group.element, first, last)?;
                if group.label.is_some() {
                    self.mark_named();
                }
            }
            GroupKind::Paren
            | GroupKind::List
            | GroupKind::Index
            | GroupKind::Comprehension
            | GroupKind::Interp => {
                self.pop_operand();
            }
        }
        Ok(())
    }

    fn mark_named(&mut self) {
        if let Some(Operator::Group(group)) = self.stacks.operators.last_mut() {
            group.named = true;
        }
    }

    fn comma(&mut self, base: usize, group: Group) -> Parsed<State> {
        if !group.kind.is_sequence() {
            self.reduce_to(base)?;
            return Err(self.unclosed_group(group));
        }
        self.finish_element(base, group)?;
        self.bump();
        self.element_start()
    }

    /// The refusal of a group whose closer does not come next. A list, a record or a call
    /// may want a `,`; a parenthesis, an index, an interpolation or a comprehension holds
    /// one expression, so its hint says so rather than suggest a `,`.
    fn unclosed_group(&self, group: Group) -> Diagnostic {
        let wanted = Wanted::Token(closer(group.kind));
        let one = match group.kind {
            GroupKind::Paren => {
                "A parenthesis holds one expression; close it with `)`, or join the parts \
                 with an operator."
            }
            GroupKind::Index => "An index is one expression; close it with `]`.",
            GroupKind::Interp => "An interpolation holds one expression; close it with `}`.",
            GroupKind::Comprehension => {
                "A comprehension ends after its value, or after `if` and a condition; close \
                 it with `]`."
            }
            GroupKind::List | GroupKind::Record | GroupKind::Call => {
                return self.unclosed(wanted, group.open);
            }
        };
        if self.starts_line() || self.peek() == Kind::End {
            return self.unclosed(wanted, group.open);
        }
        self.unexpected_hint(wanted, one).related(self.span(group.open))
    }

    /// The refusal of a comprehension whose value has no `:` before it.
    fn missing_colon(&self) -> Diagnostic {
        let hint = "Write `:` before the comprehension's value, as in `[for x in xs: x]`.";
        self.unexpected_hint(Wanted::Token(":"), hint)
    }

    fn close(&mut self, base: usize, group: Group) -> Parsed<State> {
        if group.kind == GroupKind::Comprehension && group.phase == 0 {
            self.reduce_to(base)?;
            return Err(self.missing_colon());
        }
        self.finish_element(base, group)?;
        if group.kind == GroupKind::Interp {
            let tail = self.here();
            self.emit(NodeKind::StrPart, tail, self.count(), tail, tail)?;
        }
        self.close_empty(group)
    }

    /// Emits the node of the innermost group, whose elements are complete, at its
    /// closing bracket.
    fn close_empty(&mut self, group: Group) -> Parsed<State> {
        let last = self.bump();
        self.stacks.operators.pop();
        self.close_one();
        let id = self.emit(group.kind.node(), group.open, group.start, group.first, last)?;
        self.stacks.operands.push(id);
        Ok(State::Operator)
    }
}

/// `)`, `]` or `}`: the closing bracket a group wants; an interpolation ends at `}`.
fn closer(kind: GroupKind) -> &'static str {
    match kind {
        GroupKind::Interp => "}",
        _ => kind.closer().spelling().unwrap_or("?"),
    }
}

/// Whether `kind` is `+` or `-`, which may begin an expression, so a line that begins
/// with one never continues the line before.
fn binary_sign(kind: Kind) -> bool {
    matches!(kind, Kind::Plus | Kind::Minus)
}
