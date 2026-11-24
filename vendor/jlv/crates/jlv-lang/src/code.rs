//! The program as flat code for the evaluation machine (JDD 0013, "The program and its
//! evaluation").
//!
//! Each function and the constants' initializers become a run of instructions in one
//! table: an expression's operands come before its operation, as in postorder, and a
//! [`Op::Step`] stands where the recursive evaluator charged a step, before the
//! operands, so the machine charges the same amounts in the same order (Theorem 4).
//! `&&`, `||`, `if` and `for` jump over what they do not evaluate. Compiling recurses
//! over one function's expressions, as deep as the source's depth limit allows.

use std::sync::Arc;

use jlv_core::Span;

use crate::program::{
    ArgSlot, Args, BinaryOp, Block, Builtin, Comprehension, Expr, ExprKind, FunctionId, NativeId,
    Program, Stmt, UnaryOp,
};
use crate::value::Value;

/// One instruction.
#[derive(Debug, Clone)]
pub(crate) enum Op {
    /// Charges one step at the span.
    Step(Span),
    /// Pushes a literal.
    Literal(u32),
    /// Pushes a local's value.
    Local(u32, Span),
    /// Pushes a module constant's value.
    Constant(u32, Span),
    /// Pops `count` values into a list.
    List(u32, Span),
    /// Pops `count` values into a map with the keys starting at `keys`.
    Map { keys: u32, count: u32, span: Span },
    /// Applies a prefix operator to the top value.
    Unary(UnaryOp, Span),
    /// Applies a binary operator to the two top values.
    Binary(BinaryOp, Span),
    /// Indexes the second value by the top one.
    Index(Span),
    /// Selects the field named by entry `name` of the name table.
    Field(u32, Span),
    /// `&&`: pops a condition; when false, pushes `false` and jumps to `end`.
    AndThen { end: u32, span: Span },
    /// `||`: pops a condition; when true, pushes `true` and jumps to `end`.
    OrElse { end: u32, span: Span },
    /// Pops a condition and pushes it back as a boolean, checked.
    Truth(Span),
    /// Calls a source function with the arguments of argument list `args`.
    Call { function: FunctionId, args: u32, span: Span },
    /// Calls a native.
    Native { native: NativeId, args: u32, span: Span },
    /// Calls a builtin.
    Builtin { builtin: Builtin, args: u32, span: Span },
    /// Pops a value into a local.
    Store(u32),
    /// Pops a value into a module constant.
    StoreConstant(u32),
    /// Drops the top value.
    Pop,
    /// Returns the top value from the current function.
    Return,
    /// An `if` arm: pops its condition and jumps to `otherwise` when it is false.
    Branch { otherwise: u32, span: Span },
    /// Continues at `to`.
    Jump(u32),
    /// Starts a `for` over the list on top, or over the map on top when `entries`;
    /// `items` locates a value of the wrong kind.
    ForEach { items: Span, entries: bool },
    /// Gives the loop's next item to local `slot`, charging a step at `span`, or ends
    /// the loop and jumps to `exit`.
    Next { slot: u32, exit: u32, span: Span },
    /// Gives the loop's next map entry to locals `key` and `value`, charging a step at
    /// `span`, or ends the loop and jumps to `exit`.
    NextEntry { key: u32, value: u32, exit: u32, span: Span },
    /// Pops a value and appends it to the list in local `slot`, within the container
    /// bound.
    Append(u32, Span),
    /// Pops `count` texts, integers and booleans and joins them, an integer in decimal
    /// and a boolean as `true` or `false`, charging the size of the text, as `+` on texts
    /// does.
    Concat(u32, Span),
    /// Stops the machine with the value on top of the stack, or null when there is
    /// none: the end of the constants' initialization, and where the entry returns.
    Halt,
}

/// A call's arguments as the machine arranges them: how many the source gives, and
/// what fills each parameter.
#[derive(Debug, Clone)]
pub(crate) struct ArgList {
    pub given: u32,
    pub slots: Vec<ArgSlot>,
}

/// The whole program as code.
#[derive(Debug, Clone, Default)]
pub(crate) struct Code {
    pub ops: Vec<Op>,
    /// Where each function's code starts.
    pub entries: Vec<u32>,
    /// Where the constants' initialization starts.
    pub init: u32,
    /// A `Halt` that the entry call returns to.
    pub exit: u32,
    pub literals: Vec<Value>,
    pub names: Vec<Arc<str>>,
    pub keys: Vec<(Arc<str>, Span)>,
    pub args: Vec<ArgList>,
}

impl Code {
    /// Compiles `program`.
    pub fn compile(program: &Program) -> Code {
        let mut code = Code::default();
        for function in &program.functions {
            code.entries.push(code.here());
            code.block(&function.body);
            // A body that ends without `return` returns null.
            let null = code.literal(Value::Null);
            code.ops.push(Op::Literal(null));
            code.ops.push(Op::Return);
        }
        code.init = code.here();
        for (slot, constant) in program.constants.iter().enumerate() {
            code.ops.push(Op::Step(constant.value.span));
            code.expr(&constant.value);
            code.ops.push(Op::StoreConstant(slot as u32));
        }
        code.ops.push(Op::Halt);
        code.exit = code.here();
        code.ops.push(Op::Halt);
        code
    }

    fn here(&self) -> u32 {
        self.ops.len() as u32
    }

    fn literal(&mut self, value: Value) -> u32 {
        self.literals.push(value);
        self.literals.len() as u32 - 1
    }

    /// Emits a jump whose target is set later by [`Code::land`].
    fn jump_slot(&mut self, op: Op) -> usize {
        self.ops.push(op);
        self.ops.len() - 1
    }

    /// Points the jump at `at` to the next instruction.
    fn land(&mut self, at: usize) {
        let here = self.here();
        match &mut self.ops[at] {
            Op::AndThen { end, .. } | Op::OrElse { end, .. } => *end = here,
            Op::Branch { otherwise, .. } => *otherwise = here,
            Op::Jump(to) => *to = here,
            Op::Next { exit, .. } | Op::NextEntry { exit, .. } => *exit = here,
            _ => {}
        }
    }

    fn block(&mut self, block: &Block) {
        for statement in &block.statements {
            self.statement(statement);
        }
    }

    fn statement(&mut self, statement: &Stmt) {
        match statement {
            Stmt::Let { slot, value } | Stmt::Assign { slot, value } => {
                self.ops.push(Op::Step(value.span));
                self.expr(value);
                self.ops.push(Op::Store(*slot));
            }
            Stmt::Return { value, span } => {
                self.ops.push(Op::Step(*span));
                match value {
                    Some(e) => self.expr(e),
                    None => {
                        let null = self.literal(Value::Null);
                        self.ops.push(Op::Literal(null));
                    }
                }
                self.ops.push(Op::Return);
            }
            Stmt::Expr(e) => {
                self.ops.push(Op::Step(e.span));
                self.expr(e);
                self.ops.push(Op::Pop);
            }
            Stmt::If { arms, otherwise } => {
                let mut ends = Vec::with_capacity(arms.len());
                for (condition, block) in arms {
                    self.ops.push(Op::Step(condition.span));
                    self.expr(condition);
                    let branch = self.jump_slot(Op::Branch { otherwise: 0, span: condition.span });
                    self.block(block);
                    ends.push(self.jump_slot(Op::Jump(0)));
                    self.land(branch);
                }
                if let Some(block) = otherwise {
                    self.block(block);
                }
                ends.into_iter().for_each(|end| self.land(end));
            }
            Stmt::For { slot, items, body, span } => {
                self.ops.push(Op::Step(*span));
                self.expr(items);
                self.ops.push(Op::ForEach { items: items.span, entries: false });
                let next = self.here();
                let exit = self.jump_slot(Op::Next { slot: *slot, exit: 0, span: *span });
                self.block(body);
                self.ops.push(Op::Jump(next));
                self.land(exit);
            }
            Stmt::ForEntries { key, value, items, body, span } => {
                self.ops.push(Op::Step(*span));
                self.expr(items);
                self.ops.push(Op::ForEach { items: items.span, entries: true });
                let next = self.here();
                let step = Op::NextEntry { key: *key, value: *value, exit: 0, span: *span };
                let exit = self.jump_slot(step);
                self.block(body);
                self.ops.push(Op::Jump(next));
                self.land(exit);
            }
        }
    }

    fn expr(&mut self, e: &Expr) {
        let span = e.span;
        self.ops.push(Op::Step(span));
        let op = match &e.kind {
            ExprKind::Literal(value) => Op::Literal(self.literal(value.clone())),
            ExprKind::Local(slot) => Op::Local(*slot, span),
            ExprKind::Constant(slot) => Op::Constant(*slot, span),
            ExprKind::List(items) => {
                items.iter().for_each(|item| self.expr(item));
                Op::List(items.len() as u32, span)
            }
            ExprKind::Map(entries) => {
                // The map's keys first, so that they stay together when a value is a
                // map of its own.
                let keys = self.keys.len() as u32;
                self.keys.extend(entries.iter().map(|e| (e.key.clone(), e.key_span)));
                entries.iter().for_each(|entry| self.expr(&entry.value));
                Op::Map { keys, count: entries.len() as u32, span }
            }
            ExprKind::Unary(op, operand) => {
                self.expr(operand);
                Op::Unary(*op, span)
            }
            ExprKind::Binary(op, a, b) => {
                self.expr(a);
                self.expr(b);
                Op::Binary(*op, span)
            }
            ExprKind::And(a, b) | ExprKind::Or(a, b) => return self.logical(e, a, b),
            ExprKind::Index(a, i) => {
                self.expr(a);
                self.expr(i);
                Op::Index(span)
            }
            ExprKind::Field(a, name) => {
                self.expr(a);
                self.names.push(name.clone());
                Op::Field(self.names.len() as u32 - 1, span)
            }
            ExprKind::Call(function, args) => {
                Op::Call { function: *function, args: self.arguments(args), span }
            }
            ExprKind::Native(native, args) => {
                Op::Native { native: *native, args: self.arguments(args), span }
            }
            ExprKind::Builtin(builtin, args) => {
                Op::Builtin { builtin: *builtin, args: self.arguments(args), span }
            }
            ExprKind::Interpolate(parts) => {
                // Each part is an expression with its own step, so `n` parts cost `n`
                // steps (JDD 0016, "Compilation and the IR").
                parts.iter().for_each(|part| self.expr(part));
                Op::Concat(parts.len() as u32, span)
            }
            ExprKind::Comprehension(c) => return self.comprehension(c, span),
        };
        self.ops.push(op);
    }

    /// `[for x in xs: body if filter]` as a loop that appends to a hidden local, which
    /// it leaves on the stack.
    fn comprehension(&mut self, c: &Comprehension, span: Span) {
        let empty = self.literal(Value::list(Vec::new()));
        self.ops.push(Op::Literal(empty));
        self.ops.push(Op::Store(c.list));
        self.expr(&c.items);
        self.ops.push(Op::ForEach { items: c.items.span, entries: c.key.is_some() });
        let next = self.here();
        let step = match c.key {
            Some(key) => Op::NextEntry { key, value: c.slot, exit: 0, span },
            None => Op::Next { slot: c.slot, exit: 0, span },
        };
        let exit = self.jump_slot(step);
        let skip = c.filter.as_ref().map(|filter| {
            self.expr(filter);
            self.jump_slot(Op::Branch { otherwise: 0, span: filter.span })
        });
        self.expr(&c.body);
        self.ops.push(Op::Append(c.list, span));
        if let Some(skip) = skip {
            self.land(skip);
        }
        self.ops.push(Op::Jump(next));
        self.land(exit);
        self.ops.push(Op::Local(c.list, span));
    }

    /// `a && b` or `a || b`: `b` runs only when `a` does not decide.
    fn logical(&mut self, e: &Expr, a: &Expr, b: &Expr) {
        self.expr(a);
        let decide = match e.kind {
            ExprKind::And(..) => Op::AndThen { end: 0, span: a.span },
            _ => Op::OrElse { end: 0, span: a.span },
        };
        let decided = self.jump_slot(decide);
        self.expr(b);
        self.ops.push(Op::Truth(b.span));
        self.land(decided);
    }

    /// Emits the source arguments, left to right, and returns their argument list.
    fn arguments(&mut self, args: &Args) -> u32 {
        args.exprs.iter().for_each(|e| self.expr(e));
        self.args.push(ArgList { given: args.exprs.len() as u32, slots: args.slots.clone() });
        self.args.len() as u32 - 1
    }
}
