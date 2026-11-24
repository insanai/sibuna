//! The evaluator (JDD 0004, "Bindings and evaluation"), as a machine over flat code
//! (JDD 0013, "The program and its evaluation").
//!
//! Evaluation is the big-step judgment `<e, Gamma, Sigma, beta> => (v, beta')`: a
//! lexical environment of local slots, the frozen store of constants, natives and the
//! invocation's builder, and the remaining budget. One step is charged per expression,
//! statement, function entry and loop iteration; a native adds its base and size cost.
//! Unselected branches and short-circuited operands are not evaluated or charged.
//! There is no clock, randomness, process, file or network transition in this module.
//!
//! The machine runs the code of [`crate::code`] with four stacks on the heap: values,
//! the locals of every active call, and the calls and loops in progress. Nothing
//! recurses, so the native stack a program needs does not grow with its calls or its
//! expressions; it charges what the recursive definition charges, in the same order.

use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;

use jlv_core::{Diagnostic, Limits, Problem, Span};

use crate::code::{Code, Op};
use crate::codes;
use crate::native::{Builder, Call, Context, Declaration, Native, NativeTable};
use crate::ops;
use crate::program::{ArgSlot, FunctionId, Program};
use crate::signature::Cost;
use crate::value::{List, Map, Value};

/// The result of one successful invocation.
#[derive(Debug)]
pub struct Outcome {
    /// The entry function's result.
    pub value: Value,
    /// The declarations the invocation's natives made, in order.
    pub declarations: Vec<Declaration>,
    /// The steps that remained, which are part of the result (JDD 0004).
    pub remaining: u64,
}

/// What a native costs, by native index; the compiler copies it from the signatures.
pub type Costs = Vec<Cost>;

/// One active call.
#[derive(Debug)]
struct Frame {
    function: FunctionId,
    /// Where the caller continues.
    return_to: u32,
    /// The first of the call's locals.
    locals: usize,
    /// The first of the call's loops.
    loops: usize,
}

/// One `for` in progress: its list and the index of its next item.
#[derive(Debug)]
struct Loop {
    items: Items,
}

/// What a loop runs over: a list's items, or a map's entries in key order. Both share the
/// value they iterate; a step visits one item, so the work of a loop that ends early, by
/// `return` or `break`, stays in proportion to the steps it is charged.
#[derive(Debug)]
enum Items {
    /// The list and the index of the next item.
    List { list: Arc<List>, next: usize },
    /// The map and the key of the entry visited last, if any.
    Entries { map: Arc<Map>, after: Option<Arc<str>> },
}

impl Items {
    /// The next item, or the next entry's key and value; `None` when none is left.
    fn advance(&mut self) -> Option<Vec<Value>> {
        match self {
            Items::List { list, next } => {
                let item = list.get(*next)?.clone();
                *next += 1;
                Some(vec![item])
            }
            Items::Entries { map, after } => {
                let (key, value) = match after.as_deref() {
                    None => map.iter().next()?,
                    Some(last) => map.range::<str, _>((Excluded(last), Unbounded)).next()?,
                };
                *after = Some(key.clone());
                Some(vec![Value::Text(key.clone()), value.clone()])
            }
        }
    }
}

/// One invocation in progress.
struct Machine<'p> {
    program: &'p Program,
    code: Code,
    natives: Vec<Arc<dyn Native>>,
    costs: &'p [Cost],
    constants: Vec<Option<Value>>,
    remaining: u64,
    limits: &'p Limits,
    active: Vec<bool>,
    builder: Builder,
    context: Context,
    initializing: bool,
    values: Vec<Value>,
    locals: Vec<Option<Value>>,
    frames: Vec<Frame>,
    loops: Vec<Loop>,
}

/// Runs `entry` with `args` under `limits` after initializing the module constants.
pub fn run(
    program: &Program,
    natives: &dyn NativeTable,
    costs: &[Cost],
    entry: FunctionId,
    args: Vec<Value>,
    context: Context,
    limits: &Limits,
) -> Result<Outcome, Diagnostic> {
    let linked = link(program, natives)?;
    let code = Code::compile(program);
    let mut machine = Machine {
        program,
        natives: linked,
        costs,
        constants: vec![None; program.constants.len()],
        remaining: limits.evaluation_steps,
        limits,
        active: vec![false; program.functions.len()],
        builder: Builder::new(limits.resources),
        context,
        initializing: true,
        values: Vec::new(),
        // The initializers run without a frame, in slots of their own.
        locals: vec![None; program.constants.iter().map(|c| c.locals as usize).max().unwrap_or(0)],
        frames: Vec::new(),
        loops: Vec::new(),
        code,
    };
    machine.execute(machine.code.init)?;
    machine.initializing = false;
    let span = program.functions.get(entry.0 as usize).map(|f| f.span).unwrap_or_default();
    let exit = machine.code.exit;
    let pc = machine.call(entry, args, span, exit)?;
    let value = machine.execute(pc)?;
    Ok(Outcome {
        value,
        declarations: machine.builder.into_declarations(),
        remaining: machine.remaining,
    })
}

/// Resolves every native the program names, or reports the first missing one.
fn link(program: &Program, table: &dyn NativeTable) -> Result<Vec<Arc<dyn Native>>, Diagnostic> {
    program
        .natives
        .iter()
        .map(|name| {
            table.native(name).ok_or_else(|| {
                Diagnostic::unplaced(codes::problem(
                    codes::OPERATIONAL_FAILURE,
                    &format!("The native `{name}` is not linked into this evaluator."),
                    "Prepare with the registry and natives of the same locked library closure.",
                ))
            })
        })
        .collect()
}

impl Machine<'_> {
    fn charge(&mut self, steps: u64, span: Span) -> Result<(), Diagnostic> {
        if self.remaining < steps {
            self.remaining = 0;
            let problem = codes::problem(
                codes::BUDGET_EXHAUSTED,
                &format!(
                    "Evaluation used its whole budget of {} steps.",
                    self.limits.evaluation_steps
                ),
                "Reduce the work the program does, or raise `[limits] evaluation_steps` \
                 (up to 10,000,000).",
            );
            return Err(Diagnostic::at(problem, span));
        }
        self.remaining -= steps;
        Ok(())
    }

    fn pop(&mut self) -> Value {
        // The code pushes every operand an instruction pops; compile guarantees it.
        let Some(value) = self.values.pop() else { unreachable!("an operand is on the stack") };
        value
    }

    /// Pops `count` values, in the order they were pushed.
    fn pop_many(&mut self, count: u32) -> Vec<Value> {
        self.values.split_off(self.values.len() - count as usize)
    }

    /// Enters function `id` with `args`, as the recursive evaluator's `invoke` did, and
    /// returns where its code starts; the caller continues at `return_to`.
    fn call(
        &mut self,
        id: FunctionId,
        args: Vec<Value>,
        span: Span,
        return_to: u32,
    ) -> Result<u32, Diagnostic> {
        let program = self.program;
        let function = &program.functions[id.0 as usize];
        self.charge(1, span)?;
        if self.active[id.0 as usize] {
            let message = format!("`{}` calls itself while it is still active.", function.name);
            let hint = "Rewrite the computation with a bounded `for` loop over a finite list.";
            return Err(Diagnostic::at(
                codes::problem(codes::RECURSIVE_CALL, &message, hint),
                span,
            ));
        }
        if self.frames.len() >= self.limits.call_depth {
            let message = format!("Calls nest deeper than {} functions.", self.limits.call_depth);
            let hint = "Flatten the call chain.";
            return Err(Diagnostic::at(
                codes::problem(codes::BUDGET_EXHAUSTED, &message, hint),
                span,
            ));
        }
        let base = self.locals.len();
        self.locals.resize(base + function.locals as usize, None);
        for (slot, value) in args.into_iter().enumerate() {
            self.locals[base + slot] = Some(value);
        }
        self.active[id.0 as usize] = true;
        let frame = Frame { function: id, return_to, locals: base, loops: self.loops.len() };
        self.frames.push(frame);
        Ok(self.code.entries[id.0 as usize])
    }

    /// Ends the innermost call with `value` on the stack and returns where its caller
    /// continues.
    fn finish(&mut self, value: Value) -> u32 {
        self.values.push(value);
        let Some(frame) = self.frames.pop() else { return self.code.exit };
        self.active[frame.function.0 as usize] = false;
        self.locals.truncate(frame.locals);
        self.loops.truncate(frame.loops);
        frame.return_to
    }

    /// Runs from `pc` until a `Halt`: the end of the constants' initialization, or the
    /// return of the entry call, whose value it returns.
    fn execute(&mut self, mut pc: u32) -> Result<Value, Diagnostic> {
        loop {
            let op = self.code.ops[pc as usize].clone();
            pc += 1;
            match op {
                Op::Return => {
                    let value = self.pop();
                    pc = self.finish(value);
                }
                Op::Halt => return Ok(self.values.pop().unwrap_or(Value::Null)),
                Op::Call { function, args, span } => {
                    let values = self.arrange(args).into_iter().map(|v| v.unwrap_or(Value::Null));
                    pc = self.call(function, values.collect(), span, pc)?;
                }
                op => {
                    if let Some(to) = self.step(op)? {
                        pc = to;
                    }
                }
            }
        }
    }

    /// Runs one instruction other than a call or a return; `Some` is a jump.
    fn step(&mut self, op: Op) -> Result<Option<u32>, Diagnostic> {
        match op {
            Op::Step(span) => self.charge(1, span)?,
            Op::Literal(at) => self.values.push(self.code.literals[at as usize].clone()),
            Op::Local(slot, span) => {
                let base = self.frames.last().map_or(0, |f| f.locals);
                let value = read(&self.locals[base..], slot, span)?;
                self.values.push(value);
            }
            Op::Constant(slot, span) => {
                let value = self.constant(slot, span)?;
                self.values.push(value);
            }
            Op::Store(slot) => {
                let base = self.frames.last().map_or(0, |f| f.locals);
                let value = self.pop();
                self.locals[base + slot as usize] = Some(value);
            }
            Op::StoreConstant(slot) => {
                let value = self.pop();
                self.constants[slot as usize] = Some(value);
            }
            Op::Pop => {
                self.pop();
            }
            Op::Jump(to) => return Ok(Some(to)),
            Op::Branch { otherwise, span } => {
                if !self.condition(span)? {
                    return Ok(Some(otherwise));
                }
            }
            Op::AndThen { end, span } | Op::OrElse { end, span } => {
                let and = matches!(op, Op::AndThen { .. });
                let value = self.condition(span)?;
                if value != and {
                    self.values.push(Value::Bool(value));
                    return Ok(Some(end));
                }
            }
            Op::Truth(span) => {
                let value = self.condition(span)?;
                self.values.push(Value::Bool(value));
            }
            Op::ForEach { items, entries } => match (self.pop(), entries) {
                (Value::List(list), false) => {
                    self.loops.push(Loop { items: Items::List { list, next: 0 } });
                }
                (Value::Map(map), true) => {
                    self.loops.push(Loop { items: Items::Entries { map, after: None } });
                }
                (other, false) => return Err(mismatch("a list", &other, items)),
                (other, true) => return Err(mismatch("a map", &other, items)),
            },
            Op::Next { slot, exit, span } => return self.next(&[slot], exit, span),
            Op::NextEntry { key, value, exit, span } => {
                return self.next(&[key, value], exit, span);
            }
            Op::Append(slot, span) => self.append(slot, span)?,
            op => self.operate(op)?,
        }
        Ok(None)
    }

    /// Gives the innermost loop's next item to the one slot of `slots`, or its next
    /// entry's key and value to the two, or ends the loop.
    fn next(&mut self, slots: &[u32], exit: u32, span: Span) -> Result<Option<u32>, Diagnostic> {
        let Some(running) = self.loops.last_mut() else { return Ok(Some(exit)) };
        let Some(values) = running.items.advance() else {
            self.loops.pop();
            return Ok(Some(exit));
        };
        self.charge(1, span)?;
        let base = self.frames.last().map_or(0, |f| f.locals);
        for (slot, value) in slots.iter().zip(values) {
            self.locals[base + *slot as usize] = Some(value);
        }
        Ok(None)
    }

    /// Appends the value on top to the list in local `slot`, within the container bound
    /// and the value depth.
    fn append(&mut self, slot: u32, span: Span) -> Result<(), Diagnostic> {
        let value = self.pop();
        let base = self.frames.last().map_or(0, |f| f.locals);
        let at = base + slot as usize;
        let mut list = match self.locals[at].take() {
            Some(Value::List(list)) => Arc::unwrap_or_clone(list),
            _ => List::default(),
        };
        list.push(value);
        let built = ops::bounded_len(Value::List(Arc::new(list)), self.limits, span)?;
        self.locals[at] = Some(built);
        Ok(())
    }

    /// Runs an instruction that computes a value from the values on the stack.
    fn operate(&mut self, op: Op) -> Result<(), Diagnostic> {
        let value = match op {
            Op::Concat(count, span) => {
                let parts = self.pop_many(count);
                let value = ops::concat(parts, self.limits, span)?;
                self.charge(value.size_units().saturating_sub(1), span)?;
                value
            }
            Op::List(count, span) => {
                let items = self.pop_many(count);
                ops::bounded_list(items, self.limits, span)?
            }
            Op::Map { keys, count, span } => {
                let values = self.pop_many(count);
                let keys = &self.code.keys[keys as usize..(keys + count) as usize];
                let pairs = keys.iter().zip(values).map(|((k, s), v)| (k.clone(), *s, v));
                ops::map_literal(pairs.collect(), self.limits, span)?
            }
            Op::Unary(op, span) => {
                let value = self.pop();
                ops::unary(op, value, span)?
            }
            Op::Binary(op, span) => {
                let b = self.pop();
                let a = self.pop();
                if matches!(op, crate::program::BinaryOp::Eq | crate::program::BinaryOp::Ne) {
                    self.charge(a.size_units().min(b.size_units()).saturating_sub(1), span)?;
                }
                let value = ops::binary(op, a, b, self.limits, span)?;
                // `+` on texts, byte strings and lists copies both operands, so it costs
                // the size of what it builds (JDD 0004, "Limits and diagnostics").
                if op == crate::program::BinaryOp::Add && !matches!(value, Value::Int(_)) {
                    self.charge(value.size_units().saturating_sub(1), span)?;
                }
                value
            }
            Op::Index(span) => {
                let i = self.pop();
                let a = self.pop();
                ops::index(a, i, span)?
            }
            Op::Field(name, span) => {
                let a = self.pop();
                ops::field(a, &self.code.names[name as usize], span)?
            }
            Op::Native { native, args, span } => {
                let values = self.arrange(args);
                self.native(native.0 as usize, &values, span)?
            }
            Op::Builtin { builtin, args, span } => {
                let values = self.arrange(args).into_iter().map(|v| v.unwrap_or(Value::Null));
                let (value, cost) = ops::builtin(builtin, values.collect(), self.limits, span)?;
                self.charge(cost, span)?;
                ops::nested(value, self.limits, span)?
            }
            _ => unreachable!("every other instruction is handled by `step` or `execute`"),
        };
        self.values.push(value);
        Ok(())
    }

    /// Pops a condition and checks that it is a boolean.
    fn condition(&mut self, span: Span) -> Result<bool, Diagnostic> {
        match self.pop() {
            Value::Bool(b) => Ok(b),
            other => Err(mismatch("a boolean condition", &other, span)),
        }
    }

    fn constant(&self, slot: u32, span: Span) -> Result<Value, Diagnostic> {
        match self.constants.get(slot as usize) {
            Some(Some(v)) => Ok(v.clone()),
            _ => {
                let name =
                    self.program.constants.get(slot as usize).map(|c| &*c.name).unwrap_or("?");
                let message = format!("The constant `{name}` is read before it is initialized.");
                let hint = "Define constants before the constants that use them.";
                Err(Diagnostic::at(
                    codes::problem(codes::UNINITIALIZED_BINDING, &message, hint),
                    span,
                ))
            }
        }
    }

    /// Pops a call's source arguments, evaluated left to right, and arranges them by
    /// parameter.
    fn arrange(&mut self, args: u32) -> Vec<Option<Value>> {
        let list = &self.code.args[args as usize];
        let from = self.values.len() - list.given as usize;
        let mut evaluated: Vec<Option<Value>> =
            self.values.split_off(from).into_iter().map(Some).collect();
        list.slots
            .iter()
            .map(|slot| match slot {
                ArgSlot::Source(i) => evaluated[*i as usize].take(),
                ArgSlot::Default(v) => Some(v.clone()),
                ArgSlot::Absent => None,
            })
            .collect()
    }

    fn native(
        &mut self,
        index: usize,
        args: &[Option<Value>],
        span: Span,
    ) -> Result<Value, Diagnostic> {
        let cost = self.costs.get(index).copied().unwrap_or_default();
        let size = args.iter().flatten().fold(0u64, |acc, v| acc.saturating_add(v.size_units()));
        self.charge(cost.base.saturating_add(cost.per_unit.saturating_mul(size)), span)?;
        let native = self.natives[index].clone();
        let initializing = self.initializing;
        let mut call = Call {
            builder: if initializing { None } else { Some(&mut self.builder) },
            context: if initializing { None } else { Some(&self.context) },
            limits: self.limits,
            span,
        };
        let value = native.call(&mut call, args).map_err(|p| Diagnostic::at(p, span))?;
        self.charge(cost.per_unit.saturating_mul(value.size_units()), span)?;
        ops::nested(value, self.limits, span)
    }
}

fn read(frame: &[Option<Value>], slot: u32, span: Span) -> Result<Value, Diagnostic> {
    match frame.get(slot as usize) {
        Some(Some(v)) => Ok(v.clone()),
        _ => {
            let problem = codes::problem(
                codes::UNINITIALIZED_BINDING,
                "This local is read before it has a value.",
                "Give the binding a value on every path before reading it.",
            );
            Err(Diagnostic::at(problem, span))
        }
    }
}

/// A type mismatch found at run time, which the compiler should have rejected.
pub(crate) fn mismatch(expected: &str, found: &Value, span: Span) -> Diagnostic {
    let message = format!("Expected {expected}, but found {}.", found.kind_name());
    let problem: Problem =
        codes::problem(codes::TYPE_MISMATCH, &message, "Use a value of the expected type.");
    Diagnostic::at(problem, span)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A loop over a map shares it and visits its entries in key order, one per step, so
    /// a loop that ends after its first entry did no work for the rest.
    #[test]
    fn a_map_loop_shares_the_map_and_visits_one_entry_per_step() {
        let Value::Map(map) = Value::map([("b", Value::Int(2)), ("a", Value::Int(1))]) else {
            unreachable!("a map literal is a map")
        };
        let mut items = Items::Entries { map: map.clone(), after: None };
        assert_eq!(Arc::strong_count(&map), 2, "the loop holds the map, not a copy");
        let first = items.advance();
        assert_eq!(first, Some(vec![Value::text("a"), Value::Int(1)]));
        let second = items.advance();
        assert_eq!(second, Some(vec![Value::text("b"), Value::Int(2)]));
        assert_eq!(items.advance(), None);
    }
}
