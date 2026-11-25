//! The interpreter: one instance of a module, and the loop that runs its operations.
//!
//! ```text
//!  stack:  | args of f | locals of f | operands of f | args of g | locals of g | ...
//!            ^ base of f                               ^ base of g
//!  frames: the callers of the running function, each with the index to resume at
//! ```
//!
//! The parameters of a call are the top of the caller's operands and become the first
//! locals of the callee. A return moves the result to the callee's base. Nothing is
//! recursive in Rust: a call in the module pushes a frame, so the depth of the module's
//! calls is bounded by [`MAX_FRAMES`] and never by the thread's stack.
//!
//! Every access to the stack, the memory and the tables is checked and returns a
//! [`Trap`]. Validation makes most of these checks redundant. They stay, so that a fault
//! in the validator would be an error value and never a panic.

use std::sync::Arc;

use super::module::{MAX_PAGES, Module, PAGE};
use super::numeric;
use super::op::{Body, Op, Target};
use super::reader::LoadError;

/// The most frames of calls inside the module.
pub const MAX_FRAMES: usize = 256;
/// The most values on the stack of one instance.
pub const MAX_STACK: usize = 16_384;
/// Bytes of `memory.copy` and `memory.fill` that cost one unit of fuel.
const BYTES_PER_FUEL: u64 = 16;
/// Bytes of new memory that cost one unit of fuel.
const GROWN_BYTES_PER_FUEL: u64 = 64;

/// Why an invocation stopped without a result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trap {
    /// The fuel of the invocation is spent.
    Fuel,
    /// The module executed `unreachable`.
    Unreachable,
    /// A read or write outside the memory.
    MemoryBounds,
    /// An integer division by zero.
    DivideByZero,
    /// A signed division or a conversion whose result does not fit.
    IntegerOverflow,
    /// A conversion of a NaN to an integer.
    InvalidConversion,
    /// More than [`MAX_FRAMES`] nested calls.
    CallDepth,
    /// More than [`MAX_STACK`] values.
    StackLimit,
    /// A call through an empty or missing table entry.
    UndefinedElement,
    /// A call through the table to a function of another type.
    SignatureMismatch,
    /// More host calls than the invocation may make.
    HostCallLimit,
    /// The host refused a call.
    Host,
    /// A state that validation rules out. It is reported, never assumed.
    Internal,
}

/// What a module calls outside itself. `import` is the index of the imported function.
pub trait Host {
    /// Runs the host function `import` with `args` and the memory of the instance.
    /// Returns the bits of its result, which are ignored for a function without one.
    ///
    /// # Errors
    ///
    /// A [`Trap`] that ends the invocation.
    fn call(&mut self, import: u32, args: &[u64], memory: &mut [u8]) -> Result<u64, Trap>;
}

/// The budget of one invocation. Both counters are decremented as the invocation runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Units of fuel left. One operation costs one unit, bulk operations more.
    pub fuel: u64,
    /// Host calls left.
    pub host_calls: u32,
}

/// Where a function runs: its index, the operation to run next and its first local.
#[derive(Clone, Copy)]
struct Frame {
    func: u32,
    pc: usize,
    base: usize,
}

/// One instance of a module: its memory, its globals and its stack.
pub struct Instance {
    module: Arc<Module>,
    memory: Vec<u8>,
    globals: Vec<u64>,
    stack: Vec<u64>,
    frames: Vec<Frame>,
    max_pages: u32,
}

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instance")
            .field("pages", &(self.memory.len() / PAGE))
            .field("max_pages", &self.max_pages)
            .finish_non_exhaustive()
    }
}

impl Instance {
    /// Instantiates `module` with a memory of at most `max_pages` pages. The start
    /// function is not run here: the caller runs it under a budget.
    ///
    /// # Errors
    ///
    /// [`LoadError::Limit`] when the module starts with more pages than `max_pages`.
    pub fn new(module: Arc<Module>, max_pages: u32) -> Result<Instance, LoadError> {
        if module.initial_pages() > max_pages {
            return Err(LoadError::Limit("initial memory above memory_pages"));
        }
        let declared = module.memory.map_or(0, |memory| memory.max);
        let max_pages = max_pages.min(declared).min(MAX_PAGES);
        let mut instance = Instance {
            module,
            memory: Vec::new(),
            globals: Vec::new(),
            stack: Vec::new(),
            frames: Vec::new(),
            max_pages,
        };
        instance.reset();
        Ok(instance)
    }

    /// Returns the instance to its initial image: memory, data segments and globals.
    pub fn reset(&mut self) {
        self.memory.clear();
        self.memory.resize(self.module.initial_pages() as usize * PAGE, 0);
        for (offset, bytes) in &self.module.data {
            let start = *offset as usize;
            if let Some(target) = self.memory.get_mut(start..start + bytes.len()) {
                target.copy_from_slice(bytes);
            }
        }
        self.globals.clear();
        self.globals.extend(self.module.globals.iter().map(|global| global.init));
        self.stack.clear();
        self.frames.clear();
    }

    /// The module of the instance.
    pub fn module(&self) -> &Arc<Module> {
        &self.module
    }

    /// The memory of the instance.
    pub fn memory(&self) -> &[u8] {
        &self.memory
    }

    /// The memory of the instance, for the host to write an input.
    pub fn memory_mut(&mut self) -> &mut [u8] {
        &mut self.memory
    }

    /// The pages the memory holds now.
    pub fn pages(&self) -> u32 {
        (self.memory.len() / PAGE) as u32
    }

    /// Calls the function `func` with `args` and returns the bits of its result.
    ///
    /// # Errors
    ///
    /// The [`Trap`] that stopped the call. The instance may then hold a half-finished
    /// state; [`Instance::reset`] returns it to the initial image.
    pub fn call(
        &mut self,
        func: u32,
        args: &[u64],
        budget: &mut Budget,
        host: &mut dyn Host,
    ) -> Result<Option<u64>, Trap> {
        let module = Arc::clone(&self.module);
        let ty = module.func_type(func).ok_or(Trap::Internal)?;
        if ty.params.len() != args.len() {
            return Err(Trap::SignatureMismatch);
        }
        self.stack.clear();
        self.frames.clear();
        self.stack.extend_from_slice(args);
        let first = self.invoke(&module, func, None, budget, host)?;
        if let Some(frame) = first {
            self.run(&module, frame, budget, host)?;
        }
        Ok(if ty.result.is_some() { self.stack.last().copied() } else { None })
    }

    // ---- the stack ----

    fn push(&mut self, value: u64) -> Result<(), Trap> {
        if self.stack.len() >= MAX_STACK {
            return Err(Trap::StackLimit);
        }
        self.stack.push(value);
        Ok(())
    }

    fn pop(&mut self) -> Result<u64, Trap> {
        self.stack.pop().ok_or(Trap::Internal)
    }

    fn top(&mut self) -> Result<&mut u64, Trap> {
        self.stack.last_mut().ok_or(Trap::Internal)
    }

    /// Leaves the stack as a branch does: keeps the top value when `keep`, and removes
    /// `drop` values below it.
    fn unwind(&mut self, target: Target) -> Result<(), Trap> {
        let drop = target.drop as usize;
        if drop == 0 {
            return Ok(());
        }
        let kept = usize::from(target.keep);
        let height = self.stack.len().checked_sub(drop + kept).ok_or(Trap::Internal)?;
        if target.keep {
            let value = self.pop()?;
            self.stack.truncate(height);
            self.stack.push(value);
        } else {
            self.stack.truncate(height);
        }
        Ok(())
    }

    // ---- calls ----

    /// Begins a call of `func`, whose arguments are on the stack. A host function runs
    /// at once and `None` is returned. For a function of the module the caller's frame
    /// is saved and the frame of the callee is returned.
    fn invoke(
        &mut self,
        module: &Module,
        func: u32,
        caller: Option<Frame>,
        budget: &mut Budget,
        host: &mut dyn Host,
    ) -> Result<Option<Frame>, Trap> {
        let ty = module.func_type(func).ok_or(Trap::Internal)?;
        let base = self.stack.len().checked_sub(ty.params.len()).ok_or(Trap::Internal)?;
        let imported = module.imports.len();
        if (func as usize) < imported {
            budget.host_calls = budget.host_calls.checked_sub(1).ok_or(Trap::HostCallLimit)?;
            let args = self.stack.get(base..).ok_or(Trap::Internal)?;
            let result = host.call(func, args, &mut self.memory)?;
            self.stack.truncate(base);
            if ty.result.is_some() {
                self.push(result)?;
            }
            return Ok(None);
        }
        let body = module.code.get(func as usize - imported).ok_or(Trap::Internal)?;
        if self.frames.len() >= MAX_FRAMES {
            return Err(Trap::CallDepth);
        }
        let needed = self.stack.len() + body.locals.len() + body.max_height as usize;
        if needed > MAX_STACK {
            return Err(Trap::StackLimit);
        }
        self.stack.resize(self.stack.len() + body.locals.len(), 0);
        if let Some(caller) = caller {
            self.frames.push(caller);
        }
        Ok(Some(Frame { func, pc: 0, base }))
    }

    /// Ends the running function: moves its result to its base and returns the frame
    /// of its caller, or `None` when the outermost function returned.
    fn leave(&mut self, module: &Module, frame: Frame) -> Result<Option<Frame>, Trap> {
        let ty = module.func_type(frame.func).ok_or(Trap::Internal)?;
        if ty.result.is_some() {
            let value = self.pop()?;
            self.stack.truncate(frame.base);
            self.stack.push(value);
        } else {
            self.stack.truncate(frame.base);
        }
        Ok(self.frames.pop())
    }

    fn body(module: &Module, func: u32) -> Result<&Body, Trap> {
        module.code.get(func as usize - module.imports.len()).ok_or(Trap::Internal)
    }

    /// The function a `call_indirect` of type `ty` reaches through the table.
    fn indirect(&mut self, module: &Module, ty: u32) -> Result<u32, Trap> {
        let index = self.pop()? as u32 as usize;
        let func = module.table.get(index).copied().flatten().ok_or(Trap::UndefinedElement)?;
        let found = module.funcs.get(func as usize).ok_or(Trap::Internal)?;
        let same = module.canon.get(*found as usize) == module.canon.get(ty as usize);
        if same { Ok(func) } else { Err(Trap::SignatureMismatch) }
    }

    // ---- the loop ----

    fn run(
        &mut self,
        module: &Module,
        mut at: Frame,
        budget: &mut Budget,
        host: &mut dyn Host,
    ) -> Result<(), Trap> {
        let mut body = Self::body(module, at.func)?;
        loop {
            budget.fuel = budget.fuel.checked_sub(1).ok_or(Trap::Fuel)?;
            let op = *body.ops.get(at.pc).ok_or(Trap::Internal)?;
            at.pc += 1;
            match op {
                Op::Jump(pc) => at.pc = pc as usize,
                Op::JumpIfZero(pc) => {
                    if self.pop()? as u32 == 0 {
                        at.pc = pc as usize;
                    }
                }
                Op::Br(target) => {
                    self.unwind(target)?;
                    at.pc = target.pc as usize;
                }
                Op::BrIf(target) => {
                    if self.pop()? as u32 != 0 {
                        self.unwind(target)?;
                        at.pc = target.pc as usize;
                    }
                }
                Op::BrTable { first, last } => {
                    let index = (self.pop()? as u32).min(last);
                    let target = body.targets.get((first + index) as usize);
                    let target = *target.ok_or(Trap::Internal)?;
                    self.unwind(target)?;
                    at.pc = target.pc as usize;
                }
                Op::Return => match self.leave(module, at)? {
                    Some(caller) => {
                        at = caller;
                        body = Self::body(module, at.func)?;
                    }
                    None => return Ok(()),
                },
                Op::Call(func) => {
                    if let Some(callee) = self.invoke(module, func, Some(at), budget, host)? {
                        at = callee;
                        body = Self::body(module, at.func)?;
                    }
                }
                Op::CallIndirect(ty) => {
                    let func = self.indirect(module, ty)?;
                    if let Some(callee) = self.invoke(module, func, Some(at), budget, host)? {
                        at = callee;
                        body = Self::body(module, at.func)?;
                    }
                }
                other => self.simple(other, at.base, budget)?,
            }
        }
    }

    /// Runs an operation that neither branches nor calls.
    fn simple(&mut self, op: Op, base: usize, budget: &mut Budget) -> Result<(), Trap> {
        match op {
            Op::Unreachable => return Err(Trap::Unreachable),
            Op::Drop => {
                self.pop()?;
            }
            Op::Select => {
                let (condition, second) = (self.pop()?, self.pop()?);
                if condition as u32 == 0 {
                    *self.top()? = second;
                }
            }
            Op::LocalGet(index) => {
                let value = self.stack.get(base + index as usize).ok_or(Trap::Internal)?;
                self.push(*value)?;
            }
            Op::LocalSet(index) => {
                let value = self.pop()?;
                *self.stack.get_mut(base + index as usize).ok_or(Trap::Internal)? = value;
            }
            Op::LocalTee(index) => {
                let value = *self.top()?;
                *self.stack.get_mut(base + index as usize).ok_or(Trap::Internal)? = value;
            }
            Op::GlobalGet(index) => {
                let value = self.globals.get(index as usize).ok_or(Trap::Internal)?;
                self.push(*value)?;
            }
            Op::GlobalSet(index) => {
                let value = self.pop()?;
                *self.globals.get_mut(index as usize).ok_or(Trap::Internal)? = value;
            }
            Op::Const(bits) => self.push(bits)?,
            Op::Unary(opcode) => {
                let top = self.top()?;
                *top = numeric::unary(opcode, *top)?;
            }
            Op::Binary(opcode) => {
                let second = self.pop()?;
                let top = self.top()?;
                *top = numeric::binary(opcode, *top, second)?;
            }
            Op::Saturate(code) => {
                let top = self.top()?;
                *top = numeric::saturate(code, *top);
            }
            other => self.memory_op(other, budget)?,
        }
        Ok(())
    }

    // ---- memory ----

    /// The bytes of the memory from `address + offset`, `length` long.
    fn range(
        &self,
        address: u64,
        offset: u32,
        length: u64,
    ) -> Result<std::ops::Range<usize>, Trap> {
        let start = (address & 0xffff_ffff) + u64::from(offset);
        let end = start + length;
        if end > self.memory.len() as u64 {
            return Err(Trap::MemoryBounds);
        }
        Ok(start as usize..end as usize)
    }

    fn memory_op(&mut self, op: Op, budget: &mut Budget) -> Result<(), Trap> {
        match op {
            Op::Load { offset, bytes, signed, wide } => {
                let address = self.pop()?;
                let range = self.range(address, offset, u64::from(bytes))?;
                let mut raw = [0u8; 8];
                let source = self.memory.get(range).ok_or(Trap::MemoryBounds)?;
                raw.get_mut(..source.len()).ok_or(Trap::Internal)?.copy_from_slice(source);
                self.push(extend(u64::from_le_bytes(raw), bytes, signed, wide))
            }
            Op::Store { offset, bytes } => {
                let (value, address) = (self.pop()?, self.pop()?);
                let range = self.range(address, offset, u64::from(bytes))?;
                let raw = value.to_le_bytes();
                let source = raw.get(..usize::from(bytes)).ok_or(Trap::Internal)?;
                self.memory.get_mut(range).ok_or(Trap::MemoryBounds)?.copy_from_slice(source);
                Ok(())
            }
            Op::MemorySize => self.push(u64::from(self.pages())),
            Op::MemoryGrow => self.grow(budget),
            Op::MemoryCopy => {
                let (length, source, target) = (self.pop()?, self.pop()?, self.pop()?);
                let length = length & 0xffff_ffff;
                charge(budget, length / BYTES_PER_FUEL)?;
                let source = self.range(source, 0, length)?;
                let target = self.range(target, 0, length)?;
                self.memory.copy_within(source, target.start);
                Ok(())
            }
            Op::MemoryFill => {
                let (length, value, target) = (self.pop()?, self.pop()?, self.pop()?);
                let length = length & 0xffff_ffff;
                charge(budget, length / BYTES_PER_FUEL)?;
                let target = self.range(target, 0, length)?;
                self.memory.get_mut(target).ok_or(Trap::MemoryBounds)?.fill(value as u8);
                Ok(())
            }
            _ => Err(Trap::Internal),
        }
    }

    /// `memory.grow`: adds the popped number of pages and pushes the old size, or
    /// pushes -1 and adds nothing when the result would pass the page budget.
    fn grow(&mut self, budget: &mut Budget) -> Result<(), Trap> {
        let delta = self.pop()? & 0xffff_ffff;
        let old = u64::from(self.pages());
        if old + delta > u64::from(self.max_pages) {
            return self.push(0xffff_ffff);
        }
        let bytes = delta * PAGE as u64;
        charge(budget, bytes / GROWN_BYTES_PER_FUEL)?;
        self.memory.resize(self.memory.len() + bytes as usize, 0);
        self.push(old)
    }
}

/// Spends `cost` more units of fuel.
fn charge(budget: &mut Budget, cost: u64) -> Result<(), Trap> {
    budget.fuel = budget.fuel.checked_sub(cost).ok_or(Trap::Fuel)?;
    Ok(())
}

/// Extends the `bytes` low bytes of `raw` to the bits of an `i32` or, when `wide`, an
/// `i64`, with or without the sign.
fn extend(raw: u64, bytes: u8, signed: bool, wide: bool) -> u64 {
    if !signed || bytes == 8 {
        return raw;
    }
    let shift = 64 - 8 * u32::from(bytes);
    let extended = ((raw << shift) as i64 >> shift) as u64;
    if wide { extended } else { extended & 0xffff_ffff }
}
