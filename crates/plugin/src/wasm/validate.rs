//! Validation of function bodies, and their translation to [`Op`]s in the same pass.
//!
//! This is the algorithm of the appendix of the WebAssembly specification: a stack of
//! operand types and a stack of control frames. A type that follows an unconditional
//! branch is unknown and matches anything. While we check an instruction we also emit
//! its operation, and at the `end` of a block we patch the branches that left it.
//!
//! ```text
//!   block .. br 0 .. end          Br{pc: ?}  ..   <- patched to the index after `end`
//!   loop  .. br 0 .. end          Br{pc: index of the loop start}
//!   if .. else .. end             JumpIfZero{else} .. Jump{end} .. (else) .. (end)
//! ```
//!
//! Because only code that passes here runs, the interpreter never meets an operand of
//! the wrong type, a branch to nowhere or an index out of range.

use super::module::{MAX_LOCALS, Module, ValType, eight, four};
use super::numeric;
use super::op::{Body, Op, Target};
use super::reader::{Load, LoadError, Reader};

const MISMATCH: LoadError = LoadError::Malformed("type mismatch");

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Func,
    Block,
    Loop,
    If,
    Else,
}

/// A branch whose target index is known only at the `end` of its block.
enum Fixup {
    Op(usize),
    Table(usize),
}

struct Frame {
    kind: Kind,
    result: Option<ValType>,
    /// The height of the operand stack when the block began.
    height: usize,
    /// The rest of the block cannot be reached, so its operands have any type.
    unreachable: bool,
    /// The first operation of a loop.
    start: u32,
    fixups: Vec<Fixup>,
    /// The `JumpIfZero` of an `if`, until its `else` or `end`.
    else_fixup: Option<usize>,
}

struct Validator<'m> {
    module: &'m Module,
    /// The parameters and then the locals.
    locals: Vec<ValType>,
    result: Option<ValType>,
    /// The operand types; `None` is the unknown type.
    stack: Vec<Option<ValType>>,
    frames: Vec<Frame>,
    ops: Vec<Op>,
    targets: Vec<Target>,
    max_height: usize,
}

/// Validates and translates every function body in `code` into `module.code`.
pub(crate) fn bodies(module: &mut Module, code: Option<Reader<'_>>) -> Load<()> {
    let imported = module.imports.len();
    let defined = module.funcs.len() - imported;
    let Some(mut reader) = code else {
        return if defined == 0 { Ok(()) } else { Err(LoadError::Malformed("no code section")) };
    };
    if reader.u32()? as usize != defined {
        return Err(LoadError::Malformed("function and code counts differ"));
    }
    let mut translated = Vec::with_capacity(defined);
    for index in 0..defined {
        let size = reader.u32()? as usize;
        let mut body = reader.sub(size)?;
        let ty = *module.funcs.get(imported + index).ok_or(MISMATCH)?;
        translated.push(Validator::new(module, ty)?.function(&mut body)?);
    }
    if !reader.is_empty() {
        return Err(LoadError::Malformed("code section has trailing bytes"));
    }
    module.code = translated;
    Ok(())
}

impl<'m> Validator<'m> {
    fn new(module: &'m Module, ty: u32) -> Load<Self> {
        let ty = module.type_of(ty)?;
        Ok(Validator {
            module,
            locals: ty.params.to_vec(),
            result: ty.result,
            stack: Vec::new(),
            frames: Vec::new(),
            ops: Vec::new(),
            targets: Vec::new(),
            max_height: 0,
        })
    }

    fn function(mut self, r: &mut Reader<'_>) -> Load<Body> {
        let params = self.locals.len();
        for _ in 0..r.u32()? {
            let count = r.u32()? as usize;
            let ty = ValType::from_byte(r.byte()?)?;
            if count > MAX_LOCALS || self.locals.len() - params + count > MAX_LOCALS {
                return Err(LoadError::Limit("locals of a function"));
            }
            self.locals.extend(std::iter::repeat_n(ty, count));
        }
        self.enter(Kind::Func, self.result);
        while !self.frames.is_empty() {
            let opcode = r.byte()?;
            self.step(opcode, r)?;
        }
        if !r.is_empty() {
            return Err(LoadError::Malformed("code after the end of a function"));
        }
        Ok(Body {
            locals: self.locals.get(params..).unwrap_or_default().into(),
            ops: self.ops.into(),
            targets: self.targets.into(),
            max_height: u32::try_from(self.max_height).map_err(|_| MISMATCH)?,
        })
    }

    fn step(&mut self, opcode: u8, r: &mut Reader<'_>) -> Load<()> {
        match opcode {
            0x00..=0x11 => self.control(opcode, r),
            0x1a | 0x1b => self.parametric(opcode),
            0x20..=0x24 => self.variable(opcode, r),
            0x28..=0x40 => self.memory(opcode, r),
            0x41..=0x44 => self.constant(opcode, r),
            0x45..=0xc4 => self.numeric(opcode),
            0xfc => self.prefixed(r),
            0xfd | 0xfe | 0xd0..=0xd2 | 0x12..=0x14 | 0x25 | 0x26 | 0x1c => {
                Err(LoadError::Unsupported("an instruction beyond the supported set"))
            }
            _ => Err(LoadError::Malformed("unknown instruction")),
        }
    }

    // ---- the operand stack ----

    fn push(&mut self, ty: ValType) {
        self.stack.push(Some(ty));
        self.max_height = self.max_height.max(self.stack.len());
    }

    fn pop(&mut self) -> Load<Option<ValType>> {
        let frame = self.frames.last().ok_or(MISMATCH)?;
        if self.stack.len() == frame.height {
            return if frame.unreachable { Ok(None) } else { Err(MISMATCH) };
        }
        Ok(self.stack.pop().flatten())
    }

    fn expect(&mut self, ty: ValType) -> Load<()> {
        match self.pop()? {
            Some(found) if found != ty => Err(MISMATCH),
            _ => Ok(()),
        }
    }

    fn expect_result(&mut self, result: Option<ValType>) -> Load<()> {
        result.map_or(Ok(()), |ty| self.expect(ty))
    }

    /// Marks the rest of the current block unreachable.
    fn unreachable(&mut self) -> Load<()> {
        let frame = self.frames.last_mut().ok_or(MISMATCH)?;
        self.stack.truncate(frame.height);
        frame.unreachable = true;
        Ok(())
    }

    // ---- control ----

    fn enter(&mut self, kind: Kind, result: Option<ValType>) {
        self.frames.push(Frame {
            kind,
            result,
            height: self.stack.len(),
            unreachable: false,
            start: self.ops.len() as u32,
            fixups: Vec::new(),
            else_fixup: None,
        });
    }

    fn block_type(r: &mut Reader<'_>) -> Load<Option<ValType>> {
        match r.byte()? {
            0x40 => Ok(None),
            byte @ 0x7c..=0x7f => ValType::from_byte(byte).map(Some),
            _ => Err(LoadError::Unsupported("a block with parameters or several results")),
        }
    }

    fn control(&mut self, opcode: u8, r: &mut Reader<'_>) -> Load<()> {
        match opcode {
            0x00 => {
                self.ops.push(Op::Unreachable);
                self.unreachable()
            }
            0x01 => Ok(()),
            0x02 => Self::block_type(r).map(|result| self.enter(Kind::Block, result)),
            0x03 => Self::block_type(r).map(|result| self.enter(Kind::Loop, result)),
            0x04 => self.begin_if(r),
            0x05 => self.begin_else(),
            0x0b => self.end(),
            0x0c => {
                let depth = r.u32()?;
                let (target, frame) = self.target(depth)?;
                self.expect_result(self.label_type(frame))?;
                self.emit_branch(Op::Br(target), frame);
                self.unreachable()
            }
            0x0d => {
                let depth = r.u32()?;
                self.expect(ValType::I32)?;
                let (target, frame) = self.target(depth)?;
                let ty = self.label_type(frame);
                self.expect_result(ty)?;
                if let Some(ty) = ty {
                    self.push(ty);
                }
                self.emit_branch(Op::BrIf(target), frame);
                Ok(())
            }
            0x0e => self.br_table(r),
            0x0f => {
                self.expect_result(self.result)?;
                self.ops.push(Op::Return);
                self.unreachable()
            }
            0x10 => self.call(r),
            0x11 => self.call_indirect(r),
            _ => Err(LoadError::Malformed("unknown instruction")),
        }
    }

    fn begin_if(&mut self, r: &mut Reader<'_>) -> Load<()> {
        let result = Self::block_type(r)?;
        self.expect(ValType::I32)?;
        let at = self.ops.len();
        self.ops.push(Op::JumpIfZero(0));
        self.enter(Kind::If, result);
        if let Some(frame) = self.frames.last_mut() {
            frame.else_fixup = Some(at);
        }
        Ok(())
    }

    /// Checks that the arm of a block that ends here left exactly its result.
    fn finish_arm(&mut self) -> Load<()> {
        let frame = self.frames.last().ok_or(MISMATCH)?;
        let (result, height) = (frame.result, frame.height);
        self.expect_result(result)?;
        if self.stack.len() == height { Ok(()) } else { Err(MISMATCH) }
    }

    fn begin_else(&mut self) -> Load<()> {
        self.finish_arm()?;
        let at = self.ops.len();
        self.ops.push(Op::Jump(0));
        let here = self.ops.len() as u32;
        let frame = self.frames.last_mut().ok_or(MISMATCH)?;
        if frame.kind != Kind::If {
            return Err(LoadError::Malformed("else without if"));
        }
        frame.kind = Kind::Else;
        frame.unreachable = false;
        frame.fixups.push(Fixup::Op(at));
        let test = frame.else_fixup.take();
        self.patch(test.map(Fixup::Op), here);
        Ok(())
    }

    fn end(&mut self) -> Load<()> {
        self.finish_arm()?;
        let frame = self.frames.pop().ok_or(MISMATCH)?;
        if frame.kind == Kind::If && frame.result.is_some() {
            // Without an else the false side would leave no result.
            return Err(MISMATCH);
        }
        let here = self.ops.len() as u32;
        for fixup in frame.fixups {
            self.patch(Some(fixup), here);
        }
        self.patch(frame.else_fixup.map(Fixup::Op), here);
        if frame.kind == Kind::Func {
            self.ops.push(Op::Return);
        } else if let Some(ty) = frame.result {
            self.push(ty);
        }
        Ok(())
    }

    fn patch(&mut self, fixup: Option<Fixup>, here: u32) {
        match fixup {
            Some(Fixup::Op(at)) => match self.ops.get_mut(at) {
                Some(Op::Br(target) | Op::BrIf(target)) => target.pc = here,
                Some(Op::Jump(pc) | Op::JumpIfZero(pc)) => *pc = here,
                _ => {}
            },
            Some(Fixup::Table(at)) => {
                if let Some(target) = self.targets.get_mut(at) {
                    target.pc = here;
                }
            }
            None => {}
        }
    }

    /// The branch target of the label `depth` from the current stack, and the index of
    /// its frame.
    fn target(&self, depth: u32) -> Load<(Target, usize)> {
        let index = self.frames.len().checked_sub(1 + depth as usize);
        let index = index.ok_or(LoadError::Malformed("branch to an unknown label"))?;
        let frame = self.frames.get(index).ok_or(MISMATCH)?;
        let keep = self.label_type(index).is_some();
        // In unreachable code the stack may be lower than a real one. Such a branch
        // never runs, so any count will do.
        let drop = self.stack.len().saturating_sub(frame.height + usize::from(keep));
        let pc = if frame.kind == Kind::Loop { frame.start } else { 0 };
        Ok((Target { pc, drop: drop as u32, keep }, index))
    }

    /// What a branch to the frame `index` carries: a loop takes nothing, a block its
    /// result.
    fn label_type(&self, index: usize) -> Option<ValType> {
        let frame = self.frames.get(index)?;
        if frame.kind == Kind::Loop { None } else { frame.result }
    }

    fn emit_branch(&mut self, op: Op, frame: usize) {
        let at = self.ops.len();
        self.ops.push(op);
        if let Some(frame) = self.frames.get_mut(frame)
            && frame.kind != Kind::Loop
        {
            frame.fixups.push(Fixup::Op(at));
        }
    }

    fn br_table(&mut self, r: &mut Reader<'_>) -> Load<()> {
        // Each label takes at least one byte, so the input bounds the count.
        let count = r.count(r.rest(), "branch table")?;
        self.expect(ValType::I32)?;
        let first = self.targets.len();
        let mut carried = None;
        for position in 0..=count {
            let (target, frame) = self.target(r.u32()?)?;
            let ty = self.label_type(frame);
            if position > 0 && ty != carried {
                return Err(MISMATCH);
            }
            carried = ty;
            let at = self.targets.len();
            self.targets.push(target);
            if let Some(frame) = self.frames.get_mut(frame)
                && frame.kind != Kind::Loop
            {
                frame.fixups.push(Fixup::Table(at));
            }
        }
        self.expect_result(carried)?;
        self.ops.push(Op::BrTable { first: first as u32, last: count as u32 });
        self.unreachable()
    }

    fn call(&mut self, r: &mut Reader<'_>) -> Load<()> {
        let index = r.u32()?;
        let ty = self.module.func_type(index);
        let ty = ty.ok_or(LoadError::Malformed("call of an unknown function"))?;
        self.apply(&ty.params, ty.result)?;
        self.ops.push(Op::Call(index));
        Ok(())
    }

    fn call_indirect(&mut self, r: &mut Reader<'_>) -> Load<()> {
        let index = r.u32()?;
        if r.u32()? != 0 || !self.module.has_table {
            return Err(LoadError::Malformed("call through an unknown table"));
        }
        let ty = self.module.type_of(index)?;
        self.expect(ValType::I32)?;
        self.apply(&ty.params, ty.result)?;
        self.ops.push(Op::CallIndirect(index));
        Ok(())
    }

    /// Pops `params` in reverse and pushes `result`.
    fn apply(&mut self, params: &[ValType], result: Option<ValType>) -> Load<()> {
        for &param in params.iter().rev() {
            self.expect(param)?;
        }
        if let Some(ty) = result {
            self.push(ty);
        }
        Ok(())
    }

    // ---- the other instructions ----

    fn parametric(&mut self, opcode: u8) -> Load<()> {
        if opcode == 0x1a {
            self.pop()?;
            self.ops.push(Op::Drop);
            return Ok(());
        }
        self.expect(ValType::I32)?;
        let (second, first) = (self.pop()?, self.pop()?);
        if let (Some(a), Some(b)) = (first, second)
            && a != b
        {
            return Err(MISMATCH);
        }
        self.stack.push(first.or(second));
        self.max_height = self.max_height.max(self.stack.len());
        self.ops.push(Op::Select);
        Ok(())
    }

    fn variable(&mut self, opcode: u8, r: &mut Reader<'_>) -> Load<()> {
        let index = r.u32()?;
        if opcode >= 0x23 {
            let global = self.module.globals.get(index as usize);
            let global = global.ok_or(LoadError::Malformed("unknown global"))?;
            if opcode == 0x23 {
                self.push(global.ty);
                self.ops.push(Op::GlobalGet(index));
                return Ok(());
            }
            if !global.mutable {
                return Err(LoadError::Malformed("write to an immutable global"));
            }
            self.expect(global.ty)?;
            self.ops.push(Op::GlobalSet(index));
            return Ok(());
        }
        let ty = *self.locals.get(index as usize).ok_or(LoadError::Malformed("unknown local"))?;
        match opcode {
            0x20 => {
                self.push(ty);
                self.ops.push(Op::LocalGet(index));
            }
            0x21 => {
                self.expect(ty)?;
                self.ops.push(Op::LocalSet(index));
            }
            _ => {
                self.expect(ty)?;
                self.push(ty);
                self.ops.push(Op::LocalTee(index));
            }
        }
        Ok(())
    }

    fn memory(&mut self, opcode: u8, r: &mut Reader<'_>) -> Load<()> {
        if self.module.memory.is_none() {
            return Err(LoadError::Malformed("memory instruction without a memory"));
        }
        if opcode >= 0x3f {
            if r.byte()? != 0 {
                return Err(LoadError::Malformed("unknown memory"));
            }
            if opcode == 0x40 {
                self.expect(ValType::I32)?;
            }
            self.push(ValType::I32);
            self.ops.push(if opcode == 0x3f { Op::MemorySize } else { Op::MemoryGrow });
            return Ok(());
        }
        let (align, offset) = (r.u32()?, r.u32()?);
        let (ty, bytes, signed) = access(opcode);
        if align >= 32 || (1u64 << align) > u64::from(bytes) {
            return Err(LoadError::Malformed("alignment larger than natural"));
        }
        if opcode <= 0x35 {
            self.expect(ValType::I32)?;
            self.push(ty);
            let wide = ty == ValType::I64;
            self.ops.push(Op::Load { offset, bytes, signed, wide });
        } else {
            self.expect(ty)?;
            self.expect(ValType::I32)?;
            self.ops.push(Op::Store { offset, bytes });
        }
        Ok(())
    }

    fn constant(&mut self, opcode: u8, r: &mut Reader<'_>) -> Load<()> {
        let (ty, bits) = match opcode {
            0x41 => (ValType::I32, u64::from(r.i32()? as u32)),
            0x42 => (ValType::I64, r.i64()? as u64),
            0x43 => (ValType::F32, u64::from(u32::from_le_bytes(four(r)?))),
            _ => (ValType::F64, u64::from_le_bytes(eight(r)?)),
        };
        self.push(ty);
        self.ops.push(Op::Const(bits));
        Ok(())
    }

    fn numeric(&mut self, opcode: u8) -> Load<()> {
        let (operand, count, result) = numeric::signature(opcode);
        for _ in 0..count {
            self.expect(operand)?;
        }
        self.push(result);
        self.ops.push(if count == 1 { Op::Unary(opcode) } else { Op::Binary(opcode) });
        Ok(())
    }

    fn prefixed(&mut self, r: &mut Reader<'_>) -> Load<()> {
        let code = r.u32()?;
        match code {
            0..=7 => {
                let (operand, result) = numeric::saturate_signature(code as u8);
                self.expect(operand)?;
                self.push(result);
                self.ops.push(Op::Saturate(code as u8));
                Ok(())
            }
            10 | 11 => {
                let zeros = if code == 10 { 2 } else { 1 };
                if self.module.memory.is_none() || r.take(zeros)?.iter().any(|&byte| byte != 0) {
                    return Err(LoadError::Malformed("unknown memory"));
                }
                for _ in 0..3 {
                    self.expect(ValType::I32)?;
                }
                self.ops.push(if code == 10 { Op::MemoryCopy } else { Op::MemoryFill });
                Ok(())
            }
            _ => Err(LoadError::Unsupported("an instruction beyond the supported set")),
        }
    }
}

/// The value type, the width in bytes and the sign extension of a load or store.
fn access(opcode: u8) -> (ValType, u8, bool) {
    use ValType::{F32, F64, I32, I64};
    match opcode {
        0x28 | 0x36 => (I32, 4, false),
        0x29 | 0x37 => (I64, 8, false),
        0x2a | 0x38 => (F32, 4, false),
        0x2b | 0x39 => (F64, 8, false),
        0x2c => (I32, 1, true),
        0x2d | 0x3a => (I32, 1, false),
        0x2e => (I32, 2, true),
        0x2f | 0x3b => (I32, 2, false),
        0x30 => (I64, 1, true),
        0x31 | 0x3c => (I64, 1, false),
        0x32 => (I64, 2, true),
        0x33 | 0x3d => (I64, 2, false),
        0x34 => (I64, 4, true),
        _ => (I64, 4, false),
    }
}
