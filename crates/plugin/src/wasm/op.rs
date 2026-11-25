//! The operations the interpreter runs. The validator translates the structured code of
//! a function into a flat sequence of these, with every branch resolved to an index.

use super::module::ValType;

/// Where a branch goes and how it leaves the stack: it keeps the top value when the
/// label has a result, and drops `drop` values below it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Target {
    /// The index of the operation to continue at.
    pub pc: u32,
    /// Values to remove below the kept one.
    pub drop: u32,
    /// The label carries one value.
    pub keep: bool,
}

/// One operation. Numeric operations keep the opcode byte of the binary format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Unreachable,
    /// Continue at an index. The stack already has the right height.
    Jump(u32),
    /// Pop a value and jump when it is zero: the false side of an `if`.
    JumpIfZero(u32),
    Br(Target),
    /// Pop a value and branch when it is not zero.
    BrIf(Target),
    /// Pop an index and branch to the target `first + min(index, last)`.
    BrTable {
        first: u32,
        last: u32,
    },
    Return,
    Call(u32),
    /// Call through the table; the operand is the expected type index.
    CallIndirect(u32),
    Drop,
    Select,
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    /// Read `bytes` bytes at the popped address plus `offset`. With `signed` the value
    /// is sign-extended, to 64 bits when `wide` and to 32 bits otherwise.
    Load {
        offset: u32,
        bytes: u8,
        signed: bool,
        wide: bool,
    },
    /// Write the low `bytes` bytes of the popped value.
    Store {
        offset: u32,
        bytes: u8,
    },
    MemorySize,
    MemoryGrow,
    MemoryCopy,
    MemoryFill,
    /// Push the bits of a constant.
    Const(u64),
    /// A numeric operation of one operand, by its opcode.
    Unary(u8),
    /// A numeric operation of two operands, by its opcode.
    Binary(u8),
    /// A saturating conversion, by its number after the 0xFC prefix.
    Saturate(u8),
}

/// The translated body of one function.
#[derive(Debug, Default)]
pub(crate) struct Body {
    /// The locals after the parameters.
    pub locals: Box<[ValType]>,
    pub ops: Box<[Op]>,
    /// The targets of every `br_table`, one run after another.
    pub targets: Box<[Target]>,
    /// The most values the operand stack of the function holds.
    pub max_height: u32,
}
