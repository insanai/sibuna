//! A decoded and validated module: its types, functions, table, memory, globals, exports
//! and data. A [`Module`] is immutable and shared by every instance of it.
//!
//! The decoder reads the sections in the order of the binary format. Every count has a
//! bound from SID 0030, so the size of a module bounds the memory that decoding takes.

use super::op::Body;
use super::reader::{Load, LoadError, Reader};
use super::validate;

/// The most bytes of a module.
pub const MAX_MODULE_BYTES: usize = 4 << 20;
pub(crate) const MAX_TYPES: usize = 4096;
pub(crate) const MAX_FUNCTIONS: usize = 8192;
pub(crate) const MAX_GLOBALS: usize = 1024;
pub(crate) const MAX_EXPORTS: usize = 1024;
pub(crate) const MAX_SEGMENTS: usize = 4096;
pub(crate) const MAX_PARAMS: usize = 255;
pub(crate) const MAX_LOCALS: usize = 4096;
pub(crate) const MAX_TABLE: usize = 65_536;
/// The bytes of one page of memory.
pub const PAGE: usize = 65_536;
/// The most pages the format can name for a 32-bit memory.
pub(crate) const MAX_PAGES: u32 = 65_536;

/// The type of a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValType {
    /// A 32-bit integer.
    I32,
    /// A 64-bit integer.
    I64,
    /// A 32-bit float.
    F32,
    /// A 64-bit float.
    F64,
}

impl ValType {
    pub(crate) fn from_byte(byte: u8) -> Load<ValType> {
        match byte {
            0x7f => Ok(ValType::I32),
            0x7e => Ok(ValType::I64),
            0x7d => Ok(ValType::F32),
            0x7c => Ok(ValType::F64),
            0x7b | 0x70 | 0x6f => Err(LoadError::Unsupported("vector or reference value")),
            _ => Err(LoadError::Malformed("unknown value type")),
        }
    }
}

/// The type of a function: its parameters and at most one result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuncType {
    /// The parameters in order.
    pub params: Box<[ValType]>,
    /// The result, if the function has one.
    pub result: Option<ValType>,
}

/// A function that the module imports from the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// The module name of the import.
    pub module: Box<str>,
    /// The field name of the import.
    pub name: Box<str>,
    /// The index of its type.
    pub ty: u32,
}

/// What an export names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Export {
    /// The function of this index.
    Func(u32),
    /// The memory.
    Memory,
    /// The global of this index.
    Global(u32),
    /// The table.
    Table,
}

pub(crate) struct GlobalDef {
    pub ty: ValType,
    pub mutable: bool,
    pub init: u64,
}

/// The pages a memory starts with and may grow to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemoryDef {
    pub min: u32,
    pub max: u32,
}

/// A decoded and validated module.
pub struct Module {
    pub(crate) types: Vec<FuncType>,
    /// For each type, the index of the first type equal to it.
    pub(crate) canon: Vec<u32>,
    pub(crate) imports: Vec<Import>,
    /// The type index of every function, imports first.
    pub(crate) funcs: Vec<u32>,
    /// The table after its element segments: a function index or nothing.
    pub(crate) table: Vec<Option<u32>>,
    pub(crate) has_table: bool,
    pub(crate) memory: Option<MemoryDef>,
    pub(crate) globals: Vec<GlobalDef>,
    pub(crate) exports: Vec<(Box<str>, Export)>,
    pub(crate) start: Option<u32>,
    /// The bodies of the functions that the module defines.
    pub(crate) code: Vec<Body>,
    /// Data segments: where each begins and its bytes.
    pub(crate) data: Vec<(u32, Box<[u8]>)>,
}

impl std::fmt::Debug for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("functions", &self.funcs.len())
            .field("imports", &self.imports.len())
            .field("memory", &self.memory)
            .finish_non_exhaustive()
    }
}

impl Module {
    /// Decodes and validates `bytes`.
    ///
    /// # Errors
    ///
    /// A [`LoadError`] that says whether the bytes are malformed, use something
    /// unsupported or pass a bound. No input makes this function panic or allocate
    /// more than a constant times `bytes.len()` beyond the table of 65,536 entries.
    pub fn load(bytes: &[u8]) -> Load<Module> {
        if bytes.len() > MAX_MODULE_BYTES {
            return Err(LoadError::Limit("module larger than 4 MiB"));
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != b"\0asm\x01\0\0\0" {
            return Err(LoadError::Malformed("not a WebAssembly 1.0 binary"));
        }
        let mut module = Module::empty();
        let mut bodies: Option<Reader<'_>> = None;
        let mut last = 0u8;
        while !reader.is_empty() {
            let id = reader.byte()?;
            let size = reader.u32()? as usize;
            let mut section = reader.sub(size)?;
            if id == 0 {
                continue;
            }
            let rank = section_rank(id)?;
            if rank <= last {
                return Err(LoadError::Malformed("section out of order"));
            }
            last = rank;
            if id == 10 {
                bodies = Some(section);
                continue;
            }
            module.section(id, &mut section)?;
            if !section.is_empty() {
                return Err(LoadError::Malformed("section has trailing bytes"));
            }
        }
        module.canonicalize();
        validate::bodies(&mut module, bodies)?;
        module.check_exports()?;
        Ok(module)
    }

    fn empty() -> Module {
        Module {
            types: Vec::new(),
            canon: Vec::new(),
            imports: Vec::new(),
            funcs: Vec::new(),
            table: Vec::new(),
            has_table: false,
            memory: None,
            globals: Vec::new(),
            exports: Vec::new(),
            start: None,
            code: Vec::new(),
            data: Vec::new(),
        }
    }

    fn section(&mut self, id: u8, r: &mut Reader<'_>) -> Load<()> {
        match id {
            1 => self.read_types(r),
            2 => self.read_imports(r),
            3 => self.read_functions(r),
            4 => self.read_tables(r),
            5 => self.read_memories(r),
            6 => self.read_globals(r),
            7 => self.read_exports(r),
            8 => {
                self.start = Some(r.u32()?);
                Ok(())
            }
            9 => self.read_elements(r),
            11 => self.read_data(r),
            // The count of data segments. Only `memory.init` needs it, which we refuse.
            12 => r.u32().map(|_| ()),
            _ => Err(LoadError::Malformed("unknown section")),
        }
    }

    fn read_types(&mut self, r: &mut Reader<'_>) -> Load<()> {
        for _ in 0..r.count(MAX_TYPES, "types")? {
            if r.byte()? != 0x60 {
                return Err(LoadError::Malformed("type is not a function type"));
            }
            let mut params = Vec::new();
            for _ in 0..r.count(MAX_PARAMS, "parameters")? {
                params.push(ValType::from_byte(r.byte()?)?);
            }
            let result = match r.u32()? {
                0 => None,
                1 => Some(ValType::from_byte(r.byte()?)?),
                _ => return Err(LoadError::Unsupported("more than one result")),
            };
            self.types.push(FuncType { params: params.into(), result });
        }
        Ok(())
    }

    fn read_imports(&mut self, r: &mut Reader<'_>) -> Load<()> {
        for _ in 0..r.count(MAX_FUNCTIONS, "imports")? {
            let (module, name) = (r.name()?, r.name()?);
            if r.byte()? != 0 {
                // A table, a memory or a global of the host: the host has none to give.
                return Err(LoadError::Import(format!("{module}.{name}")));
            }
            let ty = r.u32()?;
            self.type_of(ty)?;
            self.funcs.push(ty);
            self.imports.push(Import { module: module.into(), name: name.into(), ty });
        }
        Ok(())
    }

    fn read_functions(&mut self, r: &mut Reader<'_>) -> Load<()> {
        let count = r.count(MAX_FUNCTIONS, "functions")?;
        if self.funcs.len() + count > MAX_FUNCTIONS {
            return Err(LoadError::Limit("functions"));
        }
        for _ in 0..count {
            let ty = r.u32()?;
            self.type_of(ty)?;
            self.funcs.push(ty);
        }
        Ok(())
    }

    fn read_tables(&mut self, r: &mut Reader<'_>) -> Load<()> {
        match r.u32()? {
            0 => return Ok(()),
            1 => {}
            _ => return Err(LoadError::Unsupported("more than one table")),
        }
        if r.byte()? != 0x70 {
            return Err(LoadError::Unsupported("a table that is not of functions"));
        }
        let (min, _) = limits(r)?;
        if min as usize > MAX_TABLE {
            return Err(LoadError::Limit("table entries"));
        }
        self.table = vec![None; min as usize];
        self.has_table = true;
        Ok(())
    }

    fn read_memories(&mut self, r: &mut Reader<'_>) -> Load<()> {
        match r.u32()? {
            0 => return Ok(()),
            1 => {}
            _ => return Err(LoadError::Unsupported("more than one memory")),
        }
        let (min, max) = limits(r)?;
        let max = max.unwrap_or(MAX_PAGES);
        if min > max || max > MAX_PAGES {
            return Err(LoadError::Malformed("memory limits"));
        }
        self.memory = Some(MemoryDef { min, max });
        Ok(())
    }

    fn read_globals(&mut self, r: &mut Reader<'_>) -> Load<()> {
        for _ in 0..r.count(MAX_GLOBALS, "globals")? {
            let ty = ValType::from_byte(r.byte()?)?;
            let mutable = match r.byte()? {
                0 => false,
                1 => true,
                _ => return Err(LoadError::Malformed("global mutability")),
            };
            let (found, init) = constant(r)?;
            if found != ty {
                return Err(LoadError::Malformed("global initializer type"));
            }
            self.globals.push(GlobalDef { ty, mutable, init });
        }
        Ok(())
    }

    fn read_exports(&mut self, r: &mut Reader<'_>) -> Load<()> {
        for _ in 0..r.count(MAX_EXPORTS, "exports")? {
            let name = r.name()?;
            let (kind, index) = (r.byte()?, r.u32()?);
            let export = match kind {
                0 => Export::Func(index),
                1 => Export::Table,
                2 => Export::Memory,
                3 => Export::Global(index),
                _ => return Err(LoadError::Malformed("export kind")),
            };
            if self.exports.iter().any(|(known, _)| &**known == name) {
                return Err(LoadError::Malformed("duplicate export name"));
            }
            self.exports.push((name.into(), export));
        }
        Ok(())
    }

    /// Element segments of the form the MVP has: an offset in table 0 and function
    /// indices. They are applied here, because nothing changes the table afterwards.
    fn read_elements(&mut self, r: &mut Reader<'_>) -> Load<()> {
        for _ in 0..r.count(MAX_SEGMENTS, "element segments")? {
            if r.u32()? != 0 {
                return Err(LoadError::Unsupported("passive or declared element segment"));
            }
            if !self.has_table {
                return Err(LoadError::Malformed("element segment without a table"));
            }
            let offset = offset(r)? as usize;
            let count = r.count(MAX_TABLE, "element segment")?;
            let end = offset.checked_add(count).filter(|&end| end <= self.table.len());
            let end = end.ok_or(LoadError::Malformed("element segment out of bounds"))?;
            for slot in offset..end {
                let func = r.u32()?;
                if func as usize >= self.funcs.len() {
                    return Err(LoadError::Malformed("element names no function"));
                }
                if let Some(entry) = self.table.get_mut(slot) {
                    *entry = Some(func);
                }
            }
        }
        Ok(())
    }

    fn read_data(&mut self, r: &mut Reader<'_>) -> Load<()> {
        for _ in 0..r.count(MAX_SEGMENTS, "data segments")? {
            match r.u32()? {
                0 => {}
                2 if r.u32()? == 0 => {}
                _ => return Err(LoadError::Unsupported("passive data segment")),
            }
            let memory = self.memory.ok_or(LoadError::Malformed("data without a memory"))?;
            let offset = offset(r)?;
            let length = r.u32()? as usize;
            let bytes = r.take(length)?;
            let end = (offset as usize).checked_add(length);
            if end.is_none_or(|end| end > memory.min as usize * PAGE) {
                return Err(LoadError::Malformed("data segment out of bounds"));
            }
            self.data.push((offset, bytes.into()));
        }
        Ok(())
    }

    /// Maps every type to the first type equal to it, so that `call_indirect` compares
    /// two indices.
    fn canonicalize(&mut self) {
        for (index, ty) in self.types.iter().enumerate() {
            let first = self.types.iter().position(|other| other == ty).unwrap_or(index);
            self.canon.push(first as u32);
        }
    }

    fn check_exports(&self) -> Load<()> {
        for (_, export) in &self.exports {
            let known = match *export {
                Export::Func(index) => (index as usize) < self.funcs.len(),
                Export::Global(index) => (index as usize) < self.globals.len(),
                Export::Memory => self.memory.is_some(),
                Export::Table => self.has_table,
            };
            if !known {
                return Err(LoadError::Malformed("export names nothing"));
            }
        }
        if let Some(start) = self.start {
            let ty = self.func_type(start).ok_or(LoadError::Malformed("start names nothing"))?;
            if !ty.params.is_empty() || ty.result.is_some() {
                return Err(LoadError::Malformed("start function has parameters or a result"));
            }
        }
        Ok(())
    }

    pub(crate) fn type_of(&self, index: u32) -> Load<&FuncType> {
        self.types.get(index as usize).ok_or(LoadError::Malformed("unknown type index"))
    }

    /// The type of the function `index`, imports first.
    pub fn func_type(&self, index: u32) -> Option<&FuncType> {
        self.types.get(*self.funcs.get(index as usize)? as usize)
    }

    /// The functions that the module imports, in index order.
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// What the export `name` names.
    pub fn export(&self, name: &str) -> Option<Export> {
        self.exports.iter().find(|(known, _)| &**known == name).map(|(_, export)| *export)
    }

    /// The index of the exported function `name`.
    pub fn exported_func(&self, name: &str) -> Option<u32> {
        match self.export(name)? {
            Export::Func(index) => Some(index),
            _ => None,
        }
    }

    /// The start function of the module, which an embedder runs once after
    /// instantiation.
    pub fn start_func(&self) -> Option<u32> {
        self.start
    }

    /// The pages the memory starts with; 0 without a memory.
    pub fn initial_pages(&self) -> u32 {
        self.memory.map_or(0, |memory| memory.min)
    }
}

/// The rank of a section in the order the format prescribes. The data count section
/// (12) comes between the elements (9) and the code (10).
fn section_rank(id: u8) -> Load<u8> {
    match id {
        1..=9 => Ok(id),
        12 => Ok(10),
        10 => Ok(11),
        11 => Ok(12),
        _ => Err(LoadError::Malformed("unknown section")),
    }
}

/// Reads limits: a minimum and an optional maximum.
fn limits(r: &mut Reader<'_>) -> Load<(u32, Option<u32>)> {
    match r.byte()? {
        0 => Ok((r.u32()?, None)),
        1 => {
            let min = r.u32()?;
            Ok((min, Some(r.u32()?)))
        }
        _ => Err(LoadError::Unsupported("shared or 64-bit limits")),
    }
}

/// Reads a constant expression: one `const` instruction and `end`.
fn constant(r: &mut Reader<'_>) -> Load<(ValType, u64)> {
    let value = match r.byte()? {
        0x41 => (ValType::I32, u64::from(r.i32()? as u32)),
        0x42 => (ValType::I64, r.i64()? as u64),
        0x43 => (ValType::F32, u64::from(u32::from_le_bytes(four(r)?))),
        0x44 => (ValType::F64, u64::from_le_bytes(eight(r)?)),
        0x23 => return Err(LoadError::Unsupported("initializer that reads a global")),
        _ => return Err(LoadError::Malformed("initializer is not a constant")),
    };
    if r.byte()? != 0x0b {
        return Err(LoadError::Malformed("initializer is not a constant"));
    }
    Ok(value)
}

/// Reads the `i32.const` offset of a segment.
fn offset(r: &mut Reader<'_>) -> Load<u32> {
    match constant(r)? {
        (ValType::I32, value) => Ok(value as u32),
        _ => Err(LoadError::Malformed("segment offset is not an i32")),
    }
}

pub(crate) fn four(r: &mut Reader<'_>) -> Load<[u8; 4]> {
    r.take(4)?.try_into().map_err(|_| LoadError::Malformed("unexpected end"))
}

pub(crate) fn eight(r: &mut Reader<'_>) -> Load<[u8; 8]> {
    r.take(8)?.try_into().map_err(|_| LoadError::Malformed("unexpected end"))
}
