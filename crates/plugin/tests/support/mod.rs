//! A small assembler for the tests: builds the binary of a module from its parts, so
//! that hostile and malformed modules are written here and need no toolchain.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

pub const I32: u8 = 0x7f;
pub const I64: u8 = 0x7e;

/// Unsigned LEB128.
pub fn u(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Signed LEB128.
pub fn s(mut value: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// `i32.const value`.
pub fn i32c(value: i32) -> Vec<u8> {
    [vec![0x41], s(i64::from(value))].concat()
}

/// `i64.const value`.
pub fn i64c(value: i64) -> Vec<u8> {
    [vec![0x42], s(value)].concat()
}

fn vector(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = u(items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn name(text: &str) -> Vec<u8> {
    [u(text.len() as u64), text.as_bytes().to_vec()].concat()
}

fn section(id: u8, body: Vec<u8>) -> Vec<u8> {
    [vec![id], u(body.len() as u64), body].concat()
}

/// One function: its type, its locals after the parameters, and its code without the
/// final `end`.
pub struct Func {
    pub params: Vec<u8>,
    pub result: Option<u8>,
    pub locals: Vec<u8>,
    pub code: Vec<u8>,
}

/// The parts of a module.
#[derive(Default)]
pub struct Builder {
    pub imports: Vec<(&'static str, &'static str, Vec<u8>, Option<u8>)>,
    pub funcs: Vec<Func>,
    pub exports: Vec<(&'static str, u32)>,
    /// The initial pages and the maximum of the memory, exported as `memory`.
    pub memory: Option<(u32, Option<u32>)>,
    /// The functions of the table, from its first entry.
    pub table: Vec<u32>,
    pub globals: Vec<(u8, bool, Vec<u8>)>,
    pub data: Vec<(u32, Vec<u8>)>,
    pub start: Option<u32>,
}

impl Builder {
    /// Adds a function and returns its index, counting imports.
    pub fn func(&mut self, params: &[u8], result: Option<u8>, locals: &[u8], code: Vec<u8>) -> u32 {
        self.funcs.push(Func { params: params.to_vec(), result, locals: locals.to_vec(), code });
        (self.imports.len() + self.funcs.len() - 1) as u32
    }

    /// Adds a function and exports it as `export`.
    pub fn export(&mut self, export: &'static str, params: &[u8], result: Option<u8>, code: Vec<u8>) -> u32 {
        let index = self.func(params, result, &[], code);
        self.exports.push((export, index));
        index
    }

    fn func_type(params: &[u8], result: Option<u8>) -> Vec<u8> {
        let mut out = vec![0x60];
        out.extend(u(params.len() as u64));
        out.extend_from_slice(params);
        match result {
            Some(ty) => out.extend([1, ty]),
            None => out.push(0),
        }
        out
    }

    /// The binary of the module. Every function has a type of its own.
    pub fn build(&self) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        let mut types = Vec::new();
        for (_, _, params, result) in &self.imports {
            types.push(Self::func_type(params, *result));
        }
        for func in &self.funcs {
            types.push(Self::func_type(&func.params, func.result));
        }
        out.extend(section(1, vector(&types)));
        let imports: Vec<Vec<u8>> = self
            .imports
            .iter()
            .enumerate()
            .map(|(index, (module, field, _, _))| {
                [name(module), name(field), vec![0], u(index as u64)].concat()
            })
            .collect();
        if !imports.is_empty() {
            out.extend(section(2, vector(&imports)));
        }
        let first = self.imports.len();
        let indices: Vec<Vec<u8>> = (0..self.funcs.len()).map(|i| u((first + i) as u64)).collect();
        out.extend(section(3, vector(&indices)));
        if !self.table.is_empty() {
            out.extend(section(4, [vec![1, 0x70, 0], u(self.table.len() as u64)].concat()));
        }
        if let Some((min, max)) = self.memory {
            let limits = match max {
                Some(max) => [vec![1], u(u64::from(min)), u(u64::from(max))].concat(),
                None => [vec![0], u(u64::from(min))].concat(),
            };
            out.extend(section(5, [vec![1], limits].concat()));
        }
        let globals: Vec<Vec<u8>> = self
            .globals
            .iter()
            .map(|(ty, mutable, init)| [vec![*ty, u8::from(*mutable)], init.clone(), vec![0x0b]].concat())
            .collect();
        if !globals.is_empty() {
            out.extend(section(6, vector(&globals)));
        }
        let mut exports: Vec<Vec<u8>> =
            self.exports.iter().map(|(text, index)| [name(text), vec![0], u(u64::from(*index))].concat()).collect();
        if self.memory.is_some() {
            exports.push([name("memory"), vec![2, 0]].concat());
        }
        out.extend(section(7, vector(&exports)));
        if let Some(start) = self.start {
            out.extend(section(8, u(u64::from(start))));
        }
        if !self.table.is_empty() {
            let entries: Vec<Vec<u8>> = self.table.iter().map(|f| u(u64::from(*f))).collect();
            let segment = [vec![0, 0x41, 0, 0x0b], vector(&entries)].concat();
            out.extend(section(9, vector(&[segment])));
        }
        let bodies: Vec<Vec<u8>> = self
            .funcs
            .iter()
            .map(|func| {
                let groups: Vec<Vec<u8>> = func.locals.iter().map(|ty| vec![1, *ty]).collect();
                let body = [vector(&groups), func.code.clone(), vec![0x0b]].concat();
                [u(body.len() as u64), body].concat()
            })
            .collect();
        out.extend(section(10, vector(&bodies)));
        let data: Vec<Vec<u8>> = self
            .data
            .iter()
            .map(|(offset, bytes)| {
                [vec![0], i32c(*offset as i32), vec![0x0b], u(bytes.len() as u64), bytes.clone()].concat()
            })
            .collect();
        if !data.is_empty() {
            out.extend(section(11, vector(&data)));
        }
        out
    }
}

/// The address and the size of the input buffer of the hooks built by [`hook`].
pub const HOOK_INPUT: i32 = 1024;
pub const HOOK_INPUT_SIZE: i32 = 4096;

/// A module that meets the ABI of version 1. Each of its three stage functions has
/// the parameter `len` as local 0, the `i32` locals 1 and 2, and the body `judge`.
/// It imports `sibuna.add_header` as function 0 and `sibuna.now_ms` as function 1.
pub fn hook(judge: &[u8]) -> Builder {
    let mut builder = Builder {
        imports: vec![
            ("sibuna", "add_header", vec![I32, I32], Some(I32)),
            ("sibuna", "now_ms", vec![], Some(I64)),
        ],
        memory: Some((1, None)),
        ..Builder::default()
    };
    builder.export("sibuna_abi", &[], Some(I32), i32c(1));
    builder.export("sibuna_input", &[], Some(I32), i32c(HOOK_INPUT));
    builder.export("sibuna_input_size", &[], Some(I32), i32c(HOOK_INPUT_SIZE));
    for stage in ["sibuna_on_connection", "sibuna_on_request", "sibuna_on_telemetry"] {
        let index = builder.func(&[I32], Some(I32), &[I32, I32], judge.to_vec());
        builder.exports.push((stage, index));
    }
    builder
}

/// A hook that returns `code` at every stage.
pub fn constant_hook(code: i32) -> Vec<u8> {
    hook(&i32c(code)).build()
}

/// A hook that never returns: `loop br 0 end`, then an unreachable constant.
pub fn spinning_hook() -> Vec<u8> {
    hook(&[vec![0x03, 0x40, 0x0c, 0x00, 0x0b], i32c(0)].concat()).build()
}

/// A hook that executes `unreachable`.
pub fn trapping_hook() -> Vec<u8> {
    hook(&[0x00]).build()
}

static SERIAL: AtomicU32 = AtomicU32::new(0);

/// A fresh path under the system's temporary directory, unique to this process and call.
pub fn temp_path(label: &str) -> PathBuf {
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let name = format!("sibuna-plugin-{}-{serial}-{label}", std::process::id());
    std::env::temp_dir().join(name)
}

/// Writes `bytes` to a fresh file and returns its path as text.
pub fn temp_file(label: &str, bytes: &[u8]) -> String {
    let path = temp_path(label);
    std::fs::write(&path, bytes).expect("write a test module");
    path.to_string_lossy().into_owned()
}
