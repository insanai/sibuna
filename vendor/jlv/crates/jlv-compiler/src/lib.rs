//! The JLV compiler (JDD 0004; tier `domain` of JDD 0002).
//!
//! [`compile`] reads a captured source [`Closure`], resolves every import against the
//! closure or the library [`Registry`] it receives as data, checks names, types,
//! definite returns, finite calls and stage rules, and lowers the result into the
//! kernel's checked [`Program`]. It never links the libraries whose signatures it
//! reads, performs no I/O and evaluates nothing; `jlv_lang::eval::run` evaluates the
//! program it produces.

#![forbid(unsafe_code)]

mod calls;
mod check;

pub use jlv_syntax::is_segment;

/// The dotted path that names the module `label`, such as `lib.app` for
/// `//lib:app.jlv` (JDD 0016, "Modules and imports").
pub fn dotted_path(label: &str) -> String {
    modules::dotted(label)
}
mod expr;
mod forms;
mod index;
mod modules;
mod scope;
mod typing;

pub use index::{Analysis, AnalysisRequest, Reference, Referent, analyze};

use std::collections::BTreeMap;
use std::sync::Arc;

use jlv_core::{Diagnostic, Limits, SourceId, Sources};
use jlv_lang::Type;
use jlv_lang::program::{FunctionId, Program};
use jlv_lang::signature::{Cost, Registry};

/// One captured source module.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Its number in the closure.
    pub id: SourceId,
    /// Its canonical label, such as `//lib:labels.jlv` or `@labels//lib:labels.jlv`.
    pub label: Arc<str>,
    /// The path to show in diagnostics, such as `lib/labels.jlv`.
    pub path: Arc<str>,
    /// Its exact text.
    pub text: Arc<str>,
}

/// The captured source modules of one compilation.
#[derive(Debug, Clone, Default)]
pub struct Closure {
    /// The files, in closure order.
    pub files: Vec<SourceFile>,
}

impl Closure {
    /// Adds a module with the next source number and returns that number.
    pub fn add(&mut self, label: &str, path: &str, text: &str) -> SourceId {
        let id = SourceId(self.files.len() as u32);
        self.files.push(SourceFile {
            id,
            label: label.into(),
            path: path.into(),
            text: text.into(),
        });
        id
    }

    /// The file with this canonical label.
    pub fn file(&self, label: &str) -> Option<&SourceFile> {
        self.files.iter().find(|f| &*f.label == label)
    }
}

impl Sources for Closure {
    fn file(&self, source: SourceId) -> Option<(&str, &str)> {
        self.files.get(source.0 as usize).map(|f| (&*f.path, &*f.text))
    }
}

/// The role of an entrypoint (JDD 0004, "Conventions and program roles").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Takes `DeployContext` and returns `Stack`.
    Deployment,
    /// Takes `OpContext` and returns `Recipe`.
    Operation,
    /// Takes and returns typed plain data.
    Transform,
    /// Takes nothing and returns any value; tools use it to read an exported constant,
    /// such as an input `Schema`. It is not a manifest role.
    Export,
}

impl Role {
    /// The manifest spelling.
    pub fn name(self) -> &'static str {
        match self {
            Role::Deployment => "deployment",
            Role::Operation => "operation",
            Role::Transform => "transform",
            Role::Export => "export",
        }
    }

    /// The role spelled `name` in a manifest.
    pub fn named(name: &str) -> Option<Role> {
        match name {
            "deployment" => Some(Role::Deployment),
            "operation" => Some(Role::Operation),
            "transform" => Some(Role::Transform),
            _ => None,
        }
    }
}

/// What to compile: the closure's entry module and function, and its role.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The entry module's canonical label.
    pub module: Arc<str>,
    /// The entry function's name.
    pub function: Arc<str>,
    /// Its role.
    pub role: Role,
}

/// The types of the keyed lookups, such as `input` for `ctx.input("name")`: for each
/// table, the type of each literal key.
pub type KeyedTypes = BTreeMap<Arc<str>, BTreeMap<Arc<str>, Type>>;

/// What one compilation needs.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The source modules.
    pub closure: &'a Closure,
    /// The library signatures and types.
    pub registry: &'a Registry,
    /// The entrypoint.
    pub entry: &'a Entry,
    /// The keyed lookup types.
    pub keyed: &'a KeyedTypes,
    /// The bounds.
    pub limits: &'a Limits,
}

/// A checked program and its entrypoint.
#[derive(Debug, Clone)]
pub struct Compiled {
    /// The lowered program.
    pub program: Program,
    /// The cost of each native of [`Program::natives`], in the same order.
    pub costs: Vec<Cost>,
    /// The entry function.
    pub entry: FunctionId,
    /// The entry's parameter types.
    pub params: Vec<Type>,
    /// The entry's result type.
    pub result: Type,
}

/// Compiles the closure's entrypoint, or returns the first diagnostic in canonical
/// module order and source position.
pub fn compile(request: Request<'_>) -> Result<Compiled, Diagnostic> {
    let loaded = modules::load(request)?;
    check::check_all(request, loaded)
}
