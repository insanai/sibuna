//! The resolution index: what each name of a module refers to, recorded by the checker
//! as it resolves names (JDD 0012, "Resolution").
//!
//! Editors read it for hover, completion and go to definition. Because the checker
//! records a name at the moment it resolves it, the index and the checker cannot
//! disagree about what a name means. [`analyze`] checks one module as a root, without
//! an entrypoint, and keeps what it recorded before the first problem, so a module
//! that does not check yet still answers for the names before its mistake.

use std::sync::Arc;

use jlv_core::{Diagnostic, Span};
use jlv_lang::Type;
use jlv_lang::signature::{Export, Signature};

use crate::{Entry, Request, Role};

/// What a name refers to.
#[derive(Debug, Clone, PartialEq)]
pub enum Referent {
    /// A parameter, `let` binding or loop variable.
    Local {
        /// The name where it is bound.
        definition: Span,
        /// Its type.
        ty: Type,
        /// Where it may be named: a parameter in the function's body, a `let` from the
        /// end of its statement to the end of its block, a loop's names in its body, and
        /// a comprehension's names in its body and filter.
        visible: Span,
    },
    /// A source module, named by an import's path.
    Module {
        /// The start of the module.
        definition: Span,
    },
    /// A function of a source module.
    Function {
        /// Its name.
        name: Arc<str>,
        /// The whole definition, from `fn` to its closing brace.
        definition: Span,
        /// Its parameters and their types.
        params: Vec<(Arc<str>, Type)>,
        /// Its result; `None` when it returns no value.
        result: Option<Type>,
    },
    /// A constant of a source module.
    Constant {
        /// The whole definition.
        definition: Span,
        /// Its type, once checked.
        ty: Option<Type>,
    },
    /// An export of a library, such as the namespace `host` or the function
    /// `host.file`, with the path of names that reach it.
    Export {
        /// The names from the imported one to this export, such as `["host", "file"]`.
        path: Vec<Arc<str>>,
        /// The export.
        export: Export,
    },
    /// A method of a nominal type, such as `address` of `TargetRef`.
    Method {
        /// The type.
        type_name: Arc<str>,
        /// The method.
        name: Arc<str>,
        /// Its signature without the receiver.
        signature: Signature,
    },
    /// A function of the prelude, such as `len` or `fail`.
    Prelude {
        /// Its name.
        name: Arc<str>,
    },
    /// A parameter that a named argument passes to.
    Parameter {
        /// The callee: a source function's name, or a library function's native name,
        /// such as `@host//:plugin.jlv#host.file`.
        callee: Arc<str>,
        /// The parameter.
        name: Arc<str>,
        /// Its type.
        ty: Type,
    },
}

/// One name and what it refers to.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    /// Where the name is written.
    pub span: Span,
    /// What it refers to.
    pub referent: Referent,
}

/// What analysing one module found.
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    /// The names resolved before the first problem, in the order the checker met them.
    pub references: Vec<Reference>,
    /// The first problem, if any.
    pub problem: Option<Diagnostic>,
}

impl Analysis {
    /// The reference whose name covers byte `offset` of the source `source`.
    pub fn at(&self, source: jlv_core::SourceId, offset: u32) -> Option<&Reference> {
        self.references
            .iter()
            .filter(|r| r.span.source == source && r.span.start <= offset && offset <= r.span.end)
            .min_by_key(|r| r.span.end - r.span.start)
    }
}

/// What one analysis needs: [`Request`] without an entrypoint, and the module to check
/// as the root, by its canonical label.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisRequest<'a> {
    /// The source modules.
    pub closure: &'a crate::Closure,
    /// The library signatures and types.
    pub registry: &'a jlv_lang::signature::Registry,
    /// The module to analyse, such as `//lib:nginx.jlv`.
    pub module: &'a str,
    /// The keyed lookup types.
    pub keyed: &'a crate::KeyedTypes,
    /// The bounds.
    pub limits: &'a jlv_core::Limits,
}

/// Checks the module and every module it imports, and returns what each name refers to
/// together with the first problem. It never evaluates anything.
pub fn analyze(request: AnalysisRequest<'_>) -> Analysis {
    let entry = Entry { module: request.module.into(), function: "".into(), role: Role::Export };
    let full = Request {
        closure: request.closure,
        registry: request.registry,
        entry: &entry,
        keyed: request.keyed,
        limits: request.limits,
    };
    match crate::modules::load(full) {
        Ok(loaded) => crate::check::analyze_all(full, loaded),
        Err(problem) => Analysis { references: Vec::new(), problem: Some(problem) },
    }
}
