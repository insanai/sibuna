//! Lexical scopes: module symbols and the local bindings of one function.
//!
//! Modules have immutable import/export environments. Parameters and `let` bindings
//! are local to their blocks, nested blocks open child scopes, and a duplicate binding
//! in one block is an error (JDD 0004, "Bindings and evaluation"). Every binding gets
//! a fresh slot, so a child scope's binding never overwrites a parent's value.

use std::collections::BTreeMap;
use std::sync::Arc;

use jlv_core::{Diagnostic, Span};
use jlv_lang::Type;
use jlv_lang::codes;
use jlv_lang::program::FunctionId;
use jlv_lang::signature::Export;

/// What a module-level name refers to.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Symbol<'r> {
    /// A source function.
    Function(FunctionId),
    /// A module constant, by global slot.
    Constant(u32),
    /// An export of a registry library.
    Export(&'r Export),
}

/// The names visible at the top of one module and where each was introduced.
#[derive(Debug, Default)]
pub(crate) struct ModuleScope<'r> {
    pub symbols: BTreeMap<Arc<str>, (Symbol<'r>, Span)>,
}

impl<'r> ModuleScope<'r> {
    /// Adds a name; a second definition or import of one name is an error.
    pub fn define(
        &mut self,
        name: &str,
        symbol: Symbol<'r>,
        span: Span,
    ) -> Result<(), Diagnostic> {
        if let Some((_, first)) = self.symbols.get(name) {
            let message = format!("`{name}` is defined or imported twice in this module.");
            let hint = "Rename one of them; a module name has one meaning.";
            let problem = codes::problem(codes::DUPLICATE_KEY, &message, hint);
            return Err(Diagnostic::at(problem, span).related(*first));
        }
        self.symbols.insert(Arc::from(name), (symbol, span));
        Ok(())
    }
}

/// How a local was bound, which decides whether it may be assigned and what a second
/// binding of its name is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// A function's parameter.
    Parameter,
    /// A `let` in a block.
    Let,
    /// A `var` in a block, the only kind that may be assigned again (JDD 0016).
    Var,
    /// A name of a `for` loop or of a comprehension.
    Loop,
}

/// One local binding.
#[derive(Debug, Clone)]
pub(crate) struct Local {
    pub slot: u32,
    pub ty: Type,
    pub span: Span,
    pub origin: Origin,
    /// Where it may be named, which editors read from the resolution index.
    pub visible: Span,
}

impl Local {
    /// What a name that resolves to it refers to, for the resolution index.
    pub fn referent(&self) -> crate::Referent {
        let (definition, ty, visible) = (self.span, self.ty.clone(), self.visible);
        crate::Referent::Local { definition, ty, visible }
    }

    /// Whether it may be assigned again: only a `var` may.
    pub fn is_mutable(&self) -> bool {
        self.origin == Origin::Var
    }
}

/// One scope: the source its bindings are visible in, and the bindings.
#[derive(Debug)]
struct Frame {
    region: Span,
    names: BTreeMap<Arc<str>, Local>,
}

/// The block scopes of one function body.
#[derive(Debug, Default)]
pub(crate) struct Locals {
    frames: Vec<Frame>,
    next: u32,
}

impl Locals {
    /// Opens a child scope whose bindings are visible within `region`.
    pub fn push(&mut self, region: Span) {
        self.frames.push(Frame { region, names: BTreeMap::new() });
    }

    /// Where a binding made now in the innermost scope is visible: from `after`, or the
    /// scope's start when later, to the scope's end.
    pub fn visible_from(&self, after: u32) -> Span {
        let region = self.frames.last().map_or(Span::default(), |f| f.region);
        Span { start: after.max(region.start), ..region }
    }

    /// Closes the innermost scope.
    pub fn pop(&mut self) {
        self.frames.pop();
    }

    /// Binds `name` in the innermost scope, as `origin` says, and returns its fresh slot.
    pub fn declare(
        &mut self,
        name: &Arc<str>,
        ty: Type,
        span: Span,
        origin: Origin,
        visible: Span,
    ) -> Result<u32, Diagnostic> {
        let slot = self.next;
        let frame = self.frames.last_mut().ok_or_else(|| {
            Diagnostic::at(
                codes::problem(codes::OPERATIONAL_FAILURE, "No open scope.", "Report this."),
                span,
            )
        })?;
        if let Some(first) = frame.names.get(name) {
            let message = format!("`{name}` is bound twice in the same block.");
            let hint = rebound(name, first.origin, origin);
            let problem = codes::problem(codes::DUPLICATE_KEY, &message, &hint);
            return Err(Diagnostic::at(problem, span).related(first.span));
        }
        frame.names.insert(name.clone(), Local { slot, ty, span, origin, visible });
        self.next += 1;
        Ok(slot)
    }

    /// A fresh slot that no name binds, such as the list a comprehension builds.
    pub fn hidden(&mut self) -> u32 {
        self.next += 1;
        self.next - 1
    }

    /// The nearest binding of `name`.
    pub fn lookup(&self, name: &str) -> Option<&Local> {
        self.frames.iter().rev().find_map(|f| f.names.get(name))
    }

    /// The names of the visible bindings, for suggestions.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.frames.iter().flat_map(|f| f.names.keys().map(|k| &**k))
    }

    /// The number of slots used so far.
    pub fn count(&self) -> u32 {
        self.next
    }
}

/// The hint for `name`, bound as `first` and then again as `second` in one block.
fn rebound(name: &str, first: Origin, second: Origin) -> String {
    match (first, second) {
        (Origin::Loop, Origin::Loop) => {
            "Give the loop's two names different names, as in `for key, value in m`.".to_string()
        }
        (Origin::Parameter, _) => {
            format!("`{name}` is a parameter; give the local another name, such as `new_{name}`.")
        }
        (Origin::Loop, _) => {
            format!("`{name}` names the loop's item; give the local another name.")
        }
        (Origin::Var, _) => format!("`{name}` is a `var`; assign to it with `{name} = ...`."),
        (Origin::Let, _) => format!(
            "Use another name, or declare the first with `var` and assign with `{name} = ...`."
        ),
    }
}
