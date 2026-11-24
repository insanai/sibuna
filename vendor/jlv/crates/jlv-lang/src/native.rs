//! Native library functions and the state they may touch.
//!
//! A native is pure and bounded. It receives its arguments, the invocation's frozen
//! context tables and, outside module initialization, the invocation-local
//! [`Builder`], which only accumulates declarations (JDD 0004, "Bindings and
//! evaluation"). It has no database, provider, process, filesystem, clock, random or
//! network access: the evaluator gives it nothing to reach them with.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use jlv_core::{Limits, Problem, Span};

use crate::codes;
use crate::value::Value;

/// A native function implementation.
pub trait Native: Send + Sync + fmt::Debug {
    /// Calls the native with one entry per parameter: `None` for an omitted optional
    /// parameter. Defaults and types are already checked by the compiler.
    fn call(&self, call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem>;
}

/// What a native call may use.
#[derive(Debug)]
pub struct Call<'a> {
    /// The invocation's builder, absent while module constants initialize.
    pub builder: Option<&'a mut Builder>,
    /// The invocation's frozen context tables, absent while constants initialize.
    pub context: Option<&'a Context>,
    /// The bounds of this invocation.
    pub limits: &'a Limits,
    /// Where the call is, for the declarations it makes.
    pub span: Span,
}

impl Call<'_> {
    /// The builder, or a problem saying that declarations cannot happen here.
    pub fn builder(&mut self) -> Result<&mut Builder, Problem> {
        self.builder.as_deref_mut().ok_or_else(outside_invocation)
    }

    /// The context, or a problem saying that it is not available here.
    pub fn context(&self) -> Result<&Context, Problem> {
        self.context.ok_or_else(outside_invocation)
    }
}

fn outside_invocation() -> Problem {
    codes::problem(
        codes::TYPE_MISMATCH,
        "This call needs an invocation and cannot run while module constants initialize.",
        "Move the call into the entry function or a function it calls.",
    )
}

/// Named frozen tables of plain data that natives read, such as the captured inputs,
/// the lock entries and the inventory selection of one invocation.
#[derive(Debug, Clone, Default)]
pub struct Context {
    tables: BTreeMap<Arc<str>, Value>,
}

impl Context {
    /// An empty context.
    pub fn new() -> Context {
        Context::default()
    }

    /// Adds or replaces the table `name`.
    pub fn insert(&mut self, name: &str, table: Value) {
        self.tables.insert(Arc::from(name), table);
    }

    /// The table `name`.
    pub fn table(&self, name: &str) -> Option<&Value> {
        self.tables.get(name)
    }
}

/// One declaration a native made: a kind, a unique address and a plain payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Declaration {
    /// The kind, such as `resource`.
    pub kind: Arc<str>,
    /// The unique address, such as `incus.instance.web`.
    pub address: Arc<str>,
    /// The declared data.
    pub payload: Value,
    /// Where it was declared.
    pub span: Span,
}

/// The invocation-local accumulator of declarations.
#[derive(Debug, Default)]
pub struct Builder {
    declarations: Vec<Declaration>,
    index: BTreeMap<Arc<str>, usize>,
    limit: usize,
}

impl Builder {
    /// A builder that accepts at most `limit` declarations.
    pub fn new(limit: usize) -> Builder {
        Builder { limit, ..Builder::default() }
    }

    /// Records a declaration and returns its index; a repeated address is
    /// `duplicate_address` and an overfull builder is `budget_exhausted`.
    pub fn declare(&mut self, declaration: Declaration) -> Result<usize, Problem> {
        if self.index.contains_key(&declaration.address) {
            return Err(codes::problem(
                codes::DUPLICATE_ADDRESS,
                &format!("The address `{}` is declared twice.", declaration.address),
                "Give each resource a distinct name; addresses must be unique in a stack.",
            ));
        }
        if self.declarations.len() >= self.limit {
            return Err(codes::problem(
                codes::BUDGET_EXHAUSTED,
                &format!("The invocation declares more than {} resources.", self.limit),
                "Split the stack, or raise `[limits] resources` in jlv.toml.",
            ));
        }
        let at = self.declarations.len();
        self.index.insert(declaration.address.clone(), at);
        self.declarations.push(declaration);
        Ok(at)
    }

    /// The declaration with this address.
    pub fn get(&self, address: &str) -> Option<&Declaration> {
        self.index.get(address).map(|&i| &self.declarations[i])
    }

    /// The declarations, consuming the builder.
    pub fn into_declarations(self) -> Vec<Declaration> {
        self.declarations
    }
}

/// The natives of one program, linked by qualified name before evaluation.
pub trait NativeTable {
    /// The implementation of the native named `name`.
    fn native(&self, name: &str) -> Option<Arc<dyn Native>>;
}

impl NativeTable for BTreeMap<Arc<str>, Arc<dyn Native>> {
    fn native(&self, name: &str) -> Option<Arc<dyn Native>> {
        self.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jlv_core::SourceId;

    fn declaration(address: &str) -> Declaration {
        Declaration {
            kind: Arc::from("resource"),
            address: Arc::from(address),
            payload: Value::Null,
            span: Span::new(SourceId(0), 0, 1),
        }
    }

    #[test]
    fn addresses_are_unique_and_bounded() {
        let mut builder = Builder::new(2);
        assert_eq!(builder.declare(declaration("a")).unwrap(), 0);
        assert_eq!(builder.declare(declaration("a")).unwrap_err().code, "duplicate_address");
        builder.declare(declaration("b")).unwrap();
        assert_eq!(builder.declare(declaration("c")).unwrap_err().code, "budget_exhausted");
        assert_eq!(builder.get("b").unwrap().address.as_ref(), "b");
    }
}
