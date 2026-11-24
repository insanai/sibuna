//! Checking a loaded closure and lowering it into one program.
//!
//! The order is fixed so that the first diagnostic is deterministic: symbol tables in
//! module initialization order, function signatures, constants in initialization
//! order, function bodies in module and source order, then the call graph, which must
//! be acyclic, and finally the entrypoint's role contract.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use jlv_core::{Diagnostic, Span};
use jlv_lang::Type;
use jlv_lang::codes;
use jlv_lang::program::{self, FunctionId, NativeId, Program};
use jlv_lang::signature::{Cost, Export};
use jlv_lang::types::assignable;
use jlv_syntax::view::{self as ast, Item, Stmt};

use crate::index::{Analysis, Reference, Referent};
use crate::modules::{Loaded, Target};
use crate::scope::{Locals, ModuleScope, Origin, Symbol};
use crate::typing::{fault, mismatch, resolve};
use crate::{Compiled, Request, Role};

/// A source function's checked signature.
#[derive(Debug, Clone)]
pub(crate) struct FunctionInfo {
    pub name: Arc<str>,
    pub module: usize,
    pub params: Vec<(Arc<str>, Type)>,
    /// The result type; `None` when the function returns no value.
    pub result: Option<Type>,
    pub span: Span,
}

/// A module constant's name, its type once checked, and its definition.
#[derive(Debug, Clone)]
pub(crate) struct ConstantInfo {
    pub name: Arc<str>,
    pub ty: Option<Type>,
    pub span: Span,
}

/// The state of checking one closure.
pub(crate) struct Checker<'a> {
    pub request: Request<'a>,
    pub scopes: Vec<ModuleScope<'a>>,
    pub functions: Vec<FunctionInfo>,
    pub constants: Vec<ConstantInfo>,
    native_ids: BTreeMap<Arc<str>, NativeId>,
    pub natives: Vec<Arc<str>>,
    pub costs: Vec<Cost>,
    pub calls: Vec<(FunctionId, FunctionId, Span)>,
    /// The source functions each constant initializer calls: constant slot, callee and
    /// call site.
    pub constant_calls: Vec<(u32, FunctionId, Span)>,
    /// The constants each function reads: function, constant slot and use.
    pub constant_reads: Vec<(FunctionId, u32, Span)>,
    /// The calls of natives that need an entrypoint invocation, by calling function.
    pub invocation_calls: Vec<(FunctionId, Span)>,
    /// What each resolved name refers to, for editors (JDD 0012). A cell, because names
    /// are resolved in methods that only read the checker.
    pub references: RefCell<Vec<Reference>>,
}

/// The context of the function or constant being checked.
pub(crate) struct Fx {
    pub module: usize,
    pub locals: Locals,
    pub current: Option<FunctionId>,
    /// The function's result type; `None` when it returns no value or outside a function.
    pub result: Option<Type>,
    /// While checking constant `n`, constants `n` and later are not yet initialized.
    pub constant: Option<u32>,
}

impl<'a> Checker<'a> {
    fn new(request: Request<'a>) -> Checker<'a> {
        Checker {
            request,
            scopes: Vec::new(),
            functions: Vec::new(),
            constants: Vec::new(),
            native_ids: BTreeMap::new(),
            natives: Vec::new(),
            costs: Vec::new(),
            calls: Vec::new(),
            constant_calls: Vec::new(),
            constant_reads: Vec::new(),
            invocation_calls: Vec::new(),
            references: RefCell::new(Vec::new()),
        }
    }

    /// Records that the name at `span` refers to `referent`.
    pub fn record_reference(&self, span: Span, referent: Referent) {
        self.references.borrow_mut().push(Reference { span, referent });
    }

    /// The referent of a source function.
    pub fn function_referent(&self, id: FunctionId) -> Referent {
        let info = &self.functions[id.0 as usize];
        Referent::Function {
            name: info.name.clone(),
            definition: info.span,
            params: info.params.clone(),
            result: info.result.clone(),
        }
    }

    /// The referent of a module-level symbol, as it is known now.
    pub fn symbol_referent(&self, symbol: Symbol<'_>, name: &str) -> Referent {
        match symbol {
            Symbol::Function(id) => self.function_referent(id),
            Symbol::Constant(slot) => {
                let info = &self.constants[slot as usize];
                Referent::Constant { definition: info.span, ty: info.ty.clone() }
            }
            Symbol::Export(export) => {
                Referent::Export { path: vec![Arc::from(name)], export: export.clone() }
            }
        }
    }

    /// The native's index in the program, interning its name and cost.
    pub fn native(&mut self, name: &Arc<str>, cost: Cost) -> NativeId {
        if let Some(id) = self.native_ids.get(name) {
            return *id;
        }
        let id = NativeId(self.natives.len() as u32);
        self.natives.push(name.clone());
        self.costs.push(cost);
        self.native_ids.insert(name.clone(), id);
        id
    }
}

/// Checks every module of `loaded` and lowers the closure.
pub(crate) fn check_all(request: Request<'_>, loaded: Loaded) -> Result<Compiled, Diagnostic> {
    let mut checker = Checker::new(request);
    let (functions, constants) = check_modules(&mut checker, &loaded)?;
    let entry = entry(&checker, &loaded)?;
    let info = &checker.functions[entry.0 as usize];
    let params = info.params.iter().map(|(_, t)| t.clone()).collect();
    let result = info.result.clone().unwrap_or(Type::Null);
    let program = Program { functions, constants, natives: checker.natives };
    Ok(Compiled { program, costs: checker.costs, entry, params, result })
}

/// Checks every module of `loaded` without an entrypoint and returns what each name
/// refers to, with the first problem (JDD 0012).
pub(crate) fn analyze_all(request: Request<'_>, loaded: Loaded) -> Analysis {
    let mut checker = Checker::new(request);
    let problem = check_modules(&mut checker, &loaded).err();
    Analysis { references: checker.references.into_inner(), problem }
}

/// Checks the symbols, signatures, constants and bodies of every module, and the call
/// graph, and lowers the functions and constants.
fn check_modules(
    checker: &mut Checker<'_>,
    loaded: &Loaded,
) -> Result<(Vec<program::Function>, Vec<program::Constant>), Diagnostic> {
    let own = declare(checker, loaded)?;
    import_all(checker, loaded, &own)?;
    signatures(checker, loaded)?;
    let constants = constants(checker, loaded)?;
    record_imports(checker, loaded);
    let mut functions = Vec::new();
    let mut next = 0u32;
    for (module, unit) in loaded.modules.iter().enumerate() {
        for item in unit.module().items() {
            if let Item::Function(f) = item {
                functions.push(function(checker, module, FunctionId(next), &f)?);
                next += 1;
            }
        }
    }
    acyclic(checker)?;
    initializers_are_pure(checker)?;
    Ok((functions, constants))
}

/// Records what each imported name refers to, once signatures and constant types are
/// known.
fn record_imports(checker: &Checker<'_>, loaded: &Loaded) {
    for (module, unit) in loaded.modules.iter().enumerate() {
        for (import, target) in unit.module().imports().iter().zip(&unit.targets) {
            let Target::Source(j) = target else { continue };
            let Some(file) = checker.request.closure.file(&loaded.modules[*j].key) else {
                continue;
            };
            let definition = Span { source: file.id, start: 0, end: 0 };
            checker.record_reference(import.path_span, Referent::Module { definition });
        }
        for name in unit.module().imports().iter().flat_map(|i| &i.names) {
            if let Some((symbol, _)) = checker.scopes[module].symbols.get(name.text) {
                checker.record_reference(name.span, checker.symbol_referent(*symbol, name.text));
            }
        }
    }
}

/// Allocates function ids and constant slots in initialization order and returns each
/// module's own definitions.
fn declare<'a>(
    checker: &mut Checker<'a>,
    loaded: &Loaded,
) -> Result<Vec<ModuleScope<'a>>, Diagnostic> {
    let mut own = Vec::with_capacity(loaded.modules.len());
    for (module, unit) in loaded.modules.iter().enumerate() {
        let mut scope = ModuleScope::default();
        for item in unit.module().items() {
            match item {
                Item::Function(f) => {
                    let id = FunctionId(checker.functions.len() as u32);
                    let name = Arc::from(f.name.text);
                    let info = FunctionInfo {
                        name,
                        module,
                        params: Vec::new(),
                        result: None,
                        span: f.span,
                    };
                    checker.functions.push(info);
                    scope.define(f.name.text, Symbol::Function(id), f.name.span)?;
                }
                Item::Constant(c) => {
                    let slot = checker.constants.len() as u32;
                    let name = Arc::from(c.name.text);
                    checker.constants.push(ConstantInfo { name, ty: None, span: c.span });
                    scope.define(c.name.text, Symbol::Constant(slot), c.name.span)?;
                }
            }
        }
        own.push(scope);
    }
    Ok(own)
}

/// Builds each module's scope from its own definitions and its imports.
fn import_all<'a>(
    checker: &mut Checker<'a>,
    loaded: &Loaded,
    own: &[ModuleScope<'a>],
) -> Result<(), Diagnostic> {
    let registry = checker.request.registry;
    for (module, unit) in loaded.modules.iter().enumerate() {
        let mut scope = ModuleScope { symbols: own[module].symbols.clone() };
        for (import, target) in unit.module().imports().iter().zip(&unit.targets) {
            for name in &import.names {
                let symbol = match target {
                    Target::Source(j) => own[*j].symbols.get(name.text).map(|(s, _)| *s),
                    Target::Library(label) => registry
                        .library(label)
                        .and_then(|l| l.exports.get(name.text))
                        .map(Symbol::Export),
                };
                let Some(symbol) = symbol else {
                    return Err(missing_export(
                        name.text,
                        &import.dotted(),
                        target,
                        own,
                        registry,
                        name.span,
                    ));
                };
                scope.define(name.text, symbol, name.span)?;
            }
        }
        checker.scopes.push(scope);
    }
    Ok(())
}

fn missing_export(
    name: &str,
    label: &str,
    target: &Target,
    own: &[ModuleScope<'_>],
    registry: &jlv_lang::signature::Registry,
    span: Span,
) -> Diagnostic {
    let names: Vec<&str> = match target {
        Target::Source(j) => own[*j].symbols.keys().map(|k| &**k).collect(),
        Target::Library(l) => registry
            .library(l)
            .map(|l| l.exports.keys().map(|k| &**k).collect())
            .unwrap_or_default(),
    };
    // With no close name, the names it does export say what to write instead.
    let shown: Vec<String> = names.iter().take(12).map(|n| format!("`{n}`")).collect();
    let more = if names.len() > shown.len() { ", ..." } else { "" };
    let mut hint = format!("`{label}` exports {}{more}.", shown.join(", "));
    if names.is_empty() {
        hint = format!("`{label}` exports nothing; define the name there first.");
    }
    if let Some(s) = gd_report::suggest(name, names) {
        hint = format!("Did you mean `{s}`?");
    }
    if let Some(removed) = crate::forms::removed(name) {
        hint = removed.to_string();
    }
    fault(codes::UNBOUND_NAME, &format!("`{label}` exports no `{name}`."), &hint, span)
}

/// Resolves every source function's parameter and result types.
fn signatures(checker: &mut Checker<'_>, loaded: &Loaded) -> Result<(), Diagnostic> {
    let registry = checker.request.registry;
    let mut next = 0usize;
    for (module, unit) in loaded.modules.iter().enumerate() {
        for item in unit.module().items() {
            let Item::Function(f) = item else { continue };
            let scope = &checker.scopes[module];
            let mut params = Vec::with_capacity(f.params.len());
            for p in &f.params {
                if params.iter().any(|(n, _): &(Arc<str>, Type)| **n == *p.name.text) {
                    let message = format!("The parameter `{}` appears twice.", p.name.text);
                    return Err(fault(
                        codes::DUPLICATE_KEY,
                        &message,
                        "Rename one parameter.",
                        p.name.span,
                    ));
                }
                params.push((Arc::from(p.name.text), resolve(&p.ty, scope, registry)?));
            }
            let result = match &f.result {
                Some(ty) => Some(no_null_result(ty, &f.name, scope, registry)?),
                None => None,
            };
            checker.functions[next].params = params;
            checker.functions[next].result = result;
            checker
                .record_reference(f.name.span, checker.function_referent(FunctionId(next as u32)));
            next += 1;
        }
    }
    Ok(())
}

/// A written result type; `Null` is refused there, because a function that returns
/// nothing says so by declaring no result.
fn no_null_result(
    ty: &ast::TypeExpr<'_>,
    function: &ast::Name<'_>,
    scope: &ModuleScope<'_>,
    registry: &jlv_lang::signature::Registry,
) -> Result<Type, Diagnostic> {
    let resolved = resolve(ty, scope, registry)?;
    if resolved != Type::Null {
        return Ok(resolved);
    }
    let message = format!("`{}` declares the result `Null`.", function.text);
    let hint = format!(
        "A function that returns nothing declares no result: write `fn {}(...) {{ ... }}`.",
        function.text
    );
    Err(fault(codes::TYPE_MISMATCH, &message, &hint, ty.span))
}

/// Checks the constants in initialization order and lowers their initializers.
fn constants(
    checker: &mut Checker<'_>,
    loaded: &Loaded,
) -> Result<Vec<program::Constant>, Diagnostic> {
    let mut lowered = Vec::new();
    for (module, unit) in loaded.modules.iter().enumerate() {
        for item in unit.module().items() {
            let Item::Constant(c) = item else { continue };
            let slot = lowered.len() as u32;
            let declared = match &c.ty {
                Some(t) => Some(resolve(t, &checker.scopes[module], checker.request.registry)?),
                None => None,
            };
            let mut fx = Fx {
                module,
                locals: Locals::default(),
                current: None,
                result: None,
                constant: Some(slot),
            };
            fx.locals.push(c.value.span);
            let (value, ty) = checker.expr(&mut fx, &c.value, declared.as_ref())?;
            let ty = declared.unwrap_or(ty);
            checker.constants[slot as usize].ty = Some(ty.clone());
            checker.record_reference(
                c.name.span,
                Referent::Constant { definition: c.span, ty: Some(ty) },
            );
            let locals = fx.locals.count();
            lowered.push(program::Constant { name: Arc::from(c.name.text), value, locals });
        }
    }
    Ok(lowered)
}

/// Checks one function body and lowers it.
fn function(
    checker: &mut Checker<'_>,
    module: usize,
    id: FunctionId,
    f: &ast::Function<'_>,
) -> Result<program::Function, Diagnostic> {
    let info = checker.functions[id.0 as usize].clone();
    let mut fx = Fx {
        module,
        locals: Locals::default(),
        current: Some(id),
        result: info.result.clone(),
        constant: None,
    };
    fx.locals.push(f.body.span);
    for (p, (_, ty)) in f.params.iter().zip(&info.params) {
        checker.declare(&mut fx, &p.name, ty.clone(), Origin::Parameter, 0)?;
    }
    let (body, returns) = checker.statements(&mut fx, &f.body.statements())?;
    if let (false, Some(result)) = (returns, &info.result) {
        let message = format!(
            "`{}` can reach its end without returning a value of type `{result}`.",
            info.name
        );
        let hint = "Return a value on every path; JLV has no implicit final-expression return.";
        let end = Span { start: f.body.span.end.saturating_sub(1), ..f.body.span };
        return Err(fault(codes::TYPE_MISMATCH, &message, hint, end));
    }
    Ok(program::Function {
        name: info.name,
        params: info.params.len() as u32,
        locals: fx.locals.count(),
        body,
        span: f.span,
    })
}

impl<'a> Checker<'a> {
    /// Checks a block's statements in a fresh child scope; reports whether every path
    /// through them returns or fails.
    pub fn block(
        &mut self,
        fx: &mut Fx,
        block: &ast::Block<'_>,
    ) -> Result<(program::Block, bool), Diagnostic> {
        fx.locals.push(block.span);
        let checked = self.statements(fx, &block.statements());
        fx.locals.pop();
        checked
    }

    fn statements(
        &mut self,
        fx: &mut Fx,
        statements: &[Stmt<'_>],
    ) -> Result<(program::Block, bool), Diagnostic> {
        let mut lowered = Vec::with_capacity(statements.len());
        let mut returns = false;
        for statement in statements {
            let (stmt, ends) = self.statement(fx, statement)?;
            lowered.push(stmt);
            returns |= ends;
        }
        Ok((program::Block { statements: lowered }, returns))
    }

    fn statement(
        &mut self,
        fx: &mut Fx,
        stmt: &Stmt<'_>,
    ) -> Result<(program::Stmt, bool), Diagnostic> {
        match stmt {
            Stmt::Let { mutable, name, ty, value, span } => {
                let declared = match ty {
                    Some(t) => Some(resolve(t, &self.scopes[fx.module], self.request.registry)?),
                    None => None,
                };
                let (value, found) = self.expr(fx, value, declared.as_ref())?;
                let ty = declared.unwrap_or(found);
                let origin = if *mutable { Origin::Var } else { Origin::Let };
                let slot = self.declare(fx, name, ty, origin, span.end)?;
                Ok((program::Stmt::Let { slot, value }, false))
            }
            Stmt::Assign { name, value, .. } => self.assign(fx, name, value),
            Stmt::Return { value, span } => self.return_statement(fx, value.as_ref(), *span),
            Stmt::Expr(e) => {
                let (value, ty) = match e.kind() {
                    ast::ExprKind::Call(callee, args) => {
                        self.call_statement(fx, &callee, &args, e.span)?
                    }
                    _ => self.expr(fx, e, None)?,
                };
                if ty.is_nominal("Recipe") {
                    let message = "This recipe is built and then dropped.";
                    let hint = "Return it, or include it in the recipe the operation returns; \
                                a recipe has effect only when returned.";
                    return Err(fault(codes::INVALID_SOURCE, message, hint, e.span));
                }
                Ok((program::Stmt::Expr(value), ty == Type::Never))
            }
            Stmt::If { arms, otherwise, .. } => self.if_statement(fx, arms, otherwise.as_ref()),
            Stmt::For { key, name, items, body, span } => {
                self.for_statement(fx, key.as_ref(), name, items, body, *span)
            }
        }
    }

    /// `for name in list { }` or `for key, value in map { }`.
    fn for_statement(
        &mut self,
        fx: &mut Fx,
        key: Option<&ast::Name<'_>>,
        name: &ast::Name<'_>,
        items: &ast::Expr<'_>,
        body: &ast::Block<'_>,
        span: Span,
    ) -> Result<(program::Stmt, bool), Diagnostic> {
        let (items, ty) = self.expr(fx, items, None)?;
        let (key_ty, item) =
            crate::forms::loop_types(1 + usize::from(key.is_some()), &ty, items.span)?;
        fx.locals.push(body.span);
        let bound = (|| {
            let key = match (key, key_ty) {
                (Some(key), Some(ty)) => Some(self.bind(fx, key, ty)?),
                _ => None,
            };
            let slot = self.bind(fx, name, item)?;
            let (body, _) = self.block(fx, body)?;
            Ok::<_, Diagnostic>((key, slot, body))
        })();
        fx.locals.pop();
        let (key, slot, body) = bound?;
        let stmt = match key {
            Some(key) => program::Stmt::ForEntries { key, value: slot, items, body, span },
            None => program::Stmt::For { slot, items, body, span },
        };
        Ok((stmt, false))
    }

    fn assign(
        &mut self,
        fx: &mut Fx,
        name: &ast::Name<'_>,
        value: &ast::Expr<'_>,
    ) -> Result<(program::Stmt, bool), Diagnostic> {
        let Some(local) = fx.locals.lookup(name.text).cloned() else {
            let hint = if self.scopes[fx.module].symbols.contains_key(name.text) {
                "Module constants and imports are fixed; declare a local copy with `var`, as \
                 in `var count = COUNT`, and assign to that."
            } else {
                "Declare it first with `var`, as in `var x = 0`; only a `var` can be assigned."
            };
            let message = format!("There is no local `{}` to assign.", name.text);
            return Err(fault(codes::UNBOUND_NAME, &message, hint, name.span));
        };
        if !local.is_mutable() {
            let message = format!("`{}` cannot be assigned again.", name.text);
            let hint = "Declare it with `var` to assign to it; a `let`, a parameter and a \
                        loop's names are fixed.";
            let problem = codes::problem(codes::INVALID_SOURCE, &message, hint);
            return Err(Diagnostic::at(problem, name.span).related(local.span));
        }
        self.record_reference(name.span, local.referent());
        let (value, ty) = self.expr(fx, value, Some(&local.ty))?;
        if !assignable(&ty, &local.ty) {
            return Err(mismatch(&local.ty, &ty, value.span));
        }
        Ok((program::Stmt::Assign { slot: local.slot, value }, false))
    }

    fn return_statement(
        &mut self,
        fx: &mut Fx,
        value: Option<&ast::Expr<'_>>,
        span: Span,
    ) -> Result<(program::Stmt, bool), Diagnostic> {
        if fx.current.is_none() {
            return Err(fault(
                codes::INVALID_SOURCE,
                "`return` outside a function.",
                "Remove it.",
                span,
            ));
        }
        let value = match (value, fx.result.clone()) {
            (Some(e), Some(result)) => Some(self.expect(fx, e, &result)?),
            (None, None) => None,
            (None, Some(result)) => {
                return Err(fault(
                    codes::TYPE_MISMATCH,
                    &format!("This function returns `{result}`, so `return` needs a value."),
                    "Return a value of that type.",
                    span,
                ));
            }
            (Some(e), None) => {
                let name = fx.current.map(|id| self.functions[id.0 as usize].name.clone());
                let name = name.unwrap_or_default();
                return Err(fault(
                    codes::TYPE_MISMATCH,
                    &format!("`{name}` declares no result, so it cannot return a value."),
                    &if *self.request.entry.function == *name
                        && self.request.entry.role == Role::Deployment
                    {
                        "A deployment returns nothing or its outputs: declare `-> \
                         Map<OutputRef>` and return a map of outputs, or write `return` alone."
                            .to_string()
                    } else {
                        format!(
                            "Declare the result, as in `fn {name}(...) -> Int`, or write `return` \
                             alone."
                        )
                    },
                    e.span,
                ));
            }
        };
        Ok((program::Stmt::Return { value, span }, true))
    }

    fn if_statement(
        &mut self,
        fx: &mut Fx,
        arms: &[(ast::Expr<'_>, ast::Block<'_>)],
        otherwise: Option<&ast::Block<'_>>,
    ) -> Result<(program::Stmt, bool), Diagnostic> {
        let mut lowered = Vec::with_capacity(arms.len());
        let mut all_return = true;
        for (condition, block) in arms {
            let condition = self.condition(fx, condition)?;
            let (block, returns) = self.block(fx, block)?;
            all_return &= returns;
            lowered.push((condition, block));
        }
        let otherwise = match otherwise {
            Some(block) => {
                let (block, returns) = self.block(fx, block)?;
                all_return &= returns;
                Some(block)
            }
            None => {
                all_return = false;
                None
            }
        };
        Ok((program::Stmt::If { arms: lowered, otherwise }, all_return))
    }

    /// A function or export symbol that `name` refers to at module level.
    pub fn module_symbol(&self, fx: &Fx, name: &str) -> Option<Symbol<'a>> {
        self.scopes[fx.module].symbols.get(name).map(|(s, _)| *s)
    }
}

/// Fails on the first call that lies on a cycle of the call graph: a call whose caller
/// and callee share a strongly connected component. The components are computed once,
/// so the check is linear in the size of the call graph.
fn acyclic(checker: &Checker<'_>) -> Result<(), Diagnostic> {
    let n = checker.functions.len();
    let mut edges = vec![Vec::new(); n];
    for (from, to, _) in &checker.calls {
        edges[from.0 as usize].push(to.0 as usize);
    }
    for targets in &mut edges {
        targets.sort_unstable();
        targets.dedup();
    }
    let component = components(&edges);
    for (from, to, span) in &checker.calls {
        if component[from.0 as usize] == component[to.0 as usize] {
            let caller = &checker.functions[from.0 as usize].name;
            let callee = &checker.functions[to.0 as usize].name;
            let message = format!("`{caller}` calls `{callee}`, which leads back to `{caller}`.");
            let hint =
                "JLV call graphs are acyclic; rewrite the computation with a bounded `for` loop.";
            return Err(fault(codes::RECURSIVE_CALL, &message, hint, *span));
        }
    }
    Ok(())
}

/// What a function does, through every function it calls, that a constant initializer
/// must not: the latest constant it reads, with the read, and a call that needs an
/// entrypoint invocation.
#[derive(Debug, Clone, Copy, Default)]
struct Reach {
    latest_read: Option<(u32, Span)>,
    invocation: Option<Span>,
}

impl Reach {
    fn join(self, other: Reach) -> Reach {
        let latest_read = match (self.latest_read, other.latest_read) {
            (Some(a), Some(b)) => Some(if b.0 > a.0 { b } else { a }),
            (a, b) => a.or(b),
        };
        Reach { latest_read, invocation: self.invocation.or(other.invocation) }
    }
}

/// Fails when a constant initializer calls a function that, directly or through the
/// functions it calls, reads a constant not yet initialized or calls a native that
/// needs an entrypoint invocation (JDD 0004: module constants are pure and initialized
/// in source order). The call graph is acyclic here, so each function is visited once.
fn initializers_are_pure(checker: &Checker<'_>) -> Result<(), Diagnostic> {
    if checker.constant_calls.is_empty() {
        return Ok(());
    }
    let n = checker.functions.len();
    let mut own = vec![Reach::default(); n];
    for (f, slot, span) in &checker.constant_reads {
        let reach = Reach { latest_read: Some((*slot, *span)), invocation: None };
        own[f.0 as usize] = own[f.0 as usize].join(reach);
    }
    for (f, span) in &checker.invocation_calls {
        let reach = Reach { latest_read: None, invocation: Some(*span) };
        own[f.0 as usize] = own[f.0 as usize].join(reach);
    }
    let mut callees = vec![Vec::new(); n];
    for (from, to, _) in &checker.calls {
        callees[from.0 as usize].push(to.0 as usize);
    }
    let reach = reach_through_calls(&callees, own);
    for (slot, f, _) in &checker.constant_calls {
        let constant = &checker.constants[*slot as usize].name;
        let callee = &checker.functions[f.0 as usize].name;
        let found = reach[f.0 as usize];
        if let Some((read, span)) = found.latest_read.filter(|(read, _)| read >= slot) {
            let read = &checker.constants[read as usize].name;
            let message = format!(
                "The constant `{constant}` calls `{callee}`, which reads the constant \
                 `{read}` before it is initialized."
            );
            let hint = format!("Define `{read}` before `{constant}`, or compute it without it.");
            return Err(fault(codes::UNINITIALIZED_BINDING, &message, &hint, span));
        }
        if let Some(span) = found.invocation {
            let message = format!(
                "The constant `{constant}` calls `{callee}`, which makes a call that needs an \
                 entrypoint invocation."
            );
            let hint = "Call it from a function the entrypoint calls, not from a constant.";
            return Err(fault(codes::TYPE_MISMATCH, &message, hint, span));
        }
    }
    Ok(())
}

/// Joins each function's own reach with the reach of every function it calls, in one
/// depth-first pass without recursion over the acyclic call graph.
fn reach_through_calls(callees: &[Vec<usize>], own: Vec<Reach>) -> Vec<Reach> {
    let mut reach = own;
    let mut done = vec![false; callees.len()];
    for root in 0..callees.len() {
        if done[root] {
            continue;
        }
        let mut frames = vec![(root, 0)];
        while let Some(&mut (node, ref mut edge)) = frames.last_mut() {
            if let Some(&to) = callees[node].get(*edge) {
                *edge += 1;
                if !done[to] {
                    frames.push((to, 0));
                }
                continue;
            }
            frames.pop();
            done[node] = true;
            let joined = callees[node].iter().fold(reach[node], |acc, &to| acc.join(reach[to]));
            reach[node] = joined;
        }
    }
    reach
}

/// The strongly connected component of every node, by Tarjan's algorithm without
/// recursion, so a deep call chain cannot overflow the stack.
fn components(edges: &[Vec<usize>]) -> Vec<usize> {
    const UNSEEN: usize = usize::MAX;
    let n = edges.len();
    let (mut index, mut low, mut component) = (vec![UNSEEN; n], vec![0; n], vec![UNSEEN; n]);
    let (mut on_stack, mut stack) = (vec![false; n], Vec::new());
    let (mut next_index, mut next_component) = (0, 0);
    for root in 0..n {
        if index[root] != UNSEEN {
            continue;
        }
        // Each frame is a node and the position of the next edge to follow from it.
        let mut frames = vec![(root, 0)];
        index[root] = next_index;
        low[root] = next_index;
        next_index += 1;
        stack.push(root);
        on_stack[root] = true;
        while let Some(&mut (node, ref mut edge)) = frames.last_mut() {
            if let Some(&to) = edges[node].get(*edge) {
                *edge += 1;
                if index[to] == UNSEEN {
                    index[to] = next_index;
                    low[to] = next_index;
                    next_index += 1;
                    stack.push(to);
                    on_stack[to] = true;
                    frames.push((to, 0));
                } else if on_stack[to] {
                    low[node] = low[node].min(index[to]);
                }
                continue;
            }
            frames.pop();
            if let Some(&(parent, _)) = frames.last() {
                low[parent] = low[parent].min(low[node]);
            }
            if low[node] == index[node] {
                while let Some(member) = stack.pop() {
                    on_stack[member] = false;
                    component[member] = next_component;
                    if member == node {
                        break;
                    }
                }
                next_component += 1;
            }
        }
    }
    component
}

/// Finds the entry function and checks its role contract.
fn entry(checker: &Checker<'_>, loaded: &Loaded) -> Result<FunctionId, Diagnostic> {
    let request = checker.request;
    let unit = &loaded.modules[loaded.entry];
    let found = checker.scopes[loaded.entry].symbols.get(&request.entry.function).and_then(
        |(s, _)| match s {
            Symbol::Function(id) if checker.functions[id.0 as usize].module == loaded.entry => {
                Some(*id)
            }
            _ => None,
        },
    );
    let Some(id) = found else {
        let module = crate::modules::dotted(&unit.key);
        let message = format!("`{module}` defines no function `{}`.", request.entry.function);
        let hint = "Name the entry's `function` as it is defined in its `source`.";
        return Err(Diagnostic::unplaced(codes::problem(codes::UNBOUND_NAME, &message, hint)));
    };
    let info = &checker.functions[id.0 as usize];
    let params: Vec<&Type> = info.params.iter().map(|(_, t)| t).collect();
    let fits = match request.entry.role {
        Role::Deployment => {
            // No result, or the stack's outputs (JDD 0016, "Entries").
            let outputs = Type::map(Type::nominal("OutputRef"));
            params.len() == 1
                && params[0].is_nominal("DeployContext")
                && info.result.as_ref().is_none_or(|r| *r == outputs)
        }
        Role::Operation => {
            params.len() == 1
                && params[0].is_nominal("OpContext")
                && info.result.as_ref().is_some_and(|r| r.is_nominal("Recipe"))
        }
        Role::Transform => {
            params.iter().all(|t| t.is_plain()) && info.result.as_ref().is_some_and(Type::is_plain)
        }
        Role::Export => params.is_empty(),
    };
    if !fits {
        let wanted = match request.entry.role {
            Role::Deployment => {
                "`fn NAME(ctx: DeployContext)` or `fn NAME(ctx: DeployContext) -> Map<OutputRef>`"
            }
            Role::Operation => "`fn NAME(ctx: OpContext) -> Recipe`",
            Role::Transform => "plain-data parameters and a plain-data result",
            Role::Export => "no parameters",
        };
        let role = request.entry.role.name();
        let article = if role.starts_with(['a', 'e', 'i', 'o', 'u']) { "An" } else { "A" };
        let message = format!("{article} {role} entry needs {wanted}.");
        let hint = "Change the signature, or the entry's `kind` in jlv.toml.";
        return Err(fault(codes::TYPE_MISMATCH, &message, hint, info.span));
    }
    Ok(id)
}

/// The export a library symbol names, for diagnostics.
pub(crate) fn export_kind(export: &Export) -> &'static str {
    match export {
        Export::Function { .. } => "a function",
        Export::Namespace(_) => "a namespace",
        Export::Type(_) => "a type",
        Export::Constant { .. } => "a constant",
    }
}
