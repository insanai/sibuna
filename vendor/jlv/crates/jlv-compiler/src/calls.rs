//! Call checking (JDD 0004, "Grammar" and "Values and type system").
//!
//! A call target resolves statically to a source function, a library native, an
//! approved method of a nominal type, or a prelude builtin; computed function values
//! and dynamic dispatch do not exist. Positional arguments fill parameters in order,
//! named arguments fill the parameter they name, and unknown, duplicate or missing
//! arguments are `argument_error`. Arguments are checked and evaluated in the order
//! they are written. Library signatures may use type variables, which unify with the
//! argument types, and keyed results, whose type comes from a captured schema.

use std::collections::BTreeMap;
use std::sync::Arc;

use jlv_core::{Diagnostic, Span};
use jlv_lang::program::{self, ArgSlot, Args, Builtin, ExprKind};
use jlv_lang::signature::{Export, Omitted, Param, Signature};
use jlv_lang::types::assignable;
use jlv_lang::{Type, codes};
use jlv_syntax::view::{self as ast, ExprKind as Ast};

use crate::check::{Checker, Fx};
use crate::expr::Typed;
use crate::index::Referent;
use crate::scope::Symbol;
use crate::typing::{fault, mismatch};

/// Type variable bindings of one native call.
type Subst = BTreeMap<u8, Type>;

/// The callee of a native call: its name, signature and an optional receiver.
struct NativeCallee<'s> {
    name: Arc<str>,
    signature: &'s Signature,
    receiver: Option<(program::Expr, Type)>,
}

impl Checker<'_> {
    /// Checks a call expression.
    pub fn call(
        &mut self,
        fx: &mut Fx,
        callee: &ast::Expr<'_>,
        args: &[ast::Arg<'_>],
        expected: Option<&Type>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        match callee.kind() {
            Ast::Name(name) if fx.locals.lookup(name).is_none() => {
                let symbol = self.module_symbol(fx, name);
                match symbol {
                    Some(symbol) => {
                        self.record_reference(callee.span, self.symbol_referent(symbol, name));
                    }
                    None if Builtin::named(name).is_some() => {
                        let referent = Referent::Prelude { name: Arc::from(name) };
                        self.record_reference(callee.span, referent);
                    }
                    None => {}
                }
                match symbol {
                    Some(Symbol::Function(id)) => self.source_call(fx, id, args, span, false),
                    Some(Symbol::Export(Export::Function { native, signature })) => {
                        let callee =
                            NativeCallee { name: native.clone(), signature, receiver: None };
                        self.native_call(fx, callee, args, expected, span)
                    }
                    Some(_) => Err(not_callable(name, callee.span)),
                    None => match Builtin::named(name) {
                        Some(builtin) => self.builtin(fx, builtin, args, span),
                        None => Err(self.unbound(fx, name, callee.span)),
                    },
                }
            }
            Ast::Field(base, method) => {
                if let Some(export) = self.namespace_member(fx, &base, &method)? {
                    let Export::Function { native, signature } = export else {
                        return Err(not_callable(method.text, method.span));
                    };
                    let callee = NativeCallee { name: native.clone(), signature, receiver: None };
                    return self.native_call(fx, callee, args, expected, span);
                }
                self.method_call(fx, &base, &method, args, expected, span)
            }
            _ => Err(fault(
                codes::TYPE_MISMATCH,
                "Only named functions and methods can be called.",
                "JLV has no computed function values; call a function by its name.",
                callee.span,
            )),
        }
    }

    /// Checks a call that stands as a statement, the one place where a call of a
    /// function that returns no value may appear.
    pub fn call_statement(
        &mut self,
        fx: &mut Fx,
        callee: &ast::Expr<'_>,
        args: &[ast::Arg<'_>],
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        if let Ast::Name(name) = callee.kind()
            && fx.locals.lookup(name).is_none()
            && let Some(Symbol::Function(id)) = self.module_symbol(fx, name)
        {
            self.record_reference(callee.span, self.function_referent(id));
            return self.source_call(fx, id, args, span, true);
        }
        self.call(fx, callee, args, None, span)
    }

    /// Checks a call of a source function; `statement` when its value is discarded.
    fn source_call(
        &mut self,
        fx: &mut Fx,
        id: program::FunctionId,
        args: &[ast::Arg<'_>],
        span: Span,
        statement: bool,
    ) -> Result<Typed, Diagnostic> {
        let info = self.functions[id.0 as usize].clone();
        if info.result.is_none() && !statement {
            let message = format!(
                "`{}` returns no value, so its call cannot be bound or used in an expression.",
                info.name
            );
            let hint = format!(
                "Call it as a statement, `{}(...)`, or give it a result with `-> T` and \
                 return one.",
                info.name
            );
            return Err(fault(codes::TYPE_MISMATCH, &message, &hint, span));
        }
        let params: Vec<Param> =
            info.params.iter().map(|(n, t)| Param::required(n, t.clone())).collect();
        let filled = match_arguments(&params, None, args, span)?;
        let mut exprs = Vec::with_capacity(args.len());
        for (j, arg) in args.iter().enumerate() {
            let p = param_of(&filled, j);
            if let Some(name) = &arg.name {
                let (callee, param) = (info.name.clone(), &params[p]);
                self.record_parameter(name.span, callee, param);
            }
            exprs.push(self.expect(fx, &arg.value, &params[p].ty)?);
        }
        let slots = filled.iter().map(|j| ArgSlot::Source(j.unwrap_or(0) as u32)).collect();
        if let Some(caller) = fx.current {
            self.calls.push((caller, id, span));
        } else if let Some(slot) = fx.constant {
            self.constant_calls.push((slot, id, span));
        }
        let kind = ExprKind::Call(id, Args { exprs, slots });
        Ok((program::Expr { kind, span }, info.result.unwrap_or(Type::Null)))
    }

    fn method_call(
        &mut self,
        fx: &mut Fx,
        base: &ast::Expr<'_>,
        method: &ast::Name<'_>,
        args: &[ast::Arg<'_>],
        expected: Option<&Type>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        let (receiver, ty) = self.expr(fx, base, None)?;
        let registry = self.request.registry;
        let def = match &ty {
            Type::Nominal(name, _) => registry.type_def(name),
            _ => None,
        };
        let Some(def) = def else {
            let message =
                format!("`{ty}` has no methods; `{}` cannot be called on it.", method.text);
            let hint = "Call a library function with the value as an argument instead.";
            return Err(fault(codes::TYPE_MISMATCH, &message, hint, method.span));
        };
        let found = def.methods.get(method.text);
        if let Some((_, signature)) = found {
            let referent = Referent::Method {
                type_name: def.name.clone(),
                name: Arc::from(method.text),
                signature: signature.clone(),
            };
            self.record_reference(method.span, referent);
        }
        let Some((native, signature)) = found else {
            let names: Vec<&str> = def.methods.keys().map(|k| &**k).collect();
            let hint = match (
                crate::forms::removed(method.text),
                gd_report::suggest(method.text, names.clone()),
            ) {
                (Some(hint), _) => hint.to_string(),
                (None, Some(s)) => format!("Did you mean `{s}`?"),
                (None, None) => format!("`{}` has the methods {}.", def.name, names.join(", ")),
            };
            let message = format!("`{}` has no method `{}`.", def.name, method.text);
            return Err(fault(codes::UNBOUND_NAME, &message, &hint, method.span));
        };
        let callee = NativeCallee {
            name: native.clone(),
            signature,
            receiver: Some((receiver, ty.clone())),
        };
        self.native_call(fx, callee, args, expected, span)
    }

    fn native_call(
        &mut self,
        fx: &mut Fx,
        callee: NativeCallee<'_>,
        args: &[ast::Arg<'_>],
        expected: Option<&Type>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        let signature = callee.signature;
        if signature.needs_invocation && fx.constant.is_some() {
            let message =
                "This call needs an entrypoint invocation; it cannot initialize a constant.";
            let hint = "Move the call into a function the entrypoint calls.";
            return Err(fault(codes::TYPE_MISMATCH, message, hint, span));
        }
        if let (true, Some(current)) = (signature.needs_invocation, fx.current) {
            self.invocation_calls.push((current, span));
        }
        let filled = match_arguments(&signature.params, signature.positional, args, span)?;
        let mut subst = Subst::new();
        let offset = usize::from(callee.receiver.is_some());
        let mut exprs = Vec::with_capacity(args.len() + offset);
        if let Some((receiver, _)) = callee.receiver {
            exprs.push(receiver);
        }
        for (j, arg) in args.iter().enumerate() {
            let param = &signature.params[param_of(&filled, j)];
            if let Some(name) = &arg.name {
                self.record_parameter(name.span, callee.name.clone(), param);
            }
            let closed = substitute(&param.ty, &subst);
            let hint = if !param.ty.is_open() || (!closed.is_open() && needs_hint(&arg.value)) {
                Some(&closed)
            } else {
                None
            };
            let (value, found) = self.synthesize(fx, &arg.value, hint)?;
            if !unify(&param.ty, &found, &mut subst) {
                return Err(mismatch(&substitute(&param.ty, &subst), &found, value.span));
            }
            exprs.push(value);
        }
        let result = self.result_type(signature, &filled, args, &mut subst, expected, span)?;
        let slots = filled.iter().zip(&signature.params).map(|(j, p)| match (j, &p.omitted) {
            (Some(j), _) => ArgSlot::Source((j + offset) as u32),
            (None, Omitted::Default(v)) => ArgSlot::Default(v.clone()),
            (None, _) => ArgSlot::Absent,
        });
        let slots = (0..offset).map(|_| ArgSlot::Source(0)).chain(slots).collect();
        let id = self.native(&callee.name, signature.cost);
        let kind = ExprKind::Native(id, Args { exprs, slots });
        Ok((program::Expr { kind, span }, result))
    }

    fn result_type(
        &self,
        signature: &Signature,
        filled: &[Option<usize>],
        args: &[ast::Arg<'_>],
        subst: &mut Subst,
        expected: Option<&Type>,
        span: Span,
    ) -> Result<Type, Diagnostic> {
        if let Type::Keyed(table) = &signature.result {
            return self.keyed(
                table,
                filled.first().copied().flatten().map(|j| &args[j].value),
                span,
            );
        }
        let result = substitute(&signature.result, subst);
        if !result.is_open() {
            return Ok(result);
        }
        if let Some(expected) = expected
            && unify(&signature.result, expected, subst)
        {
            return Ok(substitute(&signature.result, subst));
        }
        let hint = "Annotate the binding so the element type is known.";
        Err(fault(codes::TYPE_MISMATCH, "The result type cannot be inferred here.", hint, span))
    }

    /// The type of a keyed lookup such as `ctx.input("name")`.
    fn keyed(
        &self,
        table: &str,
        key: Option<&ast::Expr<'_>>,
        span: Span,
    ) -> Result<Type, Diagnostic> {
        let found = key.map(|k| (k.kind(), k.span));
        let Some((Ast::Str(key), key_span)) = found else {
            let message = format!("A `{table}` lookup needs a literal text key.");
            let hint = "Write the key as a string literal; lookups follow the closed schema.";
            return Err(fault(
                codes::ARGUMENT_ERROR,
                &message,
                hint,
                key.map_or(span, |k| k.span),
            ));
        };
        let entries = self.request.keyed.get(table);
        match entries.and_then(|e| e.get(key)) {
            Some(ty) => Ok(ty.clone()),
            None => {
                let names: Vec<&str> =
                    entries.map(|e| e.keys().map(|k| &**k).collect()).unwrap_or_default();
                let hint = match gd_report::suggest(key, names) {
                    Some(s) => format!("Did you mean `{s}`?"),
                    None => format!("Declare `{key}` in the entry's {table} schema."),
                };
                let message = match table {
                    "lock" => format!("jlv.lock pins no value named `{key}`."),
                    _ => format!("The {table} schema has no key `{key}`."),
                };
                Err(fault(codes::ARGUMENT_ERROR, &message, &hint, key_span))
            }
        }
    }

    fn builtin(
        &mut self,
        fx: &mut Fx,
        builtin: Builtin,
        args: &[ast::Arg<'_>],
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        if let Some(named) = args.iter().find_map(|a| a.name.as_ref()) {
            let message =
                format!("Prelude functions take positional arguments; `{}` is named.", named.text);
            return Err(fault(codes::ARGUMENT_ERROR, &message, "Remove the name.", named.span));
        }
        let arity = match builtin {
            Builtin::Len | Builtin::Keys | Builtin::Fail => 1..=1,
            Builtin::Contains => 2..=2,
            Builtin::Range => 1..=2,
        };
        if !arity.contains(&args.len()) {
            let message = format!(
                "This prelude function takes {} to {} arguments.",
                arity.start(),
                arity.end()
            );
            return Err(fault(
                codes::ARGUMENT_ERROR,
                &message,
                "Pass the documented arguments.",
                span,
            ));
        }
        let mut exprs = Vec::with_capacity(args.len());
        let result = match builtin {
            Builtin::Fail => {
                exprs.push(self.expect(fx, &args[0].value, &Type::Text)?);
                Type::Never
            }
            Builtin::Range => {
                for arg in args {
                    exprs.push(self.expect(fx, &arg.value, &Type::Int)?);
                }
                Type::list(Type::Int)
            }
            Builtin::Len | Builtin::Keys | Builtin::Contains => {
                self.collection_builtin(fx, builtin, args, &mut exprs)?
            }
        };
        let kind = ExprKind::Builtin(builtin, Args::positional(exprs));
        Ok((program::Expr { kind, span }, result))
    }

    fn collection_builtin(
        &mut self,
        fx: &mut Fx,
        builtin: Builtin,
        args: &[ast::Arg<'_>],
        exprs: &mut Vec<program::Expr>,
    ) -> Result<Type, Diagnostic> {
        let (collection, ty) = self.expr(fx, &args[0].value, None)?;
        let span = collection.span;
        exprs.push(collection);
        match (builtin, &ty) {
            (Builtin::Len, Type::Text | Type::Bytes | Type::List(_) | Type::Map(_)) => {
                Ok(Type::Int)
            }
            (Builtin::Keys, Type::Map(_)) => Ok(Type::list(Type::Text)),
            (Builtin::Contains, Type::List(item)) => {
                let item = (**item).clone();
                exprs.push(self.expect(fx, &args[1].value, &item)?);
                Ok(Type::Bool)
            }
            (Builtin::Contains, Type::Map(_) | Type::Record(_) | Type::Text) => {
                exprs.push(self.expect(fx, &args[1].value, &Type::Text)?);
                Ok(Type::Bool)
            }
            _ => {
                let message = format!("This prelude function does not apply to `{ty}`.");
                let hint = "`len` takes a text, bytes, list or map; `keys` a map.";
                Err(fault(codes::TYPE_MISMATCH, &message, hint, span))
            }
        }
    }
}

/// For each parameter, the index of the argument that fills it. With `positional`, the
/// first that many parameters are passed only by position and the rest only by name.
fn match_arguments(
    params: &[Param],
    positional: Option<usize>,
    args: &[ast::Arg<'_>],
    span: Span,
) -> Result<Vec<Option<usize>>, Diagnostic> {
    let mut filled: Vec<Option<usize>> = vec![None; params.len()];
    for (j, arg) in args.iter().enumerate() {
        if let Some(count) = positional {
            passing_style(params, count, j, arg)?;
        }
        let at = match &arg.name {
            None if j < params.len() => j,
            None => {
                let message = format!(
                    "The call passes {} arguments, but takes at most {}.",
                    args.len(),
                    params.len()
                );
                return Err(fault(
                    codes::ARGUMENT_ERROR,
                    &message,
                    "Remove the extra arguments.",
                    arg.value.span,
                ));
            }
            Some(name) => match params.iter().position(|p| *p.name == *name.text) {
                Some(at) => at,
                None => {
                    let names: Vec<&str> = params.iter().map(|p| &*p.name).collect();
                    let hint = match gd_report::suggest(name.text, names.clone()) {
                        Some(s) => format!("Did you mean `{s}`?"),
                        None => format!("The parameters are {}.", names.join(", ")),
                    };
                    let message = format!("There is no parameter `{}`.", name.text);
                    return Err(fault(codes::ARGUMENT_ERROR, &message, &hint, name.span));
                }
            },
        };
        if filled[at].is_some() {
            let message = format!("The parameter `{}` is given twice.", params[at].name);
            return Err(fault(
                codes::ARGUMENT_ERROR,
                &message,
                "Give each parameter once.",
                arg.value.span,
            ));
        }
        filled[at] = Some(j);
    }
    for (i, (p, f)) in params.iter().zip(&filled).enumerate() {
        if f.is_none() && p.omitted == Omitted::Required {
            let message = format!("The call does not give the required parameter `{}`.", p.name);
            let hint = if positional.is_some_and(|count| i < count) {
                format!(
                    "Write the {} first, by position, as in `(\"web\", ...)`; it is not passed \
                     by name.",
                    p.name
                )
            } else {
                format!("Add `{}: ...` to the call.", p.name)
            };
            return Err(fault(codes::ARGUMENT_ERROR, &message, &hint, span));
        }
    }
    Ok(filled)
}

/// Refuses the `j`th argument when it is named but its parameter is positional-only,
/// or positional where the parameters are named-only.
fn passing_style(
    params: &[Param],
    count: usize,
    j: usize,
    arg: &ast::Arg<'_>,
) -> Result<(), Diagnostic> {
    match &arg.name {
        Some(name) if params[..count.min(params.len())].iter().any(|p| *p.name == *name.text) => {
            let message = format!("`{}` is passed by position, not by name.", name.text);
            let hint = format!("Write the value first, without `{}:`.", name.text);
            Err(fault(codes::ARGUMENT_ERROR, &message, &hint, name.span))
        }
        None if j >= count && j < params.len() => {
            let param = &params[j].name;
            let message = format!("This argument must be named; it would fill `{param}`.");
            let hint = format!("Write `{param}: ...`, naming the field it sets.");
            Err(fault(codes::ARGUMENT_ERROR, &message, &hint, arg.value.span))
        }
        _ => Ok(()),
    }
}

/// The parameter the `j`th argument fills.
fn param_of(filled: &[Option<usize>], j: usize) -> usize {
    filled.iter().position(|f| *f == Some(j)).unwrap_or(0)
}

/// `ty` with the bound variables replaced.
fn substitute(ty: &Type, subst: &Subst) -> Type {
    match ty {
        Type::Var(n) => subst.get(n).cloned().unwrap_or(Type::Var(*n)),
        Type::List(item) => Type::list(substitute(item, subst)),
        Type::Map(item) => Type::map(substitute(item, subst)),
        Type::Nominal(name, args) => {
            Type::Nominal(name.clone(), args.iter().map(|a| substitute(a, subst)).collect())
        }
        other => other.clone(),
    }
}

/// Unifies a signature type with an argument type, binding variables; reports whether
/// the argument fits.
fn unify(param: &Type, found: &Type, subst: &mut Subst) -> bool {
    unify_mode(param, found, subst, false)
}

fn unify_mode(param: &Type, found: &Type, subst: &mut Subst, invariant: bool) -> bool {
    match (param, found) {
        (Type::Var(n), _) => match subst.get(n) {
            Some(bound) if invariant => *found == Type::Never || bound == found,
            Some(bound) if assignable(found, bound) => true,
            Some(bound) if assignable(bound, found) => {
                subst.insert(*n, found.clone());
                true
            }
            Some(_) => false,
            None => {
                if *found != Type::Never {
                    subst.insert(*n, found.clone());
                }
                true
            }
        },
        (_, Type::Never) => true,
        (Type::List(p), Type::List(f)) | (Type::Map(p), Type::Map(f)) => {
            unify_mode(p, f, subst, invariant)
        }
        (Type::Nominal(pn, pa), Type::Nominal(fn_, fa)) if pn == fn_ && pa.len() == fa.len() => {
            pa.iter().zip(fa).all(|(p, f)| unify_mode(p, f, subst, true))
        }
        _ if invariant => !param.is_open() && found == param,
        _ => !param.is_open() && assignable(found, param),
    }
}

impl Checker<'_> {
    /// Records that the named argument at `span` passes to `param` of `callee`.
    fn record_parameter(&self, span: Span, callee: Arc<str>, param: &Param) {
        let referent =
            Referent::Parameter { callee, name: param.name.clone(), ty: param.ty.clone() };
        self.record_reference(span, referent);
    }
}

fn not_callable(name: &str, span: Span) -> Diagnostic {
    let message = format!("`{name}` is not a function.");
    fault(codes::TYPE_MISMATCH, &message, "Call a function or method by its name.", span)
}

fn needs_hint(expr: &ast::Expr<'_>) -> bool {
    match expr.kind() {
        Ast::Paren(inner) => needs_hint(&inner),
        Ast::List(items) => items.is_empty(),
        Ast::Record(entries) => entries.is_empty(),
        _ => false,
    }
}
