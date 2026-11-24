//! Expression checking: bidirectional typing and lowering (JDD 0004, "Values and type
//! system").
//!
//! An expected type flows into literals: a list or map literal checks its elements
//! against an expected `List<T>` or `Map<T>`, and a record literal against an expected
//! record shape. Without an expected collection type, a literal's elements must share
//! one type; an expected `Value` alone does not select a mixed element type. Inside a
//! literal already expected as `List<Value>` or `Map<Value>`, a nested list or map
//! literal is expected as `List<Value>` or `Map<Value>` too, so JSON-like data needs
//! one annotation, not one per level (JDD 0011).

use std::sync::Arc;

use jlv_core::{Diagnostic, Span};
use jlv_lang::program::{self, BinaryOp, ExprKind, MapEntry, UnaryOp};
use jlv_lang::signature::Export;
use jlv_lang::types::{RecordType, assignable, common_type};
use jlv_lang::{Type, Value, codes};
use jlv_syntax::view::{self as ast, ExprKind as Ast};

use crate::check::{Checker, Fx, export_kind};
use crate::index::Referent;
use crate::scope::Symbol;
use crate::typing::{fault, mismatch};

/// A lowered expression and its type.
pub(crate) type Typed = (program::Expr, Type);

fn lowered(kind: ExprKind, span: Span) -> program::Expr {
    program::Expr { kind, span }
}

impl<'a> Checker<'a> {
    /// Checks `e` against an expected type and returns it with the type it has.
    pub fn expr(
        &mut self,
        fx: &mut Fx,
        e: &ast::Expr<'_>,
        expected: Option<&Type>,
    ) -> Result<Typed, Diagnostic> {
        let (value, ty) = self.synthesize(fx, e, expected)?;
        if let Some(expected) = expected
            && !expected.is_open()
            && !assignable(&ty, expected)
        {
            return Err(mismatch(expected, &ty, e.span));
        }
        Ok((value, ty))
    }

    /// Checks `e` against `ty` and returns the lowered expression.
    pub fn expect(
        &mut self,
        fx: &mut Fx,
        e: &ast::Expr<'_>,
        ty: &Type,
    ) -> Result<program::Expr, Diagnostic> {
        Ok(self.expr(fx, e, Some(ty))?.0)
    }

    /// Checks a condition: a `Bool`, never an unresolved provider output.
    pub fn condition(
        &mut self,
        fx: &mut Fx,
        e: &ast::Expr<'_>,
    ) -> Result<program::Expr, Diagnostic> {
        let (value, ty) = self.synthesize(fx, e, Some(&Type::Bool))?;
        if ty.is_nominal("OutputRef") {
            let message = "A provider output is not available during declaration evaluation.";
            let hint = "Declare a dependency or a health requirement. The planner binds \
                        provider outputs after it verifies the producing resource.";
            return Err(fault(codes::UNRESOLVED_REFERENCE, message, hint, e.span));
        }
        if !assignable(&ty, &Type::Bool) {
            return Err(mismatch(&Type::Bool, &ty, e.span));
        }
        Ok(value)
    }

    pub(crate) fn synthesize(
        &mut self,
        fx: &mut Fx,
        e: &ast::Expr<'_>,
        expected: Option<&Type>,
    ) -> Result<Typed, Diagnostic> {
        let span = e.span;
        match e.kind() {
            Ast::Int(n) => int_literal(n, false, span),
            Ast::Str(s) => Ok((lowered(ExprKind::Literal(Value::text(s)), span), Type::Text)),
            Ast::Bool(b) => Ok((lowered(ExprKind::Literal(Value::Bool(b)), span), Type::Bool)),
            Ast::Null => Ok((lowered(ExprKind::Literal(Value::Null), span), Type::Null)),
            Ast::Name(name) => self.name(fx, name, span),
            Ast::Paren(inner) => self.synthesize(fx, &inner, expected),
            Ast::List(items) => self.list(fx, &items, expected, span),
            Ast::Record(entries) => self.record(fx, &entries, expected, span),
            Ast::Unary(op, operand) => self.unary(fx, op, &operand, span),
            Ast::Binary(op, a, b) => self.binary(fx, op, &a, &b, span),
            Ast::And(a, b) => {
                let (a, b) = (self.condition(fx, &a)?, self.condition(fx, &b)?);
                Ok((lowered(ExprKind::And(Box::new(a), Box::new(b)), span), Type::Bool))
            }
            Ast::Or(a, b) => {
                let (a, b) = (self.condition(fx, &a)?, self.condition(fx, &b)?);
                Ok((lowered(ExprKind::Or(Box::new(a), Box::new(b)), span), Type::Bool))
            }
            Ast::Index(a, i) => self.index(fx, &a, &i, span),
            Ast::Field(base, name) => self.field(fx, &base, &name, span),
            Ast::Call(callee, args) => self.call(fx, &callee, &args, expected, span),
            Ast::Interp(parts) => self.interpolation(fx, &parts, span),
            Ast::Comprehension { names, items, body, filter } => {
                let form = crate::forms::Form {
                    names: &names,
                    items: &items,
                    body: &body,
                    filter: filter.as_ref(),
                };
                self.comprehension(fx, &form, expected, span)
            }
        }
    }

    fn name(&mut self, fx: &mut Fx, name: &str, span: Span) -> Result<Typed, Diagnostic> {
        if let Some(local) = fx.locals.lookup(name) {
            self.record_reference(span, local.referent());
            return Ok((lowered(ExprKind::Local(local.slot), span), local.ty.clone()));
        }
        let symbol = self.module_symbol(fx, name);
        if let Some(symbol) = symbol {
            self.record_reference(span, self.symbol_referent(symbol, name));
        }
        match symbol {
            Some(Symbol::Constant(slot)) => {
                if let Some(current) = fx.current {
                    self.constant_reads.push((current, slot, span));
                }
                self.constant(fx, slot, name, span)
            }
            Some(Symbol::Export(Export::Constant { value, ty })) => {
                Ok((lowered(ExprKind::Literal(value.clone()), span), ty.clone()))
            }
            Some(Symbol::Export(export)) => {
                let message = format!("`{name}` is {}, not a value.", export_kind(export));
                Err(fault(
                    codes::TYPE_MISMATCH,
                    &message,
                    "Call a function; JLV has no function values.",
                    span,
                ))
            }
            Some(Symbol::Function(_)) => {
                let message = format!("`{name}` is a function, not a value.");
                Err(fault(
                    codes::TYPE_MISMATCH,
                    &message,
                    "Call it; JLV has no function values or callbacks.",
                    span,
                ))
            }
            None if jlv_lang::program::Builtin::named(name).is_some() => {
                let message = format!("`{name}` is a prelude function, not a value.");
                Err(fault(codes::TYPE_MISMATCH, &message, "Call it with its arguments.", span))
            }
            None => Err(self.unbound(fx, name, span)),
        }
    }

    fn constant(&self, fx: &Fx, slot: u32, name: &str, span: Span) -> Result<Typed, Diagnostic> {
        let ready = fx.constant.is_none_or(|current| slot < current);
        match (&self.constants[slot as usize].ty, ready) {
            (Some(ty), true) => Ok((lowered(ExprKind::Constant(slot), span), ty.clone())),
            _ => {
                let message = format!("The constant `{name}` is read before it is initialized.");
                let hint = "Define a constant before the constants that use it.";
                Err(fault(codes::UNINITIALIZED_BINDING, &message, hint, span))
            }
        }
    }

    /// An `unbound_name` diagnostic with a suggestion from the names in scope.
    pub fn unbound(&self, fx: &Fx, name: &str, span: Span) -> Diagnostic {
        let module = self.scopes[fx.module].symbols.keys().map(|k| &**k);
        let builtins = ["len", "keys", "contains", "range", "fail"].into_iter();
        let names: Vec<&str> = fx.locals.names().chain(module).chain(builtins).collect();
        let elsewhere = crate::forms::removed(name)
            .map(str::to_string)
            .or_else(|| self.parameter_elsewhere(fx, name));
        let hint = match (elsewhere, gd_report::suggest(name, names)) {
            (Some(hint), _) => hint,
            (None, Some(s)) => format!("Did you mean `{s}`?"),
            (None, None) => "Bind it with `let`, define it in this module, or import it.".into(),
        };
        fault(codes::UNBOUND_NAME, &format!("No `{name}` is in scope."), &hint, span)
    }

    /// When `name` is a parameter of another function of the module, such as the `ctx` of
    /// an entry used in a helper, the hint to pass it on; a function sees only its own
    /// parameters and the module's names.
    fn parameter_elsewhere(&self, fx: &Fx, name: &str) -> Option<String> {
        let current = self.functions.get(fx.current?.0 as usize)?;
        let (owner, ty) =
            self.functions.iter().filter(|f| f.module == fx.module).find_map(|f| {
                f.params.iter().find(|(p, _)| **p == *name).map(|(_, ty)| (&f.name, ty))
            })?;
        Some(format!(
            "`{name}` is a parameter of `{owner}`; pass it on, as in `fn {}({name}: {ty}, ...)`.",
            current.name
        ))
    }

    /// A literal and the type it forms, when that type nests no deeper than `[limits]
    /// type_depth`; the recursive functions over types then recurse a bounded depth.
    fn formed(&self, code: program::Expr, ty: Type) -> Result<Typed, Diagnostic> {
        let limit = self.request.limits.type_depth;
        if ty.depth() <= limit {
            return Ok((code, ty));
        }
        let message = format!("This value's type would nest more than {limit} levels deep.");
        let hint = "Build flatter data: a list of records rather than records within records.";
        Err(fault(codes::BUDGET_EXHAUSTED, &message, hint, code.span))
    }

    fn list(
        &mut self,
        fx: &mut Fx,
        items: &[ast::Expr<'_>],
        expected: Option<&Type>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        if let Some(Type::List(item)) = expected {
            let item = (**item).clone();
            let mut values = Vec::with_capacity(items.len());
            for e in items {
                values.push(self.expect(fx, e, &nested(&item, e))?);
            }
            return self.formed(lowered(ExprKind::List(values), span), Type::list(item));
        }
        let mut values = Vec::with_capacity(items.len());
        let mut types = Vec::with_capacity(items.len());
        for e in items {
            let (v, t) = self.expr(fx, e, None)?;
            values.push(v);
            types.push(t);
        }
        let Some(item) = common_type(types.iter()) else {
            return Err(no_element_type("list", &types, span));
        };
        self.formed(lowered(ExprKind::List(values), span), Type::list(item))
    }

    fn record(
        &mut self,
        fx: &mut Fx,
        entries: &[ast::Entry<'_>],
        expected: Option<&Type>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        if let Some(Type::Record(shape)) = expected {
            return self.record_shape(fx, entries, shape.clone(), span);
        }
        let item = match expected {
            Some(Type::Map(item)) => Some((**item).clone()),
            _ => None,
        };
        let mut lowered_entries = Vec::with_capacity(entries.len());
        let mut types = Vec::with_capacity(entries.len());
        for entry in entries {
            let inner = item.as_ref().map(|item| nested(item, &entry.value));
            let (value, ty) = self.expr(fx, &entry.value, inner.as_ref())?;
            types.push(ty);
            lowered_entries.push(MapEntry {
                key: Arc::from(entry.key.text),
                key_span: entry.key.span,
                value,
            });
        }
        let item = match item {
            Some(item) => item,
            None => {
                common_type(types.iter()).ok_or_else(|| no_element_type("map", &types, span))?
            }
        };
        self.formed(lowered(ExprKind::Map(lowered_entries), span), Type::map(item))
    }

    fn record_shape(
        &mut self,
        fx: &mut Fx,
        entries: &[ast::Entry<'_>],
        shape: Arc<RecordType>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        let mut lowered_entries = Vec::with_capacity(entries.len());
        for entry in entries {
            let field_ty = match shape.field(entry.key.text) {
                Some(field) => field.ty.clone(),
                None => match &shape.rest {
                    Some(rest) => rest.clone(),
                    None => {
                        let names: Vec<&str> = shape.fields.iter().map(|f| &*f.name).collect();
                        let hint = match gd_report::suggest(entry.key.text, names.clone()) {
                            Some(s) => format!("Did you mean `{s}`?"),
                            None => format!("The record takes {}.", names.join(", ")),
                        };
                        let message = format!("The record has no field `{}`.", entry.key.text);
                        return Err(fault(codes::TYPE_MISMATCH, &message, &hint, entry.key.span));
                    }
                },
            };
            let value = self.expect(fx, &entry.value, &field_ty)?;
            lowered_entries.push(MapEntry {
                key: Arc::from(entry.key.text),
                key_span: entry.key.span,
                value,
            });
        }
        for field in shape.fields.iter().filter(|f| f.required) {
            if !entries.iter().any(|e| e.key.text == &*field.name) {
                let message = format!("The record needs the field `{}`.", field.name);
                return Err(fault(
                    codes::TYPE_MISMATCH,
                    &message,
                    &format!("Add `{}: ...`.", field.name),
                    span,
                ));
            }
        }
        self.formed(lowered(ExprKind::Map(lowered_entries), span), Type::Record(shape))
    }

    fn unary(
        &mut self,
        fx: &mut Fx,
        op: UnaryOp,
        operand: &ast::Expr<'_>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        if op == UnaryOp::Neg
            && let Ast::Int(n) = operand.kind()
        {
            return int_literal(n, true, span);
        }
        let ty = if op == UnaryOp::Not { Type::Bool } else { Type::Int };
        let value = self.expect(fx, operand, &ty)?;
        Ok((lowered(ExprKind::Unary(op, Box::new(value)), span), ty))
    }

    fn binary(
        &mut self,
        fx: &mut Fx,
        op: BinaryOp,
        a: &ast::Expr<'_>,
        b: &ast::Expr<'_>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        let (va, ta) = self.expr(fx, a, None)?;
        let (vb, tb) =
            self.expr(fx, b, (op == BinaryOp::Add && matches!(ta, Type::List(_))).then_some(&ta))?;
        let ty = match op {
            BinaryOp::Add => match (&ta, &tb) {
                (Type::Int, Type::Int) => Type::Int,
                (Type::Text, Type::Text) => Type::Text,
                (Type::Bytes, Type::Bytes) => Type::Bytes,
                (Type::List(_), Type::List(_)) => common_type([&ta, &tb].into_iter())
                    .ok_or_else(|| mismatch(&ta, &tb, vb.span))?,
                _ => return Err(operands(op, &ta, &tb, span)),
            },
            BinaryOp::Sub | BinaryOp::Mul => {
                if ta != Type::Int || tb != Type::Int {
                    return Err(operands(op, &ta, &tb, span));
                }
                Type::Int
            }
            BinaryOp::Eq | BinaryOp::Ne => {
                if !self.comparable(&ta, &tb) {
                    return Err(operands(op, &ta, &tb, span));
                }
                Type::Bool
            }
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                if !matches!((&ta, &tb), (Type::Int, Type::Int) | (Type::Text, Type::Text)) {
                    return Err(operands(op, &ta, &tb, span));
                }
                Type::Bool
            }
        };
        Ok((lowered(ExprKind::Binary(op, Box::new(va), Box::new(vb)), span), ty))
    }

    /// Whether `==` may compare values of these types: plain data of related types, or
    /// a nominal type whose library defines equality.
    fn comparable(&self, a: &Type, b: &Type) -> bool {
        let nominal_eq = |ty: &Type| match ty {
            Type::Nominal(name, _) => {
                self.request.registry.type_def(name).is_some_and(|d| d.equality)
            }
            _ => false,
        };
        let related = assignable(a, b) || assignable(b, a);
        related && ((a.is_plain() && b.is_plain()) || nominal_eq(a) || nominal_eq(b))
    }

    fn index(
        &mut self,
        fx: &mut Fx,
        a: &ast::Expr<'_>,
        i: &ast::Expr<'_>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        let (va, ta) = self.expr(fx, a, None)?;
        let (key, result) = match &ta {
            Type::List(item) => (Type::Int, (**item).clone()),
            Type::Bytes => (Type::Int, Type::Int),
            Type::Map(item) => (Type::Text, (**item).clone()),
            other => {
                let hint = "Index a list, bytes or a map; narrow a `Value` explicitly first.";
                let message = format!("`{other}` cannot be indexed.");
                return Err(fault(codes::TYPE_MISMATCH, &message, hint, a.span));
            }
        };
        let vi = self.expect(fx, i, &key)?;
        Ok((lowered(ExprKind::Index(Box::new(va), Box::new(vi)), span), result))
    }

    fn field(
        &mut self,
        fx: &mut Fx,
        base: &ast::Expr<'_>,
        name: &ast::Name<'_>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        if let Some(export) = self.namespace_member(fx, base, name)? {
            return match export {
                Export::Constant { value, ty } => {
                    Ok((lowered(ExprKind::Literal(value.clone()), span), ty.clone()))
                }
                other => {
                    let message =
                        format!("`{}` is {}, not a value.", name.text, export_kind(other));
                    Err(fault(
                        codes::TYPE_MISMATCH,
                        &message,
                        "Call a function; JLV has no function values.",
                        span,
                    ))
                }
            };
        }
        let (value, ty) = self.expr(fx, base, None)?;
        let Type::Record(shape) = &ty else {
            let method = match &ty {
                Type::Nominal(type_name, _) => self
                    .request
                    .registry
                    .type_def(type_name)
                    .is_some_and(|d| d.methods.contains_key(name.text)),
                _ => false,
            };
            let hint = if matches!(ty, Type::Map(_)) {
                format!("A map has no declared fields; index it with `m[\"{}\"]`.", name.text)
            } else if method {
                format!("`{}` is a method of `{ty}`; call it, `.{}()`.", name.text, name.text)
            } else {
                "Select declared fields of records only; use a method call for library types."
                    .to_string()
            };
            let message = format!("`{ty}` has no field `{}`.", name.text);
            return Err(fault(codes::TYPE_MISMATCH, &message, &hint, name.span));
        };
        let Some(field) =
            shape.field(name.text).map(|f| f.ty.clone()).or_else(|| shape.rest.clone())
        else {
            let message = format!("The record has no field `{}`.", name.text);
            return Err(fault(
                codes::TYPE_MISMATCH,
                &message,
                "Select one of its declared fields.",
                name.span,
            ));
        };
        Ok((lowered(ExprKind::Field(Box::new(value), Arc::from(name.text)), span), field))
    }

    /// The library export `base.name` names when `base` is a namespace path rather than
    /// a value; `None` when `base` is a value.
    pub fn namespace_member(
        &self,
        fx: &Fx,
        base: &ast::Expr<'_>,
        name: &ast::Name<'_>,
    ) -> Result<Option<&'a Export>, Diagnostic> {
        let Some(members) = self.namespace(fx, base) else { return Ok(None) };
        match members.get(name.text) {
            Some(export) => {
                let mut path = namespace_path(base);
                path.push(Arc::from(name.text));
                self.record_reference(
                    name.span,
                    Referent::Export { path, export: export.clone() },
                );
                Ok(Some(export))
            }
            None => {
                let candidates: Vec<&str> = members.keys().map(|k| &**k).collect();
                let hint = match (
                    crate::forms::removed(name.text),
                    gd_report::suggest(name.text, candidates),
                ) {
                    (Some(hint), _) => hint.to_string(),
                    (None, Some(s)) => format!("Did you mean `{s}`?"),
                    (None, None) => {
                        "Check the library's exports with `jlvd schema show`.".to_string()
                    }
                };
                Err(fault(
                    codes::UNBOUND_NAME,
                    &format!("The namespace has no `{}`.", name.text),
                    &hint,
                    name.span,
                ))
            }
        }
    }

    /// The members of the namespace `e` names, if it names one.
    fn namespace(
        &self,
        fx: &Fx,
        e: &ast::Expr<'_>,
    ) -> Option<&'a std::collections::BTreeMap<Arc<str>, Export>> {
        match e.kind() {
            Ast::Name(n) if fx.locals.lookup(n).is_none() => match self.module_symbol(fx, n)? {
                Symbol::Export(export @ Export::Namespace(members)) => {
                    let path = vec![Arc::from(n)];
                    self.record_reference(
                        e.span,
                        Referent::Export { path, export: export.clone() },
                    );
                    Some(members)
                }
                _ => None,
            },
            Ast::Field(inner, n) => {
                let export @ Export::Namespace(members) =
                    self.namespace(fx, &inner)?.get(n.text)?
                else {
                    return None;
                };
                let mut path = namespace_path(&inner);
                path.push(Arc::from(n.text));
                self.record_reference(n.span, Referent::Export { path, export: export.clone() });
                Some(members)
            }
            _ => None,
        }
    }
}

/// The names of a namespace path such as `a.b`, from the first.
fn namespace_path(e: &ast::Expr<'_>) -> Vec<Arc<str>> {
    match e.kind() {
        Ast::Name(n) => vec![Arc::from(n)],
        Ast::Field(inner, n) => {
            let mut path = namespace_path(&inner);
            path.push(Arc::from(n.text));
            path
        }
        _ => Vec::new(),
    }
}

fn int_literal(n: u64, negative: bool, span: Span) -> Result<Typed, Diagnostic> {
    let value = match (negative, i64::try_from(n)) {
        (false, Ok(v)) => v,
        (true, Ok(v)) => -v,
        (true, Err(_)) if n == 1 << 63 => i64::MIN,
        _ => {
            let hint = "Keep integers between -9223372036854775808 and 9223372036854775807.";
            return Err(fault(
                codes::INTEGER_OVERFLOW,
                "This integer literal is out of range.",
                hint,
                span,
            ));
        }
    };
    Ok((lowered(ExprKind::Literal(Value::Int(value)), span), Type::Int))
}

fn no_element_type(kind: &str, types: &[Type], span: Span) -> Diagnostic {
    if types.is_empty() {
        let message = format!("An empty {kind} literal has no element type here.");
        let example = if kind == "list" { "xs: List<Text> = []" } else { "m: Map<Int> = {}" };
        let hint = format!(
            "Give the binding a type, as in `var {example}` or `let {example}`, so its {kind} \
             type is known."
        );
        return fault(codes::TYPE_MISMATCH, &message, &hint, span);
    }
    let found: Vec<String> = types.iter().map(Type::to_string).collect();
    let message = format!("The {kind} mixes elements of types {}.", found.join(", "));
    let hint = if kind == "list" {
        "Annotate the binding as `List<Value>` to hold plain values of different types."
    } else {
        "Annotate the binding as `Map<Value>` to hold plain values of different types."
    };
    fault(codes::TYPE_MISMATCH, &message, hint, span)
}

fn operands(op: BinaryOp, a: &Type, b: &Type, span: Span) -> Diagnostic {
    let message = format!("`{}` does not apply to `{a}` and `{b}`.", op.symbol());
    let hint = match op {
        BinaryOp::Add if matches!((a, b), (Type::Text, Type::Int) | (Type::Int, Type::Text)) => {
            "Interpolate the number instead, as in `\"count=${n}\"`."
        }
        BinaryOp::Add => "Add two integers, or join two texts, two byte strings or two lists.",
        BinaryOp::Sub | BinaryOp::Mul => {
            "Arithmetic applies to two integers; mixed kinds are rejected."
        }
        BinaryOp::Eq | BinaryOp::Ne if a.is_nominal("TargetRef") => {
            "Targets have no equality; compare their names, as in `a.name() == b.name()`."
        }
        BinaryOp::Eq | BinaryOp::Ne => {
            "Compare plain values of related types; opaque references have no equality."
        }
        _ => "Order two integers or two texts.",
    };
    fault(codes::TYPE_MISMATCH, &message, hint, span)
}

/// The type an element `e` of a collection of `item` is expected to have: a nested
/// list or map literal in plain data is `List<Value>` or `Map<Value>`.
fn nested(item: &Type, e: &ast::Expr<'_>) -> Type {
    match (item, e.kind()) {
        (Type::Value, Ast::List(_)) => Type::list(Type::Value),
        (Type::Value, Ast::Record(_)) => Type::map(Type::Value),
        _ => item.clone(),
    }
}
