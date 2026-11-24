//! The expressions JLV/2 adds: interpolated strings and comprehensions (JDD 0016,
//! "Strings", "Loops and comprehensions", "Compilation and the IR").
//!
//! An interpolated expression has the type `Text`, `Int` or `Bool`, plain data with one
//! spelling, so a secret, a provider output or a handle can never become text by
//! accident. A comprehension binds its one
//! or two names in a scope of its own, beside a hidden slot that holds the list it
//! builds; one name runs over a list's items and two over a map's entries.

use std::sync::Arc;

use jlv_core::{Diagnostic, Span};
use jlv_lang::program::{self, Comprehension, ExprKind};
use jlv_lang::{Type, Value, codes};
use jlv_syntax::view::{self as ast, Part};

use crate::check::{Checker, Fx};
use crate::expr::Typed;
use crate::index::Referent;
use crate::scope::Origin;
use crate::typing::fault;

/// The parts of a comprehension, as the view gives them.
pub(crate) struct Form<'v, 'a> {
    pub names: &'v [ast::Name<'a>],
    pub items: &'v ast::Expr<'a>,
    pub body: &'v ast::Expr<'a>,
    pub filter: Option<&'v ast::Expr<'a>>,
}

impl Checker<'_> {
    /// An interpolated string: its parts, each expression a `Text`, an `Int` or a `Bool`.
    pub(crate) fn interpolation(
        &mut self,
        fx: &mut Fx,
        parts: &[Part<'_>],
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        let mut lowered = Vec::with_capacity(parts.len());
        for part in parts {
            match part {
                // An empty literal part, such as the head of `"${x}"`, adds nothing, so it
                // is not evaluated or charged.
                Part::Text { text: "", .. } => {}
                Part::Text { text, .. } => {
                    let kind = ExprKind::Literal(Value::text(text));
                    lowered.push(program::Expr { kind, span });
                }
                Part::Expr(e) => {
                    let (value, ty) = self.synthesize(fx, e, None)?;
                    if !matches!(ty, Type::Text | Type::Int | Type::Bool) {
                        return Err(not_interpolable(&ty, e.span));
                    }
                    lowered.push(value);
                }
            }
        }
        Ok((program::Expr { kind: ExprKind::Interpolate(lowered), span }, Type::Text))
    }

    /// `[for names in items: body if filter]`, a `List` of the body's type.
    pub(crate) fn comprehension(
        &mut self,
        fx: &mut Fx,
        form: &Form<'_, '_>,
        expected: Option<&Type>,
        span: Span,
    ) -> Result<Typed, Diagnostic> {
        let (items, ty) = self.synthesize(fx, form.items, None)?;
        let (key, item) = loop_types(form.names.len(), &ty, form.items.span)?;
        // The names are visible in the body and the filter, which follow the `:`.
        let end = form.filter.map_or(form.body.span.end, |f| f.span.end);
        fx.locals.push(Span { end, ..form.body.span });
        let checked = self.comprehension_body(fx, form, key, item, expected);
        fx.locals.pop();
        let Inside { key, slot, list, filter, body, ty } = checked?;
        let comprehension = Comprehension { key, slot, list, items, filter, body };
        let kind = ExprKind::Comprehension(Box::new(comprehension));
        Ok((program::Expr { kind, span }, Type::list(ty)))
    }

    /// Binds the names and checks the filter and body inside the comprehension's scope.
    fn comprehension_body(
        &mut self,
        fx: &mut Fx,
        form: &Form<'_, '_>,
        key: Option<Type>,
        item: Type,
        expected: Option<&Type>,
    ) -> Result<Inside, Diagnostic> {
        let list = fx.locals.hidden();
        let key = match key {
            Some(ty) => Some(self.bind(fx, &form.names[0], ty)?),
            None => None,
        };
        let slot = self.bind(fx, &form.names[form.names.len() - 1], item)?;
        let filter = match form.filter {
            Some(filter) => Some(self.condition(fx, filter)?),
            None => None,
        };
        let element = match expected {
            Some(Type::List(element)) => Some(element.as_ref().clone()),
            _ => None,
        };
        let (body, ty) = self.expr(fx, form.body, element.as_ref())?;
        Ok(Inside { key, slot, list, filter, body, ty })
    }

    /// Binds a name that cannot be assigned, a loop's or a comprehension's.
    pub(crate) fn bind(
        &mut self,
        fx: &mut Fx,
        name: &ast::Name<'_>,
        ty: Type,
    ) -> Result<u32, Diagnostic> {
        self.declare(fx, name, ty, Origin::Loop, 0)
    }

    /// Binds `name` in the innermost scope as `origin` says, visible from byte `after`
    /// or the scope's start, and records it in the resolution index.
    pub(crate) fn declare(
        &mut self,
        fx: &mut Fx,
        name: &ast::Name<'_>,
        ty: Type,
        origin: Origin,
        after: u32,
    ) -> Result<u32, Diagnostic> {
        let visible = fx.locals.visible_from(after);
        let referent = Referent::Local { definition: name.span, ty: ty.clone(), visible };
        self.record_reference(name.span, referent);
        fx.locals.declare(&Arc::from(name.text), ty, name.span, origin, visible)
    }
}

/// What a comprehension's scope yields: its slots, its lowered filter and body, and
/// the body's type.
struct Inside {
    key: Option<u32>,
    slot: u32,
    list: u32,
    filter: Option<program::Expr>,
    body: program::Expr,
    ty: Type,
}

/// The key and item types of a loop or comprehension with `names` names over a value
/// of type `ty`: a list's item, or a map's `Text` key and its value.
pub(crate) fn loop_types(
    names: usize,
    ty: &Type,
    span: Span,
) -> Result<(Option<Type>, Type), Diagnostic> {
    match (names, ty) {
        (1, Type::List(item)) => Ok((None, item.as_ref().clone())),
        (2, Type::Map(value)) => Ok((Some(Type::Text), value.as_ref().clone())),
        (1, Type::Map(_)) => {
            let hint =
                "Bind a key and a value, `for key, value in map`, or loop over `keys(map)`.";
            let message = "A loop over a map visits its entries.";
            Err(fault(codes::TYPE_MISMATCH, message, hint, span))
        }
        (2, Type::List(_)) => {
            let hint = "Bind one name to loop over a list's items.";
            let message = "Two names loop over a map's entries, but this is a list.";
            Err(fault(codes::TYPE_MISMATCH, message, hint, span))
        }
        (_, other) => {
            let message = format!("A loop runs over a list or a map, but this is `{other}`.");
            let hint = "Loop over a list, or over a map's entries with `for key, value in map`.";
            Err(fault(codes::TYPE_MISMATCH, &message, hint, span))
        }
    }
}

/// The hint for a name that JLV/1 had and JLV/2 removed, so its refusal shows the new
/// spelling (JDD 0016, "Backwards compatibility").
pub(crate) fn removed(name: &str) -> Option<&'static str> {
    Some(match name {
        "stack" | "Stack" => {
            "A deployment's stack is every resource it declares: end the entry without a \
             result, or return its outputs, as in `fn deploy(ctx: DeployContext) -> \
             Map<OutputRef>`."
        }
        "template" => "Write an interpolated string or text block: `\"listen ${port};\"`.",
        "target_names" => {
            "Use `ctx.targets(group)`, which gives the targets themselves; `t.name()` is a \
             target's name."
        }
        _ => return None,
    })
}

/// The refusal of an interpolated value that is not a `Text`, an `Int` or a `Bool`.
fn not_interpolable(ty: &Type, span: Span) -> Diagnostic {
    if ty.is_nominal("SecretRef") {
        let message = "A secret cannot be interpolated; its value never exists in JLV.";
        let hint = "Install it with `host.secret_file`, whose template fills it on the worker.";
        return fault(codes::TYPE_MISMATCH, message, hint, span);
    }
    if ty.is_nominal("OutputRef") {
        let message = "A provider output cannot be interpolated; it is not known while the \
                       declarations are evaluated.";
        let hint = "Pass the output to a resource field, which the planner binds after it \
                    verifies the producing resource.";
        return fault(codes::TYPE_MISMATCH, message, hint, span);
    }
    let message =
        format!("Only a `Text`, an `Int` or a `Bool` can be interpolated, but this is `{ty}`.");
    let hint = match ty {
        Type::List(_) => "Join the list into a text first, as in `text.join(names, \", \")`.",
        Type::Map(_) | Type::Record(_) => {
            "Write the data as text first, as in `config.json(data)` or \
             `config.key_values(data, \" = \")`."
        }
        _ => "Interpolate a text, an integer or a boolean, such as a target's `name()`.",
    };
    fault(codes::TYPE_MISMATCH, &message, hint, span)
}
