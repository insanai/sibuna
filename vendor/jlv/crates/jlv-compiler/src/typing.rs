//! Resolving written types and reporting type errors.

use std::sync::Arc;

use jlv_core::{Diagnostic, Span};
use jlv_lang::Type;
use jlv_lang::codes;
use jlv_lang::signature::{Export, Registry};
use jlv_syntax::view::TypeExpr;

use crate::scope::{ModuleScope, Symbol};

/// The core type names, always in scope.
const CORE: &[&str] = &["Null", "Bool", "Int", "Text", "Bytes", "Value", "List", "Map"];

/// Resolves `ty` in `scope`: a core type, or a nominal type the module imports.
pub(crate) fn resolve(
    ty: &TypeExpr<'_>,
    scope: &ModuleScope<'_>,
    registry: &Registry,
) -> Result<Type, Diagnostic> {
    // Recursion over a written type is bounded by the syntax's depth limit (JDD 0013).
    let args =
        ty.args().iter().map(|a| resolve(a, scope, registry)).collect::<Result<Vec<_>, _>>()?;
    let path = ty.path();
    let first = path[0].text;
    if path.len() == 1
        && let Some(core) = Type::core(first, &args)
    {
        return Ok(core);
    }
    if path.len() == 1 && CORE.contains(&first) {
        let message = format!(
            "`{first}` takes {} type arguments here.",
            if matches!(first, "List" | "Map") { 1 } else { 0 }
        );
        return Err(Diagnostic::at(
            codes::problem(codes::TYPE_MISMATCH, &message, "Write `List<T>` or `Map<T>`."),
            ty.span,
        ));
    }
    let name = nominal_name(ty, scope, registry)?;
    let arity = registry.type_def(&name).map_or(0, |d| d.arity) as usize;
    if arity != args.len() {
        let message =
            format!("`{name}` takes {arity} type arguments, but {} are given.", args.len());
        let hint = "Match the type's declared parameters.";
        return Err(Diagnostic::at(codes::problem(codes::TYPE_MISMATCH, &message, hint), ty.span));
    }
    Ok(Type::Nominal(name, args))
}

/// The nominal type a path names through the module's imports and namespaces.
fn nominal_name(
    ty: &TypeExpr<'_>,
    scope: &ModuleScope<'_>,
    registry: &Registry,
) -> Result<Arc<str>, Diagnostic> {
    let path = ty.path();
    let first = &path[0];
    let unknown = || {
        let candidates = scope.symbols.keys().map(|k| &**k).chain(CORE.iter().copied());
        let suggestion = gd_report::suggest(first.text, candidates.collect::<Vec<_>>());
        // A library that exports the type says the import to write.
        let home = registry.labels().find(|label| {
            registry.library(label).is_some_and(|l| l.exports.contains_key(first.text))
        });
        if let Some(removed) = crate::forms::removed(first.text) {
            let message = format!("JLV/2 has no type `{}`.", first.text);
            return Diagnostic::at(
                codes::problem(codes::UNBOUND_NAME, &message, removed),
                ty.span,
            );
        }
        let mut hint = match home {
            Some(label) => format!(
                "Import it: `import {{ {} }} from {}`.",
                first.text,
                crate::modules::dotted(label)
            ),
            None => "Import the type from the library that defines it.".to_string(),
        };
        if let Some(s) = suggestion.filter(|_| home.is_none()) {
            hint = format!("Did you mean `{s}`?");
        }
        let message = format!(
            "No type `{}` is in scope.",
            path.iter().map(|n| n.text).collect::<Vec<_>>().join(".")
        );
        Diagnostic::at(codes::problem(codes::UNBOUND_NAME, &message, &hint), ty.span)
    };
    let mut export = match scope.symbols.get(first.text) {
        Some((Symbol::Export(export), _)) => *export,
        _ => return Err(unknown()),
    };
    for part in &path[1..] {
        export = match export {
            Export::Namespace(members) => members.get(part.text).ok_or_else(unknown)?,
            _ => return Err(unknown()),
        };
    }
    match export {
        Export::Type(name) => Ok(name.clone()),
        _ => Err(unknown()),
    }
}

/// A type mismatch between the expected and the found type.
pub(crate) fn mismatch(expected: &Type, found: &Type, span: Span) -> Diagnostic {
    let message = format!("Expected `{expected}`, but this is `{found}`.");
    let hint = if *expected == Type::Value && !found.is_plain() {
        "Only plain data is a `Value`; references and secrets cannot become one.".to_string()
    } else if matches!(expected, Type::Bool) {
        "Conditions need a `Bool`; integers, texts and collections have no truthiness.".to_string()
    } else {
        format!("Give a `{expected}` here, or convert explicitly.")
    };
    Diagnostic::at(codes::problem(codes::TYPE_MISMATCH, &message, &hint), span)
}

/// A diagnostic of `code` at `span`.
pub(crate) fn fault(code: &str, message: &str, hint: &str, span: Span) -> Diagnostic {
    Diagnostic::at(codes::problem(code, message, hint), span)
}
