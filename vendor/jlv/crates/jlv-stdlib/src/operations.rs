//! `jlv.std.operations`: operation contexts and recipe constructors (JDD 0003,
//! "Imperative operation entrypoints"; JDD 0016, "Resources and actions").
//!
//! An operation entry returns a `Recipe`: ordered and bounded-parallel steps of typed
//! actions. Each action has a name, written first like a resource's, and names its
//! kind, identity-bound target, arguments and repeatability, which comes from the
//! action's approved schema, never from source; the recipe keeps the name under the key
//! `id`. Constructing a recipe performs no effect; effects follow plan admission.

use jlv_core::Problem;
use jlv_lang::native::Call;
use jlv_lang::signature::{Library, Param, Signature};
use jlv_lang::types::{FieldType, RecordType};
use jlv_lang::{Type, Value, codes};
use jlv_model::Repeatability;
use jlv_model::refs;

use crate::deploy::context_methods;
use crate::support::{LibraryBuilder, NativeFn, Natives, arg, text};

/// The library label.
pub const LABEL: &str = "@jlv//std:operations.jlv";

/// The operation context type.
pub const OP_CONTEXT: &str = "OpContext";

/// The actions of the standard vocabulary and their repeatability.
pub const ACTIONS: &[(&str, Repeatability)] = &[
    ("service_restart", Repeatability::NonRepeatable),
    ("service_start", Repeatability::Idempotent),
    ("service_stop", Repeatability::Idempotent),
    ("http_probe", Repeatability::ReadOnly),
    ("exec", Repeatability::NonRepeatable),
];

fn recipe() -> Type {
    Type::nominal(refs::RECIPE)
}

fn probe_shape() -> Type {
    let field =
        |name: &str, ty: Type, required: bool| FieldType { name: name.into(), ty, required };
    Type::Record(std::sync::Arc::new(RecordType {
        fields: vec![
            field("consecutive_successes", Type::Int, false),
            field("deadline_seconds", Type::Int, false),
            field("expect_status", Type::Int, false),
            field("host", Type::Text, false),
            field("path", Type::Text, false),
            field("port", Type::Int, true),
            field("scheme", Type::Text, false),
        ],
        rest: None,
    }))
}

/// The operations library and its natives.
pub fn library(natives: &mut Natives) -> Library {
    let mut lib = LibraryBuilder::new(LABEL);
    lib.type_def(natives, OP_CONTEXT, 0, context_methods());
    lib.type_def(natives, refs::RECIPE, 0, Vec::new());
    let target = || Param::required("target", Type::nominal(refs::TARGET_REF));
    let id = || Param::required("name", Type::Text);
    let steps = Signature::new(vec![Param::required("steps", Type::list(recipe()))], recipe());
    let service =
        Signature::new(vec![id(), target(), Param::required("unit", Type::Text)], recipe())
            .positional_only(1);
    let probe =
        Signature::new(vec![id(), target(), Param::required("check", probe_shape())], recipe())
            .positional_only(1);
    let exec = Signature::new(
        vec![
            id(),
            target(),
            Param::required("argv", Type::list(Type::Text)),
            Param::defaulted("timeout_seconds", Type::Int, Value::Int(300)),
        ],
        recipe(),
    )
    .positional_only(1);
    let functions: Vec<(&str, Signature, NativeFn)> = vec![
        ("sequence", steps.clone(), sequence),
        ("parallel", steps, parallel),
        ("service_restart", service.clone(), service_restart),
        ("service_start", service.clone(), service_start),
        ("service_stop", service, service_stop),
        ("http_probe", probe, http_probe),
        ("exec", exec, exec_action),
    ];
    lib.namespace(natives, "ops", functions);
    lib.finish()
}

fn group(kind: &str, args: &[Option<Value>]) -> Result<Value, Problem> {
    let payload = Value::map([("kind", Value::text(kind)), ("steps", arg(args, 0).clone())]);
    Ok(Value::opaque(refs::RECIPE, refs::VERSION, payload))
}

fn sequence(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    group("sequence", args)
}

fn parallel(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    group("parallel", args)
}

/// One action step of `kind` with these arguments.
fn action(kind: &str, args: &[Option<Value>], action_args: Value) -> Result<Value, Problem> {
    let repeatability =
        ACTIONS.iter().find(|(k, _)| *k == kind).map_or(Repeatability::NonRepeatable, |(_, r)| *r);
    step(kind, text(args, 0)?, arg(args, 1).clone(), action_args, repeatability)
}

/// The recipe step of one action: its name `id`, its kind, its target, its arguments and
/// its repeatability. The core constructors and a plugin's action constructors (JDD 0017)
/// build the same step.
pub(crate) fn step(
    kind: &str,
    id: &str,
    target: Value,
    action_args: Value,
    repeatability: Repeatability,
) -> Result<Value, Problem> {
    if crate::resources::check_name(id).is_err() {
        let message = format!("`{id}` is not a valid action name.");
        let hint = "Use 1 to 63 lower-case letters, digits, `-` or `_`, starting and ending \
                    with a letter or digit, such as `restart-site`.";
        return Err(codes::problem(codes::ARGUMENT_ERROR, message.as_str(), hint));
    }
    let payload = Value::map([
        ("kind", Value::text("action")),
        ("id", Value::text(id)),
        ("action", Value::text(kind)),
        ("target", target),
        ("args", action_args),
        ("repeatability", Value::text(repeatability.name())),
    ]);
    Ok(Value::opaque(refs::RECIPE, refs::VERSION, payload))
}

fn service_restart(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    action("service_restart", args, Value::map([("unit", arg(args, 2).clone())]))
}

fn service_start(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    action("service_start", args, Value::map([("unit", arg(args, 2).clone())]))
}

fn service_stop(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    action("service_stop", args, Value::map([("unit", arg(args, 2).clone())]))
}

fn http_probe(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    action("http_probe", args, arg(args, 2).clone())
}

fn exec_action(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let argv = arg(args, 2).as_list().unwrap_or_default();
    if argv.is_empty() {
        let hint =
            "Pass the program and its arguments, such as `[\"/usr/bin/pg_dump\", \"site\"]`.";
        return Err(codes::problem(codes::ARGUMENT_ERROR, "`argv` is empty.", hint));
    }
    let action_args =
        Value::map([("argv", arg(args, 2).clone()), ("timeout_seconds", arg(args, 3).clone())]);
    action("exec", args, action_args)
}

#[cfg(test)]
mod tests {
    /// JDD 0017: the standard library constructs exactly the core action kinds, which a
    /// plugin may carry out without a namespace.
    #[test]
    fn the_standard_actions_are_the_core_action_kinds() {
        let ours: Vec<&str> = super::ACTIONS.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(ours, jlv_model::names::CORE_ACTIONS);
    }

    /// JDD 0017: a plugin's namespace never takes a namespace the standard library
    /// exports.
    #[test]
    fn the_standard_namespaces_are_reserved() {
        let (registry, _) = crate::standard(&[]).unwrap();
        let mut ours: Vec<String> = registry
            .labels()
            .filter_map(|label| registry.library(label))
            .flat_map(|l| l.exports.iter())
            .filter(|(_, e)| matches!(e, jlv_lang::signature::Export::Namespace(_)))
            .map(|(name, _)| name.to_string())
            .collect();
        ours.push("jlv".into());
        ours.sort();
        let mut reserved: Vec<&str> = jlv_model::names::RESERVED_NAMESPACES.to_vec();
        reserved.sort();
        assert_eq!(ours, reserved);
    }
}
