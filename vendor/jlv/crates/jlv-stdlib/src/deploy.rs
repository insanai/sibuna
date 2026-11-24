//! `jlv.std.deploy`: deployment contexts, handles and artifacts (JDD 0004, "Domain
//! library contracts"; JDD 0016, "Targets").
//!
//! `DeployContext` exposes the captured typed `input` and `lock` views and the
//! identity-bound inventory `target` handles of one invocation: one by name, all or one
//! group's with `targets`, and a group's waves (JDD 0015). A deployment entry returns
//! nothing or its outputs; its stack is every resource it declared. `artifact(...)`
//! turns a locked content entry into an `ArtifactRef` without downloading or building
//! anything. Resource constructors come from plugin facades ([`crate::resources`]), not
//! from this library.

use std::sync::Arc;

use jlv_core::Problem;
use jlv_lang::native::Call;
use jlv_lang::signature::{Library, Param, Signature};
use jlv_lang::{Type, Value, codes};
use jlv_model::refs;

use crate::support::{LibraryBuilder, Natives, arg, text};

/// The library label.
pub const LABEL: &str = "@jlv//std:deploy.jlv";

/// The deployment context type.
pub const DEPLOY_CONTEXT: &str = "DeployContext";

/// The context methods shared by `DeployContext` and `OpContext`.
pub(crate) fn context_methods() -> Vec<(&'static str, Signature, crate::support::NativeFn)> {
    let key = |name: &str| vec![Param::required(name, Type::Text)];
    vec![
        ("input", Signature::new(key("key"), Type::Keyed(Arc::from("input"))).invocation(), input),
        ("lock", Signature::new(key("key"), Type::Keyed(Arc::from("lock"))).invocation(), lock),
        (
            "target",
            Signature::new(key("name"), Type::nominal(refs::TARGET_REF)).invocation(),
            target,
        ),
        (
            "targets",
            Signature::new(vec![Param::optional("group", Type::Text)], Type::list(target_ref()))
                .invocation(),
            targets,
        ),
        (
            "waves",
            Signature::new(key("group"), Type::list(Type::list(target_ref()))).invocation(),
            waves,
        ),
    ]
}

fn target_ref() -> Type {
    Type::nominal(refs::TARGET_REF)
}

/// The deploy library and its natives.
pub fn library(natives: &mut Natives) -> Library {
    let mut lib = LibraryBuilder::new(LABEL);
    lib.type_def(natives, DEPLOY_CONTEXT, 0, context_methods());
    let output = Signature::new(
        vec![Param::required("field", Type::Text)],
        Type::nominal(refs::OUTPUT_REF),
    )
    .invocation();
    lib.type_def(natives, refs::RESOURCE_REF, 0, vec![("output", output, resource_output)]);
    for name in [refs::OUTPUT_REF, refs::ARTIFACT_REF, refs::LOCKED] {
        lib.type_def(natives, name, 0, Vec::new());
    }
    // A target's name and address are captured with the inventory, so reading them is
    // as deterministic as the rest of the inventory: one host's configuration can name
    // another host, such as the database host a firewall connects to.
    let text_method = || Signature::new(Vec::new(), Type::Text);
    let label = Signature::new(vec![Param::required("key", Type::Text)], Type::Text);
    lib.type_def(
        natives,
        refs::TARGET_REF,
        0,
        vec![
            ("name", text_method(), target_name),
            ("address", text_method(), target_address),
            ("label", label, target_label),
        ],
    );
    lib.type_def(natives, refs::SECRET_REF, 1, Vec::new());
    let artifact = Signature::new(
        vec![Param::required("locked", Type::nominal(refs::LOCKED))],
        Type::nominal(refs::ARTIFACT_REF),
    );
    lib.function(natives, "artifact", artifact, artifact_ref);
    lib.finish()
}

/// The context table `name` entry `key`, or an `argument_error` naming the keys.
fn table_entry<'a>(call: &'a Call<'_>, name: &str, key: &str) -> Result<&'a Value, Problem> {
    let table = call.context()?.table(name);
    table.and_then(|t| t.get(key)).ok_or_else(|| {
        let keys: Vec<&str> = table
            .and_then(Value::as_map)
            .map(|m| m.keys().map(|k| &**k).collect())
            .unwrap_or_default();
        let hint = match crate::suggest(key, &keys) {
            Some(s) => format!("Did you mean `{s}`?"),
            None => format!("Declare `{key}` in the {name} of this invocation."),
        };
        codes::problem(codes::ARGUMENT_ERROR, &format!("The {name} has no entry `{key}`."), &hint)
    })
}

fn input(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(table_entry(call, "input", text(args, 1)?)?.clone())
}

fn lock(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let entry = table_entry(call, "lock", text(args, 1)?)?.clone();
    Ok(Value::opaque(refs::LOCKED, refs::VERSION, entry))
}

fn target(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let name = text(args, 1)?;
    let targets = call.context()?.table("targets");
    if let Some(payload) = targets.and_then(|t| t.get(name)) {
        return Ok(Value::opaque(refs::TARGET_REF, refs::VERSION, payload.clone()));
    }
    let names: Vec<&str> = targets
        .and_then(Value::as_map)
        .map(|m| m.keys().map(|k| &**k).collect())
        .unwrap_or_default();
    let message = format!("The captured inventory selection has no target `{name}`.");
    let mut hint =
        "Select an inventory that contains the target, or correct its name.".to_string();
    if let Some(close) = crate::suggest(name, &names) {
        hint.push_str(&format!(" Did you mean `{close}`?"));
    }
    Err(codes::problem(codes::INVALID_TARGET_SET, &message, &hint))
}

/// `ctx.targets(group?)`: the inventory's targets in name order, or a group's members,
/// so one entry can configure a whole inventory: `for t in ctx.targets("web") { ... }`.
/// An unknown group is an error, since a loop over a misspelt group would silently do
/// nothing.
fn targets(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let context = call.context()?;
    let table = context.table("targets");
    let handle = |name: &Value| {
        let payload = name.as_text().and_then(|n| table?.get(n)).cloned();
        Value::opaque(refs::TARGET_REF, refs::VERSION, payload.unwrap_or(Value::Null))
    };
    let Some(group) = arg(args, 1).as_text() else {
        let all = table.and_then(Value::as_map).into_iter().flat_map(|m| m.values());
        let handles = all.map(|p| Value::opaque(refs::TARGET_REF, refs::VERSION, p.clone()));
        return Ok(Value::list(handles.collect()));
    };
    let members = group_entry(context.table("groups"), group, "members")?;
    let names = members.as_list().unwrap_or_default();
    Ok(Value::list(names.iter().map(handle).collect()))
}

/// `ctx.waves(group)`: the group's waves, lists of member handles in name order, cut by
/// its `wave_size` (JDD 0015, "Groups"); an unknown group is an error.
fn waves(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let context = call.context()?;
    let table = context.table("targets");
    let waves = group_entry(context.table("groups"), text(args, 1)?, "waves")?;
    let handle = |name: &Value| {
        let payload = name.as_text().and_then(|n| table?.get(n)).cloned();
        Value::opaque(refs::TARGET_REF, refs::VERSION, payload.unwrap_or(Value::Null))
    };
    let lists = waves.as_list().unwrap_or_default();
    let handles = lists.iter().map(|wave| {
        let names = wave.as_list().unwrap_or_default();
        Value::list(names.iter().map(handle).collect())
    });
    Ok(Value::list(handles.collect()))
}

/// The entry `key` of the inventory group `group`, or an `argument_error` naming the
/// closest group.
fn group_entry<'v>(
    groups: Option<&'v Value>,
    group: &str,
    key: &str,
) -> Result<&'v Value, Problem> {
    if let Some(entry) = groups.and_then(|g| g.get(group)?.get(key)) {
        return Ok(entry);
    }
    let names: Vec<&str> = groups
        .and_then(Value::as_map)
        .map(|m| m.keys().map(|k| &**k).collect())
        .unwrap_or_default();
    let message = format!("The captured inventory has no group `{group}`.");
    let mut hint = "Name a group of the inventory, or define it under `[groups]`.".to_string();
    if let Some(close) = crate::suggest(group, &names) {
        hint.push_str(&format!(" Did you mean `{close}`?"));
    }
    Err(codes::problem(codes::ARGUMENT_ERROR, &message, &hint))
}

/// `t.label(key)`: the target's label `key`, or `""` when it has none.
fn target_label(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let payload = refs::payload(arg(args, 0), refs::TARGET_REF);
    let key = text(args, 1)?;
    let label = payload.and_then(|p| p.get("labels")?.get(key)).cloned();
    Ok(label.unwrap_or(Value::text("")))
}

/// `t.name()`: the target's name in the inventory.
fn target_name(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    target_field(args, "name")
}

/// `t.address()`: the target's address, `localhost` for a local target.
fn target_address(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    target_field(args, "address")
}

fn target_field(args: &[Option<Value>], key: &str) -> Result<Value, Problem> {
    let payload = refs::payload(arg(args, 0), refs::TARGET_REF);
    Ok(payload.and_then(|p| p.get(key)).cloned().unwrap_or(Value::text("")))
}

fn resource_output(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let address = refs::referenced_address(arg(args, 0)).unwrap_or_default().to_string();
    let field = text(args, 1)?;
    let declared = call.builder()?.get(&address).map(|d| d.payload.clone());
    let outputs = declared
        .as_ref()
        .and_then(|p| p.get("outputs"))
        .and_then(Value::as_map)
        .cloned()
        .unwrap_or_default();
    match outputs.get(field).and_then(Value::as_text) {
        Some(ty) => Ok(refs::output_ref(&address, field, ty)),
        None => {
            let names: Vec<&str> = outputs.keys().map(|k| &**k).collect();
            let hint = match crate::suggest(field, &names) {
                Some(s) => format!("Did you mean `{s}`?"),
                None if names.is_empty() => "The resource declares no outputs.".to_string(),
                None => format!("The resource's outputs are {}.", names.join(", ")),
            };
            Err(codes::problem(
                codes::ARGUMENT_ERROR,
                &format!("`{address}` has no output `{field}`."),
                &hint,
            ))
        }
    }
}

fn artifact_ref(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let entry = refs::payload(arg(args, 0), refs::LOCKED).cloned().unwrap_or(Value::Null);
    if entry.get("digest").and_then(Value::as_text).is_none() {
        let hint = "Pin the artifact's content with `jlvd lock update`.";
        return Err(codes::problem(
            codes::TYPE_MISMATCH,
            "The lock entry has no content digest.",
            hint,
        ));
    }
    Ok(Value::opaque(refs::ARTIFACT_REF, refs::VERSION, entry))
}
