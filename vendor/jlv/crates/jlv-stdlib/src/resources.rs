//! Plugin facades: libraries generated from resource schemas (JDD 0007, "Schema and
//! model contract").
//!
//! A locked plugin package publishes resource schemas as data. Its facade is a library
//! such as `@host//:plugin.jlv` exporting one namespace, such as `host`, with a
//! constructor per resource type: `host.file(name: ..., path: ..., ...)`. Every
//! constructor takes the schema's fields plus `name`, `lifecycle`, `depends_on` and
//! `health`; it validates the name, records a declaration in the invocation's builder
//! and returns a `ResourceRef`. It performs no I/O: it declares intent.

use std::sync::Arc;

use jlv_core::Problem;
use jlv_lang::native::{Call, Declaration, Native};
use jlv_lang::signature::{Export, Library, Omitted, Param, Signature};
use jlv_lang::types::{FieldType, RecordType};
use jlv_lang::value::Entries;
use jlv_lang::{Type, Value, codes};
use jlv_model::{ActionSchema, ResourceSchema, refs};

use crate::support::{Natives, arg};

/// Parameters every constructor takes besides its schema's fields.
const COMMON: &[&str] = &["name", "lifecycle", "depends_on", "health"];

/// The facade library `label` exporting `namespace` with one constructor per resource
/// schema and one per action kind `NAMESPACE.NAME` of `actions` (JDD 0017, "Part 5:
/// action constructors"); the core action kinds keep their constructors in `ops`.
///
/// Fails with `jlv.schema.invalid` when a schema has a field named like a common
/// parameter, or two fields of one name, since its constructor could not take both.
pub fn facade(
    label: &str,
    namespace: &str,
    schemas: &[ResourceSchema],
    actions: &[ActionSchema],
    natives: &mut Natives,
) -> Result<Library, Problem> {
    let mut members = std::collections::BTreeMap::new();
    let prefix = format!("{namespace}.");
    for schema in actions.iter().filter(|a| a.kind.starts_with(&prefix)) {
        let short = &schema.kind[prefix.len()..];
        let native: Arc<str> = Arc::from(format!("{label}#{}", schema.kind));
        natives.insert(native.clone(), Arc::new(ActionConstructor { schema: schema.clone() }));
        let signature = action_signature(schema);
        members.insert(Arc::from(short), Export::Function { native, signature });
    }
    for schema in schemas {
        check_fields(label, schema)?;
        let short = schema.type_name.rsplit('.').next().unwrap_or(&schema.type_name).to_string();
        let native: Arc<str> = Arc::from(format!("{label}#{}", schema.type_name));
        natives.insert(native.clone(), Arc::new(Constructor { schema: schema.clone() }));
        members.insert(
            Arc::from(short.as_str()),
            Export::Function { native, signature: signature(schema) },
        );
    }
    let mut exports = std::collections::BTreeMap::new();
    exports.insert(Arc::from(namespace), Export::Namespace(members));
    Ok(Library { label: Arc::from(label), exports, types: Vec::new() })
}

/// Fails when a field of `schema` is named like a common parameter or like an earlier
/// field: a constructor's parameters must have distinct names.
fn check_fields(label: &str, schema: &ResourceSchema) -> Result<(), Problem> {
    for (i, field) in schema.fields.iter().enumerate() {
        let name = &field.name;
        let (message, hint) = if is_common_parameter(name) {
            let message = format!(
                "The resource schema `{}` of `{label}` has a field `{name}`, which every \
                 constructor already takes.",
                schema.type_name
            );
            let hint = "Rename the field; `name`, `lifecycle`, `depends_on` and `health` are \
                        the parameters every resource has.";
            (message, hint)
        } else if schema.fields[..i].iter().any(|f| f.name == *name) {
            let message = format!(
                "The resource schema `{}` of `{label}` has the field `{name}` twice.",
                schema.type_name
            );
            (message, "Give each field of a schema its own name.")
        } else {
            continue;
        };
        return Err(Problem::new("jlv.schema.invalid", "INVALID SCHEMA", &message)
            .consequence("The plugin's facade was not built, so nothing was compiled.")
            .hint(hint));
    }
    Ok(())
}

fn record(fields: &[(&str, Type, bool)]) -> Type {
    let fields = fields
        .iter()
        .map(|(n, t, r)| FieldType { name: Arc::from(*n), ty: t.clone(), required: *r })
        .collect();
    Type::Record(Arc::new(RecordType { fields, rest: None }))
}

/// The health contract shape of JDD 0003's worked deployment.
fn health() -> Type {
    record(&[
        ("command", Type::list(Type::Text), false),
        ("consecutive_successes", Type::Int, false),
        ("deadline_seconds", Type::Int, false),
        ("kind", Type::Text, true),
        ("path", Type::Text, false),
        ("port", Type::Int, false),
        ("unit", Type::Text, false),
    ])
}

/// A constructor's signature: `name` first, the schema's fields, then the common ones.
fn signature(schema: &ResourceSchema) -> Signature {
    let mut params = vec![Param::required("name", Type::Text)];
    for field in &schema.fields {
        let omitted = match (&field.default, field.required) {
            (Some(v), _) => Omitted::Default(v.clone()),
            (None, true) => Omitted::Required,
            (None, false) => Omitted::Absent,
        };
        params.push(Param { name: field.name.clone(), ty: field.ty.clone(), omitted });
    }
    params.push(Param::optional(
        "lifecycle",
        record(&[("protect", Type::Bool, false), ("adopt", Type::Bool, false)]),
    ));
    params.push(Param::optional("depends_on", Type::list(Type::nominal(refs::RESOURCE_REF))));
    params.push(Param::optional("health", health()));
    Signature::new(params, Type::nominal(refs::RESOURCE_REF)).invocation().positional_only(1)
}

/// A plugin action constructor's signature: the step's name first, by position, then
/// the schema's arguments by name; it returns a `Recipe`, as the constructors of `ops` do.
fn action_signature(schema: &ActionSchema) -> Signature {
    let mut params = vec![Param::required("name", Type::Text)];
    for field in &schema.args {
        let omitted = match (&field.default, field.required) {
            (Some(v), _) => Omitted::Default(v.clone()),
            (None, true) => Omitted::Required,
            (None, false) => Omitted::Absent,
        };
        params.push(Param { name: field.name.clone(), ty: field.ty.clone(), omitted });
    }
    Signature::new(params, Type::nominal(refs::RECIPE)).positional_only(1)
}

/// The native of one plugin action constructor (JDD 0017): the step of the schema's
/// kind, with the `target` argument as its target and the others as its arguments.
#[derive(Debug)]
struct ActionConstructor {
    schema: ActionSchema,
}

impl Native for ActionConstructor {
    fn call(&self, _call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
        let id = arg(args, 0).as_text().unwrap_or_default().to_string();
        let mut target = Value::Null;
        let mut entries = Entries::new();
        for (field, value) in self.schema.args.iter().zip(&args[1..]) {
            let Some(value) = value else { continue };
            if &*field.name == "target" {
                target = value.clone();
            } else {
                entries.insert(field.name.clone(), value.clone());
            }
        }
        let kind = &self.schema.kind;
        let repeatability = self.schema.repeatability;
        crate::operations::step(kind, &id, target, Value::of_entries(entries), repeatability)
    }
}

/// The native of one resource constructor.
#[derive(Debug)]
struct Constructor {
    schema: ResourceSchema,
}

impl Native for Constructor {
    fn call(&self, call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
        let name = arg(args, 0).as_text().unwrap_or_default().to_string();
        check_name(&name)?;
        let address = format!("{}.{name}", self.schema.type_name);
        let mut properties = Entries::new();
        let mut triggers = Vec::new();
        for (field, value) in self.schema.fields.iter().zip(&args[1..]) {
            let Some(value) = value else { continue };
            // A trigger list is kept in the properties too, unowned, so a plugin can tell
            // which list a fired trigger belongs to, as `reload_on` and `restart_on` do.
            if field.trigger {
                triggers.push(value.clone());
            }
            properties.insert(field.name.clone(), value.clone());
        }
        let common = &args[1 + self.schema.fields.len()..];
        let lifecycle = |key: &str| {
            common
                .first()
                .and_then(|l| l.as_ref())
                .and_then(|l| l.get(key))
                .and_then(Value::as_bool)
        };
        let protect = lifecycle("protect");
        let owned: Vec<Value> = self
            .schema
            .fields
            .iter()
            .filter(|f| f.owned && properties.contains_key(&f.name))
            .map(|f| Value::Text(f.name.clone()))
            .collect();
        let outputs =
            self.schema.outputs.iter().map(|o| (&*o.name, Value::text(&o.ty.to_string())));
        let payload = Value::map([
            ("type", Value::text(&self.schema.type_name)),
            ("name", Value::text(&name)),
            ("schema_version", Value::Int(i64::from(self.schema.version))),
            ("properties", Value::of_entries(properties)),
            ("owned", Value::list(owned)),
            ("protect", Value::Bool(protect.unwrap_or(false))),
            ("adopt", Value::Bool(lifecycle("adopt").unwrap_or(self.schema.adopts))),
            ("depends_on", common.get(1).cloned().flatten().unwrap_or(Value::list(vec![]))),
            ("triggers", Value::list(triggers)),
            ("health", common.get(2).cloned().flatten().unwrap_or(Value::Null)),
            ("outputs", Value::map(outputs)),
        ]);
        let declaration = Declaration {
            kind: Arc::from("resource"),
            address: Arc::from(address.as_str()),
            payload,
            span: call.span,
        };
        call.builder()?.declare(declaration)?;
        Ok(refs::resource_ref(&address))
    }
}

/// Resource names are stable identities: 1 to 63 lower-case letters, digits, `-` and
/// `_`, starting and ending with a letter or digit.
pub(crate) fn check_name(name: &str) -> Result<(), Problem> {
    let bytes = name.as_bytes();
    let inner = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_';
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if (1..=63).contains(&bytes.len())
        && bytes.iter().all(inner)
        && edge(bytes.first())
        && edge(bytes.last())
    {
        return Ok(());
    }
    let message = format!("`{name}` is not a valid resource name.");
    let hint = "Use 1 to 63 lower-case letters, digits, `-` or `_`, such as `web-index`.";
    Err(codes::problem(codes::ARGUMENT_ERROR, &message, hint))
}

/// Whether `name` is one of the parameters every constructor has.
fn is_common_parameter(name: &str) -> bool {
    COMMON.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jlv_model::FieldSchema;

    fn schema(fields: &[&str]) -> ResourceSchema {
        ResourceSchema {
            type_name: "host.file".into(),
            version: 1,
            fields: fields.iter().map(|f| FieldSchema::owned(f, Type::Text, "A field.")).collect(),
            outputs: Vec::new(),
            adopts: false,
            retain_on_delete: false,
            made_elsewhere: false,
            target: None,
            description: "A file.".into(),
        }
    }

    #[test]
    fn fields_named_like_common_parameters_or_twice_are_refused() {
        let build = |fields: &[&str]| {
            facade("@x//:p.jlv", "x", &[schema(fields)], &[], &mut Natives::new())
        };
        assert!(build(&["path", "content"]).is_ok());
        for fields in [&["path", "health"][..], &["depends_on"], &["path", "path"]] {
            let problem = build(fields).unwrap_err();
            assert_eq!(problem.code, "jlv.schema.invalid", "{fields:?}");
        }
    }
}
