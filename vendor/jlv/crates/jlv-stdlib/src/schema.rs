//! `jlv.std.schema`: schemas as values (JDD 0004, "Values and type system").
//!
//! A schema is a value of the nominal type `Schema`, built with pure constructors and
//! exported as a module constant; a project names its input schema by module label and
//! export. [`to_type`] gives the static type the compiler uses for `ctx.input("key")`,
//! and [`validate`] checks captured input data against the schema, applies exact
//! defaults and turns secret references into opaque `SecretRef` handles. Validation is
//! bounded by the size of the data.

use std::collections::BTreeMap;
use std::sync::Arc;

use jlv_core::Problem;
use jlv_lang::native::Call;
use jlv_lang::signature::{Library, Param, Signature};
use jlv_lang::types::{FieldType, RecordType};
use jlv_lang::value::Entries;
use jlv_lang::{Type, Value, codes};
use jlv_model::refs;

use crate::support::{LibraryBuilder, Natives, arg};

/// The library label.
pub const LABEL: &str = "@jlv//std:schema.jlv";

fn schema_type() -> Type {
    Type::nominal(refs::SCHEMA)
}

/// The schema library and its natives.
pub fn library(natives: &mut Natives) -> Library {
    let mut lib = LibraryBuilder::new(LABEL);
    lib.type_def(natives, refs::SCHEMA, 0, Vec::new());
    let s = schema_type();
    let optional_int = |name: &str| Param::optional(name, Type::Int);
    let plain = |params: Vec<Param>| Signature::new(params, s.clone());
    lib.namespace(
        natives,
        "schema",
        vec![
            ("text", plain(vec![optional_int("min_len"), optional_int("max_len")]), text),
            ("int", plain(vec![optional_int("min"), optional_int("max")]), int),
            ("bool", plain(vec![]), boolean),
            ("bytes", plain(vec![]), bytes),
            ("value", plain(vec![]), value),
            ("secret", plain(vec![]), secret),
            ("one_of", plain(vec![Param::required("values", Type::list(Type::Text))]), one_of),
            (
                "list",
                plain(vec![Param::required("item", s.clone()), optional_int("max_items")]),
                list,
            ),
            ("map", plain(vec![Param::required("item", s.clone())]), map),
            ("record", plain(vec![Param::required("fields", Type::map(s.clone()))]), record),
            // An omitted field takes its default, so a program never reads a field that
            // is absent from validated data (JDD 0006, ERGO-01).
            (
                "optional",
                plain(vec![
                    Param::required("schema", s.clone()),
                    Param::required("default", Type::Value),
                ]),
                optional,
            ),
        ],
    );
    lib.finish()
}

fn make(kind: &str, extra: Vec<(&str, Value)>) -> Value {
    let mut entries: Entries = extra.into_iter().map(|(k, v)| (Arc::from(k), v)).collect();
    entries.insert(Arc::from("kind"), Value::text(kind));
    Value::opaque(refs::SCHEMA, refs::VERSION, Value::of_entries(entries))
}

fn given<'a>(args: &'a [Option<Value>], names: &[&'a str]) -> Vec<(&'a str, Value)> {
    names.iter().zip(args).filter_map(|(n, v)| v.clone().map(|v| (*n, v))).collect()
}

fn text(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("text", given(args, &["min_len", "max_len"])))
}

fn int(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("int", given(args, &["min", "max"])))
}

fn boolean(_: &mut Call<'_>, _: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("bool", vec![]))
}

fn bytes(_: &mut Call<'_>, _: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("bytes", vec![]))
}

fn value(_: &mut Call<'_>, _: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("value", vec![]))
}

fn secret(_: &mut Call<'_>, _: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("secret", vec![]))
}

fn one_of(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("one_of", vec![("values", arg(args, 0).clone())]))
}

fn list(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("list", given(args, &["item", "max_items"])))
}

fn map(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("map", vec![("item", arg(args, 0).clone())]))
}

fn record(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(make("record", vec![("fields", arg(args, 0).clone())]))
}

/// `schema.optional(schema, default)`: a field that may be omitted and then takes the
/// default, which must satisfy `schema`.
fn optional(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let inner = arg(args, 0).clone();
    let Some(Some(default)) = args.get(1) else {
        let message = "An optional field needs a default.";
        let hint = "Pass `default:`, the value the field takes when the input omits it.";
        return Err(codes::problem(codes::ARGUMENT_ERROR, message, hint));
    };
    let checked = validate(&inner, default, "default")?;
    Ok(make("optional", vec![("schema", inner), ("default", checked)]))
}

/// The plain description of a schema value, if it is one.
fn describe(schema: &Value) -> Option<&Value> {
    refs::payload(schema, refs::SCHEMA)
}

fn kind(schema: &Value) -> &str {
    describe(schema).and_then(|d| d.get("kind")).and_then(Value::as_text).unwrap_or("value")
}

fn part<'a>(schema: &'a Value, key: &str) -> Option<&'a Value> {
    describe(schema).and_then(|d| d.get(key))
}

/// The static type of values that satisfy `schema`.
pub fn to_type(schema: &Value) -> Type {
    match kind(schema) {
        "text" | "one_of" => Type::Text,
        "int" => Type::Int,
        "bool" => Type::Bool,
        "bytes" => Type::Bytes,
        "secret" => Type::Nominal(Arc::from(refs::SECRET_REF), vec![Type::Text]),
        "list" => Type::list(part(schema, "item").map_or(Type::Value, to_type)),
        "map" => Type::map(part(schema, "item").map_or(Type::Value, to_type)),
        "optional" => part(schema, "schema").map_or(Type::Value, to_type),
        "record" => Type::Record(Arc::new(record_type(schema))),
        _ => Type::Value,
    }
}

fn record_type(schema: &Value) -> RecordType {
    let fields = part(schema, "fields").and_then(Value::as_map).cloned().unwrap_or_default();
    let fields = fields
        .iter()
        .map(|(name, field)| FieldType {
            name: name.clone(),
            ty: to_type(field),
            required: kind(field) != "optional",
        })
        .collect();
    RecordType { fields, rest: None }
}

/// The type of each top-level field of a record schema, for keyed lookups.
pub fn field_types(schema: &Value) -> BTreeMap<Arc<str>, Type> {
    record_type(schema).fields.into_iter().map(|f| (f.name, f.ty)).collect()
}

/// Whether `value` is a schema.
pub fn is_schema(value: &Value) -> bool {
    describe(value).is_some()
}

/// Checks `data` against `schema` and returns it with defaults applied and secret
/// references as opaque handles. `path` names the data in messages, such as `inputs`.
pub fn validate(schema: &Value, data: &Value, path: &str) -> Result<Value, Problem> {
    let fail = |expected: &str| {
        let message = format!("`{path}` must be {expected}, but it is {}.", data.kind_name());
        Err(codes::problem(
            codes::TYPE_MISMATCH,
            &message,
            "Correct the value in the stack's input file.",
        ))
    };
    match (kind(schema), data) {
        ("value", d) if d.is_plain() => Ok(d.clone()),
        ("bool", Value::Bool(_)) | ("bytes", Value::Bytes(_)) => Ok(data.clone()),
        ("text", Value::Text(t)) => {
            bounded(schema, "min_len", "max_len", t.len() as i64, path).map(|()| data.clone())
        }
        ("int", Value::Int(n)) => bounded(schema, "min", "max", *n, path).map(|()| data.clone()),
        ("one_of", Value::Text(t)) => {
            let values = part(schema, "values").and_then(Value::as_list).unwrap_or_default();
            if values.iter().any(|v| v.as_text() == Some(t)) {
                return Ok(data.clone());
            }
            let names: Vec<&str> = values.iter().filter_map(Value::as_text).collect();
            let message = format!("`{path}` is `{t}`, which is not one of {}.", names.join(", "));
            Err(codes::problem(codes::TYPE_MISMATCH, &message, "Choose one of the listed values."))
        }
        ("secret", Value::Map(m)) => secret_ref(m, path),
        ("list", Value::List(items)) => {
            let item = part(schema, "item").cloned().unwrap_or(Value::Null);
            if let Some(max) = part(schema, "max_items").and_then(Value::as_int)
                && items.len() as i64 > max
            {
                let message =
                    format!("`{path}` has {} items; at most {max} are allowed.", items.len());
                let hint = "Remove items, or raise `max_items` in the schema.";
                return Err(codes::problem(codes::TYPE_MISMATCH, &message, hint));
            }
            let checked =
                items.iter().enumerate().map(|(i, v)| validate(&item, v, &format!("{path}[{i}]")));
            Ok(Value::list(checked.collect::<Result<_, _>>()?))
        }
        ("map", Value::Map(entries)) => {
            let item = part(schema, "item").cloned().unwrap_or(Value::Null);
            let checked = entries
                .iter()
                .map(|(k, v)| Ok((k.clone(), validate(&item, v, &format!("{path}.{k}"))?)));
            Ok(Value::of_entries(checked.collect::<Result<_, Problem>>()?))
        }
        ("record", Value::Map(entries)) => validate_record(schema, entries, path),
        ("optional", _) => validate(part(schema, "schema").unwrap_or(&Value::Null), data, path),
        (expected, _) => fail(&article(expected)),
    }
}

fn article(kind: &str) -> String {
    match kind {
        "int" => "an integer".into(),
        "one_of" => "one of the listed texts".into(),
        "secret" => "a secret reference `{ secret = \"name\", version = N }`".into(),
        "value" => "plain data".into(),
        other => format!("a {other}"),
    }
}

fn bounded(schema: &Value, low: &str, high: &str, n: i64, path: &str) -> Result<(), Problem> {
    let get = |k: &str| part(schema, k).and_then(Value::as_int);
    if get(low).is_some_and(|min| n < min) || get(high).is_some_and(|max| n > max) {
        let message = format!("`{path}` is outside its allowed range ({n}).");
        let hint = format!(
            "Keep it within {}..{}.",
            get(low).map_or("-".into(), |v| v.to_string()),
            get(high).map_or("-".into(), |v| v.to_string())
        );
        return Err(codes::problem(codes::TYPE_MISMATCH, &message, &hint));
    }
    Ok(())
}

fn validate_record(schema: &Value, entries: &Entries, path: &str) -> Result<Value, Problem> {
    let fields = part(schema, "fields").and_then(Value::as_map).cloned().unwrap_or_default();
    for key in entries.keys() {
        if !fields.contains_key(key) {
            let names: Vec<&str> = fields.keys().map(|k| &**k).collect();
            let message = format!("`{path}` has the unknown field `{key}`.");
            let hint = match crate::suggest(key, &names) {
                Some(s) => format!("Did you mean `{s}`? The schema is closed."),
                None => format!("The schema allows {}.", names.join(", ")),
            };
            return Err(codes::problem(codes::TYPE_MISMATCH, &message, &hint));
        }
    }
    let mut out = Entries::new();
    for (name, field) in &fields {
        let at = format!("{path}.{name}");
        match (entries.get(name), kind(field)) {
            (Some(v), _) => {
                out.insert(name.clone(), validate(field, v, &at)?);
            }
            (None, "optional") => {
                if let Some(default) = part(field, "default") {
                    out.insert(name.clone(), default.clone());
                }
            }
            (None, _) => {
                let message = format!("`{at}` is required, but it is missing.");
                return Err(codes::problem(
                    codes::TYPE_MISMATCH,
                    &message,
                    &format!("Set `{name}` in the stack's input file."),
                ));
            }
        }
    }
    Ok(Value::of_entries(out))
}

fn secret_ref(entries: &Entries, path: &str) -> Result<Value, Problem> {
    let name = entries.get("secret").and_then(Value::as_text);
    let version = entries.get("version").and_then(Value::as_int);
    match (name, version, entries.len()) {
        (Some(name), Some(version), 2) if version > 0 => {
            let payload =
                Value::map([("name", Value::text(name)), ("version", Value::Int(version))]);
            Ok(Value::opaque(refs::SECRET_REF, refs::VERSION, payload))
        }
        _ => {
            let message = format!("`{path}` must be `{{ secret = \"name\", version = N }}`.");
            let hint = "Secrets are versioned references; plaintext never appears in inputs.";
            Err(codes::problem(codes::TYPE_MISMATCH, &message, hint))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_respect_max_items() {
        let schema =
            make("list", vec![("item", make("int", vec![])), ("max_items", Value::Int(2))]);
        let two = Value::list(vec![Value::Int(80), Value::Int(443)]);
        assert_eq!(validate(&schema, &two, "ports").unwrap(), two);
        let three = Value::list(vec![Value::Int(80), Value::Int(443), Value::Int(8080)]);
        let problem = validate(&schema, &three, "ports").unwrap_err();
        assert!(problem.message.contains("at most 2"), "{problem:?}");
    }
}
