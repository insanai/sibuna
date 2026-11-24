//! `jlv.std.config`: configuration files written from plain data (JDD 0011).
//!
//! A format that is sections of keys, keys and values, or JSON is best written from a
//! map, so a misspelt key is a map key we can see and the file is always well formed.
//! Each function is pure and gives the same text for the same data: keys, and the
//! sections of an INI file, appear in sorted order; `config.systemd` puts `[Unit]`
//! first and `[Install]` last, as unit files are written by hand. A list value repeats
//! its key once per item, as `Environment=` or `ExecStartPre=` do; a `null` value
//! leaves the key out. A key, a section or a value that could break the file, such as
//! one with a line break, is an `argument_error`.

use gd_json::Value as Json;
use jlv_core::Problem;
use jlv_lang::native::Call;
use jlv_lang::{Type, Value, codes};

use crate::support::{LibraryBuilder, NativeFn, Natives, arg, sig, text};

/// The library label.
pub const LABEL: &str = "@jlv//std:config.jlv";

/// The config library and its natives.
pub fn library(natives: &mut Natives) -> jlv_lang::signature::Library {
    let mut lib = LibraryBuilder::new(LABEL);
    let sections = || Type::map(Type::map(Type::Value));
    let functions: Vec<(&str, jlv_lang::signature::Signature, NativeFn)> = vec![
        ("systemd", sig(&[("sections", sections())], Type::Text), systemd),
        ("ini", sig(&[("sections", sections())], Type::Text), ini),
        (
            "key_values",
            sig(&[("values", Type::map(Type::Value)), ("separator", Type::Text)], Type::Text),
            key_values,
        ),
        ("json", sig(&[("value", Type::map(Type::Value))], Type::Text), json),
    ];
    lib.namespace(natives, "config", functions);
    lib.finish()
}

/// How a format spells a boolean, or `None` when it has no spelling for one.
type Booleans = Option<(&'static str, &'static str)>;

fn invalid(message: &str, hint: &str) -> Problem {
    codes::problem(codes::ARGUMENT_ERROR, message, hint)
}

/// A key or a section name: letters, digits and `_ . -`, and spaces in a section.
fn checked<'a>(name: &'a str, what: &str, spaces: bool) -> Result<&'a str, Problem> {
    let good = |c: char| c.is_ascii_alphanumeric() || "_.-".contains(c) || (spaces && c == ' ');
    if !name.is_empty() && name.chars().all(good) {
        return Ok(name);
    }
    let message = format!("`{name}` is not a {what} the file can hold.");
    Err(invalid(&message, "Use letters, digits and `_ . -`."))
}

/// The spellings of `value` for `key`: one per item of a list, none for `null`.
fn spellings(key: &str, value: &Value, booleans: Booleans) -> Result<Vec<String>, Problem> {
    let one = |v: &Value| -> Result<String, Problem> {
        let spelled = match (v, booleans) {
            (Value::Text(t), _) => t.to_string(),
            (Value::Int(n), _) => n.to_string(),
            (Value::Bool(b), Some((yes, no))) => (if *b { yes } else { no }).to_string(),
            (Value::Bool(_), None) => {
                let message = format!("`{key}` is a Bool, which this format has no spelling for.");
                let hint = "Write the text the program expects, such as \"yes\" or \"1\".";
                return Err(invalid(&message, hint));
            }
            _ => {
                let message = format!("`{key}` must be text, a number, a list of them or null.");
                return Err(invalid(&message, "Write one value, or a list to repeat the key."));
            }
        };
        if spelled.contains(['\n', '\r']) {
            let message = format!("The value of `{key}` has a line break.");
            return Err(invalid(&message, "Write the value on one line."));
        }
        Ok(spelled)
    };
    match value {
        Value::Null => Ok(Vec::new()),
        Value::List(items) => items.iter().map(one).collect(),
        v => Ok(vec![one(v)?]),
    }
}

fn push_bounded(out: &mut String, piece: &str, limit: usize) -> Result<(), Problem> {
    if out.len().saturating_add(piece.len()) > limit {
        let message = format!("The text would exceed {limit} bytes.");
        return Err(codes::problem(codes::BUDGET_EXHAUSTED, &message, "Build smaller texts."));
    }
    out.push_str(piece);
    Ok(())
}

/// The lines `key{separator}value` of one map, keys sorted.
fn write_keys(
    out: &mut String,
    values: &Value,
    separator: &str,
    booleans: Booleans,
    limit: usize,
) -> Result<(), Problem> {
    let map = values.as_map().ok_or_else(|| invalid("A section is not a map.", "Write `#{}`."))?;
    for (key, value) in map.iter() {
        let key = checked(key, "key", false)?;
        for spelled in spellings(key, value, booleans)? {
            push_bounded(out, key, limit)?;
            push_bounded(out, separator, limit)?;
            push_bounded(out, &spelled, limit)?;
            push_bounded(out, "\n", limit)?;
        }
    }
    Ok(())
}

/// Sections in `order`, each as `[name]` and its keys, separated by blank lines.
fn write_sections(
    sections: &Value,
    order: impl Fn(&str) -> u8,
    booleans: Booleans,
    limit: usize,
) -> Result<String, Problem> {
    let map =
        sections.as_map().ok_or_else(|| invalid("`sections` is not a map.", "Write `#{}`."))?;
    let mut names: Vec<&str> = map.keys().map(|k| &**k).collect();
    names.sort_by_key(|n| (order(n), *n));
    let mut out = String::new();
    for name in names {
        if !out.is_empty() {
            push_bounded(&mut out, "\n", limit)?;
        }
        push_bounded(&mut out, &format!("[{}]\n", checked(name, "section", true)?), limit)?;
        write_keys(&mut out, &map[name], "=", booleans, limit)?;
    }
    Ok(out)
}

/// `config.systemd`: a unit file or drop-in. `[Unit]` comes first and `[Install]`
/// last; booleans are `yes` and `no`.
fn systemd(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let order = |name: &str| match name {
        "Unit" => 0,
        "Install" => 2,
        _ => 1,
    };
    let text = write_sections(arg(args, 0), order, Some(("yes", "no")), call.limits.string_bytes)?;
    bounded(call, text)
}

/// `config.ini`: sections and keys in sorted order; no boolean spelling.
fn ini(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let text = write_sections(arg(args, 0), |_| 0, None, call.limits.string_bytes)?;
    bounded(call, text)
}

/// `config.key_values`: one `key{separator}value` line per key, such as `sshd_config`
/// with `" "`, `sysctl.d` with `" = "` or an environment file with `"="`.
fn key_values(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let separator = text(args, 1)?;
    if separator.is_empty() || separator.contains(['\n', '\r']) {
        let hint = "Pass the separator the program reads, such as \" \" or \"=\".";
        return Err(invalid("The separator is empty or has a line break.", hint));
    }
    let mut out = String::new();
    write_keys(&mut out, arg(args, 0), separator, None, call.limits.string_bytes)?;
    bounded(call, out)
}

/// `config.json`: the value as indented JSON with a final line feed.
fn json(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let limit = call.limits.string_bytes;
    let mut out = String::new();
    write_json(&mut out, arg(args, 0), 0, limit)?;
    push_bounded(&mut out, "\n", limit)?;
    bounded(call, out)
}

fn write_json(
    out: &mut String,
    value: &Value,
    indent: usize,
    limit: usize,
) -> Result<(), Problem> {
    match value {
        Value::Null => push_bounded(out, "null", limit),
        Value::Bool(b) => push_bounded(out, if *b { "true" } else { "false" }, limit),
        Value::Int(n) => push_bounded(out, &n.to_string(), limit),
        Value::Text(t) => push_json_string(out, t, limit),
        Value::List(items) if items.is_empty() => push_bounded(out, "[]", limit),
        Value::List(items) => {
            push_bounded(out, "[\n", limit)?;
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    push_bounded(out, ",\n", limit)?;
                }
                push_spaces(out, (indent + 1) * 2, limit)?;
                write_json(out, item, indent + 1, limit)?;
            }
            push_bounded(out, "\n", limit)?;
            push_spaces(out, indent * 2, limit)?;
            push_bounded(out, "]", limit)
        }
        Value::Map(map) if map.is_empty() => push_bounded(out, "{}", limit),
        Value::Map(map) => {
            push_bounded(out, "{\n", limit)?;
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    push_bounded(out, ",\n", limit)?;
                }
                push_spaces(out, (indent + 1) * 2, limit)?;
                push_json_string(out, k, limit)?;
                push_bounded(out, ": ", limit)?;
                write_json(out, v, indent + 1, limit)?;
            }
            push_bounded(out, "\n", limit)?;
            push_spaces(out, indent * 2, limit)?;
            push_bounded(out, "}", limit)
        }
        Value::Bytes(_) => {
            let hint = "Encode bytes as text first, such as with `bytes.to_base64url`.";
            Err(invalid("JSON has no spelling for bytes.", hint))
        }
        Value::Opaque(o) => {
            let message = format!("JSON has no spelling for `{}` handles.", o.type_id);
            let hint = "Pass plain data; resource, target and secret handles are not JSON.";
            Err(invalid(&message, hint))
        }
    }
}

fn push_spaces(out: &mut String, mut count: usize, limit: usize) -> Result<(), Problem> {
    const SPACES: &str = "                                                                ";
    while count > 0 {
        let step = count.min(SPACES.len());
        push_bounded(out, &SPACES[..step], limit)?;
        count -= step;
    }
    Ok(())
}

fn push_json_string(out: &mut String, text: &str, limit: usize) -> Result<(), Problem> {
    if !text.bytes().any(|b| b < 0x20 || b == b'"' || b == b'\\') {
        push_bounded(out, "\"", limit)?;
        push_bounded(out, text, limit)?;
        return push_bounded(out, "\"", limit);
    }
    let escaped = gd_json::to_string(&Json::String(text.to_string()));
    push_bounded(out, &escaped, limit)
}

fn bounded(call: &Call<'_>, text: String) -> Result<Value, Problem> {
    crate::foundation::bounded_text(call, text)
}
