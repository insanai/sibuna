//! `jlv.std.foundation`: exact arithmetic, text, sequences, maps and bytes
//! (JDD 0004, "Modules, context and foundation").
//!
//! Every function returns a new value; none mutates its arguments. Texts count UTF-8
//! bytes unless a function names scalars, and base64url is canonical and unpadded.

use std::sync::Arc;

use jlv_core::Problem;
use jlv_lang::native::Call;
use jlv_lang::signature::{Library, Signature};
use jlv_lang::{Type, Value, base64, codes};

use crate::support::{LibraryBuilder, NativeFn, Natives, arg, int, list, sig, text};

/// The library label.
pub const LABEL: &str = "@jlv//std:foundation.jlv";

/// The foundation library and its natives.
pub fn library(natives: &mut Natives) -> Library {
    let mut lib = LibraryBuilder::new(LABEL);
    math(&mut lib, natives);
    texts(&mut lib, natives);
    collections(&mut lib, natives);
    lib.finish()
}

fn math(lib: &mut LibraryBuilder, natives: &mut Natives) {
    let int2 = [("a", Type::Int), ("b", Type::Int)];
    let functions: Vec<(&str, Signature, NativeFn)> = vec![
        ("div_floor", sig(&int2, Type::Int), div_floor),
        ("rem_floor", sig(&int2, Type::Int), rem_floor),
        ("min", sig(&int2, Type::Int), min),
        ("max", sig(&int2, Type::Int), max),
        ("abs", sig(&[("a", Type::Int)], Type::Int), abs),
    ];
    lib.namespace(natives, "math", functions);
}

fn texts(lib: &mut LibraryBuilder, natives: &mut Natives) {
    let t = || Type::Text;
    let two = |a: &'static str, b: &'static str| [(a, t()), (b, t())];
    let functions: Vec<(&str, Signature, NativeFn)> = vec![
        ("scalar_count", sig(&[("text", t())], Type::Int), scalar_count),
        ("from_int", sig(&[("value", Type::Int)], t()), from_int),
        ("starts_with", sig(&two("text", "prefix"), Type::Bool), starts_with),
        ("ends_with", sig(&two("text", "suffix"), Type::Bool), ends_with),
        ("join", sig(&[("parts", Type::list(t())), ("separator", t())], t()), join),
        ("split", sig(&two("text", "separator"), Type::list(t())), split),
        ("replace", sig(&[("text", t()), ("old", t()), ("new", t())], t()), replace),
        ("lower", sig(&[("text", t())], t()), lower),
        ("upper", sig(&[("text", t())], t()), upper),
    ];
    lib.namespace(natives, "text", functions);
    let functions: Vec<(&str, Signature, NativeFn)> = vec![
        ("from_base64url", sig(&[("text", t())], Type::Bytes), from_base64url),
        ("to_base64url", sig(&[("bytes", Type::Bytes)], t()), to_base64url),
        ("from_text", sig(&[("text", t())], Type::Bytes), from_text),
    ];
    lib.namespace(natives, "bytes", functions);
}

fn collections(lib: &mut LibraryBuilder, natives: &mut Natives) {
    let (item, items) = (Type::Var(0), Type::list(Type::Var(0)));
    let functions: Vec<(&str, Signature, NativeFn)> = vec![
        (
            "append",
            sig(&[("items", items.clone()), ("item", item.clone())], items.clone()),
            append,
        ),
        ("reverse", sig(&[("items", items.clone())], items), reverse),
    ];
    lib.namespace(natives, "seq", functions);
    let entries = Type::map(Type::Var(0));
    let key = ("key", Type::Text);
    let functions: Vec<(&str, Signature, NativeFn)> = vec![
        (
            "set",
            sig(
                &[("entries", entries.clone()), key.clone(), ("value", item.clone())],
                entries.clone(),
            ),
            set,
        ),
        ("remove", sig(&[("entries", entries.clone()), key.clone()], entries.clone()), remove),
        ("get_or", sig(&[("entries", entries), key, ("default", item)], Type::Var(0)), get_or),
    ];
    lib.namespace(natives, "map", functions);
}

fn zero() -> Problem {
    codes::problem(
        codes::DIVISION_BY_ZERO,
        "The divisor is zero.",
        "Check the divisor before dividing.",
    )
}

pub(crate) fn overflow() -> Problem {
    codes::problem(
        codes::INTEGER_OVERFLOW,
        "The result is outside the signed 64-bit integer range.",
        "Keep values within -9223372036854775808..9223372036854775807.",
    )
}

/// `q = floor(a / b)`.
fn div_floor(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let (a, b) = (int(args, 0)?, int(args, 1)?);
    if b == 0 {
        return Err(zero());
    }
    let q = a.checked_div(b).ok_or_else(overflow)?;
    let q = if (a % b != 0) && ((a < 0) != (b < 0)) { q - 1 } else { q };
    Ok(Value::Int(q))
}

/// `r = a - b * floor(a / b)`.
fn rem_floor(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let (a, b) = (int(args, 0)?, int(args, 1)?);
    if b == 0 {
        return Err(zero());
    }
    // `i64::MIN % -1` is mathematically zero, though the machine operation overflows.
    let r = if b == -1 { 0 } else { a % b };
    Ok(Value::Int(if r != 0 && ((r < 0) != (b < 0)) { r + b } else { r }))
}

fn min(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::Int(int(args, 0)?.min(int(args, 1)?)))
}

fn max(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::Int(int(args, 0)?.max(int(args, 1)?)))
}

fn abs(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    int(args, 0)?.checked_abs().map(Value::Int).ok_or_else(overflow)
}

fn scalar_count(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::Int(text(args, 0)?.chars().count() as i64))
}

fn from_int(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::text(&int(args, 0)?.to_string()))
}

fn starts_with(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::Bool(text(args, 0)?.starts_with(text(args, 1)?)))
}

fn ends_with(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::Bool(text(args, 0)?.ends_with(text(args, 1)?)))
}

pub(crate) fn bounded_text(call: &Call<'_>, text: String) -> Result<Value, Problem> {
    if text.len() > call.limits.string_bytes {
        let message = format!("The text would exceed {} bytes.", call.limits.string_bytes);
        return Err(codes::problem(codes::BUDGET_EXHAUSTED, &message, "Build smaller texts."));
    }
    Ok(Value::Text(Arc::from(text)))
}

/// A budget problem for a text that would exceed `limit` bytes.
fn text_too_long(limit: usize) -> Problem {
    let message = format!("The text would exceed {limit} bytes.");
    codes::problem(codes::BUDGET_EXHAUSTED, &message, "Build smaller texts.")
}

fn join(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let parts: Vec<&str> = list(args, 0)?.iter().filter_map(Value::as_text).collect();
    let separator = text(args, 1)?;
    // The parts may share one large text, so measure before joining.
    let total = parts
        .iter()
        .fold(0usize, |sum, p| sum.saturating_add(p.len()))
        .saturating_add(separator.len().saturating_mul(parts.len().saturating_sub(1)));
    if total > call.limits.string_bytes {
        return Err(text_too_long(call.limits.string_bytes));
    }
    bounded_text(call, parts.join(separator))
}

fn split(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let separator = text(args, 1)?;
    if separator.is_empty() {
        let hint = "Pass a nonempty separator; use `text.scalar_count` to count scalars.";
        return Err(codes::problem(codes::ARGUMENT_ERROR, "The separator is empty.", hint));
    }
    let mut items = Vec::new();
    for part in text(args, 0)?.split(separator) {
        if items.len() >= call.limits.container_len {
            let message = format!("The list would exceed {} items.", call.limits.container_len);
            return Err(codes::problem(codes::BUDGET_EXHAUSTED, &message, "Build smaller lists."));
        }
        items.push(Value::text(part));
    }
    Ok(Value::list(items))
}

/// `text.replace(text, old, new)`: every `old` replaced by `new`, within the string
/// budget.
fn replace(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let old = text(args, 1)?;
    if old.is_empty() {
        let hint = "Pass the nonempty text to replace.";
        return Err(codes::problem(codes::ARGUMENT_ERROR, "The text to replace is empty.", hint));
    }
    let (source, new) = (text(args, 0)?, text(args, 2)?);
    let grows = new.len().saturating_sub(old.len()) * source.matches(old).count();
    if source.len() + grows > call.limits.string_bytes {
        let message = format!("The text would exceed {} bytes.", call.limits.string_bytes);
        return Err(codes::problem(codes::BUDGET_EXHAUSTED, &message, "Build smaller texts."));
    }
    Ok(Value::text(&source.replace(old, new)))
}

fn lower(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::text(&text(args, 0)?.to_ascii_lowercase()))
}

fn upper(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::text(&text(args, 0)?.to_ascii_uppercase()))
}

fn append(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let mut items = list(args, 0)?.to_vec();
    if items.len() >= call.limits.container_len {
        let message = format!("The list would exceed {} items.", call.limits.container_len);
        return Err(codes::problem(codes::BUDGET_EXHAUSTED, &message, "Build smaller lists."));
    }
    items.push(arg(args, 1).clone());
    nested_value(call, Value::list(items))
}

fn nested_value(call: &Call<'_>, value: Value) -> Result<Value, Problem> {
    if value.depth() as usize <= call.limits.value_depth {
        return Ok(value);
    }
    let message = format!("A value would nest more than {} levels deep.", call.limits.value_depth);
    let hint = "Build flatter data: a list of records rather than records within records.";
    Err(codes::problem(codes::BUDGET_EXHAUSTED, &message, hint))
}

fn reverse(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::list(list(args, 0)?.iter().rev().cloned().collect()))
}

fn entries(args: &[Option<Value>]) -> Result<jlv_lang::value::Entries, Problem> {
    arg(args, 0).as_map().cloned().ok_or_else(|| {
        codes::problem(codes::TYPE_MISMATCH, "The first argument must be a map.", "Pass a map.")
    })
}

fn set(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let mut map = entries(args)?;
    let key = text(args, 1)?;
    if !map.contains_key(key) && map.len() >= call.limits.container_len {
        let message = format!("The map would exceed {} entries.", call.limits.container_len);
        return Err(codes::problem(codes::BUDGET_EXHAUSTED, &message, "Build smaller maps."));
    }
    map.insert(Arc::from(key), arg(args, 2).clone());
    nested_value(call, Value::of_entries(map))
}

fn remove(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let mut map = entries(args)?;
    map.remove(text(args, 1)?);
    Ok(Value::of_entries(map))
}

fn get_or(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let map = entries(args)?;
    Ok(map.get(text(args, 1)?).cloned().unwrap_or_else(|| arg(args, 2).clone()))
}

fn from_base64url(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let spelled = text(args, 0)?;
    let bytes = base64::decode(spelled).ok_or_else(|| {
        let message = format!("`{spelled}` is not canonical unpadded base64url.");
        codes::problem(
            codes::ARGUMENT_ERROR,
            &message,
            "Use A-Z, a-z, 0-9, `-` and `_` without padding.",
        )
    })?;
    Ok(Value::Bytes(bytes.into()))
}

fn to_base64url(call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    let bytes = arg(args, 0).as_bytes().unwrap_or_default();
    if bytes.len().saturating_mul(4).div_ceil(3) > call.limits.string_bytes {
        let message = format!("The text would exceed {} bytes.", call.limits.string_bytes);
        return Err(codes::problem(codes::BUDGET_EXHAUSTED, &message, "Build smaller texts."));
    }
    bounded_text(call, base64::encode(bytes))
}

fn from_text(_: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
    Ok(Value::Bytes(text(args, 0)?.as_bytes().into()))
}
