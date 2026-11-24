//! Operators, indexing and the prelude builtins.
//!
//! Integer arithmetic is checked in the signed 64-bit range; `+` also concatenates two
//! texts, two byte strings or two lists within the size bounds. Equality is structural
//! and tag-sensitive, ordering applies only to two integers or two texts, and indices
//! must be nonnegative and in range (JDD 0004, "Bindings and evaluation").

use std::sync::Arc;

use jlv_core::{Diagnostic, Limits, Span};

use crate::codes;
use crate::eval::mismatch;
use crate::program::{BinaryOp, Builtin, UnaryOp};
use crate::value::{Entries, Value};

fn fault(code: &str, message: &str, hint: &str, span: Span) -> Diagnostic {
    Diagnostic::at(codes::problem(code, message, hint), span)
}

fn overflow(span: Span) -> Diagnostic {
    fault(
        codes::INTEGER_OVERFLOW,
        "The result is outside the signed 64-bit integer range.",
        "Keep values between -9223372036854775808 and 9223372036854775807.",
        span,
    )
}

/// Applies a unary operator.
pub(crate) fn unary(op: UnaryOp, v: Value, span: Span) -> Result<Value, Diagnostic> {
    match (op, v) {
        (UnaryOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
        (UnaryOp::Neg, Value::Int(n)) => {
            n.checked_neg().map(Value::Int).ok_or_else(|| overflow(span))
        }
        (UnaryOp::Plus, Value::Int(n)) => Ok(Value::Int(n)),
        (UnaryOp::Not, other) => Err(mismatch("a boolean", &other, span)),
        (_, other) => Err(mismatch("an integer", &other, span)),
    }
}

/// Applies a strict binary operator.
pub(crate) fn binary(
    op: BinaryOp,
    a: Value,
    b: Value,
    limits: &Limits,
    span: Span,
) -> Result<Value, Diagnostic> {
    match op {
        BinaryOp::Eq => Ok(Value::Bool(a == b)),
        BinaryOp::Ne => Ok(Value::Bool(a != b)),
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => compare(op, &a, &b, span),
        BinaryOp::Add => add(a, b, limits, span),
        BinaryOp::Sub | BinaryOp::Mul => {
            let (Value::Int(x), Value::Int(y)) = (&a, &b) else {
                let bad = if a.as_int().is_none() { &a } else { &b };
                return Err(mismatch("an integer", bad, span));
            };
            let result = if op == BinaryOp::Sub { x.checked_sub(*y) } else { x.checked_mul(*y) };
            result.map(Value::Int).ok_or_else(|| overflow(span))
        }
    }
}

fn compare(op: BinaryOp, a: &Value, b: &Value, span: Span) -> Result<Value, Diagnostic> {
    let ordering = match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        (Value::Text(x), Value::Text(y)) => x.as_bytes().cmp(y.as_bytes()),
        _ => {
            return Err(mismatch(
                "two integers or two texts",
                if a.as_int().is_some() { b } else { a },
                span,
            ));
        }
    };
    let result = match op {
        BinaryOp::Lt => ordering.is_lt(),
        BinaryOp::Le => ordering.is_le(),
        BinaryOp::Gt => ordering.is_gt(),
        _ => ordering.is_ge(),
    };
    Ok(Value::Bool(result))
}

fn add(a: Value, b: Value, limits: &Limits, span: Span) -> Result<Value, Diagnostic> {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => {
            x.checked_add(y).map(Value::Int).ok_or_else(|| overflow(span))
        }
        (Value::Text(x), Value::Text(y)) => {
            check_bytes(x.len() + y.len(), limits, span)?;
            Ok(Value::Text(Arc::from(format!("{x}{y}"))))
        }
        (Value::Bytes(x), Value::Bytes(y)) => {
            check_bytes(x.len() + y.len(), limits, span)?;
            Ok(Value::Bytes([&x[..], &y[..]].concat().into()))
        }
        (Value::List(x), Value::List(y)) => {
            if x.len().saturating_add(y.len()) > limits.container_len {
                let message = format!("A list would exceed {} items.", limits.container_len);
                return Err(fault(
                    codes::BUDGET_EXHAUSTED,
                    &message,
                    "Build smaller collections.",
                    span,
                ));
            }
            let mut items = Arc::unwrap_or_clone(x).into_items();
            items.extend(y.iter().cloned());
            bounded_list(items, limits, span)
        }
        (a, _) => Err(mismatch("two integers, texts, byte strings or lists", &a, span)),
    }
}

fn check_bytes(len: usize, limits: &Limits, span: Span) -> Result<(), Diagnostic> {
    if len > limits.string_bytes {
        let message = format!("A text or byte string would exceed {} bytes.", limits.string_bytes);
        return Err(fault(codes::BUDGET_EXHAUSTED, &message, "Build smaller values.", span));
    }
    Ok(())
}

/// A list that comprehensions build, within the container bound and the value depth.
pub(crate) fn bounded_len(list: Value, limits: &Limits, span: Span) -> Result<Value, Diagnostic> {
    if list.as_list().is_some_and(|items| items.len() > limits.container_len) {
        let message = format!("A list would exceed {} items.", limits.container_len);
        return Err(fault(codes::BUDGET_EXHAUSTED, &message, "Build smaller collections.", span));
    }
    nested(list, limits, span)
}

/// The parts of an interpolated string joined: texts as they are, integers in decimal
/// and booleans as `true` or `false`, within the text size bound.
pub(crate) fn concat(parts: Vec<Value>, limits: &Limits, span: Span) -> Result<Value, Diagnostic> {
    let mut text = String::new();
    for part in parts {
        match part {
            Value::Text(t) => text.push_str(&t),
            Value::Int(n) => text.push_str(&n.to_string()),
            Value::Bool(b) => text.push_str(if b { "true" } else { "false" }),
            other => return Err(mismatch("a text, an integer or a boolean", &other, span)),
        }
        check_bytes(text.len(), limits, span)?;
    }
    Ok(Value::Text(Arc::from(text)))
}

/// A list value within the container bound.
pub(crate) fn bounded_list(
    items: Vec<Value>,
    limits: &Limits,
    span: Span,
) -> Result<Value, Diagnostic> {
    if items.len() > limits.container_len {
        let message = format!("A list would exceed {} items.", limits.container_len);
        return Err(fault(codes::BUDGET_EXHAUSTED, &message, "Build smaller collections.", span));
    }
    nested(Value::list(items), limits, span)
}

/// `value` when it nests no deeper than `[limits] value_depth`; the functions that
/// recurse over a value then recurse a bounded depth (JDD 0013).
pub(crate) fn nested(value: Value, limits: &Limits, span: Span) -> Result<Value, Diagnostic> {
    if value.depth() as usize <= limits.value_depth {
        return Ok(value);
    }
    let message = format!("A value would nest more than {} levels deep.", limits.value_depth);
    let hint = "Build flatter data: a list of records rather than records within records.";
    Err(fault(codes::BUDGET_EXHAUSTED, &message, hint, span))
}

/// A map literal's value; entries are checked in source order for duplicate keys.
pub(crate) fn map_literal(
    pairs: Vec<(Arc<str>, Span, Value)>,
    limits: &Limits,
    span: Span,
) -> Result<Value, Diagnostic> {
    let mut entries = Entries::new();
    for (key, span, value) in pairs {
        if entries.contains_key(&key) {
            let message = format!("The key `{key}` appears twice in one map.");
            return Err(fault(codes::DUPLICATE_KEY, &message, "Remove one of the entries.", span));
        }
        if entries.len() >= limits.container_len {
            let message = format!("A map would exceed {} entries.", limits.container_len);
            return Err(fault(
                codes::BUDGET_EXHAUSTED,
                &message,
                "Build smaller collections.",
                span,
            ));
        }
        entries.insert(key, value);
    }
    nested(Value::of_entries(entries), limits, span)
}

/// `a[i]`: a list item, a byte or a map entry.
pub(crate) fn index(a: Value, i: Value, span: Span) -> Result<Value, Diagnostic> {
    match (&a, &i) {
        (Value::List(items), Value::Int(n)) => {
            position(*n, items.len(), span).map(|at| items[at].clone())
        }
        (Value::Bytes(bytes), Value::Int(n)) => {
            position(*n, bytes.len(), span).map(|at| Value::Int(i64::from(bytes[at])))
        }
        (Value::Map(entries), Value::Text(key)) => {
            entries.get(key).cloned().ok_or_else(|| missing_key(key, span))
        }
        (Value::Map(_), other) => Err(mismatch("a text key", other, span)),
        (Value::List(_) | Value::Bytes(_), other) => {
            Err(mismatch("an integer index", other, span))
        }
        (other, _) => Err(mismatch("a list, bytes or a map", other, span)),
    }
}

fn position(n: i64, len: usize, span: Span) -> Result<usize, Diagnostic> {
    match usize::try_from(n) {
        Ok(at) if at < len => Ok(at),
        _ => {
            let message = format!("The index {n} is outside 0..{len}.");
            let hint =
                "Use an index from 0 to the length minus one; JLV has no negative indexing.";
            Err(fault(codes::INDEX_ERROR, &message, hint, span))
        }
    }
}

fn missing_key(key: &str, span: Span) -> Diagnostic {
    let message = format!("The map has no key `{key}`.");
    fault(
        codes::INDEX_ERROR,
        &message,
        "Check with `contains` first; a missing key is not null.",
        span,
    )
}

/// `a.name` on a record value.
pub(crate) fn field(a: Value, name: &str, span: Span) -> Result<Value, Diagnostic> {
    match &a {
        Value::Map(entries) => entries.get(name).cloned().ok_or_else(|| missing_key(name, span)),
        other => Err(mismatch("a record", other, span)),
    }
}

/// Runs a prelude builtin and returns its value and its size cost in steps.
pub(crate) fn builtin(
    b: Builtin,
    args: Vec<Value>,
    limits: &Limits,
    span: Span,
) -> Result<(Value, u64), Diagnostic> {
    let arg = |i: usize| args.get(i).cloned().unwrap_or(Value::Null);
    match b {
        Builtin::Len => {
            let n = match arg(0) {
                Value::Text(t) => t.len(),
                Value::Bytes(x) => x.len(),
                Value::List(items) => items.len(),
                Value::Map(entries) => entries.len(),
                other => return Err(mismatch("a text, bytes, list or map", &other, span)),
            };
            Ok((Value::Int(n as i64), 1))
        }
        Builtin::Keys => match arg(0) {
            Value::Map(entries) => {
                let keys: Vec<Value> = entries.keys().map(|k| Value::Text(k.clone())).collect();
                let cost = keys.len() as u64;
                Ok((Value::list(keys), cost))
            }
            other => Err(mismatch("a map", &other, span)),
        },
        Builtin::Contains => contains(arg(0), &arg(1), limits, span),
        Builtin::Range => range(&args, limits, span),
        Builtin::Fail => {
            let message = arg(0).as_text().unwrap_or("fail() was called").to_string();
            let problem =
                jlv_core::Problem::new(codes::USER_ERROR, "PREPARATION FAILED", &message)
                    .status(422)
                    .consequence(codes::CONSEQUENCE)
                    .hint(
                        "The program's own check stopped preparation; correct the input it names.",
                    );
            Err(Diagnostic::at(problem, span))
        }
    }
}

/// `contains`; a list search that would cost more than the invocation's whole step
/// budget fails before it compares anything.
fn contains(
    collection: Value,
    item: &Value,
    limits: &Limits,
    span: Span,
) -> Result<(Value, u64), Diagnostic> {
    match (&collection, item) {
        (Value::List(items), _) => {
            let cost =
                collection.size_units().min(item.size_units().saturating_mul(items.len() as u64));
            if cost > limits.evaluation_steps {
                let message = "Comparing this list element exceeds the evaluation budget.";
                return Err(fault(codes::BUDGET_EXHAUSTED, message, "Use smaller values.", span));
            }
            Ok((Value::Bool(items.contains(item)), cost.max(items.len() as u64)))
        }
        (Value::Map(entries), Value::Text(key)) => Ok((Value::Bool(entries.contains_key(key)), 1)),
        (Value::Text(text), Value::Text(part)) => {
            Ok((Value::Bool(text.contains(&**part)), (text.len() as u64).div_ceil(64)))
        }
        (other, _) => Err(mismatch("a list, a map with a text key, or two texts", other, span)),
    }
}

fn range(args: &[Value], limits: &Limits, span: Span) -> Result<(Value, u64), Diagnostic> {
    let ints: Vec<i64> = args.iter().filter_map(Value::as_int).collect();
    let (start, end) = match ints[..] {
        [end] => (0, end),
        [start, end] => (start, end),
        _ => {
            return Err(mismatch(
                "one or two integers",
                args.first().unwrap_or(&Value::Null),
                span,
            ));
        }
    };
    let len = end.saturating_sub(start).max(0) as u64;
    if len > limits.container_len as u64 {
        let message =
            format!("range would produce {len} items, more than {}.", limits.container_len);
        return Err(fault(codes::BUDGET_EXHAUSTED, &message, "Use a smaller range.", span));
    }
    Ok((Value::list((start..end).map(Value::Int).collect()), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span() -> Span {
        Span::default()
    }

    #[test]
    fn arithmetic_is_checked() {
        let limits = Limits::default();
        let max = Value::Int(i64::MAX);
        let error = binary(BinaryOp::Add, max, Value::Int(1), &limits, span()).unwrap_err();
        assert_eq!(error.code(), "integer_overflow");
        assert_eq!(
            unary(UnaryOp::Neg, Value::Int(i64::MIN), span()).unwrap_err().code(),
            "integer_overflow"
        );
        assert_eq!(
            binary(BinaryOp::Eq, Value::Bool(true), Value::Int(1), &limits, span()).unwrap(),
            Value::Bool(false)
        );
    }

    #[test]
    fn indices_are_nonnegative_and_keys_present() {
        let list = Value::list(vec![Value::Int(1)]);
        assert_eq!(index(list.clone(), Value::Int(-1), span()).unwrap_err().code(), "index_error");
        assert_eq!(index(list, Value::Int(0), span()).unwrap(), Value::Int(1));
        let map = Value::map([("a", Value::Int(1))]);
        assert_eq!(index(map, Value::text("b"), span()).unwrap_err().code(), "index_error");
    }

    #[test]
    fn len_counts_utf8_bytes() {
        let limits = Limits::default();
        let (n, _) = builtin(Builtin::Len, vec![Value::text("A\u{e9}")], &limits, span()).unwrap();
        assert_eq!(n, Value::Int(3));
    }

    #[test]
    fn contains_checks_the_invocations_own_budget() {
        let list = Value::list((0..100).map(|_| Value::text(&"x".repeat(640))).collect());
        let item = Value::text(&"y".repeat(640));
        let args = || vec![list.clone(), item.clone()];
        let tight = Limits { evaluation_steps: 500, ..Limits::default() };
        let error = builtin(Builtin::Contains, args(), &tight, span()).unwrap_err();
        assert_eq!(error.code(), "budget_exhausted");
        let (found, cost) =
            builtin(Builtin::Contains, args(), &Limits::default(), span()).unwrap();
        assert_eq!((found, cost), (Value::Bool(false), 1000));
    }

    #[test]
    fn duplicate_keys_are_found_in_order() {
        let pairs =
            vec![(Arc::from("a"), span(), Value::Int(1)), (Arc::from("a"), span(), Value::Int(2))];
        assert_eq!(
            map_literal(pairs, &Limits::default(), Span::default()).unwrap_err().code(),
            "duplicate_key"
        );
    }
}
