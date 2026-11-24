//! Canonical external representation (JDD 0004, "Canonical external representation").
//!
//! Canonical records are UTF-8 JSON with object keys sorted by their UTF-8 bytes,
//! ordered arrays and no insignificant whitespace. Control characters are written as
//! lowercase `\u00xx`, quotes and backslashes are escaped, `/` is not, and every other
//! scalar is written as UTF-8. Integers are decimal; floats are excluded.
//!
//! A JLV value is written as a tagged array:
//!
//! ```text
//! Null ["null"]   Bool(b) ["bool",b]   Int(n) ["int",n]   Text(s) ["text",s]
//! Bytes(x) ["bytes",base64url(x)]   List ["list",[...]]   Map ["map",[[k,v]...]]
//! Opaque ["opaque",type_id,schema_version,payload]
//! ```

use gd_json::Value as Json;
use jlv_core::Problem;

use crate::base64;
use crate::value::{Opaque, Value};

/// The canonical bytes of a JLV value.
pub fn encode(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// Appends the canonical encoding of `value` to `out`.
pub fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("[\"null\"]"),
        Value::Bool(b) => out.push_str(if *b { "[\"bool\",true]" } else { "[\"bool\",false]" }),
        Value::Int(n) => {
            out.push_str("[\"int\",");
            out.push_str(&n.to_string());
            out.push(']');
        }
        Value::Text(t) => {
            out.push_str("[\"text\",");
            write_string(out, t);
            out.push(']');
        }
        Value::Bytes(b) => {
            out.push_str("[\"bytes\",\"");
            base64::encode_into(out, b);
            out.push_str("\"]");
        }
        Value::List(items) => {
            out.push_str("[\"list\",[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push_str("]]");
        }
        Value::Map(entries) => {
            out.push_str("[\"map\",[");
            for (i, (key, item)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('[');
                write_string(out, key);
                out.push(',');
                write_value(out, item);
                out.push(']');
            }
            out.push_str("]]");
        }
        Value::Opaque(o) => write_opaque(out, o),
    }
}

fn write_opaque(out: &mut String, o: &Opaque) {
    out.push_str("[\"opaque\",");
    write_string(out, &o.type_id);
    out.push(',');
    out.push_str(&o.version.to_string());
    out.push(',');
    write_value(out, &o.payload);
    out.push(']');
}

/// The tagged JSON tree of a value, for embedding in a JSON record; its canonical
/// rendering equals [`encode`].
pub fn to_json(value: &Value) -> Json {
    let tagged = |tag: &str, rest: Vec<Json>| {
        let mut items = vec![Json::String(tag.to_string())];
        items.extend(rest);
        Json::Array(items)
    };
    match value {
        Value::Null => tagged("null", vec![]),
        Value::Bool(b) => tagged("bool", vec![Json::Bool(*b)]),
        Value::Int(n) => tagged("int", vec![Json::from(*n)]),
        Value::Text(t) => tagged("text", vec![Json::String(t.to_string())]),
        Value::Bytes(b) => tagged("bytes", vec![Json::String(base64::encode(b))]),
        Value::List(items) => {
            tagged("list", vec![Json::Array(items.iter().map(to_json).collect())])
        }
        Value::Map(entries) => {
            let pairs = entries
                .iter()
                .map(|(k, v)| Json::Array(vec![Json::String(k.to_string()), to_json(v)]))
                .collect();
            tagged("map", vec![Json::Array(pairs)])
        }
        Value::Opaque(o) => tagged(
            "opaque",
            vec![Json::String(o.type_id.to_string()), Json::from(o.version), to_json(&o.payload)],
        ),
    }
}

/// Appends `text` as a canonical JSON string.
pub fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() && (c as u32) < 0x100 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The canonical bytes of a JSON record: sorted keys, integers only.
pub fn to_canonical_json(value: &Json) -> Result<String, Problem> {
    let mut out = String::new();
    write_json(&mut out, value)?;
    Ok(out)
}

/// Appends the canonical form of a JSON record to `out`.
pub fn write_json(out: &mut String, value: &Json) -> Result<(), Problem> {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(n) if n.is_i64() || n.is_u64() => out.push_str(&n.to_string()),
        Json::Number(_) => return Err(float_excluded()),
        Json::String(s) => write_string(out, s),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(out, item)?;
            }
            out.push(']');
        }
        Json::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_json(out, &object[key])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn float_excluded() -> Problem {
    Problem::new(
        "jlv.canonical.float",
        "FLOAT IN CANONICAL DATA",
        "Canonical records hold integers only; version 1 excludes floating-point values.",
    )
    .consequence("Nothing was encoded.")
    .hint("Use an integer in explicit units, such as milliseconds or bytes.")
}

/// Reads canonical value bytes back into a value. The text must be exactly the
/// canonical encoding of the value it describes, so equal values have one spelling.
pub fn decode(text: &str) -> Result<Value, Problem> {
    let json = gd_json::parse(text).map_err(|e| not_canonical(&e.to_string()))?;
    let value = from_json(&json)?;
    if encode(&value) != text {
        return Err(not_canonical("the text is valid but not in canonical form"));
    }
    Ok(value)
}

const MAX_CANONICAL_DEPTH: usize = 64;

/// Reads a tagged JSON tree into a value.
pub fn from_json(json: &Json) -> Result<Value, Problem> {
    from_json_at(json, 0)
}

fn from_json_at(json: &Json, depth: usize) -> Result<Value, Problem> {
    let limits = jlv_core::Limits::default();
    if depth > MAX_CANONICAL_DEPTH {
        return Err(not_canonical("the value nests deeper than canonical data allows"));
    }
    let items = json.as_array().ok_or_else(|| not_canonical("a value must be a tagged array"))?;
    let tag = items.first().and_then(Json::as_str).unwrap_or_default();
    let arg = |i: usize| items.get(i).ok_or_else(|| not_canonical("a tagged value is short"));
    let value = match (tag, items.len()) {
        ("null", 1) => Value::Null,
        ("bool", 2) => Value::Bool(arg(1)?.as_bool().ok_or_else(|| not_canonical("bool"))?),
        ("int", 2) => Value::Int(arg(1)?.as_i64().ok_or_else(|| not_canonical("int"))?),
        ("text", 2) => {
            let s = arg(1)?.as_str().ok_or_else(|| not_canonical("text"))?;
            if s.len() > limits.string_bytes {
                return Err(not_canonical("text exceeds byte limit"));
            }
            Value::text(s)
        }
        ("bytes", 2) => {
            let text = arg(1)?.as_str().ok_or_else(|| not_canonical("bytes"))?;
            if text.len() > limits.string_bytes.saturating_mul(2) {
                return Err(not_canonical("bytes exceed byte limit"));
            }
            let raw = base64::decode(text).ok_or_else(|| not_canonical("base64url"))?;
            if raw.len() > limits.string_bytes {
                return Err(not_canonical("bytes exceed byte limit"));
            }
            Value::Bytes(raw.into())
        }
        ("list", 2) => {
            let list = arg(1)?.as_array().ok_or_else(|| not_canonical("list"))?;
            if list.len() > limits.container_len {
                return Err(not_canonical("list exceeds container limit"));
            }
            let decoded = list.iter().map(|v| from_json_at(v, depth + 1));
            Value::list(decoded.collect::<Result<_, _>>()?)
        }
        ("map", 2) => map_from_json(arg(1)?, depth + 1, &limits)?,
        ("opaque", 4) => {
            let type_id = arg(1)?.as_str().ok_or_else(|| not_canonical("opaque type"))?;
            let version = arg(2)?.as_u64().and_then(|v| u32::try_from(v).ok());
            let version = version.ok_or_else(|| not_canonical("opaque version"))?;
            Value::opaque(type_id, version, from_json_at(arg(3)?, depth + 1)?)
        }
        _ => return Err(not_canonical(&format!("`{tag}` is not a value tag of this arity"))),
    };
    Ok(value)
}

fn map_from_json(json: &Json, depth: usize, limits: &jlv_core::Limits) -> Result<Value, Problem> {
    let pairs = json.as_array().ok_or_else(|| not_canonical("map entries"))?;
    if pairs.len() > limits.container_len {
        return Err(not_canonical("map exceeds container limit"));
    }
    let mut entries = crate::value::Entries::new();
    for pair in pairs {
        let pair = pair.as_array().filter(|p| p.len() == 2);
        let pair = pair.ok_or_else(|| not_canonical("a map entry is a pair"))?;
        let key = pair[0].as_str().ok_or_else(|| not_canonical("a map key is text"))?;
        if key.len() > limits.string_bytes {
            return Err(not_canonical("map key exceeds byte limit"));
        }
        if entries.insert(key.into(), from_json_at(&pair[1], depth)?).is_some() {
            return Err(not_canonical("a map repeats a key"));
        }
    }
    Ok(Value::of_entries(entries))
}

fn not_canonical(detail: &str) -> Problem {
    Problem::new(
        "jlv.canonical.invalid",
        "NOT CANONICAL DATA",
        &format!("The bytes are not a canonical JLV value: {detail}."),
    )
    .consequence("The value was not read.")
    .hint("Produce canonical bytes with the JLV encoder rather than editing them by hand.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_encode_as_the_report_shows() {
        let map = Value::map([("b", Value::Int(2)), ("a", Value::Bool(true))]);
        assert_eq!(encode(&map), r#"["map",[["a",["bool",true]],["b",["int",2]]]]"#);
        assert_eq!(encode(&Value::Bytes(vec![0, 255].into())), r#"["bytes","AP8"]"#);
        assert_eq!(encode(&Value::text("A\u{e9}\n\"/")), "[\"text\",\"A\u{e9}\\u000a\\\"/\"]");
        assert_eq!(encode(&Value::Int(i64::MIN)), r#"["int",-9223372036854775808]"#);
    }

    #[test]
    fn decoding_accepts_only_the_canonical_spelling() {
        let text = r#"["list",[["int",1],["opaque","ResourceRef",1,["text","web"]]]]"#;
        assert_eq!(encode(&decode(text).unwrap()), text);
        assert!(decode(r#"[ "null" ]"#).is_err());
        assert!(decode(r#"["map",[["b",["null"]],["a",["null"]]]]"#).is_err());
        assert!(decode(r#"["map",[["a",["null"]],["a",["null"]]]]"#).is_err());
    }

    #[test]
    fn the_json_tree_renders_as_the_encoding() {
        let value = Value::map([("b", Value::Bytes(vec![1].into())), ("a", Value::Null)]);
        let tree =
            to_json(&Value::list(vec![value.clone(), Value::opaque("X", 2, Value::Int(-1))]));
        let text = to_canonical_json(&tree).unwrap();
        assert_eq!(text, encode(&Value::list(vec![value, Value::opaque("X", 2, Value::Int(-1))])));
        assert_eq!(from_json(&tree).unwrap(), decode(&text).unwrap());
    }

    #[test]
    fn json_records_sort_their_keys_and_refuse_floats() {
        let json = gd_json::parse(r#"{"b":1,"a":{"d":[true,null],"c":"x"}}"#).unwrap();
        assert_eq!(to_canonical_json(&json).unwrap(), r#"{"a":{"c":"x","d":[true,null]},"b":1}"#);
        assert!(to_canonical_json(&gd_json::parse("1.5").unwrap()).is_err());
    }
}
