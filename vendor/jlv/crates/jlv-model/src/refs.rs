//! The nominal handles that libraries construct and the IR records (JDD 0004,
//! "Values and type system").
//!
//! Each handle is an opaque value with a fixed type name, schema version and a plain
//! payload map. Source cannot construct one, and a plain map that spells the same
//! fields is still a map. These functions are the one place that knows the payloads.

use jlv_lang::Value;

/// A declared resource: `{ address }`.
pub const RESOURCE_REF: &str = "ResourceRef";
/// A typed output of a resource: `{ address, field, type }`.
pub const OUTPUT_REF: &str = "OutputRef";
/// Captured immutable content: `{ digest, media_type, size, source }`.
pub const ARTIFACT_REF: &str = "ArtifactRef";
/// An identity-bound inventory target: `{ inventory, name, id, transport, address }`.
pub const TARGET_REF: &str = "TargetRef";
/// An opaque versioned secret: `{ name, version }`.
pub const SECRET_REF: &str = "SecretRef";
/// A lock entry: `{ key, kind, digest, ... }`.
pub const LOCKED: &str = "Locked";
/// An operation recipe: a tree of steps.
pub const RECIPE: &str = "Recipe";
/// A schema value of `jlv.std.schema`.
pub const SCHEMA: &str = "Schema";

/// The version of every handle payload in this release.
pub const VERSION: u32 = 1;

/// A `ResourceRef` to `address`.
pub fn resource_ref(address: &str) -> Value {
    Value::opaque(RESOURCE_REF, VERSION, Value::map([("address", Value::text(address))]))
}

/// An `OutputRef` to output `field` of type `ty` of resource `address`.
pub fn output_ref(address: &str, field: &str, ty: &str) -> Value {
    let payload = Value::map([
        ("address", Value::text(address)),
        ("field", Value::text(field)),
        ("type", Value::text(ty)),
    ]);
    Value::opaque(OUTPUT_REF, VERSION, payload)
}

/// The address a `ResourceRef` or `OutputRef` names.
pub fn referenced_address(value: &Value) -> Option<&str> {
    let Value::Opaque(o) = value else { return None };
    if &*o.type_id == RESOURCE_REF || &*o.type_id == OUTPUT_REF {
        o.payload.get("address").and_then(Value::as_text)
    } else {
        None
    }
}

/// The payload of an opaque value of `type_id`.
pub fn payload<'a>(value: &'a Value, type_id: &str) -> Option<&'a Value> {
    value.as_opaque(type_id).map(|o| &o.payload)
}

/// Why a target's SSH fields are unsafe to pass to OpenSSH, or `None` when they are
/// safe. The address must be a host name or an IP address and the user a plain login
/// name, neither starting with `-`, so that no field can become an `ssh` option such as
/// `-oProxyCommand`; the port is 1 to 65535; the pinned host key is `TYPE BASE64` on one
/// line, since it is written into a known-hosts file.
pub fn ssh_target_problem(address: &str, user: &str, port: i64, host_key: &str) -> Option<String> {
    let host_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']');
    if address.is_empty() || address.len() > 253 || address.starts_with('-') {
        return Some(format!("the address `{address}` is not a host name or IP address"));
    }
    if !address.chars().all(host_char) {
        return Some(format!("the address `{address}` holds a character a host name cannot"));
    }
    let user_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-');
    if user.starts_with('-') || user.len() > 64 || !user.chars().all(user_char) {
        return Some(format!("the user `{user}` is not a plain login name"));
    }
    if !(1..=65535).contains(&port) {
        return Some(format!("the port {port} is not between 1 and 65535"));
    }
    let key_char = |c: char| {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '@' | '.' | ' ')
    };
    let words = host_key.split(' ').filter(|w| !w.is_empty()).count();
    if !host_key.is_empty() && (!(2..=3).contains(&words) || !host_key.chars().all(key_char)) {
        return Some("the host key is not `TYPE BASE64` on one line".to_string());
    }
    None
}

/// Whether `value` or any container inside it holds an unresolved `OutputRef`.
pub fn has_output_ref(value: &Value) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    has_output_ref_seen(value, &mut seen)
}

fn has_output_ref_seen(value: &Value, seen: &mut std::collections::BTreeSet<usize>) -> bool {
    match value {
        Value::Opaque(o) if &*o.type_id == OUTPUT_REF => true,
        Value::List(items) => {
            seen.insert(std::sync::Arc::as_ptr(items) as usize)
                && items.iter().any(|v| has_output_ref_seen(v, seen))
        }
        Value::Map(entries) => {
            seen.insert(std::sync::Arc::as_ptr(entries) as usize)
                && entries.values().any(|v| has_output_ref_seen(v, seen))
        }
        Value::Opaque(o) => {
            seen.insert(std::sync::Arc::as_ptr(o) as usize)
                && has_output_ref_seen(&o.payload, seen)
        }
        _ => false,
    }
}

/// Every resource address referenced anywhere inside `value`, in encounter order.
pub fn addresses_in(value: &Value, out: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    addresses_in_seen(value, out, &mut seen);
}

fn addresses_in_seen(
    value: &Value,
    out: &mut Vec<String>,
    seen: &mut std::collections::BTreeSet<usize>,
) {
    if let Some(address) = referenced_address(value) {
        out.push(address.to_string());
        return;
    }
    match value {
        Value::List(items) if seen.insert(std::sync::Arc::as_ptr(items) as usize) => {
            items.iter().for_each(|v| addresses_in_seen(v, out, seen));
        }
        Value::Map(entries) if seen.insert(std::sync::Arc::as_ptr(entries) as usize) => {
            entries.values().for_each(|v| addresses_in_seen(v, out, seen));
        }
        Value::Opaque(o) if seen.insert(std::sync::Arc::as_ptr(o) as usize) => {
            addresses_in_seen(&o.payload, out, seen);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_fields_cannot_become_options() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI";
        assert_eq!(ssh_target_problem("web1.example.org", "deploy", 22, key), None);
        assert_eq!(ssh_target_problem("2001:db8::1", "", 2222, ""), None);
        for address in ["-oProxyCommand=sh", "a b", "a;b", "", "web\n"] {
            assert!(ssh_target_problem(address, "", 22, "").is_some(), "{address}");
        }
        assert!(ssh_target_problem("h", "-oX", 22, "").is_some());
        assert!(ssh_target_problem("h", "", 0, "").is_some());
        assert!(ssh_target_problem("h", "", 22, "ssh-ed25519 AAAA\nh2 ssh-rsa B").is_some());
    }

    #[test]
    fn references_name_their_resource() {
        let refs = Value::list(vec![
            resource_ref("host.file.a"),
            Value::map([("x", output_ref("incus.instance.web", "address", "Text"))]),
        ]);
        let mut found = Vec::new();
        addresses_in(&refs, &mut found);
        assert_eq!(found, ["host.file.a", "incus.instance.web"]);
        let forged = Value::map([("address", Value::text("host.file.a"))]);
        assert_eq!(referenced_address(&forged), None);
        let mut dag = Value::map([("r", resource_ref("host.file.leaf"))]);
        for _ in 0..30 {
            dag = Value::map([("a", dag.clone()), ("b", dag)]);
        }
        let mut dag_found = Vec::new();
        addresses_in(&dag, &mut dag_found);
        assert_eq!(dag_found, ["host.file.leaf"]);
        assert!(has_output_ref(&refs));
        assert!(!has_output_ref(&dag));
    }
}
