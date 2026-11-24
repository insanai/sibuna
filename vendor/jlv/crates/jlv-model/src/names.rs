//! The spelling rules of inventory names, labels and workers (JDD 0015, "The inventory
//! document"), shared by the inventory document, listed records and plugins.

/// Whether `name` can name a target, a source or a group: 1 to 63 letters, digits, `.`,
/// `-` and `_`, starting with a letter or a digit.
pub fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    (1..=63).contains(&name.len())
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Whether `key` can be a label key: 1 to 63 lower-case letters, digits, `.`, `-`, `_`
/// and `/`.
pub fn is_label_key(key: &str) -> bool {
    (1..=63).contains(&key.len())
        && key.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_' | b'/')
        })
}

/// Whether `value` can be a label value: at most 255 bytes without control characters.
pub fn is_label_value(value: &str) -> bool {
    value.len() <= 255 && !value.chars().any(char::is_control)
}

/// Whether `id` can be a provider's external identity: 1 to 255 bytes without control
/// characters.
pub fn is_external_id(id: &str) -> bool {
    (1..=255).contains(&id.len()) && !id.chars().any(char::is_control)
}

/// Whether `name` can name a worker that a local target is pinned to (JDD 0014): 1 to
/// 63 letters, digits, `.`, `-` and `_`, and not `localhost`, which would pin nothing.
pub fn is_worker_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && name != "localhost"
}

/// The normal form of an API target's address (JDD 0017, "Part 6"): `https://` or
/// `http://`, a host name or IPv4 address of letters, digits, `.` and `-`, and an
/// optional port, lower-cased, without a default port or a trailing `/`. `None` when
/// the address has any other part, such as a user, a path, a query or a fragment, so a
/// profile pattern over hosts can never be met by a path that ends like a host.
pub fn api_address(address: &str) -> Option<String> {
    let lower = address.to_ascii_lowercase();
    let (scheme, rest) = lower.split_once("://")?;
    let default_port = match scheme {
        "https" => "443",
        "http" => "80",
        _ => return None,
    };
    let rest = rest.trim_suffix('/');
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    let edge = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_alphanumeric());
    let host_ok = !host.is_empty()
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && edge(host.bytes().next())
        && edge(host.bytes().last());
    // Digits only, written back as a number, so `0443` and `+443` are not other keys.
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            Some(p.parse::<u16>().ok().filter(|n| *n > 0)?.to_string())
        }
        Some(_) => return None,
    };
    if !host_ok {
        return None;
    }
    let normal = match port.filter(|p| p != default_port) {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    (normal.len() <= 255).then_some(normal)
}

/// The names a plugin's namespace may not take (JDD 0017): `jlv` and the namespaces
/// of the standard library, which a module may import beside a plugin's.
pub const RESERVED_NAMESPACES: &[&str] =
    &["jlv", "bytes", "config", "map", "math", "ops", "schema", "seq", "text"];

/// The core action kinds (JDD 0017, "Part 3: plugin namespaces"): the standard library
/// constructs exactly these, and a plugin may carry them out without a namespace. Every
/// other action kind a plugin declares is `NAMESPACE.NAME`.
pub const CORE_ACTIONS: &[&str] =
    &["service_restart", "service_start", "service_stop", "http_probe", "exec"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_labels_and_workers_follow_their_rules() {
        assert!(is_name("web1") && is_name("cp.spare-2_a") && !is_name("-web") && !is_name(""));
        assert!(!is_name(&"a".repeat(64)) && !is_name("a b"));
        assert!(is_label_key("app.kubernetes.io/role") && !is_label_key("Role"));
        assert!(is_label_value("control plane") && !is_label_value("a\nb"));
        assert!(is_worker_name("w1") && !is_worker_name("localhost") && !is_worker_name("w 1"));
        assert!(is_external_id("cmdb:4711") && !is_external_id("") && !is_external_id("a\tb"));
    }

    /// JDD 0017, Part 6: an API address is a scheme, a host and a port, in one form.
    #[test]
    fn api_addresses_have_one_form_and_no_path() {
        assert_eq!(
            api_address("https://API.Example.org:443/").as_deref(),
            Some("https://api.example.org")
        );
        assert_eq!(
            api_address("https://incus.lab:8443").as_deref(),
            Some("https://incus.lab:8443")
        );
        assert_eq!(api_address("http://10.0.0.5:80").as_deref(), Some("http://10.0.0.5"));
        assert_eq!(api_address("https://a.org:0443").as_deref(), Some("https://a.org"));
        assert_eq!(api_address("https://a.org:08443").as_deref(), Some("https://a.org:8443"));
        assert_eq!(api_address("https://a.org:+443"), None);
        for bad in [
            "https://evil.net/x.example.org",
            "https://user@api.example.org",
            "https://api.example.org?x=1",
            "https://api.example.org#f",
            "ftp://api.example.org",
            "api.example.org",
            "https://",
            "https://[::1]:443",
            "https://api.example.org:0",
            "https://api.example.org:99999",
            "https://-bad.example.org",
        ] {
            assert_eq!(api_address(bad), None, "{bad}");
        }
    }
}
