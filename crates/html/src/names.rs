//! Rust names for snippets and placeholders.

use alloc::string::String;

/// Names that cannot be Rust fields even as raw identifiers.
const RESERVED: [&str; 5] = ["_", "self", "Self", "super", "crate"];

/// Rust keywords (strict and reserved, edition 2024); fields with these names are written
/// as raw identifiers such as `r#type`.
const KEYWORDS: [&str; 51] = [
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "crate",
    "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl",
    "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "true", "try", "type",
    "typeof", "unsafe", "unsized", "use", "virtual", "where", "while",
];

/// Returns the last path component of `name`.
pub(crate) fn file_name(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

/// Returns the stem of the file named in `name` when it can name Rust items: a lowercase
/// ASCII letter, then lowercase letters, digits, `-` and `_`, then optional extensions of
/// ASCII letters and digits.
pub(crate) fn snippet_stem(name: &str) -> Option<&str> {
    let file = file_name(name);
    let (stem, extensions) = file.split_once('.').unwrap_or((file, ""));
    let mut bytes = stem.bytes();
    let first_valid = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
    let rest_valid = bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    });
    let extensions_valid =
        extensions.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.');
    (first_valid && rest_valid && extensions_valid).then_some(stem)
}

/// Returns `render_` and the stem with `-` replaced by `_`.
pub(crate) fn function_name(stem: &str) -> String {
    let mut name = String::from("render_");
    name.extend(stem.chars().map(|character| if character == '-' { '_' } else { character }));
    name
}

/// Returns the stem in upper camel case followed by `Values`: `audit-detail` becomes
/// `AuditDetailValues`.
pub(crate) fn struct_name(stem: &str) -> String {
    let mut name = String::new();
    for word in stem.split(['-', '_']) {
        let mut characters = word.chars();
        if let Some(first) = characters.next() {
            name.push(first.to_ascii_uppercase());
            name.push_str(characters.as_str());
        }
    }
    name.push_str("Values");
    name
}

/// Reports whether `name` passes Zig's placeholder check but cannot name a Rust field.
pub(crate) fn is_reserved(name: &str) -> bool {
    RESERVED.contains(&name)
}

/// Returns `name` as a Rust field identifier, raw when it is a keyword.
pub(crate) fn field_identifier(name: &str) -> String {
    let mut identifier = String::new();
    if KEYWORDS.contains(&name) {
        identifier.push_str("r#");
    }
    identifier.push_str(name);
    identifier
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn snippet_names_become_rust_item_names() {
        assert_eq!(snippet_stem("src/snippets/audit-detail.html"), Some("audit-detail"));
        assert_eq!(snippet_stem("C:\\x\\field.html"), Some("field"));
        assert_eq!(snippet_stem("a1_b.min.html"), Some("a1_b"));
        assert_eq!(snippet_stem("plain"), Some("plain"));
        for invalid in ["", ".html", "1x.html", "Field.html", "a b.html", "a.h-t", "dir/"] {
            assert_eq!(snippet_stem(invalid), None, "{invalid}");
        }
        assert_eq!(function_name("audit-detail"), "render_audit_detail");
        assert_eq!(struct_name("audit-detail"), "AuditDetailValues");
        assert_eq!(struct_name("a1-b2_c--d"), "A1B2CDValues");
    }

    #[test]
    fn keywords_become_raw_identifiers_and_reserved_names_are_refused() {
        assert_eq!(field_identifier("type"), "r#type");
        assert_eq!(field_identifier("gen"), "r#gen");
        assert_eq!(field_identifier("label"), "label");
        assert!(is_reserved("self") && is_reserved("_") && !is_reserved("type"));
    }
}
