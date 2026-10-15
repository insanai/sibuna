//! Every diagnostic code with its exact text, and the order in which checks apply.
//! `HTML007` is a rustc error; `tests/value_types.rs` checks it.
//!
//! The `summary` strings are the `@compileError` texts of the Zig renderer
//! (`libs/html/src/root.zig`), except where the crate documentation lists a change.

#![allow(clippy::unwrap_used)]

use sibuna_html::{Diagnostic, ErrorKind, RenderError, compile};

fn diagnose(name: &str, source: &str) -> Diagnostic {
    match compile(name, source) {
        Ok(_) => panic!("{name} compiled"),
        Err(diagnostic) => diagnostic,
    }
}

#[test]
fn html001_snippet_too_large() {
    let diagnostic = diagnose("snippets/big.html", &"a".repeat(32 * 1024 + 1));
    let expected = format!(
        "\
-- SNIPPET TOO LARGE --------------------------------- snippets/big.html:1:32769

HTML001: snippet exceeds 32 KiB.

1| ...{}
{}^
Hint: Split it into smaller snippets.
",
        "a".repeat(41),
        " ".repeat(46)
    );
    assert_eq!(diagnostic.to_string(), expected);
    assert_eq!(
        diagnostic.summary(),
        "HTML001: snippet exceeds 32 KiB; split it into smaller snippets"
    );
    assert!(compile("edge.html", &"a".repeat(32 * 1024)).is_ok());
}

#[test]
fn html002_unsupported_tag() {
    let diagnostic = diagnose("tag.html", "<ul>\n    {{ before }}{% for row in rows %}\n</ul>");
    let expected = "\
-- UNSUPPORTED TAG ----------------------------------------------- tag.html:2:17

HTML002: unsupported tag.

2|     {{ before }}{% for row in rows %}
                   ^^
Hint: Use Rust control flow and composition.
";
    assert_eq!(diagnostic.to_string(), expected);
    assert_eq!(
        diagnostic.summary(),
        "HTML002: unsupported tag; use Rust control flow and composition"
    );
    let comment = diagnose("comment.html", "<p>{# note #}</p>");
    let expected = "\
-- UNSUPPORTED TAG -------------------------------------------- comment.html:1:4

HTML002: unsupported tag.

1| <p>{# note #}</p>
      ^^
Hint: Use Rust control flow and composition.
";
    assert_eq!(comment.to_string(), expected);
}

#[test]
fn html003_unclosed_placeholder() {
    let diagnostic = diagnose("open.html", "<p>\n  {{ name </p>\n");
    let expected = "\
-- UNCLOSED PLACEHOLDER ------------------------------------------ open.html:2:3

HTML003: unclosed placeholder.

2|   {{ name </p>
     ^^
Hint: Add }}.
";
    assert_eq!(diagnostic.to_string(), expected);
    assert_eq!(diagnostic.summary(), "HTML003: unclosed placeholder; add }}");
}

#[test]
fn html004_missing_value() {
    let template =
        compile("field.html", "<label for=\"{{ id }}\">\n  {{ label }}</label>").unwrap();
    let mut out = String::new();
    let Err(RenderError::Missing(diagnostic)) = template.render(&mut out, &[("id", &"x")]) else {
        panic!("rendered without a label");
    };
    let expected = "\
-- MISSING VALUE ------------------------------------------------ field.html:2:6

HTML004: missing value 'label'.

2|   {{ label }}</label>
        ^^^^^
Hint: Supply the named field.
";
    assert_eq!(diagnostic.to_string(), expected);
    assert_eq!(diagnostic.summary(), "HTML004: missing value 'label'; supply the named field");
    assert!(out.is_empty(), "nothing is written before every value is found");
}

#[test]
fn html005_too_many_placeholders() {
    let source = "{{ a }}".repeat(128) + "\n<b>{{ b }}</b>";
    let diagnostic = diagnose("many.html", &source);
    let expected = "\
-- TOO MANY PLACEHOLDERS ----------------------------------------- many.html:2:4

HTML005: more than 128 placeholders.

2| <b>{{ b }}</b>
      ^^^^^^^
Hint: Split the snippet.
";
    assert_eq!(diagnostic.to_string(), expected);
    assert_eq!(diagnostic.summary(), "HTML005: more than 128 placeholders; split the snippet");
    let limit = compile("limit.html", &"{{ a }}".repeat(128)).unwrap();
    assert_eq!((limit.placeholder_count(), limit.field_count()), (128, 1));
}

#[test]
fn html006_empty_invalid_and_reserved_placeholders() {
    let empty = diagnose("empty.html", "<p>{{ }}</p>");
    let expected = "\
-- EMPTY PLACEHOLDER -------------------------------------------- empty.html:1:4

HTML006: empty placeholder.

1| <p>{{ }}</p>
      ^^^^^
Hint: Supply a field name.
";
    assert_eq!(empty.to_string(), expected);
    assert_eq!(empty.summary(), "HTML006: empty placeholder; supply a field name");
    let invalid = diagnose("dash.html", "<p title=\"{{ first-name }}\"></p>");
    let expected = "\
-- INVALID PLACEHOLDER ------------------------------------------ dash.html:1:14

HTML006: invalid placeholder.

1| <p title=\"{{ first-name }}\"></p>
                ^^^^^^^^^^
Hint: Only simple field names are supported.
";
    assert_eq!(invalid.to_string(), expected);
    assert_eq!(
        invalid.summary(),
        "HTML006: invalid placeholder; only simple field names are supported"
    );
    let reserved = diagnose("reserved.html", "<p>{{ self }}</p>");
    let expected = "\
-- RESERVED PLACEHOLDER -------------------------------------- reserved.html:1:7

HTML006: reserved placeholder 'self'.

1| <p>{{ self }}</p>
         ^^^^
Hint: Rename it, since Rust reserves this name.
";
    assert_eq!(reserved.to_string(), expected);
}

#[test]
fn html006_follows_zigs_name_rule() {
    for invalid in ["1st", "a-b", "a.b", "a b", "{x", "\u{e9}t\u{e9}", "a\nb"] {
        let source = format!("{{{{ {invalid} }}}}");
        assert_eq!(diagnose("x.html", &source).kind, ErrorKind::InvalidPlaceholder, "{invalid}");
    }
    for empty in ["{{}}", "{{ }}", "{{\r\n\t }}"] {
        assert_eq!(diagnose("x.html", empty).kind, ErrorKind::EmptyPlaceholder, "{empty}");
    }
    for reserved in ["_", "self", "Self", "super", "crate"] {
        let source = format!("{{{{{reserved}}}}}");
        let kind = diagnose("x.html", &source).kind;
        assert_eq!(kind, ErrorKind::ReservedPlaceholder { name: reserved.to_string() });
    }
    for valid in ["a", "_a", "a1", "A_b_9", "__", "type", "\n\tname\r "] {
        let source = format!("{{{{{valid}}}}}");
        assert!(compile("x.html", &source).is_ok(), "{valid:?}");
    }
}

#[test]
fn html008_invalid_snippet_name() {
    let diagnostic = diagnose("Bad Name.html", "<p></p>");
    let expected = "\
-- INVALID SNIPPET NAME ------------------------------------------ Bad Name.html

HTML008: invalid snippet name.

Hint: Name the file with lowercase letters, digits, '-' and '_', starting with a letter.
";
    assert_eq!(diagnostic.to_string(), expected);
    assert_eq!(diagnostic.code(), "HTML008");
    assert_eq!(diagnostic.location, None);
}

#[test]
fn checks_apply_in_zigs_order() {
    // The size limit comes first, then tags anywhere, then each placeholder in turn.
    let large = "{{".to_string() + &"{%".repeat(16 * 1024);
    assert_eq!(diagnose("x.html", &large).code(), "HTML001");
    assert_eq!(diagnose("x.html", "{{ a {%").code(), "HTML002");
    assert_eq!(diagnose("x.html", "{{ 1 }} {{ b").code(), "HTML006");
    assert_eq!(diagnose("x.html", "{{ b {{ 1 }}").code(), "HTML006");
    assert_eq!(diagnose("x.html", "{{ b }} {{ c").code(), "HTML003");
    // The 129th placeholder's name is checked before the count.
    let source = "{{ a }}".repeat(128) + "{{ - }}";
    assert_eq!(diagnose("x.html", &source).kind, ErrorKind::InvalidPlaceholder);
    // An invalid file name is reported before anything in the source.
    assert_eq!(diagnose("X.html", "{{").code(), "HTML008");
}

#[test]
fn diagnostics_expose_their_parts() {
    let diagnostic = diagnose("dir/open.html", "ab\n{{ x");
    assert_eq!(diagnostic.code(), "HTML003");
    assert_eq!(diagnostic.title(), "UNCLOSED PLACEHOLDER");
    assert_eq!(diagnostic.message(), "HTML003: unclosed placeholder.");
    assert_eq!(diagnostic.hint(), "Add }}.");
    assert_eq!(diagnostic.snippet, "dir/open.html");
    let location = diagnostic.location.unwrap();
    assert_eq!((location.line, location.column, location.carets), (2, 1, 2));
    let error: &dyn std::error::Error = &diagnose("x.html", "{{");
    assert!(error.to_string().starts_with("-- UNCLOSED PLACEHOLDER"));
}
