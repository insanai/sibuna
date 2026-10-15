//! Rendering parity with the Zig renderer.
//!
//! `tests/data/expected/{text,mixed,wide}/*.html` were rendered by Zig 0.16 through
//! `libs/html/src/root.zig` from the same snippets and the values `sample` builds below:
//! all text (`text`); text, negative `i64`, `bool` and `u64` in turn (`mixed`, Zig's
//! compact `text_template.zig` path); and the same with `u128` instead of `u64` (`wide`,
//! Zig's direct `root.zig` path). Both the interpreter (`Template::render`) and the
//! generated code must reproduce them byte for byte.

#![allow(clippy::unwrap_used)]

mod support;

mod generated {
    include!("generated/all.rs");
}

use std::fmt;
use std::path::Path;

use sibuna_html::Value;

/// One sample value.
enum Sample {
    Text(String),
    Signed(i64),
    Bool(bool),
    Unsigned(u64),
    Wide(u128),
}

impl Sample {
    fn value(&self) -> &dyn Value {
        match self {
            Self::Text(text) => text,
            Self::Signed(number) => number,
            Self::Bool(flag) => flag,
            Self::Unsigned(number) => number,
            Self::Wide(number) => number,
        }
    }
}

/// The value the Zig generator gave field `index` named `name` in `variant`.
fn sample(variant: &str, index: usize, name: &str) -> Sample {
    let text = Sample::Text(format!("<{name} a='1' & \"b\">"));
    if variant == "text" {
        return text;
    }
    let number = u64::try_from(index).unwrap();
    match index % 4 {
        0 => text,
        1 => Sample::Signed(-i64::try_from(number * 7919 + 1).unwrap()),
        2 => Sample::Bool(index % 8 == 2),
        _ if variant == "mixed" => Sample::Unsigned(u64::MAX - number),
        _ => Sample::Wide(u128::MAX - u128::from(number)),
    }
}

fn glue(stem: &str) -> generated::Glue {
    let found = generated::GOLDEN.iter().find(|(name, _)| *name == stem);
    found.unwrap_or_else(|| panic!("{stem} is not in the snapshot")).1
}

#[test]
fn every_console_snippet_renders_like_zig_through_both_paths() {
    let expected_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/expected");
    let stems = support::snippet_stems();
    assert_eq!(stems.len(), 80);
    for stem in &stems {
        let template = support::compile_snippet(stem);
        for variant in ["text", "mixed", "wide"] {
            let path = expected_root.join(variant).join(format!("{stem}.html"));
            let expected = std::fs::read_to_string(&path).unwrap();
            let names: Vec<&str> = template.field_names().collect();
            let samples: Vec<Sample> =
                names.iter().enumerate().map(|(i, name)| sample(variant, i, name)).collect();
            let values: Vec<&dyn Value> = samples.iter().map(Sample::value).collect();
            let pairs: Vec<(&str, &dyn Value)> =
                names.iter().copied().zip(values.iter().copied()).collect();
            let mut interpreted = String::new();
            template.render(&mut interpreted, &pairs).unwrap();
            assert_eq!(interpreted, expected, "interpreter, {variant}/{stem}");
            let mut generated = String::new();
            glue(stem)(&mut generated, &values).unwrap();
            assert_eq!(generated, expected, "generated code, {variant}/{stem}");
        }
    }
}

fn run(stem: &str, values: &[&dyn Value]) -> String {
    let mut out = String::new();
    glue(stem)(&mut out, values).unwrap();
    out
}

#[test]
fn generated_code_passes_the_zig_root_tests() {
    let out = run(
        "zig-attributes",
        &[&"\" onclick='bad' &", &"<script>{{ id }}</script>", &9_007_199_254_740_993_u64],
    );
    assert_eq!(
        out,
        "<p title=\"&quot; onclick=&#39;bad&#39; &amp;\">\
         &lt;script&gt;{{ id }}&lt;/script&gt;: 9007199254740993</p>"
    );
    let out = run("zig-repeated", &[&"{{ first }}\"'", &"\u{4e16}\u{754c}<&"]);
    assert_eq!(
        out,
        "<p>\n    {{ first }}&quot;&#39; / \u{4e16}\u{754c}&lt;&amp; / \
         {{ first }}&quot;&#39;\x00</p>"
    );
    assert_eq!(run("zig-no-slots", &[]), "<p>no slots</p>");
    let out = run("zig-scalars", &[&i64::MIN, &u64::MAX, &true, &false]);
    assert_eq!(out, "-9223372036854775808 18446744073709551615 true false");
    let wide: Vec<&dyn Value> = vec![&"<&"; 128];
    let out = run("zig-wide", &wide);
    assert_eq!(out, format!("\x00\x7f\u{4e16}\u{754c}{}", "&lt;&amp;|".repeat(128)));
}

/// A fixed-capacity sink, like Zig's `Writer.fixed`: it fails once full.
struct Fixed<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> fmt::Write for Fixed<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let slot = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        slot.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[test]
fn generated_code_respects_a_fixed_output_capacity() {
    let mut out = Fixed::<8> { bytes: [0; 8], len: 0 };
    let values = generated::ZigCapacityValues { text: &"&&" };
    assert_eq!(generated::render_zig_capacity(&mut out, &values), Err(fmt::Error));
    let mut small = Fixed::<4> { bytes: [0; 4], len: 0 };
    let result = generated::render_zig_literals(&mut small, &generated::ZigLiteralsValues);
    assert_eq!(result, Err(fmt::Error));
}

#[test]
fn generated_literals_preserve_every_ascii_byte_and_utf8() {
    let ascii: String = (0u8..=127).map(char::from).collect();
    assert_eq!(run("zig-ascii", &[]), ascii);
    let (_, literals) = support::zig_test_templates()
        .into_iter()
        .find(|(stem, _)| stem == "zig-literals")
        .unwrap();
    assert_eq!(run("zig-literals", &[]), literals);
}

#[test]
fn keyword_and_upper_case_placeholders_become_usable_fields() {
    let values = generated::ZigKeywordsValues { r#type: &1_u8, Name: &"<", r#match: &false };
    let mut out = String::new();
    generated::render_zig_keywords(&mut out, &values).unwrap();
    assert_eq!(out, "1&lt;false1");
}

#[test]
fn the_snapshot_holds_every_template() {
    assert_eq!(generated::GOLDEN.len(), support::all_templates().len());
}

/// Times `operation` and prints nanoseconds per call.
#[allow(clippy::print_stdout)]
fn time(name: &str, iterations: u32, mut operation: impl FnMut() -> usize) {
    let mut bytes = 0;
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        bytes = std::hint::black_box(operation());
    }
    let nanoseconds = start.elapsed().as_secs_f64() * 1e9 / f64::from(iterations);
    println!("rust {name}: {nanoseconds:.1} ns/op ({bytes} bytes)");
}

/// The workloads of the Zig comparison benchmark (same inputs, same snippets). Run with
/// `cargo test --release -p sibuna-html --test golden -- --ignored --nocapture`.
#[test]
#[ignore = "timing; run in release"]
fn timing_matches_the_zig_benchmark() {
    let text: String = (0..4096_u32)
        .map(|i| {
            if i % 23 == 0 {
                '&'
            } else if i % 41 == 0 {
                '"'
            } else {
                char::from(b'a' + u8::try_from(i % 26).unwrap())
            }
        })
        .collect();
    let mut out = String::with_capacity(64 * 1024);
    time("escape_4k", 200_000, || {
        out.clear();
        sibuna_html::escape(&mut out, std::hint::black_box(&text)).unwrap();
        out.len()
    });
    time("render_field", 2_000_000, || {
        out.clear();
        let user = std::hint::black_box("alice & <bob>");
        let values = generated::FieldValues {
            id: &"username",
            label: &"Username",
            kind: &"text",
            autocomplete: &"username",
            value: &user,
        };
        generated::render_field(&mut out, &values).unwrap();
        out.len()
    });
    time("render_audit_detail", 2_000_000, || {
        out.clear();
        let id = std::hint::black_box(4242_u64);
        let values = generated::AuditDetailValues {
            id: &id,
            action: &"policy.update",
            actor: &"admin",
            role: &"owner",
            subject: &"policy <main>",
            target: &"rule 'block-bots'",
            client: &"203.0.113.7",
        };
        generated::render_audit_detail(&mut out, &values).unwrap();
        out.len()
    });
}
