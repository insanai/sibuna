//! Escaped HTML snippets: a build-time template compiler and a small runtime.
//!
//! A snippet is a trusted, developer-authored HTML file with `{{ name }}` placeholders:
//!
//! ```html
//! <label for="{{ id }}">{{ label }}</label>
//! <input id="{{ id }}" value="{{ value }}">
//! ```
//!
//! A build script compiles every snippet with [`compile`] and turns the results into Rust
//! with [`generate`]. Each snippet becomes a values struct and a render function:
//!
//! ```ignore
//! snippets::render_field(&mut out, &snippets::FieldValues {
//!     id: &"username",
//!     label: &"Username",
//!     value: &username,
//! })?;
//! ```
//!
//! Template errors stop the build with stable codes `HTML001` to `HTML008` and Elm-style
//! diagnostics (see [`Diagnostic`]). Values are text, integers or booleans ([`Value`]);
//! text always escapes `&`, `<`, `>`, `"` and `'`, and there is no raw HTML escape hatch.
//! Place values in text or quoted ordinary attributes: escaping does not make URLs,
//! scripts or styles safe, so never interpolate into `<script>`, `<style>`, tag names,
//! attribute names or unvalidated URLs. Sources are limited to 32 KiB and 128
//! placeholders. Rendering writes into the caller's `core::fmt::Write` sink and never
//! allocates; after a write error the partial output must be discarded.
//!
//! # Build script
//!
//! The consumer depends on this crate twice: the runtime without the compiler (keep
//! `alloc` so `String` values work; drop it in a crate without an allocator), and the
//! compiler as a build dependency.
//!
//! ```toml
//! [dependencies]
//! sibuna-html = { workspace = true, default-features = false, features = ["alloc"] }
//!
//! [build-dependencies]
//! sibuna-html = { workspace = true }
//! ```
//!
//! ```no_run
//! // build.rs
//! use std::{env, fs, path::Path, process};
//!
//! # #[cfg(not(feature = "compiler"))]
//! # fn main() {}
//! # #[cfg(feature = "compiler")]
//! fn main() {
//!     let directory = Path::new("src/snippets");
//!     println!("cargo::rerun-if-changed={}", directory.display());
//!     let mut paths: Vec<_> = fs::read_dir(directory)
//!         .expect("read src/snippets")
//!         .map(|entry| entry.expect("read src/snippets").path())
//!         .filter(|path| path.extension().is_some_and(|extension| extension == "html"))
//!         .collect();
//!     paths.sort();
//!     let mut templates = Vec::new();
//!     for path in &paths {
//!         let source = fs::read_to_string(path).expect("read a snippet");
//!         match sibuna_html::compile(&path.display().to_string(), &source) {
//!             Ok(template) => templates.push(template),
//!             Err(diagnostic) => {
//!                 eprintln!("{diagnostic}");
//!                 process::exit(1);
//!             }
//!         }
//!     }
//!     let output = Path::new(&env::var_os("OUT_DIR").expect("OUT_DIR")).join("snippets.rs");
//!     fs::write(output, sibuna_html::generate(&templates)).expect("write snippets.rs");
//! }
//! ```
//!
//! The crate then includes the generated items:
//!
//! ```ignore
//! mod snippets {
//!     include!(concat!(env!("OUT_DIR"), "/snippets.rs"));
//! }
//! ```
//!
//! # Features
//!
//! - `alloc`: `String` and `Cow<str>` values.
//! - `compiler` (default, implies `alloc`): [`compile`], [`generate`], [`Template`] and
//!   the diagnostics. Without it the crate is the allocation-free runtime only.
//!
//! # Changes from the Zig renderer
//!
//! The vocabulary is that of SID 0007 (Rendering): snippets, `{{ field }}`
//! placeholders, values. Behaviour is unchanged: the same accepted syntax, the same checks
//! in the same order, the same bytes out (the golden tests compare all 80 console
//! snippets with output of the Zig renderer). Mechanisms that Rust makes unnecessary were
//! not ported:
//!
//! - Comptime expansion inside `html.render`, with `@typeInfo` dispatch on each value's
//!   type, is replaced by build-script code generation and a sealed [`Value`] trait used
//!   through `&dyn Value`: the type checker does at the call site what the comptime
//!   switch did.
//! - The dictionary packing of literal text (`literals.zig`, `instructions.zig`) and the
//!   compact program interpreter (`text_template.zig`, with its `undefined` 64 KiB
//!   program buffer and slot table) existed to shrink the WebAssembly console. Generated
//!   Rust writes literal runs as string constants: the code stays readable, rendering does
//!   no decoding, and HTTP compression shrinks transfers better than the dictionary did.
//! - `Writer.Error.WriteFailed` becomes `core::fmt::Error` from the caller's sink.
//!
//! Visible differences, each forced by the move to Rust or added for it:
//!
//! - The values struct is generated from the snippet, so a missing value is a rustc
//!   error at the call site (E0063) rather than `HTML004`. `HTML004` remains for
//!   [`Template::render`], which looks values up by name. A value of another type fails
//!   with rustc error E0277 carrying the `HTML007` text.
//! - Rust cannot name a field `_`, `self`, `Self`, `super` or `crate`; such placeholders
//!   fail with `HTML006`. Keywords such as `type` become raw identifiers (`r#type`).
//! - New code `HTML008`: the snippet file name must yield Rust item names.
//! - The `HTML002` hint says "Rust control flow" instead of "Zig control flow".
//! - Text values are `&str`, so they are valid UTF-8; Zig accepted any bytes.
//! - Generated functions take exactly the snippet's fields; Zig ignored extra values.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "compiler")]
mod compile;
#[cfg(feature = "compiler")]
mod diagnostic;
#[cfg(feature = "compiler")]
mod generate;
#[cfg(feature = "compiler")]
mod names;
mod value;

#[cfg(feature = "compiler")]
pub use compile::{PLACEHOLDER_LIMIT, RenderError, SOURCE_LIMIT, Template, compile};
#[cfg(feature = "compiler")]
pub use diagnostic::{Diagnostic, ErrorKind, Location};
#[cfg(feature = "compiler")]
pub use generate::generate;
pub use value::{Value, escape, write_value};

/// Ports of the Zig `root.zig` tests, run through the interpreter; `tests/golden.rs`
/// runs the same templates through generated code.
#[cfg(all(test, feature = "compiler"))]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::string::String;
    use core::fmt;

    fn render(source: &str, values: &[(&str, &dyn Value)]) -> String {
        let mut out = String::new();
        compile("test.html", source).unwrap().render(&mut out, values).unwrap();
        out
    }

    #[test]
    fn text_and_quoted_attributes_escape_values_without_interpreting_injected_templates() {
        let out = render(
            "<p title=\"{{ title }}\">{{ body }}: {{ id }}</p>",
            &[
                ("title", &"\" onclick='bad' &"),
                ("body", &"<script>{{ id }}</script>"),
                ("id", &9_007_199_254_740_993_u64),
            ],
        );
        assert_eq!(
            out,
            "<p title=\"&quot; onclick=&#39;bad&#39; &amp;\">\
             &lt;script&gt;{{ id }}&lt;/script&gt;: 9007199254740993</p>"
        );
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
    fn escaping_expansion_respects_the_callers_fixed_output_capacity() {
        let template = compile("test.html", "{{ text }}").unwrap();
        let mut out = Fixed::<8> { bytes: [0; 8], len: 0 };
        assert_eq!(template.render(&mut out, &[("text", &"&&")]), Err(RenderError::Write));
    }

    #[test]
    fn compiled_text_slots_preserve_repeated_names_whitespace_literal_nul_and_injected_syntax() {
        let out = render(
            "<p>\n    {{ second }} / {{ first }} / {{ second }}\x00</p>",
            &[("first", &"\u{4e16}\u{754c}<&"), ("second", &"{{ first }}\"'")],
        );
        assert_eq!(
            out,
            "<p>\n    {{ first }}&quot;&#39; / \u{4e16}\u{754c}&lt;&amp; / \
             {{ first }}&quot;&#39;\x00</p>"
        );
        assert_eq!(render("<p>no slots</p>", &[]), "<p>no slots</p>");
    }

    #[test]
    fn shared_scalar_formatting_preserves_signed_minima_unsigned_maxima_and_booleans() {
        let out = render(
            "{{ low }} {{ high }} {{ yes }} {{ no }}",
            &[("low", &i64::MIN), ("high", &u64::MAX), ("yes", &true), ("no", &false)],
        );
        assert_eq!(out, "-9223372036854775808 18446744073709551615 true false");
    }

    #[test]
    fn extended_snippet_value_indexes_retain_escaping_and_literal_control_bytes() {
        let names: std::vec::Vec<String> = (0..128).map(|i| std::format!("f{i}")).collect();
        let values: std::vec::Vec<(&str, &dyn Value)> =
            names.iter().map(|name| (name.as_str(), &"<&" as &dyn Value)).collect();
        let out = render("\x00\x7f\u{4e16}\u{754c}{{ f0 }}|{{ f127 }}", &values);
        assert_eq!(out, "\x00\x7f\u{4e16}\u{754c}&lt;&amp;|&lt;&amp;");
    }

    /// From `literals.zig`: literal text survives byte for byte, including UTF-8,
    /// overlapping HTML fragments and NUL, and a small sink fails.
    #[test]
    fn literal_html_preserves_every_byte_utf8_and_overlapping_fragments() {
        let source = "<section class=\"panel\"><label><span>\u{4e16}\u{754c}</span> \
                      <input type=\"checkbox\" name=\"choice\" value=\"one\"></label>\
                      <button type=\"submit\" data-action=\"save\">Save</button></section>\n";
        assert_eq!(render(source, &[]), source);
        assert_eq!(render("literal\x00byte", &[]), "literal\x00byte");
        let mut small = Fixed::<4> { bytes: [0; 4], len: 0 };
        let template = compile("test.html", source).unwrap();
        assert_eq!(template.render(&mut small, &[]), Err(RenderError::Write));
    }

    /// From `instructions.zig`: every ASCII byte value survives as literal text. The
    /// generated-code counterpart is in `tests/golden.rs`.
    #[test]
    fn every_ascii_byte_roundtrips_as_literal_text() {
        let source: String = (0u8..=127).map(char::from).collect();
        assert_eq!(render(&source, &[]), source);
    }
}
