//! Shared by `snapshot.rs` and `golden.rs`: the snippets under test and the glue that
//! lets a test call every generated function with values in field order.

#![allow(dead_code, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sibuna_html::{Template, compile, generate};

/// The console snippets, copied from the Zig repository's `apps/console-ui/src/snippets`.
pub fn snippet_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/snippets")
}

/// The directory of generated code checked in for review; `snapshot.rs` keeps it current.
pub fn snapshot_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/generated")
}

/// Returns the file stems of the console snippets, sorted.
pub fn snippet_stems() -> Vec<String> {
    let mut stems: Vec<String> = std::fs::read_dir(snippet_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "html"))
        .map(|path| path.file_stem().unwrap().to_str().unwrap().to_string())
        .collect();
    stems.sort();
    stems
}

/// Compiles the console snippet `stem`.
pub fn compile_snippet(stem: &str) -> Template {
    let path = snippet_directory().join(format!("{stem}.html"));
    let source = std::fs::read_to_string(&path).unwrap();
    compile(&format!("snippets/{stem}.html"), &source).unwrap_or_else(|error| panic!("{error}"))
}

/// The templates of the Zig unit tests (`root.zig`, `literals.zig`, `instructions.zig`),
/// as (stem, source) pairs, so generated code runs them too.
pub fn zig_test_templates() -> Vec<(String, String)> {
    let wide: String = (0..128).map(|index| format!("{{{{ f{index} }}}}|")).collect();
    let ascii: String = (0u8..=127).map(char::from).collect();
    [
        ("zig-attributes", "<p title=\"{{ title }}\">{{ body }}: {{ id }}</p>".to_string()),
        ("zig-capacity", "{{ text }}".to_string()),
        ("zig-repeated", "<p>\n    {{ second }} / {{ first }} / {{ second }}\x00</p>".to_string()),
        ("zig-no-slots", "<p>no slots</p>".to_string()),
        ("zig-scalars", "{{ low }} {{ high }} {{ yes }} {{ no }}".to_string()),
        ("zig-wide", format!("\x00\x7f\u{4e16}\u{754c}{wide}")),
        (
            "zig-literals",
            "<section class=\"panel\"><label><span>\u{4e16}\u{754c}</span> \
             <input type=\"checkbox\" name=\"choice\" value=\"one\"></label>\
             <button type=\"submit\" data-action=\"save\">Save</button></section>\n"
                .to_string(),
        ),
        ("zig-ascii", ascii),
        ("zig-keywords", "{{ type }}{{ Name }}{{ match }}{{ type }}".to_string()),
    ]
    .into_iter()
    .map(|(stem, source)| (stem.to_string(), source))
    .collect()
}

/// Returns every template in the snapshot: the console snippets, then the Zig tests.
pub fn all_templates() -> Vec<Template> {
    let mut templates: Vec<Template> =
        snippet_stems().iter().map(|s| compile_snippet(s)).collect();
    for (stem, source) in zig_test_templates() {
        templates.push(compile(&format!("{stem}.html"), &source).unwrap());
    }
    templates
}

/// Returns the snippet stem of `template`, such as `audit-detail`.
pub fn stem(template: &Template) -> &str {
    template.name().rsplit('/').next().unwrap().trim_end_matches(".html")
}

/// Returns the checked-in files as (file name, contents): for each template its
/// generated code followed by a `golden_*` glue function taking values in field order,
/// and `all.rs`, which includes them all and lists the glue in the `GOLDEN` table. One
/// file per snippet keeps every file within the workspace's length limit.
pub fn snapshot_files() -> Vec<(String, String)> {
    let templates = all_templates();
    let mut all = String::from("// Written by tests/support/mod.rs; see tests/snapshot.rs.\n\n");
    all.push_str("/// A generated function taking values in field order.\n");
    all.push_str("pub type Glue = fn(&mut String, &[&dyn ::sibuna_html::Value]) -> Result;\n\n");
    all.push_str("type Result = ::core::fmt::Result;\n\n");
    let mut files = Vec::new();
    for template in &templates {
        let file = format!("{}.rs", stem(template));
        let mut code = generate(std::slice::from_ref(template));
        code.push_str("\n// Test glue, written by tests/support/mod.rs.\n");
        write_glue(&mut code, template);
        writeln!(all, "include!({file:?});").unwrap();
        files.push((file, code));
    }
    all.push_str("\n/// Every generated function by snippet stem.\n");
    all.push_str("pub const GOLDEN: &[(&str, Glue)] = &[\n");
    for template in &templates {
        let function = template.function_name().replacen("render_", "golden_", 1);
        writeln!(all, "    ({:?}, {function}),", stem(template)).unwrap();
    }
    all.push_str("];\n");
    files.push(("all.rs".to_string(), all));
    files
}

fn write_glue(code: &mut String, template: &Template) {
    let function = template.function_name();
    let glue = function.replacen("render_", "golden_", 1);
    let structure = template.struct_name();
    code.push_str("\n// xtask: allow-long-function generated test glue\n");
    code.push_str("#[allow(clippy::too_many_lines)]\n");
    writeln!(code, "fn {glue}(").unwrap();
    code.push_str(
        "    out: &mut String,\n    values: &[&dyn ::sibuna_html::Value],\n) -> Result {\n",
    );
    if template.field_count() == 0 {
        writeln!(code, "    let _ = values;\n    {function}(out, &{structure})\n}}").unwrap();
        return;
    }
    writeln!(code, "    {function}(out, &{structure} {{").unwrap();
    for (index, name) in template.field_names().enumerate() {
        let field =
            if ["type", "match"].contains(&name) { format!("r#{name}") } else { name.to_string() };
        writeln!(code, "        {field}: values[{index}],").unwrap();
    }
    writeln!(code, "    }})\n}}").unwrap();
}
