//! `HTML007`: a value that is not text, an integer or a boolean fails the build.
//!
//! The check is rustc's, driven by `#[diagnostic::on_unimplemented]` on `Value`, so this
//! test compiles a small crate holding `src/value.rs` and a misuse, and reads rustc's
//! message.

use std::path::Path;
use std::process::Command;

#[test]
fn html007_names_the_rejected_type_with_the_zig_text() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("html007");
    std::fs::create_dir_all(&directory).unwrap();
    let value_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/value.rs");
    let program = format!(
        "#[path = {value_rs:?}]\nmod value;\n\
         pub fn misuse(out: &mut String) -> core::fmt::Result {{\n\
         \x20   value::write_value(out, &1.5_f64)\n}}\n"
    );
    let source = directory.join("misuse.rs");
    std::fs::write(&source, program).unwrap();
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .args(["--edition", "2024", "--crate-type", "lib", "--emit", "metadata"])
        .arg("--out-dir")
        .arg(&directory)
        .arg(&source)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the misuse compiled");
    assert!(stderr.contains("error[E0277]: HTML007: value must be text, an integer or a boolean"));
    assert!(stderr.contains("`f64` is not text, an integer or a boolean"), "{stderr}");
    assert!(stderr.contains("note: HTML007: format this value as text before rendering"));
}
