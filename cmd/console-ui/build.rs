//! Compiles `src/snippets/*.html` into Rust render functions with `sibuna-html`, and sets
//! the WebAssembly module's memory ceiling.

use std::{env, fs, path::Path, process};

/// The largest linear memory of the WebAssembly module, in bytes (SID 0007, Budget).
const MAX_MEMORY: usize = 16 * 1024 * 1024;

fn main() {
    let directory = Path::new("src/snippets");
    println!("cargo::rerun-if-changed={}", directory.display());
    let mut paths: Vec<_> = fs::read_dir(directory)
        .expect("read src/snippets")
        .map(|entry| entry.expect("read src/snippets").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "html"))
        .collect();
    paths.sort();
    let mut templates = Vec::new();
    for path in &paths {
        let source = fs::read_to_string(path).expect("read a snippet");
        match sibuna_html::compile(&path.display().to_string(), &source) {
            Ok(template) => templates.push(template),
            Err(diagnostic) => {
                eprintln!("{diagnostic}");
                process::exit(1);
            }
        }
    }
    let output = Path::new(&env::var_os("OUT_DIR").expect("OUT_DIR")).join("snippets.rs");
    fs::write(output, sibuna_html::generate(&templates)).expect("write snippets.rs");
    if env::var("CARGO_CFG_TARGET_ARCH").is_ok_and(|arch| arch == "wasm32") {
        println!("cargo::rustc-link-arg-cdylib=--max-memory={MAX_MEMORY}");
    }
}
