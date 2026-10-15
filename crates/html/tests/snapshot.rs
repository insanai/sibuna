//! The generated code for the test snippets is checked in under `tests/generated/` so it
//! can be reviewed, and `golden.rs` compiles and runs it. This test keeps it equal to what
//! the generator writes now; run it with `SIBUNA_BLESS=1` to rewrite the files.

#![allow(clippy::unwrap_used)]

mod support;

#[test]
fn checked_in_generated_code_matches_the_generator() {
    let files = support::snapshot_files();
    let directory = support::snapshot_directory();
    if std::env::var_os("SIBUNA_BLESS").is_some() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        for (name, code) in &files {
            std::fs::write(directory.join(name), code).unwrap();
        }
    }
    let mut stale = Vec::new();
    for (name, code) in &files {
        if std::fs::read_to_string(directory.join(name)).ok().as_ref() != Some(code) {
            stale.push(name.clone());
        }
    }
    let present = std::fs::read_dir(&directory).unwrap().count();
    assert!(
        stale.is_empty() && present == files.len(),
        "tests/generated is stale ({stale:?}, {present} files for {}); rerun with \
         SIBUNA_BLESS=1 and review the diff",
        files.len()
    );
}

#[test]
fn generated_code_is_ascii_and_narrow() {
    for (name, code) in support::snapshot_files() {
        assert!(code.is_ascii(), "{name}");
        let wide = code.lines().find(|line| line.len() > 99);
        assert_eq!(wide, None, "{name}");
    }
}
