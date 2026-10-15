//! `cargo xtask check`: enforce the structural limits of the house rules on every Rust
//! source file in the workspace.
//!
//! We scan `crates/`, `cmd/` and `tools/` (or the paths given on the command line), skip
//! directories named `target` or `vendor`, and apply the rules in [`rules`] to each `*.rs`
//! file. Problems are printed as Elm-style diagnostics, followed by a one-line summary.

mod diagnostic;
mod functions;
mod lexer;
mod rules;

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use diagnostic::Severity;

/// The directories scanned when no path is given, relative to the workspace root.
const DEFAULT_ROOTS: [&str; 3] = ["crates", "cmd", "tools"];

/// Directory names that are never scanned: build output and third-party code.
const SKIPPED_DIRECTORIES: [&str; 2] = ["target", "vendor"];

/// The totals of one run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Files scanned.
    pub file_count: usize,
    /// Function bodies measured.
    pub function_count: usize,
    /// Problems that fail the check.
    pub error_count: usize,
    /// Problems reported without failing the check.
    pub warning_count: usize,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "check: scanned {} and {}: {}, {}",
            counted(self.file_count, "file"),
            counted(self.function_count, "function"),
            counted(self.error_count, "error"),
            counted(self.warning_count, "warning"),
        )
    }
}

/// Formats `count` with `noun`, adding a plural `s` unless the count is one.
fn counted(count: usize, noun: &str) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("{count} {noun}{suffix}")
}

/// Why a check could not run to the end. Limit violations are not errors of this kind;
/// they are counted in the [`Summary`].
#[derive(Debug)]
pub enum CheckError {
    /// An argument is not a path, such as an unknown `--flag`.
    Usage(String),
    /// A file or directory could not be read, or a file is not UTF-8.
    Read {
        /// The path that failed.
        path: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },
    /// The report could not be written.
    Write(io::Error),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckError::Usage(argument) => {
                write!(f, "unexpected argument `{argument}`; `check` takes only paths")
            }
            CheckError::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            CheckError::Write(source) => write!(f, "cannot write the report: {source}"),
        }
    }
}

impl std::error::Error for CheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckError::Usage(_) => None,
            CheckError::Read { source, .. } | CheckError::Write(source) => Some(source),
        }
    }
}

/// Runs the check over `arguments` (paths; none means the whole workspace under `root`)
/// and writes diagnostics and the summary to `out`.
///
/// Returns the totals; the caller fails the process when `error_count` is not zero. Fails
/// on an unknown flag, an unreadable file or directory, or a failed write.
pub fn run(
    root: &Path,
    arguments: &[OsString],
    out: &mut dyn Write,
) -> Result<Summary, CheckError> {
    let mut paths = Vec::new();
    for argument in arguments {
        if argument.to_string_lossy().starts_with('-') {
            return Err(CheckError::Usage(argument.to_string_lossy().into_owned()));
        }
        paths.push(PathBuf::from(argument));
    }
    if paths.is_empty() {
        paths = DEFAULT_ROOTS.iter().map(|name| root.join(name)).filter(|p| p.exists()).collect();
    }
    let mut files = Vec::new();
    for path in &paths {
        collect_rust_files(path, &mut files)?;
    }
    files.sort();
    files.dedup();

    let mut summary = Summary { file_count: files.len(), ..Summary::default() };
    for file in &files {
        let source = fs::read_to_string(file)
            .map_err(|source| CheckError::Read { path: file.clone(), source })?;
        let shown = file.strip_prefix(root).unwrap_or(file).display().to_string();
        let report = rules::check_source(&shown, &source);
        summary.function_count += report.function_count;
        for diagnostic in &report.diagnostics {
            match diagnostic.severity {
                Severity::Error => summary.error_count += 1,
                Severity::Warning => summary.warning_count += 1,
            }
            writeln!(out, "{diagnostic}").map_err(CheckError::Write)?;
        }
    }
    writeln!(out, "{summary}").map_err(CheckError::Write)?;
    Ok(summary)
}

/// Adds `path` to `files` if it is a `*.rs` file, or every `*.rs` file below it if it is a
/// directory. Symbolic links are not followed, so a link cycle cannot trap the walk.
///
/// Fails when a directory or the metadata of an entry cannot be read.
fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), CheckError> {
    let read_error = |source| CheckError::Read { path: path.to_path_buf(), source };
    let metadata = fs::symlink_metadata(path).map_err(read_error)?;
    if metadata.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(path).map_err(read_error)? {
        let entry = entry.map_err(read_error)?;
        let is_skipped = SKIPPED_DIRECTORIES.iter().any(|name| entry.file_name() == *name);
        if is_skipped && entry.file_type().map_err(read_error)?.is_dir() {
            continue;
        }
        collect_rust_files(&entry.path(), files)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh scratch directory under the system temporary directory.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xtask-check-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn walks_the_default_roots_and_skips_build_output() {
        let root = scratch("walk");
        for dir in ["crates/a/src", "crates/a/target", "cmd/vendor/x", "tools/t/src", "docs"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(root.join("crates/a/src/lib.rs"), "fn a() {}\n").unwrap();
        fs::write(root.join("crates/a/src/notes.txt"), "\t").unwrap();
        fs::write(root.join("crates/a/target/gen.rs"), "\t").unwrap();
        fs::write(root.join("cmd/vendor/x/lib.rs"), "\t").unwrap();
        fs::write(root.join("tools/t/src/main.rs"), "fn main() {\n\tx();\n}\n").unwrap();
        fs::write(root.join("docs/example.rs"), "\t").unwrap();

        let mut out = Vec::new();
        let summary = run(&root, &[], &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!((summary.file_count, summary.function_count), (2, 2));
        assert_eq!((summary.error_count, summary.warning_count), (1, 0));
        assert!(text.starts_with("-- TAB CHARACTER "), "{text}");
        assert!(text.contains(" tools/t/src/main.rs:2:1\n"), "{text}");
        assert!(text.ends_with("check: scanned 2 files and 2 functions: 1 error, 0 warnings\n"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn explicit_paths_replace_the_default_roots() {
        let root = scratch("paths");
        fs::write(root.join("one.rs"), "fn one() {}\n").unwrap();
        let mut out = Vec::new();
        let summary = run(&root, &[root.join("one.rs").into()], &mut out).unwrap();
        assert_eq!((summary.file_count, summary.error_count), (1, 0));
        let error = run(&root, &["--fix".into()], &mut out).unwrap_err();
        assert!(matches!(error, CheckError::Usage(ref argument) if argument == "--fix"));
        let error = run(&root, &[root.join("missing.rs").into()], &mut out).unwrap_err();
        assert!(matches!(error, CheckError::Read { .. }));
        fs::remove_dir_all(&root).unwrap();
    }
}
