//! `cargo xtask figures`: keeps the files that the documentation figures share or read
//! identical to their sources.
//!
//! Guidedog compiles every figure with its embedded Typst during the build, and a Typst
//! figure cannot read a file outside its guidedog project. So each project keeps its own
//! copy of what several projects share (the figure style, the chart helpers and word
//! tables) and of the benchmark results its charts read. [`COPIES`] lists each source and
//! its copies, relative to the workspace root.
//!
//! Without arguments the command writes every copy that differs from its source. A source
//! may be a directory: its files are copied, not its subdirectories, and a file in a copy
//! that the source lacks is removed, so the copy mirrors the source. `--check` writes
//! nothing and fails when a copy differs, is missing or has a file its source lacks; CI
//! runs it.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A file or directory and the places it is copied to, relative to the workspace root.
pub struct Copy {
    /// The file or directory that is edited.
    pub source: &'static str,
    /// Where identical copies live, each inside the project that reads it.
    pub copies: &'static [&'static str],
}

/// Everything the figures share or read: the book's files are the sources, except the
/// benchmark results, which `cargo xtask bench` writes.
pub const COPIES: [Copy; 5] = [
    Copy {
        source: "benchmarks/results/primitives-latest.json",
        copies: &[
            "docs/book/diagrams/charts/data/primitives-latest.json",
            "docs/whitepaper/diagrams/charts/data/primitives-latest.json",
        ],
    },
    Copy {
        source: "docs/book/diagrams/style.typ",
        copies: &["docs/whitepaper/diagrams/style.typ", "docs/sid/diagrams/style.typ"],
    },
    Copy {
        source: "docs/book/diagrams/charts/chart.typ",
        copies: &["docs/whitepaper/diagrams/charts/chart.typ"],
    },
    Copy {
        source: "docs/book/diagrams/charts/draw/tree.typ",
        copies: &["docs/whitepaper/diagrams/charts/draw/tree.typ"],
    },
    Copy {
        source: "docs/book/diagrams/charts/words",
        copies: &["docs/whitepaper/diagrams/charts/words"],
    },
];

/// Why the copies could not be written or checked.
#[derive(Debug)]
pub enum FiguresError {
    /// An argument other than `--check`.
    Usage(String),
    /// A file or directory could not be read, written or removed.
    Io { path: PathBuf, error: io::Error },
    /// `--check` found copies that differ from their sources; one line per copy.
    Stale(Vec<String>),
}

impl FiguresError {
    /// The upper-case title of the diagnostic.
    pub fn title(&self) -> &'static str {
        match self {
            FiguresError::Usage(_) => "UNKNOWN ARGUMENT",
            FiguresError::Io { .. } => "FILE ERROR",
            FiguresError::Stale(_) => "FIGURE COPIES OUT OF DATE",
        }
    }

    /// The file the diagnostic is about.
    pub fn location(&self) -> String {
        match self {
            FiguresError::Io { path, .. } => path.display().to_string(),
            FiguresError::Usage(_) | FiguresError::Stale(_) => "tools/xtask/src/figures.rs".into(),
        }
    }

    /// How to fix the problem.
    pub fn hint(&self) -> &'static str {
        match self {
            FiguresError::Usage(_) => "Run `cargo xtask figures`, or `--check` to only verify.",
            FiguresError::Io { .. } => "Check that the path exists and is writable.",
            FiguresError::Stale(_) => {
                "Edit the source, not the copy. Then run `cargo xtask figures` and commit the \
                 copies with their source."
            }
        }
    }
}

impl fmt::Display for FiguresError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FiguresError::Usage(argument) => {
                write!(f, "`{argument}` is not an option of `figures`.")
            }
            FiguresError::Io { path, error } => write!(f, "{}: {error}.", path.display()),
            FiguresError::Stale(lines) => {
                f.write_str("These copies do not match their sources:\n")?;
                for line in lines {
                    write!(f, "\n    {line}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for FiguresError {}

/// One copy to keep: the source file and the copy, relative to the workspace root.
#[derive(Debug, PartialEq, Eq)]
struct Pair {
    source: PathBuf,
    copy: PathBuf,
}

/// The pairs of files that `copies` describes, and the files in copied directories that
/// their source lacks.
#[derive(Debug, Default)]
struct Plan {
    pairs: Vec<Pair>,
    extra: Vec<PathBuf>,
}

/// Writes (or with `--check`, checks) the copies of [`COPIES`] in the workspace at `root`,
/// and reports what it did on `out`.
///
/// Fails with [`FiguresError`] when an argument is unknown, a file cannot be read or
/// written, or `--check` finds a copy that differs from its source.
pub fn run(root: &Path, arguments: &[OsString], out: &mut dyn Write) -> Result<(), FiguresError> {
    let check_only = match arguments {
        [] => false,
        [flag] if flag == "--check" => true,
        [other, ..] => return Err(FiguresError::Usage(other.to_string_lossy().into_owned())),
    };
    let plan = plan(root, &COPIES)?;
    if check_only { check(root, &plan, out) } else { write(root, &plan, out) }
}

/// Expands `copies` into pairs of files: a file source gives one pair per copy, and a
/// directory source one pair per file in it and copy.
fn plan(root: &Path, copies: &[Copy]) -> Result<Plan, FiguresError> {
    let mut plan = Plan::default();
    for entry in copies {
        let source = Path::new(entry.source);
        if !root.join(source).is_dir() {
            for copy in entry.copies {
                plan.pairs.push(Pair { source: source.into(), copy: copy.into() });
            }
            continue;
        }
        let names = file_names(&root.join(source))?;
        for copy in entry.copies.iter().map(Path::new) {
            for name in &names {
                plan.pairs.push(Pair { source: source.join(name), copy: copy.join(name) });
            }
            let present = match file_names(&root.join(copy)) {
                Ok(present) => present,
                Err(FiguresError::Io { error, .. }) if error.kind() == io::ErrorKind::NotFound => {
                    Vec::new()
                }
                Err(error) => return Err(error),
            };
            let extra = present.into_iter().filter(|name| !names.contains(name));
            plan.extra.extend(extra.map(|name| copy.join(name)));
        }
    }
    Ok(plan)
}

/// The names of the regular files in `directory`, sorted.
fn file_names(directory: &Path) -> Result<Vec<OsString>, FiguresError> {
    let io_error = |error| FiguresError::Io { path: directory.to_path_buf(), error };
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if entry.file_type().map_err(io_error)?.is_file() {
            names.push(entry.file_name());
        }
    }
    names.sort();
    Ok(names)
}

/// Reads the file at `path`; a missing file reads as `None`.
fn read(path: &Path) -> Result<Option<Vec<u8>>, FiguresError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(FiguresError::Io { path: path.to_path_buf(), error }),
    }
}

/// Reads the source of `pair`, which must exist, and its copy, which may not.
fn read_pair(root: &Path, pair: &Pair) -> Result<(Vec<u8>, Option<Vec<u8>>), FiguresError> {
    let source_path = root.join(&pair.source);
    let source = read(&source_path)?.ok_or_else(|| FiguresError::Io {
        path: source_path,
        error: io::Error::from(io::ErrorKind::NotFound),
    })?;
    Ok((source, read(&root.join(&pair.copy))?))
}

/// The default mode: writes every copy that differs from its source and removes the files
/// that a copied directory's source lacks.
fn write(root: &Path, plan: &Plan, out: &mut dyn Write) -> Result<(), FiguresError> {
    let mut written = 0;
    for pair in &plan.pairs {
        let (source, copy) = read_pair(root, pair)?;
        if copy.as_deref() == Some(source.as_slice()) {
            continue;
        }
        let path = root.join(&pair.copy);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| FiguresError::Io { path: parent.to_path_buf(), error })?;
        }
        std::fs::write(&path, &source).map_err(|error| FiguresError::Io { path, error })?;
        let _ = writeln!(out, "copied {} to {}", pair.source.display(), pair.copy.display());
        written += 1;
    }
    for extra in &plan.extra {
        let path = root.join(extra);
        std::fs::remove_file(&path).map_err(|error| FiguresError::Io { path, error })?;
        let _ = writeln!(out, "removed {}", extra.display());
    }
    let _ = writeln!(out, "{} copies, {written} written.", plan.pairs.len());
    Ok(())
}

/// The `--check` mode: every copy exists and equals its source, and no copied directory
/// holds a file its source lacks.
fn check(root: &Path, plan: &Plan, out: &mut dyn Write) -> Result<(), FiguresError> {
    let mut stale = Vec::new();
    for pair in &plan.pairs {
        let (source, copy) = read_pair(root, pair)?;
        let (source_name, copy_name) = (pair.source.display(), pair.copy.display());
        match copy {
            None => stale.push(format!("{copy_name} is missing (a copy of {source_name})")),
            Some(copy) if copy != source => {
                stale.push(format!("{copy_name} differs from {source_name}"));
            }
            Some(_) => {}
        }
    }
    for extra in &plan.extra {
        stale.push(format!("{} has no source", extra.display()));
    }
    if !stale.is_empty() {
        return Err(FiguresError::Stale(stale));
    }
    let _ = writeln!(out, "{} copies match their sources.", plan.pairs.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, empty directory under the system's temporary directory.
    fn scratch(name: &str) -> PathBuf {
        let process = std::process::id();
        let path = std::env::temp_dir().join(format!("xtask-figures-{process}-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    const TEST_COPIES: [Copy; 2] = [
        Copy { source: "data.json", copies: &["a/data.json", "b/data.json"] },
        Copy { source: "words", copies: &["a/words"] },
    ];

    fn workspace(name: &str) -> PathBuf {
        let root = scratch(name);
        std::fs::write(root.join("data.json"), "{}").unwrap();
        std::fs::create_dir_all(root.join("words")).unwrap();
        std::fs::write(root.join("words/en.toml"), "x = 1").unwrap();
        std::fs::write(root.join("words/de.toml"), "x = 2").unwrap();
        root
    }

    fn checked(root: &Path) -> Result<(), FiguresError> {
        check(root, &plan(root, &TEST_COPIES)?, &mut Vec::new())
    }

    #[test]
    fn writing_makes_every_copy_identical() {
        let root = workspace("write");
        assert!(matches!(checked(&root), Err(FiguresError::Stale(lines)) if lines.len() == 4));
        write(&root, &plan(&root, &TEST_COPIES).unwrap(), &mut Vec::new()).unwrap();
        checked(&root).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("a/words/de.toml")).unwrap(), "x = 2");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn check_names_a_changed_copy_and_a_stray_file() {
        let root = workspace("stale");
        write(&root, &plan(&root, &TEST_COPIES).unwrap(), &mut Vec::new()).unwrap();
        std::fs::write(root.join("b/data.json"), "{\"edited\": true}").unwrap();
        std::fs::write(root.join("a/words/fr.toml"), "x = 3").unwrap();
        let Err(FiguresError::Stale(lines)) = checked(&root) else {
            panic!("the check passed");
        };
        assert_eq!(lines, ["b/data.json differs from data.json", "a/words/fr.toml has no source"]);
        write(&root, &plan(&root, &TEST_COPIES).unwrap(), &mut Vec::new()).unwrap();
        assert!(!root.join("a/words/fr.toml").exists());
        checked(&root).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_unknown_arguments() {
        let error = run(Path::new("."), &["--force".into()], &mut Vec::new()).unwrap_err();
        assert!(matches!(error, FiguresError::Usage(argument) if argument == "--force"));
    }
}
