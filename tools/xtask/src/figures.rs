//! `cargo xtask figures`: renders the documentation figures from their Typst sources into
//! SVG files, one per figure and language, and records what each file was rendered from.
//!
//! A figure is a Typst file in one of the source directories of [`SETS`]. The languages
//! are the word tables in [`WORDS`]: `en.toml` gives the English file `name.svg`, and
//! `de.toml` gives `name.de.svg`, the name guidedog looks for in a German build
//! (`figure_language_filename`). Typst receives the language as `--input lang=<code>`.
//!
//! The SVG files are committed, and the documentation builds use them as they are. They
//! are rendered again only when their inputs change: for each file, [`MANIFEST`] records
//! the inputs Typst reported (`--deps`) inside the repository, with one SHA-256 over their
//! contents. A figure whose recorded inputs are unchanged is skipped, so a run on another
//! machine, with other fonts or another Typst, leaves the committed files alone. Typst
//! packages live outside the repository and are pinned by the version in each import.
//!
//! `--force` renders every figure. `--check` renders nothing and fails when a figure is
//! missing, out of date or no longer has a source, so CI notices a source change that was
//! not rendered; it needs neither Typst nor its fonts.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use sibuna_crypto::sha256::Sha256;
use sibuna_json::Value;

/// A directory of figure sources and the directory their SVG files go to, both relative to
/// the workspace root.
pub struct FigureSet {
    /// Where the `.typ` sources are; files in subdirectories are not figures.
    pub sources: &'static str,
    /// Where the SVG files are written, inside the guidedog project that shows them.
    pub output: &'static str,
}

/// The figure sets: the book's and the whitepaper's.
pub const SETS: [FigureSet; 2] = [
    FigureSet { sources: "docs/figures/book", output: "docs/book/assets/figures" },
    FigureSet { sources: "docs/figures/whitepaper", output: "docs/whitepaper/assets/figures" },
];

/// The directory of word tables, one per language, relative to the workspace root.
pub const WORDS: &str = "docs/figures/words";

/// The record of what each SVG file was rendered from, relative to the workspace root.
pub const MANIFEST: &str = "docs/figures/rendered.txt";

/// The language whose files carry no language in their name.
const ENGLISH: &str = "en";

/// Where Typst writes its output and dependency list before they are compared.
const SCRATCH: &str = "target/xtask-figures";

/// Why the figures could not be rendered or checked.
#[derive(Debug)]
pub enum FiguresError {
    /// An argument other than `--check` or `--force`.
    Usage(String),
    /// A file could not be read, written or removed.
    Io { path: PathBuf, error: io::Error },
    /// The manifest or a word table name cannot be read.
    Invalid { path: PathBuf, detail: String },
    /// Typst could not be started, failed, or warned.
    Typst { source: String, detail: String },
    /// `--check` found figures to render; it holds one line per figure.
    Stale(Vec<String>),
}

impl FiguresError {
    /// The upper-case title of the diagnostic.
    pub fn title(&self) -> &'static str {
        match self {
            FiguresError::Usage(_) => "UNKNOWN ARGUMENT",
            FiguresError::Io { .. } => "FILE ERROR",
            FiguresError::Invalid { .. } => "UNREADABLE FILE",
            FiguresError::Typst { .. } => "TYPST FAILED",
            FiguresError::Stale(_) => "FIGURES OUT OF DATE",
        }
    }

    /// The file the diagnostic is about.
    pub fn location(&self) -> String {
        match self {
            FiguresError::Io { path, .. } | FiguresError::Invalid { path, .. } => {
                path.display().to_string()
            }
            FiguresError::Typst { source, .. } => source.clone(),
            FiguresError::Usage(_) | FiguresError::Stale(_) => MANIFEST.to_owned(),
        }
    }

    /// How to fix the problem.
    pub fn hint(&self) -> &'static str {
        match self {
            FiguresError::Usage(_) => {
                "Run `cargo xtask figures`, with `--check` to verify or `--force` to redo all."
            }
            FiguresError::Io { .. } => "Check that the path exists and is writable.",
            FiguresError::Invalid { .. } => {
                "Run `cargo xtask figures --force` to write the manifest again."
            }
            FiguresError::Typst { .. } => {
                "Install Typst 0.15 (or set TYPST to its path), the Noto fonts (fonts-noto-core \
                 and fonts-noto-cjk) and network access for its packages, then run again."
            }
            FiguresError::Stale(_) => {
                "Run `cargo xtask figures` and commit the SVG files and docs/figures/rendered.txt."
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
            FiguresError::Invalid { path, detail } => write!(f, "{}: {detail}.", path.display()),
            FiguresError::Typst { source, detail } => {
                write!(f, "Typst could not render {source}:\n\n{}", detail.trim_end())
            }
            FiguresError::Stale(lines) => {
                f.write_str("These figures do not match their sources:\n")?;
                for line in lines {
                    write!(f, "\n    {line}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for FiguresError {}

/// What the command does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Render the figures whose inputs changed.
    Render,
    /// Render every figure.
    Force,
    /// Render nothing; fail when a figure is out of date.
    Check,
}

/// One SVG file to produce: its source, its language and its path, relative to the root.
struct Job {
    source: String,
    language: String,
    output: String,
}

/// One manifest line: the digest of an output's inputs and the inputs themselves.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    digest: String,
    inputs: Vec<String>,
}

/// Renders (or with `--check`, checks) the figures of the workspace at `root`, and reports
/// what it did on `out`.
///
/// Fails with [`FiguresError`] when an argument is unknown, a file cannot be read or
/// written, Typst fails or warns, or `--check` finds a figure out of date.
pub fn run(root: &Path, arguments: &[OsString], out: &mut dyn Write) -> Result<(), FiguresError> {
    let mode = match arguments {
        [] => Mode::Render,
        [flag] if flag == "--check" => Mode::Check,
        [flag] if flag == "--force" => Mode::Force,
        [other, ..] => return Err(FiguresError::Usage(other.to_string_lossy().into_owned())),
    };
    let jobs = jobs(root, &languages(root)?)?;
    let manifest_path = root.join(MANIFEST);
    let old = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => parse_manifest(&text)
            .map_err(|detail| FiguresError::Invalid { path: manifest_path.clone(), detail })?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(FiguresError::Io { path: manifest_path, error }),
    };
    if mode == Mode::Check {
        return check(root, &jobs, &old, out);
    }
    let mut new = BTreeMap::new();
    let mut rendered = 0;
    for job in &jobs {
        let current = old.get(&job.output).filter(|_| mode != Mode::Force);
        if let Some(entry) = current
            && is_current(root, job, entry)?
        {
            new.insert(job.output.clone(), entry.clone());
            continue;
        }
        let entry = render(root, job)?;
        let _ = writeln!(out, "rendered {}", job.output);
        rendered += 1;
        new.insert(job.output.clone(), entry);
    }
    for orphan in old.keys().filter(|output| !new.contains_key(*output)) {
        let path = root.join(orphan);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(FiguresError::Io { path, error }),
        }
        let _ = writeln!(out, "removed {orphan}");
    }
    let text = render_manifest(&new);
    if old != new || !manifest_path.exists() {
        std::fs::write(&manifest_path, text)
            .map_err(|error| FiguresError::Io { path: manifest_path, error })?;
    }
    let _ = writeln!(out, "{} figures, {rendered} rendered.", jobs.len());
    Ok(())
}

/// The `--check` mode: every job has a current entry and an output, and no entry lacks a
/// job.
fn check(
    root: &Path,
    jobs: &[Job],
    manifest: &BTreeMap<String, Entry>,
    out: &mut dyn Write,
) -> Result<(), FiguresError> {
    let mut stale = Vec::new();
    for job in jobs {
        match manifest.get(&job.output) {
            None => stale.push(format!("{}: never rendered", job.output)),
            Some(entry) if !is_current(root, job, entry)? => {
                stale.push(format!("{}: its inputs changed", job.output));
            }
            Some(_) => {}
        }
    }
    for output in manifest.keys() {
        if !jobs.iter().any(|job| &job.output == output) {
            stale.push(format!("{output}: its source is gone"));
        }
    }
    if !stale.is_empty() {
        return Err(FiguresError::Stale(stale));
    }
    let _ = writeln!(out, "{MANIFEST} is current ({} figures).", jobs.len());
    Ok(())
}

/// Whether `entry` still describes `job`: its output exists and its inputs, which must all
/// still exist, have the recorded digest.
fn is_current(root: &Path, job: &Job, entry: &Entry) -> Result<bool, FiguresError> {
    if !root.join(&job.output).is_file() {
        return Ok(false);
    }
    if entry.inputs.iter().any(|input| !root.join(input).is_file()) {
        return Ok(false);
    }
    Ok(digest(root, &job.language, &entry.inputs)? == entry.digest)
}

/// The languages of the word tables, English first, then by code.
fn languages(root: &Path) -> Result<Vec<String>, FiguresError> {
    let directory = root.join(WORDS);
    let mut codes = Vec::new();
    for name in sorted_file_names(&directory)? {
        let Some(code) = name.strip_suffix(".toml") else { continue };
        if code.is_empty() || !code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            let detail = format!("`{name}` is not a language code followed by .toml");
            return Err(FiguresError::Invalid { path: directory, detail });
        }
        codes.push(code.to_owned());
    }
    if !codes.iter().any(|code| code == ENGLISH) {
        let detail = "there is no en.toml, the table every language falls back to".to_owned();
        return Err(FiguresError::Invalid { path: directory, detail });
    }
    codes.sort_by_key(|code| (code != ENGLISH, code.clone()));
    Ok(codes)
}

/// Every (figure, language) pair of every set, in a fixed order.
fn jobs(root: &Path, languages: &[String]) -> Result<Vec<Job>, FiguresError> {
    let mut jobs = Vec::new();
    for set in &SETS {
        for name in sorted_file_names(&root.join(set.sources))? {
            let Some(stem) = name.strip_suffix(".typ") else { continue };
            for language in languages {
                let suffix =
                    if language == ENGLISH { String::new() } else { format!(".{language}") };
                jobs.push(Job {
                    source: format!("{}/{name}", set.sources),
                    language: language.clone(),
                    output: format!("{}/{stem}{suffix}.svg", set.output),
                });
            }
        }
    }
    Ok(jobs)
}

/// The names of the regular files in `directory`, sorted.
fn sorted_file_names(directory: &Path) -> Result<Vec<String>, FiguresError> {
    let io_error = |error| FiguresError::Io { path: directory.to_owned(), error };
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if entry.file_type().map_err(io_error)?.is_file()
            && let Some(name) = entry.file_name().to_str()
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// The SHA-256, in hexadecimal, of the language and of every input's path and contents.
/// Lengths separate the parts, so no two lists of inputs hash alike by concatenation.
fn digest(root: &Path, language: &str, inputs: &[String]) -> Result<String, FiguresError> {
    let mut hasher = Sha256::new();
    let mut part = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    part(language.as_bytes());
    for input in inputs {
        let path = root.join(input);
        let contents = std::fs::read(&path)
            .map_err(|error| FiguresError::Io { path: path.clone(), error })?;
        part(input.as_bytes());
        part(&contents);
    }
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// Renders `job` with Typst, writes its SVG file when the bytes differ from the committed
/// one, and returns its manifest entry.
fn render(root: &Path, job: &Job) -> Result<Entry, FiguresError> {
    let scratch = root.join(SCRATCH);
    std::fs::create_dir_all(&scratch)
        .map_err(|error| FiguresError::Io { path: scratch.clone(), error })?;
    let svg = scratch.join("figure.svg");
    let deps = scratch.join("figure.deps.json");
    let program = std::env::var_os("TYPST").unwrap_or_else(|| OsString::from("typst"));
    let typst_error = |detail: String| FiguresError::Typst { source: job.source.clone(), detail };
    let output = Command::new(program)
        .arg("compile")
        .arg("--root")
        .arg(root)
        .arg("--input")
        .arg(format!("lang={}", job.language))
        .arg("--deps")
        .arg(&deps)
        .args(["--deps-format", "json"])
        .arg(&job.source)
        .arg(&svg)
        .current_dir(root)
        .output()
        .map_err(|error| typst_error(format!("cannot run typst: {error}")))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    // A warning is a failure: a missing font would otherwise draw other letters.
    if !output.status.success() || stderr.contains("warning:") {
        return Err(typst_error(stderr.into_owned()));
    }
    let read = |path: &Path| {
        std::fs::read(path).map_err(|error| FiguresError::Io { path: path.to_owned(), error })
    };
    let listing = read(&deps)?;
    let inputs = parse_deps(root, &listing).map_err(typst_error)?;
    let bytes = read(&svg)?;
    let target = root.join(&job.output);
    if std::fs::read(&target).ok().as_deref() != Some(bytes.as_slice()) {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| FiguresError::Io { path: parent.to_owned(), error })?;
        }
        std::fs::write(&target, &bytes)
            .map_err(|error| FiguresError::Io { path: target.clone(), error })?;
    }
    Ok(Entry { digest: digest(root, &job.language, &inputs)?, inputs })
}

/// The inputs of a Typst dependency list (`{"inputs": [...], "outputs": [...]}`) that lie
/// inside `root`, relative to it with `/` separators, sorted. Paths outside the root (the
/// package cache) are left out.
fn parse_deps(root: &Path, listing: &[u8]) -> Result<Vec<String>, String> {
    let document = sibuna_json::parse(listing).map_err(|error| error.to_string())?;
    let inputs = document
        .as_object()
        .and_then(|object| object.get("inputs"))
        .and_then(Value::as_array)
        .ok_or("the dependency list has no `inputs` array")?;
    let mut paths = Vec::new();
    for input in inputs {
        let text = input.as_str().ok_or("a dependency is not a string")?;
        let path = Path::new(text);
        let relative = if path.is_absolute() {
            match path.strip_prefix(root) {
                Ok(inside) => inside,
                Err(_) => continue,
            }
        } else {
            path
        };
        let parts: Vec<&str> = relative.iter().filter_map(|part| part.to_str()).collect();
        let joined = parts.join("/");
        if joined.chars().any(char::is_whitespace) {
            return Err(format!("the input `{joined}` has white space in its path"));
        }
        paths.push(joined);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// The manifest's text: a header, then one line per output, sorted.
fn render_manifest(entries: &BTreeMap<String, Entry>) -> String {
    let mut text = String::from(
        "# The figures `cargo xtask figures` rendered, and what from. Do not edit.\n\
         # Each line: the SVG file, the SHA-256 of its language and inputs, and the inputs.\n",
    );
    for (output, entry) in entries {
        let _ = writeln!(text, "{output} {} {}", entry.digest, entry.inputs.join(" "));
    }
    text
}

/// Parses the manifest written by [`render_manifest`]; fails with a description of the
/// first malformed line.
fn parse_manifest(text: &str) -> Result<BTreeMap<String, Entry>, String> {
    let mut entries = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut words = line.split(' ');
        let (Some(output), Some(digest)) = (words.next(), words.next()) else {
            return Err(format!("line {} has no digest", number + 1));
        };
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("line {} has no SHA-256 digest", number + 1));
        }
        let inputs: Vec<String> = words.map(str::to_owned).collect();
        if inputs.is_empty() {
            return Err(format!("line {} lists no inputs", number + 1));
        }
        entries.insert(output.to_owned(), Entry { digest: digest.to_owned(), inputs });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_reads_back_what_it_wrote() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "docs/book/assets/figures/gcra.de.svg".to_owned(),
            Entry {
                digest: "ab".repeat(32),
                inputs: vec!["docs/figures/book/gcra.typ".into(), "docs/figures/style.typ".into()],
            },
        );
        let text = render_manifest(&entries);
        assert!(text.is_ascii());
        assert_eq!(parse_manifest(&text).unwrap(), entries);
    }

    #[test]
    fn malformed_manifest_lines_are_errors() {
        assert!(parse_manifest("a.svg\n").is_err());
        assert!(parse_manifest("a.svg 1234 b.typ\n").is_err());
        assert!(parse_manifest(&format!("a.svg {}\n", "0".repeat(64))).is_err());
        assert!(parse_manifest("# comment\n\n").unwrap().is_empty());
    }

    #[test]
    fn dependencies_outside_the_root_are_left_out() {
        let root = Path::new("/work/sibuna");
        let listing = br#"{"inputs": ["/home/u/.cache/typst/packages/preview/cetz/0.5.2/lib.typ",
            "docs/figures/style.typ", "/work/sibuna/docs/figures/words/en.toml",
            "docs/figures/style.typ"], "outputs": ["x.svg"]}"#;
        assert_eq!(
            parse_deps(root, listing).unwrap(),
            ["docs/figures/style.typ", "docs/figures/words/en.toml"]
        );
        assert!(parse_deps(root, b"[]").is_err());
    }

    #[test]
    fn the_digest_depends_on_language_paths_and_contents() {
        let root = std::env::temp_dir().join(format!("xtask-figures-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.typ"), "one").unwrap();
        std::fs::write(root.join("b.typ"), "one").unwrap();
        let inputs = |name: &str| vec![name.to_owned()];
        let first = digest(&root, "en", &inputs("a.typ")).unwrap();
        assert_eq!(first, digest(&root, "en", &inputs("a.typ")).unwrap());
        assert_ne!(first, digest(&root, "de", &inputs("a.typ")).unwrap());
        assert_ne!(first, digest(&root, "en", &inputs("b.typ")).unwrap());
        std::fs::write(root.join("a.typ"), "two").unwrap();
        assert_ne!(first, digest(&root, "en", &inputs("a.typ")).unwrap());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
