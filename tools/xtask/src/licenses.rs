//! `cargo xtask licenses`: writes `LICENSES/THIRD-PARTY-RUST.txt`, the list of third-party
//! crates compiled into the release executable, with their versions, license expressions
//! and repositories.
//!
//! The list covers the `sibuna` package with its default features, as the release workflow
//! builds it, on every release target ([`RELEASE_TARGETS`]), so that one file serves every
//! archive and package. Two cargo commands supply it:
//!
//! - `cargo tree -p sibuna -e normal,no-proc-macro --target <t>` decides which crates the
//!   build compiles. It applies Cargo's feature resolver to this one package. `cargo
//!   metadata` cannot: its resolve unifies the features of the whole workspace and lists
//!   optional crates that no build of `sibuna` compiles (`sqlx-macros` and its
//!   dependencies, for instance). Procedural macros run inside the compiler and are not
//!   part of the executable, so they are left out with their dependencies, as are build
//!   scripts and their dependencies.
//! - `cargo metadata` supplies each crate's license expression and repository, parsed with
//!   `sibuna-json`.
//!
//! `cargo xtask licenses --check` writes nothing and fails when the committed file differs
//! from what would be written, so CI notices a dependency change that was not recorded.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use sibuna_json::{Limits, Value};

/// The file this command writes, relative to the workspace root.
pub const OUTPUT: &str = "LICENSES/THIRD-PARTY-RUST.txt";

/// The targets the release workflow builds the executable for.
pub const RELEASE_TARGETS: [&str; 7] = [
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-freebsd",
    "x86_64-unknown-openbsd",
];

/// The largest `cargo metadata` document accepted, in bytes.
const MAX_METADATA_BYTES: usize = 256 * 1024 * 1024;

/// One third-party crate of the executable.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Crate {
    /// The package name.
    pub name: String,
    /// The exact version from `Cargo.lock`.
    pub version: String,
    /// The SPDX license expression, or a note naming the license file.
    pub license: String,
    /// The repository URL, or `-` when the package names none.
    pub repository: String,
}

/// Why the list could not be produced or checked.
#[derive(Debug)]
pub enum LicensesError {
    /// An argument other than `--check`.
    Usage(String),
    /// A cargo command could not be started or failed.
    Cargo { command: String, detail: String },
    /// `cargo metadata` printed something this command cannot read.
    Metadata(String),
    /// `cargo tree` named a crate that `cargo metadata` does not describe.
    Unknown { name: String, version: String },
    /// Reading or writing the output file failed.
    Io { path: PathBuf, error: io::Error },
    /// `--check` found that the committed file is out of date.
    Stale { path: PathBuf },
}

impl LicensesError {
    /// The upper-case title of the diagnostic.
    pub fn title(&self) -> &'static str {
        match self {
            LicensesError::Usage(_) => "UNKNOWN ARGUMENT",
            LicensesError::Cargo { .. } => "CARGO FAILED",
            LicensesError::Metadata(_) => "UNREADABLE METADATA",
            LicensesError::Unknown { .. } => "UNKNOWN CRATE",
            LicensesError::Io { .. } => "FILE NOT WRITTEN",
            LicensesError::Stale { .. } => "LICENSE LIST OUT OF DATE",
        }
    }

    /// How to fix the problem.
    pub fn hint(&self) -> &'static str {
        match self {
            LicensesError::Usage(_) => {
                "Run `cargo xtask licenses` or `cargo xtask licenses --check`."
            }
            LicensesError::Cargo { .. } => {
                "Run the command above by hand; `--locked` fails when Cargo.lock needs updating."
            }
            LicensesError::Metadata(_) | LicensesError::Unknown { .. } => {
                "Check that cargo and Cargo.lock are current, then run the command again."
            }
            LicensesError::Io { .. } => {
                "Check that the LICENSES directory exists and is writable."
            }
            LicensesError::Stale { .. } => {
                "Run `cargo xtask licenses` and commit LICENSES/THIRD-PARTY-RUST.txt."
            }
        }
    }
}

impl fmt::Display for LicensesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LicensesError::Usage(argument) => {
                write!(f, "`{argument}` is not an option of `licenses`.")
            }
            LicensesError::Cargo { command, detail } => write!(f, "`{command}` failed: {detail}"),
            LicensesError::Metadata(detail) => write!(f, "`cargo metadata` output: {detail}."),
            LicensesError::Unknown { name, version } => {
                write!(f, "`cargo tree` lists {name} {version}, which `cargo metadata` lacks.")
            }
            LicensesError::Io { path, error } => write!(f, "{}: {error}.", path.display()),
            LicensesError::Stale { path } => {
                write!(f, "{} does not match the crates of the release build.", path.display())
            }
        }
    }
}

impl std::error::Error for LicensesError {}

/// Writes (or with `--check`, compares) the list of the workspace at `root`, and reports
/// what it did on `out`.
///
/// Fails with [`LicensesError`] when an argument is unknown, a cargo command fails, its
/// output cannot be read, the file cannot be written, or `--check` finds it stale.
pub fn run(root: &Path, arguments: &[OsString], out: &mut dyn Write) -> Result<(), LicensesError> {
    let check = match arguments {
        [] => false,
        [flag] if flag == "--check" => true,
        [other, ..] => return Err(LicensesError::Usage(other.to_string_lossy().into_owned())),
    };
    let mut wanted = BTreeSet::new();
    for target in RELEASE_TARGETS {
        wanted.extend(tree_packages(root, target)?);
    }
    let metadata = cargo(root, &["metadata", "--format-version", "1", "--locked"])?;
    let crates = third_party(&metadata, &wanted)?;
    let text = render(&crates);
    let path = root.join(OUTPUT);
    let io_error = |error| LicensesError::Io { path: path.clone(), error };
    if check {
        let committed = std::fs::read_to_string(&path).map_err(io_error)?;
        if committed != text {
            return Err(LicensesError::Stale { path });
        }
        let _ = writeln!(out, "{OUTPUT} is current ({} crates).", crates.len());
    } else {
        std::fs::write(&path, text).map_err(io_error)?;
        let _ = writeln!(out, "Wrote {OUTPUT} ({} crates).", crates.len());
    }
    Ok(())
}

/// The `(name, version)` of every crate `cargo tree` lists for `sibuna` on `target`.
fn tree_packages(root: &Path, target: &str) -> Result<BTreeSet<(String, String)>, LicensesError> {
    let args = [
        "tree",
        "--locked",
        "-p",
        "sibuna",
        "-e",
        "normal,no-proc-macro",
        "--target",
        target,
        "--prefix",
        "none",
        "--format",
        "{p}",
    ];
    let listing = cargo(root, &args)?;
    Ok(listing.lines().filter_map(parse_tree_line).collect())
}

/// Parses one `cargo tree --prefix none --format {p}` line: `name vVERSION`, optionally
/// followed by ` (source)` or ` (*)`. Returns `None` for any other line.
fn parse_tree_line(line: &str) -> Option<(String, String)> {
    let mut words = line.split(' ');
    let name = words.next().filter(|name| !name.is_empty())?;
    let version = words.next()?.strip_prefix('v').filter(|version| !version.is_empty())?;
    Some((name.to_owned(), version.to_owned()))
}

/// Runs the cargo that ran us with `args` in `root` and returns its standard output.
fn cargo(root: &Path, args: &[&str]) -> Result<String, LicensesError> {
    // Cargo sets CARGO for the programs it runs, naming the cargo that ran us.
    let program = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let command = format!("cargo {}", args.join(" "));
    let output = Command::new(program).args(args).current_dir(root).output().map_err(|error| {
        LicensesError::Cargo { command: command.clone(), detail: error.to_string() }
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.lines().last().unwrap_or("no output").to_owned();
        return Err(LicensesError::Cargo { command, detail });
    }
    String::from_utf8(output.stdout)
        .map_err(|_| LicensesError::Cargo { command, detail: "output is not UTF-8".into() })
}

/// The registry crates of `metadata` (a `cargo metadata` document) whose name and version
/// are in `wanted`, sorted by name and version. Workspace crates (no source) are skipped.
///
/// Fails with [`LicensesError::Metadata`] when the document is malformed and with
/// [`LicensesError::Unknown`] when a wanted crate is missing from it.
fn third_party(
    metadata: &str,
    wanted: &BTreeSet<(String, String)>,
) -> Result<Vec<Crate>, LicensesError> {
    let limits = Limits { max_input_bytes: MAX_METADATA_BYTES, ..Limits::UNBOUNDED };
    let document = sibuna_json::parse_with_limits(metadata.as_bytes(), &limits)
        .map_err(|error| LicensesError::Metadata(error.to_string()))?;
    let packages = document
        .as_object()
        .and_then(|object| object.get("packages"))
        .and_then(Value::as_array)
        .ok_or_else(|| LicensesError::Metadata("no `packages` array".into()))?;
    let mut found = BTreeSet::new();
    let mut crates = Vec::new();
    for package in packages {
        let field = |key: &str| package.as_object().and_then(|object| object.get(key));
        let text = |key: &str| field(key).and_then(Value::as_str).map(str::to_owned);
        let (Some(name), Some(version)) = (text("name"), text("version")) else {
            return Err(LicensesError::Metadata("a package without name or version".into()));
        };
        let key = (name, version);
        if !wanted.contains(&key) {
            continue;
        }
        found.insert(key.clone());
        if field("source").is_none_or(Value::is_null) {
            continue;
        }
        let license = text("license")
            .or_else(|| text("license_file").map(|file| format!("see {file}")))
            .unwrap_or_else(|| "unspecified".into());
        let repository = text("repository").unwrap_or_else(|| "-".into());
        let (name, version) = key;
        crates.push(Crate { name, version, license, repository });
    }
    if let Some((name, version)) = wanted.difference(&found).next() {
        return Err(LicensesError::Unknown { name: name.clone(), version: version.clone() });
    }
    crates.sort();
    crates.dedup();
    Ok(crates)
}

/// The file's text: a short header, then one aligned line per crate.
fn render(crates: &[Crate]) -> String {
    let mut text = String::from(
        "Third-party Rust crates in the Sibuna release executable\n\
         ========================================================\n\n\
         Generated by `cargo xtask licenses` from Cargo.lock: the crates that the default\n\
         features of the `sibuna` package compile into the executable on any release\n\
         target. Procedural macros and build scripts run only while compiling and are\n\
         not listed. Each crate's full license text is in its source package on\n\
         crates.io and in its repository.\n\nRelease targets:",
    );
    for target in RELEASE_TARGETS {
        text.push_str("\n  ");
        text.push_str(target);
    }
    text.push_str("\n\n");
    let header = Crate {
        name: "Crate".into(),
        version: "Version".into(),
        license: "License".into(),
        repository: "Repository".into(),
    };
    let widest = |column: fn(&Crate) -> &str| {
        crates.iter().chain([&header]).map(|krate| column(krate).len()).max().unwrap_or(0)
    };
    let widths = [widest(|c| &c.name), widest(|c| &c.version), widest(|c| &c.license)];
    for krate in [&header].into_iter().chain(crates) {
        let line = format!(
            "{:name$}  {:version$}  {:license$}  {}",
            krate.name,
            krate.version,
            krate.license,
            krate.repository,
            name = widths[0],
            version = widths[1],
            license = widths[2],
        );
        let _ = writeln!(text, "{}", line.trim_end());
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_lines_yield_name_and_version() {
        assert_eq!(parse_tree_line("ring v0.17.14"), Some(("ring".into(), "0.17.14".into())));
        assert_eq!(
            parse_tree_line("sibuna-core v1.0.0-beta.1 (/src/crates/core)"),
            Some(("sibuna-core".into(), "1.0.0-beta.1".into()))
        );
        assert_eq!(parse_tree_line("tokio v1.53.0 (*)"), Some(("tokio".into(), "1.53.0".into())));
        assert_eq!(parse_tree_line(""), None);
        assert_eq!(parse_tree_line("warning: something"), None);
    }

    const METADATA: &str = r#"{"packages": [
        {"name": "ring", "version": "0.17.14", "source": "registry+https://x",
         "license": "Apache-2.0 AND ISC", "repository": "https://github.com/briansmith/ring"},
        {"name": "odd", "version": "1.0.0", "source": "registry+https://x",
         "license": null, "license_file": "LICENSE.txt", "repository": null},
        {"name": "sibuna-core", "version": "1.0.0", "source": null, "license": "LGPL"},
        {"name": "unused", "version": "2.0.0", "source": "registry+https://x", "license": "MIT"}
    ], "resolve": null}"#;

    fn wanted(names: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        names.iter().map(|&(name, version)| (name.to_owned(), version.to_owned())).collect()
    }

    #[test]
    fn only_wanted_registry_crates_are_listed() {
        let set = wanted(&[("ring", "0.17.14"), ("odd", "1.0.0"), ("sibuna-core", "1.0.0")]);
        let crates = third_party(METADATA, &set).unwrap();
        let names: Vec<&str> = crates.iter().map(|krate| krate.name.as_str()).collect();
        assert_eq!(names, ["odd", "ring"]);
        assert_eq!(crates[0].license, "see LICENSE.txt");
        assert_eq!(crates[0].repository, "-");
        assert_eq!(crates[1].license, "Apache-2.0 AND ISC");
    }

    #[test]
    fn a_crate_missing_from_the_metadata_is_an_error() {
        let set = wanted(&[("ring", "0.17.15")]);
        let error = third_party(METADATA, &set).unwrap_err();
        assert!(matches!(error, LicensesError::Unknown { ref name, .. } if name == "ring"));
        assert!(matches!(third_party("[]", &set), Err(LicensesError::Metadata(_))));
    }

    #[test]
    fn rendered_columns_line_up() {
        let crates = third_party(METADATA, &wanted(&[("ring", "0.17.14"), ("odd", "1.0.0")]));
        let text = render(&crates.unwrap());
        assert!(text.contains("\nCrate  Version  License             Repository\n"));
        assert!(text.contains("\nodd    1.0.0    see LICENSE.txt     -\n"));
        assert!(text.contains(
            "\nring   0.17.14  Apache-2.0 AND ISC  https://github.com/briansmith/ring\n"
        ));
        assert!(text.is_ascii());
    }
}
