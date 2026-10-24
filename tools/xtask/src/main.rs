//! Repository tasks for the Sibuna workspace, run as `cargo xtask <command>`.
//!
//! `main` is a small dispatcher over [`COMMANDS`]; each command lives in a module of its
//! own or in a tool crate beside this one. Today there is `check`, which enforces the
//! structural limits of the house rules, and `browser`, which runs the `sibuna-browser`
//! tool (`tools/browser`) for checks in headless Chromium, and `bench`, which builds the
//! daemon and runs the `sibuna-bench` tool (`tools/bench`) in release mode, `licenses`,
//! which writes `LICENSES/THIRD-PARTY-RUST.txt`, and `figures`, which renders the
//! documentation figures from their Typst sources. Builds of the WebAssembly solver (`wasm`)
//! are meant to join them as a further module and table entry.
//!
//! Deliberate changes from the Zig repository's `tools/check-style.sh` and
//! `check-style.awk`:
//!
//! - Functions are found by a lexer that understands strings, raw strings, characters,
//!   lifetimes and nested block comments, instead of counting every `{` on a line.
//! - Lines holding only brackets, commas or semicolons, and lines inside block comments,
//!   do not count toward a function's length. The signature, including a multi-line
//!   parameter list or `where` clause, does not count either.
//! - The file limit counts all lines (the house rule), not only code lines.
//! - Line width has a soft limit of 99 characters (a warning) and a hard limit of 108 (an
//!   error), where the Zig check failed at 99.
//! - A function may opt out of the length limit with `// xtask: allow-long-function
//!   <reason>`, meant for generated tables only.
//! - Violations are reported as Elm-style diagnostics with an excerpt and a hint.

mod check;
mod figures;
mod licenses;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::{self, ExitCode};

/// One subcommand: its name, its argument synopsis and a one-line summary for `help`.
struct Command {
    name: &'static str,
    synopsis: &'static str,
    summary: &'static str,
}

/// Every subcommand, in the order `help` lists them.
const COMMANDS: [Command; 6] = [
    Command {
        name: "check",
        synopsis: "[PATH...]",
        summary: "Check function, file and line length limits and forbid tabs",
    },
    Command {
        name: "browser",
        synopsis: "<ARGS...>",
        summary: "Run sibuna-browser checks in headless Chromium",
    },
    Command {
        name: "bench",
        synopsis: "<COMMAND> [OPTIONS]",
        summary: "Run the benchmarks (primitives, product, latency, admission) in release mode",
    },
    Command {
        name: "licenses",
        synopsis: "[--check]",
        summary: "Write the third-party crate list LICENSES/THIRD-PARTY-RUST.txt",
    },
    Command {
        name: "figures",
        synopsis: "[--check | --force]",
        summary: "Render the documentation figures whose Typst sources changed",
    },
    Command { name: "help", synopsis: "", summary: "Print this help" },
];

/// The exit status for a usage error or a failure to run, as opposed to a failed check.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some((command, rest)) = arguments.split_first() else {
        return help();
    };
    match command.to_str() {
        Some("check") => check(rest),
        Some("browser") => browser(rest),
        Some("bench") => bench(rest),
        Some("licenses") => licenses(rest),
        Some("figures") => figures(rest),
        Some("help" | "-h" | "--help") => help(),
        _ => unknown_command(&command.to_string_lossy()),
    }
}

/// Runs `cargo xtask check` over the workspace that contains this crate.
fn check(arguments: &[OsString]) -> ExitCode {
    // This crate lives at `tools/xtask`, two levels below the workspace root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.ancestors().nth(2).unwrap_or(manifest);
    let mut stdout = io::stdout().lock();
    match check::run(root, arguments, &mut stdout) {
        Ok(summary) if summary.error_count == 0 => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            let _ = writeln!(io::stderr(), "xtask check: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Runs `cargo xtask licenses` over the workspace that contains this crate.
fn licenses(arguments: &[OsString]) -> ExitCode {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.ancestors().nth(2).unwrap_or(manifest);
    match licenses::run(root, arguments, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            print_diagnostic(error.title(), licenses::OUTPUT, &error, error.hint());
            ExitCode::FAILURE
        }
    }
}

/// Runs `cargo xtask figures` over the workspace that contains this crate.
fn figures(arguments: &[OsString]) -> ExitCode {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.ancestors().nth(2).unwrap_or(manifest);
    match figures::run(root, arguments, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            print_diagnostic(error.title(), &error.location(), &error, error.hint());
            ExitCode::FAILURE
        }
    }
}

/// Prints an Elm-style diagnostic on standard error: a title rule with the location, the
/// message and a hint.
fn print_diagnostic(title: &str, location: &str, message: &dyn std::fmt::Display, hint: &str) {
    let dashes = "-".repeat(80usize.saturating_sub(title.len() + location.len() + 5).max(3));
    let _ = writeln!(io::stderr(), "-- {title} {dashes} {location}\n\n{message}\n\nHint: {hint}");
}

/// Runs `cargo run -q -p sibuna-browser -- <arguments>` and passes on its exit status.
fn browser(arguments: &[OsString]) -> ExitCode {
    // Cargo sets CARGO for the programs it runs, naming the cargo that ran us.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let status = process::Command::new(cargo)
        .args(["run", "-q", "-p", "sibuna-browser", "--"])
        .args(arguments)
        .status();
    match status {
        Ok(status) => match status.code().and_then(|code| u8::try_from(code).ok()) {
            Some(code) => ExitCode::from(code),
            // Killed by a signal, or a code outside 0 to 255.
            None => ExitCode::FAILURE,
        },
        Err(error) => {
            let _ = writeln!(io::stderr(), "xtask browser: cannot run cargo: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Builds the daemon in release mode, then runs `cargo run --release -q -p sibuna-bench --
/// <arguments>` and passes on its exit status. The benchmark finds the daemon beside its
/// own binary in the release directory.
fn bench(arguments: &[OsString]) -> ExitCode {
    let wants_help = arguments.first().is_none_or(|first| first == "help" || first == "--help");
    if !wants_help && let Err(code) = cargo(&["build", "--release", "-q", "-p", "sibuna"], &[]) {
        return code;
    }
    let run = ["run", "--release", "-q", "-p", "sibuna-bench", "--"];
    cargo(&run, arguments).map_or_else(|code| code, |()| ExitCode::SUCCESS)
}

/// Runs the cargo that ran us with `args` and `extra`; a failure carries the exit code to
/// pass on.
fn cargo(args: &[&str], extra: &[OsString]) -> Result<(), ExitCode> {
    // Cargo sets CARGO for the programs it runs, naming the cargo that ran us.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    match process::Command::new(cargo).args(args).args(extra).status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => {
            let code = status.code().and_then(|code| u8::try_from(code).ok());
            Err(code.map_or(ExitCode::FAILURE, ExitCode::from))
        }
        Err(error) => {
            let _ = writeln!(io::stderr(), "xtask: cannot run cargo: {error}");
            Err(ExitCode::from(EXIT_USAGE))
        }
    }
}

fn help() -> ExitCode {
    let mut text = String::from(
        "Repository tasks for the Sibuna workspace.\n\nUsage: cargo xtask <COMMAND>\n\n\
         Commands:\n",
    );
    for command in &COMMANDS {
        let usage = format!("{} {}", command.name, command.synopsis);
        text.push_str(&format!("  {usage:<28}{}\n", command.summary));
    }
    text.push_str(
        "\n`check` scans crates/, cmd/ and tools/ (or the given paths). It fails when a\n\
         function body has more than 70 logical lines, a file more than 1,408 lines or a\n\
         line more than 108 characters, or when a line holds a tab. Lines over 99\n\
         characters are warnings.\n\n\
         `browser` passes its arguments to the sibuna-browser tool; run\n\
         `cargo xtask browser help` for its commands.\n\n\
         `bench` builds the daemon and the sibuna-bench tool in release mode and passes its\n\
         arguments on; run `cargo xtask bench help` for its commands and options.\n\n\
         `licenses` lists the third-party crates of the release executable with their\n\
         licenses in LICENSES/THIRD-PARTY-RUST.txt; `--check` only verifies the file.\n\n\
         `figures` renders each Typst figure of docs/figures once per language into SVG,\n\
         skipping those whose inputs are unchanged since docs/figures/rendered.txt was\n\
         written; `--force` renders all, and `--check` only verifies the record.\n",
    );
    match io::stdout().lock().write_all(text.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(EXIT_USAGE),
    }
}

fn unknown_command(name: &str) -> ExitCode {
    let mut message = format!("xtask: there is no command named `{name}`.");
    if let Some(suggestion) = closest_command(name) {
        message.push_str(&format!(" Did you mean `{suggestion}`?"));
    }
    message.push_str("\nHint: Run `cargo xtask help` to list the commands.");
    let _ = writeln!(io::stderr(), "{message}");
    ExitCode::from(EXIT_USAGE)
}

/// Returns the command whose name is within two edits of `name`, if there is one.
fn closest_command(name: &str) -> Option<&'static str> {
    COMMANDS
        .iter()
        .map(|command| (edit_distance(name, command.name), command.name))
        .filter(|&(distance, _)| distance <= 2)
        .min()
        .map(|(_, command)| command)
}

/// The Levenshtein distance between `a` and `b`, counted in characters.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0; b.len() + 1];
    for (i, a_char) in a.chars().enumerate() {
        current[0] = i + 1;
        for (j, &b_char) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(a_char != b_char);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_distance_counts_insertions_deletions_and_substitutions() {
        assert_eq!(edit_distance("check", "check"), 0);
        assert_eq!(edit_distance("chek", "check"), 1);
        assert_eq!(edit_distance("chekc", "check"), 2);
        assert_eq!(edit_distance("", "help"), 4);
    }

    #[test]
    fn suggests_only_close_commands() {
        assert_eq!(closest_command("chek"), Some("check"));
        assert_eq!(closest_command("hlep"), Some("help"));
        assert_eq!(closest_command("browsr"), Some("browser"));
        assert_eq!(closest_command("wasm"), None);
    }
}
