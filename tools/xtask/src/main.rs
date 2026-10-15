//! Repository tasks for the Sibuna workspace, run as `cargo xtask <command>`.
//!
//! `main` is a small dispatcher over [`COMMANDS`]; each command lives in a module of its
//! own. Today there is `check`, which enforces the structural limits of the house rules.
//! Builds of the WebAssembly solver (`wasm`) and benchmark runs (`bench`) are meant to
//! join it as further modules and table entries.
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

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

/// One subcommand: its name, its argument synopsis and a one-line summary for `help`.
struct Command {
    name: &'static str,
    synopsis: &'static str,
    summary: &'static str,
}

/// Every subcommand, in the order `help` lists them.
const COMMANDS: [Command; 2] = [
    Command {
        name: "check",
        synopsis: "[PATH...]",
        summary: "Check function, file and line length limits and forbid tabs",
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

fn help() -> ExitCode {
    let mut text = String::from(
        "Repository tasks for the Sibuna workspace.\n\nUsage: cargo xtask <COMMAND>\n\n\
         Commands:\n",
    );
    for command in &COMMANDS {
        let usage = format!("{} {}", command.name, command.synopsis);
        text.push_str(&format!("  {usage:<18}{}\n", command.summary));
    }
    text.push_str(
        "\n`check` scans crates/, cmd/ and tools/ (or the given paths). It fails when a\n\
         function body has more than 70 logical lines, a file more than 1,408 lines or a\n\
         line more than 108 characters, or when a line holds a tab. Lines over 99\n\
         characters are warnings.\n",
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
        assert_eq!(closest_command("wasm"), None);
    }
}
