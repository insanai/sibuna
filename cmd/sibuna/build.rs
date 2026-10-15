//! Builds the WebAssembly modules the daemon embeds and copies them into `$OUT_DIR`, where
//! `include_bytes!` picks them up:
//!
//! - the browser solver (`sibuna-pow-wasm`), served as `/__sibuna/wasm/sibuna-pow.wasm`, as
//!   `$OUT_DIR/sibuna-pow.wasm`;
//! - with the `console` feature, the console interface (`sibuna-console-ui`), served under
//!   its digest, as `$OUT_DIR/console.wasm`. SID 0007 caps it at 768 KiB; a larger module
//!   fails the build.
//!
//! Both are built by a nested `cargo rustc --target wasm32-unknown-unknown --profile wasm`
//! into the workspace's own target directory, so they land in
//! `target/wasm32-unknown-unknown/wasm/` beside a hand-made build of the same profile. The
//! nested build locks only the `wasm` profile's directories, never the outer build's. The
//! final link gets `--compress-relocations`, which rewrites the padded function indices
//! and data addresses of the LTO object in their shortest form; the linker accepts it
//! because the `wasm` profile keeps no debug information.
//!
//! `SIBUNA_POW_WASM=<path>` and `SIBUNA_CONSOLE_WASM=<path>` embed prebuilt modules
//! instead, for builds without the WebAssembly target or without network access to
//! install it.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The WebAssembly target the modules are built for.
const TARGET: &str = "wasm32-unknown-unknown";
/// The cargo profile of both modules (the workspace's `[profile.wasm]`).
const PROFILE: &str = "wasm";
/// The largest console interface module, in bytes (SID 0007, Budget: 768 KiB).
const CONSOLE_CEILING: usize = 768 * 1024;

/// One embedded module: how to build it and where it goes.
struct Module {
    /// The package that builds it.
    package: &'static str,
    /// The file cargo writes.
    artifact: &'static str,
    /// The file name in `$OUT_DIR`.
    embedded: &'static str,
    /// The environment variable naming a prebuilt module.
    prebuilt: &'static str,
    /// Workspace paths whose change rebuilds it.
    watched: &'static [&'static str],
    /// The largest accepted size in bytes.
    ceiling: usize,
}

const SOLVER: Module = Module {
    package: "sibuna-pow-wasm",
    artifact: "sibuna_pow_wasm.wasm",
    embedded: "sibuna-pow.wasm",
    prebuilt: "SIBUNA_POW_WASM",
    watched: &["cmd/sibuna-pow-wasm", "crates/pow/src", "crates/crypto/src"],
    ceiling: usize::MAX,
};

const CONSOLE: Module = Module {
    package: "sibuna-console-ui",
    artifact: "sibuna_console_ui.wasm",
    embedded: "console.wasm",
    prebuilt: "SIBUNA_CONSOLE_WASM",
    watched: &[
        "cmd/console-ui/src",
        "cmd/console-ui/build.rs",
        "crates/console-protocol/src",
        "crates/html/src",
        "crates/json/src",
        "crates/crypto/src",
    ],
    ceiling: CONSOLE_CEILING,
};

fn main() -> ExitCode {
    println!("cargo:rerun-if-changed=build.rs");
    let Some(out_dir) = env::var_os("OUT_DIR").map(PathBuf::from) else {
        return fail(
            "OUT_DIR MISSING",
            "Cargo did not set OUT_DIR.",
            "Run the build through cargo.",
        );
    };
    if let Err(code) = embed(&SOLVER, &out_dir) {
        return code;
    }
    if env::var_os("CARGO_FEATURE_CONSOLE").is_some()
        && let Err(code) = embed(&CONSOLE, &out_dir)
    {
        return code;
    }
    ExitCode::SUCCESS
}

/// Builds `module` (or takes the prebuilt one), checks it and copies it into `out_dir`.
fn embed(module: &Module, out_dir: &Path) -> Result<(), ExitCode> {
    println!("cargo:rerun-if-env-changed={}", module.prebuilt);
    let source = match env::var_os(module.prebuilt) {
        Some(path) if !path.is_empty() => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            path
        }
        _ => build(module, out_dir)?,
    };
    let bytes = fs::read(&source).map_err(|error| {
        let message = format!("The module {} cannot be read: {error}.", source.display());
        let hint = format!("Check the path in {}.", module.prebuilt);
        fail("WASM MODULE UNREADABLE", &message, &hint)
    })?;
    if !bytes.starts_with(b"\0asm") {
        let message = format!("{} is not a WebAssembly module.", source.display());
        let hint = format!("Point {} at a .wasm file.", module.prebuilt);
        return Err(fail("WASM MODULE INVALID", &message, &hint));
    }
    if bytes.len() > module.ceiling {
        let message = format!(
            "{} is {} bytes; SID 0007 allows at most {} bytes for {}.",
            source.display(),
            bytes.len(),
            module.ceiling,
            module.package
        );
        let hint = "Shrink the interface (see the size notes in cmd/console-ui) before \
                    embedding it.";
        return Err(fail("WASM MODULE TOO LARGE", &message, hint));
    }
    let destination = out_dir.join(module.embedded);
    fs::write(&destination, &bytes).map_err(|error| {
        let message = format!("Writing {} failed: {error}.", destination.display());
        fail("WASM MODULE NOT WRITTEN", &message, "Check the build directory.")
    })
}

/// Runs the nested build of `module` and returns the path of the module it produced.
fn build(module: &Module, out_dir: &Path) -> Result<PathBuf, ExitCode> {
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from) else {
        return Err(fail("MANIFEST DIR MISSING", "Cargo did not set it.", "Build with cargo."));
    };
    let workspace = manifest_dir.join("..").join("..");
    for watched in module.watched.iter().chain(&["Cargo.toml"]) {
        println!("cargo:rerun-if-changed={}", workspace.join(watched).display());
    }
    let target_dir = target_root(out_dir).unwrap_or_else(|| workspace.join("target"));
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .current_dir(&workspace)
        .args(["rustc", "--quiet", "--lib", "-p", module.package])
        .args(["--target", TARGET, "--profile", PROFILE])
        .args(["--", "-C", "link-arg=--compress-relocations"])
        .env("CARGO_TARGET_DIR", &target_dir);
    // The outer build's flags and jobserver belong to the host target, not to this one.
    for variable in [
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_MAKEFLAGS",
        "MAKEFLAGS",
        "MFLAGS",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(variable);
    }
    let output = command.output().map_err(|error| {
        let message = format!("cargo could not be started to build {}: {error}.", module.package);
        fail("WASM MODULE BUILD", &message, "Check that cargo is on PATH.")
    })?;
    if !output.status.success() {
        return Err(explain_failure(module, &String::from_utf8_lossy(&output.stderr)));
    }
    Ok(target_dir.join(TARGET).join(PROFILE).join(module.artifact))
}

/// The workspace target directory: the nearest ancestor of `OUT_DIR` that Cargo marked
/// with `CACHEDIR.TAG`.
fn target_root(out_dir: &Path) -> Option<PathBuf> {
    out_dir.ancestors().find(|dir| dir.join("CACHEDIR.TAG").is_file()).map(Path::to_path_buf)
}

fn explain_failure(module: &Module, stderr: &str) -> ExitCode {
    let missing = stderr.contains("target may not be installed")
        || stderr.contains("can't find crate for `core`")
        || stderr.contains("can't find crate for `std`");
    if missing {
        let hint = format!(
            "Run `rustup target add {TARGET}`, or set {} to a prebuilt module.",
            module.prebuilt
        );
        return fail(
            "WASM TARGET MISSING",
            "The daemon embeds WebAssembly modules built for wasm32-unknown-unknown, but this \
             toolchain has no standard library for that target.",
            &hint,
        );
    }
    let mut message = format!("Building {} for the browser failed:\n\n", module.package);
    for line in stderr.lines().take(40) {
        let _ = writeln!(message, "    {line}");
    }
    let hint = format!("Fix the error above, or set {} to a prebuilt module.", module.prebuilt);
    fail("WASM MODULE BUILD", message.trim_end(), &hint)
}

/// Prints an Elm-style diagnostic for Cargo to show and fails the build script.
fn fail(title: &str, message: &str, hint: &str) -> ExitCode {
    let location = "cmd/sibuna/build.rs";
    let dashes = 80usize.saturating_sub(title.len() + location.len() + 5).max(2);
    eprintln!("-- {title} {} {location}\n\n{message}\n\nHint: {hint}\n", "-".repeat(dashes));
    ExitCode::FAILURE
}
