//! Builds the browser solver (`sibuna-pow-wasm`) for `wasm32-unknown-unknown` and copies it to
//! `$OUT_DIR/sibuna-pow.wasm`, where the daemon embeds it with `include_bytes!` and serves it
//! as `/__sibuna/wasm/sibuna-pow.wasm`.
//!
//! The solver is built by a nested `cargo build` with a target directory of its own
//! (`wasm-embed` under the workspace's target directory), so it never waits on the lock of
//! the outer build. `SIBUNA_POW_WASM=<path>` embeds a prebuilt module instead, for builds
//! without the WebAssembly target or without network access to install it.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The environment variable that names a prebuilt solver module.
const OVERRIDE: &str = "SIBUNA_POW_WASM";
/// The WebAssembly target the solver is built for.
const TARGET: &str = "wasm32-unknown-unknown";

fn main() -> ExitCode {
    println!("cargo:rerun-if-env-changed={OVERRIDE}");
    println!("cargo:rerun-if-changed=build.rs");
    let Some(out_dir) = env::var_os("OUT_DIR").map(PathBuf::from) else {
        return fail(
            "OUT_DIR MISSING",
            "Cargo did not set OUT_DIR.",
            "Run the build through cargo.",
        );
    };
    let destination = out_dir.join("sibuna-pow.wasm");
    let source = match env::var_os(OVERRIDE) {
        Some(path) if !path.is_empty() => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            path
        }
        _ => match build_solver(&out_dir) {
            Ok(path) => path,
            Err(code) => return code,
        },
    };
    let module = match fs::read(&source) {
        Ok(bytes) => bytes,
        Err(error) => {
            let message =
                format!("The solver module {} cannot be read: {error}.", source.display());
            return fail("WASM SOLVER UNREADABLE", &message, "Check the path in SIBUNA_POW_WASM.");
        }
    };
    if !module.starts_with(b"\0asm") {
        let message = format!("{} is not a WebAssembly module.", source.display());
        return fail("WASM SOLVER INVALID", &message, "Point SIBUNA_POW_WASM at a .wasm file.");
    }
    if let Err(error) = fs::write(&destination, &module) {
        let message = format!("Writing {} failed: {error}.", destination.display());
        return fail("WASM SOLVER NOT WRITTEN", &message, "Check the build directory.");
    }
    ExitCode::SUCCESS
}

/// Runs the nested build and returns the path of the module it produced.
fn build_solver(out_dir: &Path) -> Result<PathBuf, ExitCode> {
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from) else {
        return Err(fail("MANIFEST DIR MISSING", "Cargo did not set it.", "Build with cargo."));
    };
    let workspace = manifest_dir.join("..").join("..");
    for watched in ["cmd/sibuna-pow-wasm", "crates/pow/src", "crates/crypto/src", "Cargo.toml"] {
        println!("cargo:rerun-if-changed={}", workspace.join(watched).display());
    }
    let target_dir = target_root(out_dir).unwrap_or_else(|| workspace.join("target"));
    let embed_dir = target_dir.join("wasm-embed");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .current_dir(&workspace)
        .args(["build", "-p", "sibuna-pow-wasm", "--target", TARGET, "--release", "--quiet"])
        .env("CARGO_TARGET_DIR", &embed_dir);
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
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            let message = format!("cargo could not be started for the solver build: {error}.");
            return Err(fail("WASM SOLVER BUILD", &message, "Check that cargo is on PATH."));
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(explain_failure(&stderr));
    }
    Ok(embed_dir.join(TARGET).join("release").join("sibuna_pow_wasm.wasm"))
}

/// The workspace target directory: the nearest ancestor of `OUT_DIR` that Cargo marked
/// with `CACHEDIR.TAG`.
fn target_root(out_dir: &Path) -> Option<PathBuf> {
    out_dir.ancestors().find(|dir| dir.join("CACHEDIR.TAG").is_file()).map(Path::to_path_buf)
}

fn explain_failure(stderr: &str) -> ExitCode {
    let missing = stderr.contains("target may not be installed")
        || stderr.contains("can't find crate for `core`")
        || stderr.contains("can't find crate for `std`");
    if missing {
        return fail(
            "WASM TARGET MISSING",
            "The daemon embeds the browser solver, built for wasm32-unknown-unknown, but this \
             toolchain has no standard library for that target.",
            "Run `rustup target add wasm32-unknown-unknown`, or set SIBUNA_POW_WASM to a \
             prebuilt sibuna-pow.wasm.",
        );
    }
    let mut message = String::from("Building sibuna-pow-wasm for the browser failed:\n\n");
    for line in stderr.lines().take(40) {
        let _ = writeln!(message, "    {line}");
    }
    fail(
        "WASM SOLVER BUILD",
        message.trim_end(),
        "Fix the error above, or set SIBUNA_POW_WASM to a prebuilt sibuna-pow.wasm.",
    )
}

/// Prints an Elm-style diagnostic for Cargo to show and fails the build script.
fn fail(title: &str, message: &str, hint: &str) -> ExitCode {
    let location = "cmd/sibuna/build.rs";
    let dashes = 80usize.saturating_sub(title.len() + location.len() + 5).max(2);
    eprintln!("-- {title} {} {location}\n\n{message}\n\nHint: {hint}\n", "-".repeat(dashes));
    ExitCode::FAILURE
}
