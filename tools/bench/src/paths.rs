//! Where things are: the workspace, the result files and the binaries we measure.

use std::path::{Path, PathBuf};

/// Returns the workspace root. This crate lives at `tools/bench`, two levels below it.
pub fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().nth(2).unwrap_or(manifest).to_path_buf()
}

/// Returns the default directory for result files, `benchmarks/results`.
pub fn results_dir() -> PathBuf {
    workspace_root().join("benchmarks").join("results")
}

/// Returns the directory of this program, the cargo profile directory it was built into.
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(Path::to_path_buf)
}

/// Returns the default Rust daemon: `sibuna` beside this program, which `cargo xtask bench`
/// builds into the same release directory.
pub fn rust_daemon() -> PathBuf {
    exe_dir().unwrap_or_default().join("sibuna")
}

/// Returns the browser solver module in the same target directory, if one was built: the
/// daemon's build script builds it with the `wasm` profile.
pub fn wasm_solver() -> Option<PathBuf> {
    let target = exe_dir()?.parent()?.to_path_buf();
    let path = target.join("wasm32-unknown-unknown/wasm/sibuna_pow_wasm.wasm");
    path.exists().then_some(path)
}
