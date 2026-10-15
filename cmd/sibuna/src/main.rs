//! The `sibuna` daemon binary; everything lives in the library (`sibuna::cli::run`).

use std::process::ExitCode;

fn main() -> ExitCode {
    // Arguments that are not UTF-8 cannot name an option; they are passed on lossily so the
    // parser reports them as unknown.
    let args: Vec<String> =
        std::env::args_os().skip(1).map(|arg| arg.to_string_lossy().into_owned()).collect();
    let secret = std::env::var("SIBUNA_SECRET").ok();
    sibuna::cli::run(&args, secret.as_deref())
}
