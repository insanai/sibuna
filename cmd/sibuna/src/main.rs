//! The `sibuna` daemon binary; everything lives in the library (`sibuna::cli::run`).

use std::process::ExitCode;

fn main() -> ExitCode {
    // Arguments that are not UTF-8 cannot name an option; they are passed on lossily so the
    // parser reports them as unknown.
    let args: Vec<String> =
        std::env::args_os().skip(1).map(|arg| arg.to_string_lossy().into_owned()).collect();
    // A secret that is not UTF-8 is passed on lossily too, so it is refused as malformed
    // instead of being taken for an unset variable.
    let secret =
        std::env::var_os("SIBUNA_SECRET").map(|secret| secret.to_string_lossy().into_owned());
    sibuna::cli::run(&args, secret.as_deref())
}
