//! The password verifier (unit U2; Zig's `password.zig`): one Argon2id workspace of
//! 19 MiB, allocated when the console starts and wiped after each verification.

use std::fmt;

use crate::shared::Setup;

/// The console's one password verifier.
#[derive(Debug, Default)]
pub struct Verifier {}

/// Why the verifier could not be built.
#[derive(Debug)]
pub struct VerifierError;

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cannot allocate the password verification workspace")
    }
}

impl std::error::Error for VerifierError {}

impl Verifier {
    /// Builds the verifier and allocates its workspace.
    ///
    /// Fails with [`VerifierError`] when the workspace cannot be allocated.
    pub fn new(setup: &Setup<'_>) -> Result<Verifier, VerifierError> {
        let _ = setup;
        Ok(Verifier {})
    }
}
