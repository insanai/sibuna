//! Password verification and the sealing of second-factor seeds (unit U2).
//!
//! - [`password`]: the one Argon2id verifier with its workspace, allocated once at start
//!   and wiped after each use (decision 9); a second verification while one runs is
//!   refused with 429 `CONSOLE003`.
//! - [`secrets`]: TOTP seed and notification secret envelopes (XChaCha20-Poly1305 bound to
//!   the envelope version, key id and owner) and recovery-code digests (Zig's
//!   `auth_secrets.zig`).

pub mod password;
pub mod secrets;
