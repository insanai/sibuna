//! Bounded text that holds a credential.

use std::fmt;

use sibuna_console_protocol::{Text, TooLarge};

/// Owned text of at most `N` bytes that holds a credential: a CSRF token, an
/// authenticator seed or a recovery code.
///
/// Unlike [`Text::set`], [`Secret::set`] never writes into the old allocation: it builds a
/// new value and drops the old one, so a shorter value cannot leave the tail of a longer
/// one behind. In the WebAssembly module every freed block is zeroed (see the crate
/// documentation), which erases the old value. `Debug` never shows the text.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret<const N: usize>(Text<N>);

impl<const N: usize> Secret<N> {
    /// Copies `text` into a new secret.
    ///
    /// # Errors
    ///
    /// [`TooLarge`] if `text` is longer than `N` bytes.
    pub fn new(text: &str) -> Result<Secret<N>, TooLarge> {
        Text::new(text).map(Secret)
    }

    /// Replaces the value with a copy of `text`; the old value is dropped.
    ///
    /// # Errors
    ///
    /// [`TooLarge`] if `text` is longer than `N` bytes; the old value is kept.
    pub fn set(&mut self, text: &str) -> Result<(), TooLarge> {
        *self = Secret::new(text)?;
        Ok(())
    }

    /// Drops the value, leaving the empty text.
    pub fn clear(&mut self) {
        *self = Secret::default();
    }

    /// Returns the text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns the length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true for the empty text.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes)", self.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_refuse_oversized_values_and_never_print() {
        let mut secret = Secret::<4>::new("abcd").unwrap();
        assert!(secret.set("abcde").is_err());
        assert_eq!(secret.as_str(), "abcd");
        assert_eq!(format!("{secret:?}"), "Secret(4 bytes)");
        secret.clear();
        assert!(secret.is_empty());
    }
}
