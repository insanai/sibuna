//! Owned text with a byte capacity, the Rust form of Zig's fixed `Bytes(N)` buffers.
//!
//! Zig kept every bounded string in a fixed array so that values could cross the storage
//! mailbox by copy without an allocator. Rust moves owned values instead, so the bytes live
//! in a `String` and the capacity becomes a checked invariant: no `Text<N>` ever holds more
//! than `N` bytes. The unused tail that Zig had to zero and never serialize does not exist.

use std::fmt;

/// A value longer than the capacity of the field it was meant for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TooLarge {
    /// The length offered, in bytes.
    pub length: usize,
    /// The largest length the field accepts, in bytes.
    pub capacity: usize,
}

impl fmt::Display for TooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes exceed the capacity of {} bytes", self.length, self.capacity)
    }
}

impl std::error::Error for TooLarge {}

/// Owned UTF-8 text of at most `N` bytes.
///
/// ```
/// use sibuna_console_protocol::Text;
///
/// let mut name = Text::<8>::new("rule").unwrap();
/// assert!(name.set("much too long").is_err());
/// assert_eq!(name.as_str(), "rule");
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text<const N: usize>(String);

impl<const N: usize> Text<N> {
    /// The largest length, in bytes.
    pub const CAPACITY: usize = N;

    /// Copies `text` into a new value.
    ///
    /// # Errors
    ///
    /// [`TooLarge`] if `text` is longer than `N` bytes.
    pub fn new(text: &str) -> Result<Text<N>, TooLarge> {
        check(text.len(), N)?;
        Ok(Text(text.to_owned()))
    }

    /// Takes ownership of `text` without copying it.
    ///
    /// # Errors
    ///
    /// [`TooLarge`] if `text` is longer than `N` bytes; the string is dropped.
    pub fn from_string(text: String) -> Result<Text<N>, TooLarge> {
        check(text.len(), N)?;
        Ok(Text(text))
    }

    /// Replaces the value with `text`, reusing the allocation.
    ///
    /// # Errors
    ///
    /// [`TooLarge`] if `text` is longer than `N` bytes; the previous value is kept.
    pub fn set(&mut self, text: &str) -> Result<(), TooLarge> {
        check(text.len(), N)?;
        self.0.clear();
        self.0.push_str(text);
        Ok(())
    }

    /// Returns the text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the text's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true for the empty text.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

fn check(length: usize, capacity: usize) -> Result<(), TooLarge> {
    if length > capacity { Err(TooLarge { length, capacity }) } else { Ok(()) }
}

impl<const N: usize> fmt::Display for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<const N: usize> AsRef<str> for Text<N> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> PartialEq<str> for Text<N> {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl<const N: usize> PartialEq<&str> for Text<N> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl<const N: usize> TryFrom<&str> for Text<N> {
    type Error = TooLarge;

    fn try_from(text: &str) -> Result<Text<N>, TooLarge> {
        Text::new(text)
    }
}

impl<const N: usize> TryFrom<String> for Text<N> {
    type Error = TooLarge;

    fn try_from(text: String) -> Result<Text<N>, TooLarge> {
        Text::from_string(text)
    }
}

/// Checks that `bytes` holds at most `capacity` bytes, for byte payloads kept in a `Vec`.
///
/// # Errors
///
/// [`TooLarge`] if it holds more.
pub fn check_bytes(bytes: &[u8], capacity: usize) -> Result<(), TooLarge> {
    check(bytes.len(), capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of root.zig "owned payload boundaries ..." (first half) and "owned byte updates
    // preserve oversize state ...". Overlapping updates and tail erasure were properties of
    // the fixed Zig buffer; a `String` has no unused tail, and the borrow checker forbids
    // passing a slice of a value to its own `set`, so the caller copies first.
    #[test]
    fn owned_values_preserve_oversize_state() {
        let mut source = String::from("abc");
        let owned = Text::<3>::new(&source).unwrap();
        source.replace_range(0..1, "z");
        assert_eq!(owned.as_str(), "abc");
        assert_eq!(Text::<2>::new(&source), Err(TooLarge { length: 3, capacity: 2 }));

        let mut buffer = Text::<16>::new("private value").unwrap();
        let tail = buffer.as_str()[8..].to_owned();
        buffer.set(&tail).unwrap();
        assert_eq!(buffer, "value");
        assert!(buffer.set(&"x".repeat(17)).is_err());
        assert_eq!(buffer, "value");
        buffer.set("").unwrap();
        assert!(buffer.is_empty());
        assert_eq!(Text::<16>::CAPACITY, 16);
    }

    #[test]
    fn conversions_check_the_capacity() {
        assert!(Text::<4>::try_from("four").is_ok());
        assert!(Text::<4>::try_from(String::from("fives")).is_err());
        assert_eq!(check_bytes(&[0; 5], 4), Err(TooLarge { length: 5, capacity: 4 }));
        assert_eq!(
            TooLarge { length: 5, capacity: 4 }.to_string(),
            "5 bytes exceed the capacity of 4 bytes"
        );
    }
}
