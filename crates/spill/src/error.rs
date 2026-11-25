//! Why a cache cannot be opened, in a form an operator can act on.

use std::fmt;
use std::io;
use std::path::Path;

use crate::format::{MAX_SIZE, MIN_SIZE};

/// The width of the title rule, as in the other diagnostics of Sibuna.
const RULE_WIDTH: usize = 76;

/// A failure to open a cache: a code, a title, an explanation and a hint.
///
/// `Display` renders the title rule, the message and the hint on lines of their own. A
/// caller that renders diagnostics itself reads the fields.
#[derive(Debug)]
pub struct Error {
    /// The stable code, such as `SPILL002`.
    pub code: &'static str,
    /// A short title in lower case.
    pub title: &'static str,
    /// What went wrong, in one or two sentences.
    pub message: String,
    /// How to repair it.
    pub hint: String,
    /// The error of the system, when there was one.
    pub source: Option<io::Error>,
}

impl Error {
    /// `SPILL001`: the size is outside the bounds.
    pub(crate) fn size(size: u64) -> Self {
        Self {
            code: "SPILL001",
            title: "spill cache size out of range",
            message: format!("A spill cache cannot have {size} bytes."),
            hint: format!("Give a size from {MIN_SIZE} bytes (64 KiB) to {MAX_SIZE} (64 GiB)."),
            source: None,
        }
    }

    /// `SPILL002`: the file at the path is not a cache, and we do not overwrite it.
    pub(crate) fn foreign(path: &Path) -> Self {
        Self {
            code: "SPILL002",
            title: "not a spill cache",
            message: format!(
                "The file {} exists and is not a spill cache. It was left as it is.",
                path.display()
            ),
            hint: "Name another path for the cache, or remove the file if it is not needed."
                .to_owned(),
            source: None,
        }
    }

    /// `SPILL003`: another process holds the lock of the file.
    pub(crate) fn busy(path: &Path) -> Self {
        Self {
            code: "SPILL003",
            title: "spill cache in use",
            message: format!("Another process holds the spill cache {}.", path.display()),
            hint: "Give each daemon a file of its own, or wait until the other process ends."
                .to_owned(),
            source: None,
        }
    }

    /// `SPILL004`: the system refused an operation on the file.
    pub(crate) fn io(path: &Path, doing: &str, source: io::Error) -> Self {
        Self {
            code: "SPILL004",
            title: "spill cache unavailable",
            message: format!("Cannot {doing} the spill cache {}: {source}.", path.display()),
            hint: "Check that the directory exists, that the daemon may write it and that \
                   the disk has room for the whole size."
                .to_owned(),
            source: Some(source),
        }
    }

    /// Whether another process holds the file. A caller may then run without the cache.
    pub fn is_busy(&self) -> bool {
        self.code == "SPILL003"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let title = format!("{} ({})", self.title.to_ascii_uppercase(), self.code);
        let dashes = RULE_WIDTH.saturating_sub(title.len() + 4);
        writeln!(out, "-- {title} {}", "-".repeat(dashes))?;
        writeln!(out, "\n{}\n", self.message)?;
        writeln!(out, "Hint: {}", self.hint)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_renders_a_rule_a_message_and_a_hint() {
        let text = Error::foreign(Path::new("/var/lib/x")).to_string();
        let mut lines = text.lines();
        let rule = lines.next().unwrap_or_default();
        assert!(rule.starts_with("-- NOT A SPILL CACHE (SPILL002) ---"), "{rule}");
        assert_eq!(rule.len(), 76);
        assert!(text.contains("\n\nThe file /var/lib/x exists and is not a spill cache."));
        assert!(text.contains("\n\nHint: Name another path"));
        assert!(Error::busy(Path::new("x")).is_busy());
        assert!(!Error::size(1).is_busy());
    }
}
