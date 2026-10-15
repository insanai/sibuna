//! Command-line flags: `--name value` pairs and boolean switches.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// One flag a command accepts.
#[derive(Clone, Copy, Debug)]
pub struct Flag {
    /// The flag with its dashes, such as `--url`.
    pub name: &'static str,
    /// True when the flag takes a value; false for a switch.
    pub takes_value: bool,
}

/// A command-line mistake, printed with a hint.
#[derive(Debug)]
pub struct UsageError {
    message: String,
    hint: String,
}

impl UsageError {
    /// A usage error with a message and a hint.
    pub fn new(message: impl Into<String>, hint: impl Into<String>) -> UsageError {
        UsageError { message: message.into(), hint: hint.into() }
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "-- USAGE ERROR {}\n\n{}\n\nHint: {}", "-".repeat(50), self.message, self.hint)
    }
}

/// The flags given to one command.
#[derive(Debug, Default)]
pub struct Flags {
    values: Vec<(&'static str, String)>,
    switches: Vec<&'static str>,
}

impl Flags {
    /// Parses `arguments` against the flags a command `accepts`.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for an unknown flag, a missing value, a repeated flag, or an
    /// argument that is not UTF-8.
    pub fn parse(arguments: &[OsString], accepts: &[Flag]) -> Result<Flags, UsageError> {
        let mut flags = Flags::default();
        let mut iter = arguments.iter();
        while let Some(argument) = iter.next() {
            let text = argument.to_str().ok_or_else(|| {
                UsageError::new("An argument is not valid UTF-8.", "Use UTF-8 arguments.")
            })?;
            let Some(flag) = accepts.iter().find(|flag| flag.name == text) else {
                let names: Vec<&str> = accepts.iter().map(|flag| flag.name).collect();
                return Err(UsageError::new(
                    format!("This command has no option `{text}`."),
                    format!("The options are {}.", names.join(", ")),
                ));
            };
            if flags.values.iter().any(|(name, _)| *name == flag.name)
                || flags.switches.contains(&flag.name)
            {
                return Err(UsageError::new(
                    format!("`{text}` is given twice."),
                    "Give each option once.",
                ));
            }
            if !flag.takes_value {
                flags.switches.push(flag.name);
                continue;
            }
            let value = iter.next().and_then(|value| value.to_str()).ok_or_else(|| {
                UsageError::new(
                    format!("`{text}` needs a value."),
                    format!("Write `{text} <value>`."),
                )
            })?;
            flags.values.push((flag.name, value.to_owned()));
        }
        Ok(flags)
    }

    /// The value of `name`, if given.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.iter().find(|(flag, _)| *flag == name).map(|(_, value)| value.as_str())
    }

    /// The value of `name`, which must be given.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] naming the flag when it is missing.
    pub fn required(&self, name: &str) -> Result<&str, UsageError> {
        self.value(name).ok_or_else(|| {
            UsageError::new(format!("`{name}` is required."), format!("Add `{name} <value>`."))
        })
    }

    /// The path given for `name`, which must be given.
    ///
    /// # Errors
    ///
    /// As [`Flags::required`].
    pub fn required_path(&self, name: &str) -> Result<PathBuf, UsageError> {
        self.required(name).map(PathBuf::from)
    }

    /// The number given for `name`, or `default` when absent.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] when the value is not a whole number from 1 to `max`.
    pub fn number(&self, name: &str, default: u32, max: u32) -> Result<u32, UsageError> {
        let Some(text) = self.value(name) else { return Ok(default) };
        text.parse::<u32>().ok().filter(|&n| (1..=max).contains(&n)).ok_or_else(|| {
            UsageError::new(
                format!("`{name} {text}` is not a whole number from 1 to {max}."),
                format!("Write, for example, `{name} {default}`."),
            )
        })
    }

    /// The seconds given for `name` as a duration, or `default` seconds when absent.
    ///
    /// # Errors
    ///
    /// As [`Flags::number`], with a maximum of one hour.
    pub fn seconds(&self, name: &str, default: u32) -> Result<Duration, UsageError> {
        self.number(name, default, 3600).map(|seconds| Duration::from_secs(u64::from(seconds)))
    }

    /// True when the switch `name` was given.
    pub fn is_set(&self, name: &str) -> bool {
        self.switches.contains(&name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCEPTS: &[Flag] = &[
        Flag { name: "--url", takes_value: true },
        Flag { name: "--width", takes_value: true },
        Flag { name: "--no-wasm", takes_value: false },
    ];

    fn parse(arguments: &[&str]) -> Result<Flags, UsageError> {
        let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
        Flags::parse(&arguments, ACCEPTS)
    }

    #[test]
    fn reads_values_and_switches() {
        let flags = parse(&["--url", "http://a/", "--no-wasm", "--width", "640"]).unwrap();
        assert_eq!(flags.value("--url"), Some("http://a/"));
        assert!(flags.is_set("--no-wasm"));
        assert_eq!(flags.number("--width", 1280, 10_000).unwrap(), 640);
        assert_eq!(flags.number("--height", 800, 10_000).unwrap(), 800);
        assert!(flags.required("--out").is_err());
    }

    #[test]
    fn refuses_unknown_repeated_and_incomplete_flags() {
        assert!(parse(&["--colour"]).is_err());
        assert!(parse(&["--url", "a", "--url", "b"]).is_err());
        assert!(parse(&["--url"]).is_err());
        let flags = parse(&["--width", "0"]).unwrap();
        assert!(flags.number("--width", 1280, 10_000).is_err());
        let message = parse(&["--colour"]).unwrap_err().to_string();
        assert!(message.contains("Hint: The options are --url, --width, --no-wasm."));
    }
}
