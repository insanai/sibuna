//! A small command-line reader: `--name value` options, taken by name.

use std::str::FromStr;

use crate::error::{Error, Result};

/// The arguments of one command that have not been taken yet.
#[derive(Debug)]
pub struct Args {
    items: Vec<String>,
}

impl Args {
    /// Returns the arguments `items`, in order.
    pub fn new(items: Vec<String>) -> Args {
        Args { items }
    }

    /// Returns the arguments that have not been taken yet, in order.
    pub fn remaining(&self) -> &[String] {
        &self.items
    }

    /// Takes the last `name value` or `name=value` pair and returns its value.
    ///
    /// # Errors
    ///
    /// Fails when `name` is the last argument and has no value.
    pub fn value(&mut self, name: &str) -> Result<Option<String>> {
        Ok(self.values(name)?.pop())
    }

    /// Takes every `name value` or `name=value` pair, in order, and returns the values.
    ///
    /// # Errors
    ///
    /// Fails when `name` is the last argument and has no value.
    pub fn values(&mut self, name: &str) -> Result<Vec<String>> {
        let mut found = Vec::new();
        let mut index = 0;
        while index < self.items.len() {
            let item = &self.items[index];
            if item == name {
                if index + 1 >= self.items.len() {
                    return Err(Error::new("MISSING VALUE", format!("`{name}` needs a value."))
                        .hint(format!("Write `{name} <value>`.")));
                }
                found.push(self.items.remove(index + 1));
                self.items.remove(index);
            } else if let Some(value) = item.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
                found.push(value.to_owned());
                self.items.remove(index);
            } else {
                index += 1;
            }
        }
        Ok(found)
    }

    /// Takes option `name` and parses it, or returns `default` when it is absent.
    ///
    /// # Errors
    ///
    /// Fails when the value does not parse as a `T`.
    pub fn parsed<T: FromStr>(&mut self, name: &str, default: T) -> Result<T> {
        match self.value(name)? {
            None => Ok(default),
            Some(text) => text.parse().map_err(|_| {
                Error::new("INVALID VALUE", format!("`{name}` cannot be `{text}`."))
                    .hint("Run `cargo xtask bench help` for the expected values.")
            }),
        }
    }

    /// Checks that every argument was taken.
    ///
    /// # Errors
    ///
    /// Fails with the first argument nobody took, suggesting one of `known` when it is close.
    pub fn finish(self, known: &[&str]) -> Result<()> {
        let Some(first) = self.items.first() else {
            return Ok(());
        };
        let mut hint = String::from("Run `cargo xtask bench help` to list the options.");
        let name = first.split('=').next().unwrap_or(first);
        if let Some(close) = known.iter().find(|k| edit_distance(name, k) <= 2) {
            hint = format!("Did you mean `{close}`? {hint}");
        }
        Err(Error::new("UNKNOWN ARGUMENT", format!("No option is named `{first}`.")).hint(hint))
    }
}

/// The Levenshtein distance between `a` and `b`, counted in characters.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0; b.len() + 1];
    for (i, a_char) in a.chars().enumerate() {
        current[0] = i + 1;
        for (j, &b_char) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(a_char != b_char);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Args {
        Args::new(text.split_whitespace().map(str::to_owned).collect())
    }

    #[test]
    fn takes_values_in_both_spellings() {
        let mut a = args("--seconds 5 --rust=/bin/s");
        assert_eq!(a.value("--rust").unwrap().as_deref(), Some("/bin/s"));
        assert_eq!(a.parsed("--seconds", 1u64).unwrap(), 5);
        assert_eq!(a.parsed("--threads", 2u64).unwrap(), 2);
        assert!(a.finish(&[]).is_ok());
        let mut a = args("-H a:1 -H=b:2 -H c:3");
        assert_eq!(a.values("-H").unwrap(), ["a:1", "b:2", "c:3"]);
    }

    #[test]
    fn reports_missing_and_invalid_values() {
        assert!(args("--seconds").value("--seconds").is_err());
        assert!(args("--seconds five").parsed("--seconds", 1u64).is_err());
    }

    #[test]
    fn suggests_a_close_option() {
        let error = args("--secnds 3").finish(&["--seconds"]).unwrap_err();
        assert!(error.hint.unwrap().contains("Did you mean `--seconds`?"));
    }
}
