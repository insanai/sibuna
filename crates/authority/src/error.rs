//! What can go wrong, with the code, the title and the hint of each failure.

use std::fmt;

/// A failure of the authority. Each has a code of the table `DBA` (SID 0028).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A source or a document does not evaluate or does not check (`DBA001`).
    Rejected(String),
    /// The head is not the revision that the commit expected (`DBA002`).
    Conflict {
        /// The head that the writer named.
        expected: u64,
        /// The head that the database holds.
        found: u64,
    },
    /// The database cannot be reached, or it refused the statement (`DBA003`).
    Unavailable(String),
    /// Nothing is published yet (`DBA004`).
    Empty,
    /// No revision has this number (`DBA004`).
    Unknown(u64),
    /// The `authority` section, or the file that holds it, is wrong (`DBA005`).
    Settings(String),
    /// A stored revision is not what its row says (`DBA008`).
    Damaged(String),
}

impl Error {
    /// The code of the failure.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Rejected(_) => "DBA001",
            Error::Conflict { .. } => "DBA002",
            Error::Unavailable(_) => "DBA003",
            Error::Empty | Error::Unknown(_) => "DBA004",
            Error::Settings(_) => "DBA005",
            Error::Damaged(_) => "DBA008",
        }
    }

    /// The title of the failure, in capitals.
    pub fn title(&self) -> &'static str {
        match self {
            Error::Rejected(_) => "SOURCE REJECTED",
            Error::Conflict { .. } => "REVISION CONFLICT",
            Error::Unavailable(_) => "DATABASE UNAVAILABLE",
            Error::Empty | Error::Unknown(_) => "NO REVISION",
            Error::Settings(_) => "INVALID AUTHORITY",
            Error::Damaged(_) => "REVISION DAMAGED",
        }
    }

    /// How the operator repairs the failure.
    pub fn hint(&self) -> &'static str {
        match self {
            Error::Rejected(_) => {
                "Correct what the message names. `sibuna authority diff` checks a source \
                 and commits nothing."
            }
            Error::Conflict { .. } => {
                "Somebody committed in between. Run `sibuna authority diff` again, look at \
                 the difference to the new head, and apply with its number after `--expect`."
            }
            Error::Unavailable(_) => {
                "Check that the database runs and that the file or the URL under \
                 `authority` names it. A PostgreSQL URL is `postgres://ROLE:PASSWORD@HOST/DB` \
                 in a file with mode 0600. Running nodes keep the revision that they serve."
            }
            Error::Empty => {
                "Publish a first revision with `sibuna authority apply -c FILE -f SOURCE`."
            }
            Error::Unknown(_) => "List the revisions with `sibuna authority history -c FILE`.",
            Error::Settings(_) => {
                "A node file holds `authority: { sqlite: \"FILE\" }` or \
                 `authority: { postgres_url_file: \"FILE\", node: \"NAME\" }`, and no \
                 `frontends`, `backends` or `http`: the database owns those."
            }
            Error::Damaged(_) => {
                "The tables were changed by hand, or the database lost data. Roll back to \
                 an earlier revision with `sibuna authority rollback`, or apply the source \
                 again."
            }
        }
    }

    /// Whether the database could not be asked at all. A node then keeps what it serves
    /// and connects again later.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Error::Unavailable(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rejected(why) | Error::Settings(why) | Error::Damaged(why) => {
                out.write_str(why)
            }
            Error::Conflict { expected, found } => write!(
                out,
                "the commit expected revision {expected}, and the database is at revision \
                 {found}"
            ),
            Error::Unavailable(why) => write!(out, "the database did not answer: {why}"),
            Error::Empty => out.write_str("the database holds no revision yet"),
            Error::Unknown(number) => write!(out, "there is no revision {number}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_has_a_code_a_title_and_a_hint() {
        let failures = [
            Error::Rejected("x".into()),
            Error::Conflict { expected: 3, found: 4 },
            Error::Unavailable("refused".into()),
            Error::Empty,
            Error::Unknown(9),
            Error::Settings("x".into()),
            Error::Damaged("x".into()),
        ];
        for failure in failures {
            assert!(failure.code().starts_with("DBA"));
            assert!(!failure.title().is_empty());
            assert!(!failure.hint().is_empty());
            assert!(!failure.to_string().is_empty());
        }
        let conflict = Error::Conflict { expected: 3, found: 4 }.to_string();
        assert!(conflict.contains("revision 3") && conflict.contains("revision 4"));
    }
}
