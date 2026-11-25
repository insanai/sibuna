//! The failures of automatic HTTPS, each with a code, a title, an explanation and a hint.

use std::fmt;

/// Why an order, a key or a file of the store failed.
///
/// The fields are those of a Sibuna diagnostic. `message` and `hint` hold printable text
/// only: what the authority sent is filtered before it gets here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// `ACME001` to `ACME014`.
    pub code: &'static str,
    /// The title in upper case, for example `VALIDATION FAILED`.
    pub title: &'static str,
    /// What happened.
    pub message: String,
    /// How to repair it.
    pub hint: String,
    /// The seconds the authority asked us to wait, if it did.
    pub retry_after: Option<u64>,
}

impl Error {
    fn new(code: &'static str, title: &'static str, message: String, hint: &str) -> Self {
        Self { code, title, message, hint: hint.to_owned(), retry_after: None }
    }

    /// `ACME001`: the store cannot be read or written.
    pub fn storage(message: impl Into<String>) -> Self {
        Self::new(
            "ACME001",
            "STORAGE NOT WRITABLE",
            message.into(),
            "Set `global.acme.storage` to a directory that the daemon's user owns. Under \
             systemd, `StateDirectory=sibuna` provides /var/lib/sibuna.",
        )
    }

    /// `ACME002`: the authority could not be reached.
    pub fn unreachable(message: impl Into<String>) -> Self {
        Self::new(
            "ACME002",
            "AUTHORITY UNREACHABLE",
            message.into(),
            "Check `global.acme.directory` and the route to it. A private authority needs \
             its root certificate in `global.acme.ca_file`.",
        )
    }

    /// `ACME003`: the authority answered with a problem.
    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(
            "ACME003",
            "AUTHORITY REFUSED",
            message.into(),
            "Read the reason of the authority above. The daemon tries again later.",
        )
    }

    /// `ACME004`: the authority limits our requests.
    pub fn rate_limited(message: impl Into<String>, retry_after: Option<u64>) -> Self {
        let mut error = Self::new(
            "ACME004",
            "RATE LIMITED",
            message.into(),
            "The daemon waits and tries again. For tests, set `global.acme.directory` to \
             \"letsencrypt-staging\".",
        );
        error.retry_after = retry_after;
        error
    }

    /// `ACME005`: the authority could not validate the name.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(
            "ACME005",
            "VALIDATION FAILED",
            message.into(),
            "Point the DNS record of the name at this node, and let the authority reach \
             port 80 (HTTP-01) or port 443 (TLS-ALPN-01) from the Internet. With DNS-01, \
             check that the provider writes the TXT record into the public zone.",
        )
    }

    /// `ACME006`: a response broke the protocol or a bound.
    pub fn unexpected(message: impl Into<String>) -> Self {
        Self::new(
            "ACME006",
            "UNEXPECTED ANSWER",
            message.into(),
            "Check that `global.acme.directory` is the directory URL of an ACME authority.",
        )
    }

    /// `ACME008`: the issued certificate cannot be served.
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::new(
            "ACME008",
            "CERTIFICATE REJECTED",
            message.into(),
            "Check the clock of this node. The daemon orders the certificate again later.",
        )
    }
}

impl Error {
    /// `ACME009`: the DNS provider could not write or remove the record.
    pub fn provider(message: impl Into<String>) -> Self {
        Self::new(
            "ACME009",
            "DNS PROVIDER FAILED",
            message.into(),
            "Run the hook by hand with the same arguments. With `rfc2136`, check the TSIG \
             key and the update policy of the zone.",
        )
    }

    /// `ACME010`: the authoritative servers did not show the record in time.
    pub fn not_visible(message: impl Into<String>) -> Self {
        Self::new(
            "ACME010",
            "RECORD NOT VISIBLE",
            message.into(),
            "Raise `global.acme.dns.timeout`. Set `global.acme.dns.check` to false when \
             this node cannot reach the public servers of the zone.",
        )
    }

    /// `ACME011`: the local authority could not be created, read or used.
    pub fn local(message: impl Into<String>) -> Self {
        Self::new(
            "ACME011",
            "LOCAL AUTHORITY FAILED",
            message.into(),
            "Check the directory `local` under `global.acme.storage`. Remove a damaged \
             `intermediate.pem`; the daemon writes a new one.",
        )
    }
}

impl Error {
    /// `ACME012`: the authority wants an external account binding, or refused ours.
    pub fn binding(message: impl Into<String>) -> Self {
        Self::new(
            "ACME012",
            "ACCOUNT NOT BOUND",
            message.into(),
            "Set `eab: { kid, key_file }` for this authority with the key identifier and \
             the base64url key that the authority gave you. A binding is used once: ask \
             for a new one when the account was created before.",
        )
    }
}

impl Error {
    /// `ACME013`: the OCSP responder did not answer, or its answer cannot be stapled.
    pub fn stapling(message: impl Into<String>) -> Self {
        Self::new(
            "ACME013",
            "NO OCSP RESPONSE",
            message.into(),
            "The certificate is served without a stapled response. The daemon asks the \
             responder again later. Set `global.acme.ocsp` to false to stop asking.",
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.title, self.code, self.message)
    }
}

impl std::error::Error for Error {}

/// Makes text from the authority safe to print: printable ASCII, at most `limit` bytes.
pub(crate) fn printable(text: &str, limit: usize) -> String {
    text.chars()
        .take(limit)
        .map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_has_a_code_a_title_and_a_hint() {
        let all = [
            Error::storage("a"),
            Error::unreachable("a"),
            Error::refused("a"),
            Error::rate_limited("a", Some(7)),
            Error::validation("a"),
            Error::unexpected("a"),
            Error::rejected("a"),
        ];
        let codes: Vec<&str> = all.iter().map(|error| error.code).collect();
        let expected = ["ACME001", "ACME002", "ACME003", "ACME004", "ACME005", "ACME006"];
        assert_eq!(codes[..6], expected);
        assert_eq!(codes[6], "ACME008");
        assert!(all.iter().all(|error| !error.hint.is_empty() && !error.title.is_empty()));
        assert_eq!(all[3].retry_after, Some(7));
        assert_eq!(all[0].to_string(), "STORAGE NOT WRITABLE (ACME001): a");
    }

    #[test]
    fn text_of_the_authority_is_filtered() {
        assert_eq!(printable("ok \u{1b}[31m\nnext", 100), "ok ?[31m?next");
        assert_eq!(printable("abcdef", 3), "abc");
    }
}
