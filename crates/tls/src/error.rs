//! Why an outbound TLS connection failed, with a plain-language hint for the operator.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// What is wrong with a CA file named by [`crate::Trust::ca_file`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CaFileProblem {
    /// The file could not be opened or read.
    Unreadable,
    /// The path names a directory, a device or another non-regular file.
    NotRegularFile,
    /// The file is empty.
    Empty,
    /// The file is larger than [`crate::MAX_CA_FILE_BYTES`].
    TooLarge,
    /// The PEM text is malformed, or a certificate in it does not parse.
    Malformed,
    /// The file holds no `CERTIFICATE` section.
    NoCertificates,
}

impl CaFileProblem {
    fn describe(self) -> &'static str {
        match self {
            CaFileProblem::Unreadable => "cannot be read",
            CaFileProblem::NotRegularFile => "is not a regular file",
            CaFileProblem::Empty => "is empty",
            CaFileProblem::TooLarge => "is larger than 128 KiB",
            CaFileProblem::Malformed => "is not valid PEM or holds a malformed certificate",
            CaFileProblem::NoCertificates => "holds no certificate",
        }
    }
}

/// Which check the server's certificate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertificateProblem {
    /// The certificate's validity period has ended.
    Expired,
    /// The certificate's validity period has not begun.
    NotYetValid,
    /// No trusted root issued the certificate chain.
    UnknownIssuer,
    /// The certificate does not name the host we connected to.
    NameMismatch,
    /// Any other certificate failure (bad signature, bad encoding, wrong purpose, ...).
    Other,
}

/// Why trust could not be loaded or a connection could not be made.
///
/// [`fmt::Display`] gives one line naming the failure and, where there is one, the rustls
/// error category. [`TlsError::hint`] says what an operator can do about it.
#[derive(Debug)]
pub enum TlsError {
    /// [`crate::Trust`] names no trust anchors: no system roots and no CA file.
    NoTrustAnchors,
    /// The system trust store yielded no usable certificate; the text is the loader's
    /// first complaint, if it had one.
    SystemRoots(String),
    /// The operator's CA file is unusable.
    CaFile {
        /// The path as configured.
        path: PathBuf,
        /// What is wrong with it.
        problem: CaFileProblem,
    },
    /// The host is neither a DNS name nor an IP address literal.
    InvalidServerName(String),
    /// Plain HTTP was asked for a host that is not a literal loopback address; nothing was
    /// connected.
    PlaintextRefused(String),
    /// The host name did not resolve to any address.
    Unresolved(String),
    /// The TCP connection could not be made.
    Connect(io::Error),
    /// The deadline passed before the TCP connection was made.
    ConnectTimeout,
    /// The deadline passed during the TLS handshake.
    HandshakeTimeout,
    /// The server closed the connection during the handshake.
    Closed,
    /// Reading or writing the socket failed during the handshake.
    Io(io::Error),
    /// The server's certificate was refused.
    Certificate {
        /// Which check failed.
        problem: CertificateProblem,
        /// The rustls error, for logs.
        source: rustls::Error,
    },
    /// The handshake failed for a reason other than the certificate: an alert from the
    /// server, no common protocol version or cipher suite, or a protocol violation.
    Handshake(rustls::Error),
}

impl TlsError {
    /// Classifies a rustls error from the handshake.
    pub(crate) fn from_rustls(error: rustls::Error) -> TlsError {
        use rustls::CertificateError as C;
        let rustls::Error::InvalidCertificate(certificate) = &error else {
            return TlsError::Handshake(error);
        };
        let problem = match certificate {
            C::Expired | C::ExpiredContext { .. } => CertificateProblem::Expired,
            C::NotValidYet | C::NotValidYetContext { .. } => CertificateProblem::NotYetValid,
            C::UnknownIssuer => CertificateProblem::UnknownIssuer,
            C::NotValidForName | C::NotValidForNameContext { .. } => {
                CertificateProblem::NameMismatch
            }
            _ => CertificateProblem::Other,
        };
        TlsError::Certificate { problem, source: error }
    }

    /// A short title for an error report, in upper case like the daemon's diagnostics.
    pub fn title(&self) -> &'static str {
        match self {
            TlsError::NoTrustAnchors | TlsError::SystemRoots(_) => "NO TRUST ANCHORS",
            TlsError::CaFile { .. } => "UNUSABLE CA FILE",
            TlsError::InvalidServerName(_) => "INVALID SERVER NAME",
            TlsError::PlaintextRefused(_) => "PLAINTEXT REFUSED",
            TlsError::Unresolved(_) => "HOST UNRESOLVED",
            TlsError::Connect(_) | TlsError::Closed | TlsError::Io(_) => "CONNECTION FAILED",
            TlsError::ConnectTimeout | TlsError::HandshakeTimeout => "TLS DEADLINE",
            TlsError::Certificate { problem, .. } => match problem {
                CertificateProblem::Expired => "CERTIFICATE EXPIRED",
                CertificateProblem::NotYetValid => "CERTIFICATE NOT YET VALID",
                CertificateProblem::UnknownIssuer => "UNKNOWN CERTIFICATE ISSUER",
                CertificateProblem::NameMismatch => "CERTIFICATE NAME MISMATCH",
                CertificateProblem::Other => "CERTIFICATE REFUSED",
            },
            TlsError::Handshake(_) => "TLS HANDSHAKE FAILED",
        }
    }

    /// A plain-language suggestion for the operator.
    pub fn hint(&self) -> &'static str {
        match self {
            TlsError::NoTrustAnchors => {
                "Trust the system roots, or name a PEM file of CA certificates."
            }
            TlsError::SystemRoots(_) => {
                "Install the system CA bundle (for example the ca-certificates package), or \
                 name a PEM file of CA certificates."
            }
            TlsError::CaFile { .. } => {
                "Point the CA file option at a readable PEM file of at most 128 KiB holding \
                 at least one CERTIFICATE section."
            }
            TlsError::InvalidServerName(_) => "Use a DNS name or an IP address literal.",
            TlsError::PlaintextRefused(_) => {
                "Use https://, or plain http:// only to 127.0.0.1 or [::1]."
            }
            TlsError::Unresolved(_) => "Check the host name and the system resolver.",
            TlsError::Connect(_) | TlsError::Io(_) | TlsError::Closed => {
                "Check that the server is running, reachable and speaks TLS on this port."
            }
            TlsError::ConnectTimeout | TlsError::HandshakeTimeout => {
                "The server did not answer in time; check that it is reachable and that the \
                 port serves TLS, not plain HTTP."
            }
            TlsError::Certificate { problem, .. } => certificate_hint(*problem),
            TlsError::Handshake(_) => {
                "The server offers no TLS 1.2 or 1.3 cipher suite we accept, or broke the \
                 protocol; check its TLS configuration."
            }
        }
    }
}

fn certificate_hint(problem: CertificateProblem) -> &'static str {
    match problem {
        CertificateProblem::Expired => {
            "The server's certificate has expired; renew it. If it should still be valid, \
             check this machine's clock."
        }
        CertificateProblem::NotYetValid => {
            "The server's certificate is not valid yet; check the clocks of both machines."
        }
        CertificateProblem::UnknownIssuer => {
            "No trusted CA issued the server's certificate. For a private CA, name its PEM \
             file in the CA file option; the server must also send its intermediates."
        }
        CertificateProblem::NameMismatch => {
            "The certificate does not name this host. Connect by a name the certificate \
             lists, or reissue it with this name as a subject alternative name."
        }
        CertificateProblem::Other => {
            "The server's certificate is malformed, badly signed or not meant for TLS \
             servers; reissue it."
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::NoTrustAnchors => f.write_str("no trust anchors are configured"),
            TlsError::SystemRoots(detail) if detail.is_empty() => {
                f.write_str("the system trust store holds no usable certificate")
            }
            TlsError::SystemRoots(detail) => {
                write!(f, "the system trust store holds no usable certificate: {detail}")
            }
            TlsError::CaFile { path, problem } => {
                write!(f, "CA file {} {}", path.display(), problem.describe())
            }
            TlsError::InvalidServerName(name) => write!(f, "invalid server name {name:?}"),
            TlsError::PlaintextRefused(host) => {
                write!(f, "plain HTTP to {host:?} refused: only literal loopback is allowed")
            }
            TlsError::Unresolved(host) => write!(f, "host {host:?} did not resolve"),
            TlsError::Connect(error) => write!(f, "TCP connection failed: {error}"),
            TlsError::ConnectTimeout => f.write_str("deadline passed while connecting"),
            TlsError::HandshakeTimeout => f.write_str("deadline passed during the TLS handshake"),
            TlsError::Closed => f.write_str("server closed the connection during the handshake"),
            TlsError::Io(error) => write!(f, "TLS handshake I/O failed: {error}"),
            TlsError::Certificate { source, .. } => write!(f, "certificate refused: {source}"),
            TlsError::Handshake(source) => write!(f, "TLS handshake failed: {source}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::Connect(error) | TlsError::Io(error) => Some(error),
            TlsError::Certificate { source, .. } | TlsError::Handshake(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::CertificateError;

    fn classify(error: CertificateError) -> TlsError {
        TlsError::from_rustls(rustls::Error::InvalidCertificate(error))
    }

    #[test]
    fn certificate_errors_are_classified_with_a_hint() {
        let cases = [
            (CertificateError::Expired, CertificateProblem::Expired, "expired"),
            (CertificateError::NotValidYet, CertificateProblem::NotYetValid, "clocks"),
            (CertificateError::UnknownIssuer, CertificateProblem::UnknownIssuer, "CA file"),
            (CertificateError::NotValidForName, CertificateProblem::NameMismatch, "name"),
            (CertificateError::BadSignature, CertificateProblem::Other, "reissue"),
        ];
        for (error, expected, hint) in cases {
            let classified = classify(error);
            assert!(
                matches!(classified, TlsError::Certificate { problem, .. } if problem == expected)
            );
            assert!(classified.hint().contains(hint), "{}", classified.hint());
            assert!(classified.to_string().starts_with("certificate refused: "));
            assert!(std::error::Error::source(&classified).is_some());
        }
    }

    #[test]
    fn other_rustls_errors_are_handshake_failures() {
        let error = TlsError::from_rustls(rustls::Error::DecryptError);
        assert!(matches!(error, TlsError::Handshake(rustls::Error::DecryptError)));
        assert_eq!(error.title(), "TLS HANDSHAKE FAILED");
    }

    #[test]
    fn every_error_has_a_title_a_hint_and_a_message() {
        let errors = [
            TlsError::NoTrustAnchors,
            TlsError::SystemRoots(String::new()),
            TlsError::SystemRoots("no such directory".into()),
            TlsError::CaFile { path: "ca.pem".into(), problem: CaFileProblem::Empty },
            TlsError::InvalidServerName("a b".into()),
            TlsError::PlaintextRefused("example.com".into()),
            TlsError::Unresolved("example.invalid".into()),
            TlsError::Connect(io::ErrorKind::ConnectionRefused.into()),
            TlsError::ConnectTimeout,
            TlsError::HandshakeTimeout,
            TlsError::Closed,
            TlsError::Io(io::ErrorKind::BrokenPipe.into()),
        ];
        for error in errors {
            assert!(!error.title().is_empty());
            assert!(error.hint().ends_with('.'), "{}", error.hint());
            assert!(!error.to_string().is_empty());
        }
        let file = TlsError::CaFile { path: "/x/ca.pem".into(), problem: CaFileProblem::TooLarge };
        assert_eq!(file.to_string(), "CA file /x/ca.pem is larger than 128 KiB");
    }
}
