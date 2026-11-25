//! Startup failures of the edge as diagnostics: a title, what happened, and a hint that
//! says how to repair the common causes. Every one carries the code `EDGE001`.

use std::io;
use std::path::Path;

use sibuna_core::diagnostic;

/// A startup failure, classified for the operator.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Failure {
    /// `EDGE001`, or the code of a failure that has one of its own.
    pub code: &'static str,
    pub title: &'static str,
    pub message: String,
    pub hint: &'static str,
}

/// Classifies `error`, which stopped the edge from starting. `file` is the configuration
/// file, or `None` for a quick start.
pub(super) fn classify(file: Option<&str>, error: &io::Error) -> Failure {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();
    // A failure of the database authority has a title and a hint of its own (SID 0028).
    if let Some((title, hint)) = super::authority::failure(error) {
        let subject = file.map_or(String::new(), |path| format!("{path}: "));
        return Failure { title, message: format!("{subject}{text}."), hint };
    }
    if let Some(path) = file.filter(|path| !Path::new(path).exists()) {
        return Failure {
            code: "EDGE001",
            title: "configuration file not found",
            message: format!("There is no file at `{path}`."),
            hint: "Check the path after `--config-file`. `sibuna lb ... --print-config` \
                   writes a first file.",
        };
    }
    let (title, hint) = match error.kind() {
        io::ErrorKind::AddrInUse => (
            "address in use",
            "Another process listens on this address. Find it with `ss -ltnp`, stop it, or \
             change `binds`.",
        ),
        io::ErrorKind::AddrNotAvailable => (
            "address not available",
            "A listener binds an address of this host. Use 0.0.0.0 for every IPv4 address.",
        ),
        io::ErrorKind::PermissionDenied if !names_a_file(&lower) => (
            "permission denied",
            "A port below 1024 needs the capability CAP_NET_BIND_SERVICE or the root user. \
             The unit sibuna-edge.service grants the capability.",
        ),
        _ if let Some(found) = automatic_https(&lower) => found,
        _ if names_a_certificate(&lower) => (
            "certificate not loaded",
            "Each `crt` entry is one PEM file with the certificate chain, leaf first, then \
             its key: `cat fullchain.pem privkey.pem > site.pem`. The daemon's user must be \
             able to read it.",
        ),
        io::ErrorKind::InvalidData => (
            "invalid configuration",
            "Correct the key that the message names and run `sibuna check -f FILE`.",
        ),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => (
            "file not readable",
            "Check that the file exists and that the daemon's user can read it.",
        ),
        _ => ("edge not started", "Check the edge configuration and the listener addresses."),
    };
    let subject = file.map_or(String::new(), |path| format!("{path}: "));
    if let Some(reason) = text.strip_suffix(" (ACME015)") {
        return Failure {
            code: "ACME015",
            title: "KEY TOOL FAILED",
            message: format!("{subject}{reason}."),
            hint: "RSA keys are made by the program `openssl`. Install OpenSSL so that \
                   `openssl` is in the PATH of the daemon. Or set `global.acme.key` to \
                   \"p256\" or \"p384\", which need no program.",
        };
    }
    Failure { code: "EDGE001", title, message: format!("{subject}{text}."), hint }
}

/// The title and the hint of a failure of the automatic HTTPS configuration, when the
/// lower-case text `lower` is one.
fn automatic_https(lower: &str) -> Option<(&'static str, &'static str)> {
    if lower.contains("is an internal name") {
        return Some((
            "name not public",
            "A public certificate authority validates a name over the Internet. Remove \
             `issuer: \"acme\"` from the frontend, or set `issuer: \"internal\"`: the local \
             authority of the daemon then issues for the name. Or set \
             `global.acme.directory` to an authority of your own.",
        ));
    }
    if lower.contains("is outside global.acme.internal.constraints") {
        return Some((
            "name outside constraints",
            "The root of the local authority was made for the names and addresses of \
             `global.acme.internal.constraints`, and a client refuses any other name under \
             it. Remove the name, or give its frontend `issuer: \"acme\"`. A longer list \
             needs a new root: remove `root.pem`, `root.crt` and `intermediate.pem` in the \
             directory `local` of the storage, and install the new root in the clients.",
        ));
    }
    if lower.contains("without a tsig key is not signed") {
        return Some((
            "update not signed",
            "Without a key the server and everybody on the way to it can be imitated, and \
             the zone accepts updates from any host that it does not refuse by address. \
             Create a key with `tsig-keygen NAME`, give it to the zone, and set `key_name` \
             and `key_file`. On a trusted link set `unsigned: true` instead.",
        ));
    }
    if lower.contains("is a wildcard, which needs the dns challenge") {
        return Some((
            "wildcard needs dns",
            "An authority proves a wildcard through a TXT record. Name a provider: \
             `global: { acme: { dns: { hook: \"/etc/sibuna/dns-hook\" } } }`, or \
             `dns: { rfc2136: { server: \"IP:PORT\", key_name: \"NAME\", key_file: \"FILE\" } }`. \
             For an internal wildcard set `issuer: \"internal\"` on the frontend.",
        ));
    }
    if lower.contains("tls.on_demand needs a guard") {
        return Some((
            "on demand needs a guard",
            "Without a guard anybody who reaches the listener could make the daemon order \
             certificates. Name the hosts that may get one: \
             `global: { acme: { on_demand: { allow: [\"apps.example.org\"] } } }`, or a URL \
             that decides: `on_demand: { ask: \"http://127.0.0.1:9000/allowed\" }`. It is \
             asked `GET URL?domain=NAME` and allows with a status from 200 to 299.",
        ));
    }
    None
}

fn names_a_file(lower: &str) -> bool {
    lower.contains('/') || names_a_certificate(lower)
}

fn names_a_certificate(lower: &str) -> bool {
    [".pem", ".crt", ".key", "certificate", "private key"].iter().any(|word| lower.contains(word))
}

/// Prints the diagnostic of `error` to standard error.
pub(super) fn report(file: Option<&str>, error: &io::Error) {
    let failure = classify(file, error);
    let mut text = String::new();
    let title = format!("{} ({})", failure.title, failure.code);
    let _ = diagnostic::render(&mut text, &title, &failure.message, failure.hint);
    eprint!("{text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn title(file: Option<&str>, kind: io::ErrorKind, text: &str) -> &'static str {
        classify(file, &io::Error::new(kind, text)).title
    }

    #[test]
    fn a_missing_key_tool_keeps_its_own_code() {
        let text = "global.acme.key: `openssl version` could not be started: No such file \
                    or directory (os error 2) (ACME015)";
        let failure = classify(None, &io::Error::other(text));
        assert_eq!((failure.code, failure.title), ("ACME015", "KEY TOOL FAILED"));
        assert!(failure.message.ends_with("(os error 2)."), "{}", failure.message);
        assert!(failure.hint.contains("p256") && failure.hint.contains("PATH"));
        let other = classify(None, &io::Error::other("http 0.0.0.0:80: no"));
        assert_eq!(other.code, "EDGE001");
    }

    #[test]
    fn common_startup_failures_have_their_own_title_and_hint() {
        use io::ErrorKind::{AddrInUse, InvalidData, NotFound, Other, PermissionDenied};
        assert_eq!(
            title(None, AddrInUse, "http 0.0.0.0:80: Address already in use"),
            "address in use"
        );
        assert_eq!(
            title(None, PermissionDenied, "http 0.0.0.0:80: Permission denied"),
            "permission denied"
        );
        assert_eq!(
            title(None, Other, "/etc/certs/site.pem: No such file"),
            "certificate not loaded"
        );
        assert_eq!(
            title(None, PermissionDenied, "/etc/x/site.key: Permission denied"),
            "certificate not loaded"
        );
        assert_eq!(
            title(None, PermissionDenied, "/etc/sibuna/policy.json: denied"),
            "file not readable"
        );
        assert_eq!(title(None, InvalidData, "frontends.web: no binds"), "invalid configuration");
        assert_eq!(title(None, Other, "something else"), "edge not started");
        let internal = "tls.auto: `localhost` is an internal name; a public certificate \
                        authority cannot validate it";
        assert_eq!(title(None, InvalidData, internal), "name not public");
        let wildcard = "tls.auto: `*.example.org` is a wildcard, which needs the DNS \
                        challenge; set global.acme.dns";
        assert_eq!(title(None, InvalidData, wildcard), "wildcard needs dns");
        let guard = "tls.on_demand needs a guard; set global.acme.on_demand.ask or \
                     global.acme.on_demand.allow";
        assert_eq!(title(None, InvalidData, guard), "on demand needs a guard");
        let outside = "tls.auto: `bank.example` is outside \
                       global.acme.internal.constraints; the root of the local authority \
                       may not sign for it";
        assert_eq!(title(None, InvalidData, outside), "name outside constraints");
        let unsigned = "global.acme.dns.rfc2136: an update to 192.0.2.53:53 without a TSIG \
                        key is not signed; set key_name and key_file, or unsigned: true";
        assert_eq!(title(None, InvalidData, unsigned), "update not signed");
        let failure = classify(None, &io::Error::new(InvalidData, internal));
        assert!(failure.hint.contains("issuer: \"internal\""));
        let missing = "/nonexistent/sibuna/edge.jlv";
        assert_eq!(title(Some(missing), NotFound, "No such file"), "configuration file not found");
        let failure = classify(None, &io::Error::new(AddrInUse, "in use"));
        assert!(failure.hint.contains("ss -ltnp"));
    }
}
