//! `sibuna lb`: the quick start of SID 0018. It turns a few options into the topology
//! that a file would hold, then serves it, or prints it as a JLV module.

use std::net::SocketAddr;
use std::process::ExitCode;

use sibuna_core::diagnostic;
use sibuna_lb::{QuickProtocol, QuickStart};

use super::watch::Source;

/// The usage of `sibuna lb`, shown by `--help` and in hints.
const USAGE: &str = "\
sibuna lb --bind IP:PORT --server IP:PORT [--server IP:PORT]... [options]
sibuna lb --tls auto --domain NAME [--domain NAME]... --server IP:PORT [options]

  --bind IP:PORT        Listen here. `:8080` means 0.0.0.0:8080. May repeat.
  --server IP:PORT      Balance over this server. May repeat.
  --proto http|tcp|udp  The protocol (default: http)
  --tls PEM             Terminate TLS with this combined PEM file or directory
  --tls auto            Obtain and renew the certificates of each --domain (ACME)
  --domain NAME         A host name for --tls auto. May repeat.
  --http IP:PORT|off    With --tls auto: the plain listener that answers the
                        challenge and redirects to HTTPS (default: port 80)
  --acme-directory D    letsencrypt (default), letsencrypt-staging or a URL
  --acme-email ADDRESS  The contact address of the ACME account
  --acme-storage DIR    Keys and certificates (default: /var/lib/sibuna/acme)
  --acme-dns-hook PROG  The program that answers DNS-01, for a wildcard --domain
  --health PATH|tcp     Probe each server: GET PATH, or a TCP connect
  --firewall MODE       off | gate | shield (default: off, a plain load balancer)
  --admin SOCKET        Open the admin socket for `sibuna ctl SOCKET ...`
  --print-config        Print the equivalent configuration and exit
  --format jlv|json     The printed format";

/// The format `--print-config` uses by default: the one this build can load back.
const DEFAULT_FORMAT: Format = if cfg!(feature = "jlv") { Format::Jlv } else { Format::Json };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Jlv,
    Json,
}

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Help,
    Print(QuickStart, Format),
    Serve(QuickStart),
}

/// A mistake on the command line: what is wrong and what to write instead.
#[derive(Debug, PartialEq, Eq)]
struct Mistake {
    title: &'static str,
    message: String,
    hint: String,
}

fn mistake(title: &'static str, message: String, hint: &str) -> Mistake {
    Mistake { title, message, hint: hint.to_owned() }
}

/// Parses a listener or server address. `:PORT` is every IPv4 address of the host.
fn address(option: &str, value: &str) -> Result<SocketAddr, Mistake> {
    let text = match value.strip_prefix(':') {
        Some(port) if option == "--bind" => format!("0.0.0.0:{port}"),
        _ => value.to_owned(),
    };
    text.parse().map_err(|_| {
        mistake(
            "invalid address",
            format!("`{value}` after `{option}` is not a numeric address with a port."),
            "Write an IP address and a port, such as 10.0.0.1:80 or [2001:db8::1]:80. \
             Host names are not resolved.",
        )
    })
}

/// What `--http` asked for, with `--tls auto`.
#[derive(Default)]
enum PlainListener {
    /// Port 80 on each address of a `--bind`.
    #[default]
    Standard,
    Off,
    At(Vec<SocketAddr>),
}

/// Completes a quick start with `--tls auto`: the default bind, the plain listeners,
/// and the checks that the options fit together.
fn complete(start: &mut QuickStart, plain: PlainListener) -> Result<(), Mistake> {
    let hint = "sibuna lb --tls auto --domain example.org --server 10.0.0.1:80";
    let automatic = start.tls.as_deref() == Some("auto");
    if !automatic {
        if start.automatic.domains.is_empty() {
            return Ok(());
        }
        let message = "`--domain` names a certificate to obtain, which needs `--tls auto`.";
        return Err(mistake("missing option", message.to_owned(), hint));
    }
    start.tls = None;
    if start.automatic.domains.is_empty() {
        let message = "`--tls auto` needs at least one `--domain`.".to_owned();
        return Err(mistake("missing domain", message, hint));
    }
    if start.protocol != QuickProtocol::Http {
        let message = "`--tls auto` serves HTTPS, so the protocol is http.".to_owned();
        return Err(mistake("invalid protocol", message, hint));
    }
    if start.binds.is_empty() {
        start.binds.push(SocketAddr::from(([0, 0, 0, 0], 443)));
    }
    start.automatic.http_binds = match plain {
        PlainListener::Off => Vec::new(),
        PlainListener::At(binds) => binds,
        PlainListener::Standard => {
            let mut binds: Vec<_> =
                start.binds.iter().map(|bind| SocketAddr::new(bind.ip(), 80)).collect();
            binds.dedup();
            binds.retain(|plain| !start.binds.contains(plain));
            binds
        }
    };
    Ok(())
}

fn parse(args: &[String]) -> Result<Request, Mistake> {
    let mut start = QuickStart::default();
    let mut plain = PlainListener::default();
    let mut format = DEFAULT_FORMAT;
    let mut print = false;
    let mut args = args.iter();
    while let Some(option) = args.next() {
        match option.as_str() {
            "--help" => return Ok(Request::Help),
            "--print-config" => {
                print = true;
                continue;
            }
            _ => {}
        }
        let mut value = || {
            args.next().map(String::as_str).ok_or_else(|| {
                mistake("missing value", format!("`{option}` needs a value."), USAGE)
            })
        };
        match option.as_str() {
            "--bind" => start.binds.push(address(option, value()?)?),
            "--server" => start.servers.push(address(option, value()?)?),
            "--tls" => start.tls = Some(value()?.to_owned()),
            "--domain" => start.automatic.domains.push(value()?.to_owned()),
            "--http" => {
                plain = match (value()?, plain) {
                    ("off", _) => PlainListener::Off,
                    (bind, PlainListener::At(mut binds)) => {
                        binds.push(address("--bind", bind)?);
                        PlainListener::At(binds)
                    }
                    (bind, _) => PlainListener::At(vec![address("--bind", bind)?]),
                }
            }
            "--acme-directory" => start.automatic.directory = Some(value()?.to_owned()),
            "--acme-email" => start.automatic.email = Some(value()?.to_owned()),
            "--acme-storage" => start.automatic.storage = Some(value()?.to_owned()),
            "--acme-dns-hook" => start.automatic.dns_hook = Some(value()?.to_owned()),
            "--health" => start.health = Some(value()?.to_owned()),
            "--firewall" => start.surface = value()?.to_owned(),
            "--admin" => start.admin_socket = Some(value()?.to_owned()),
            "--proto" => start.protocol = protocol(value()?)?,
            "--format" => format = printed(value()?)?,
            _ => {
                let message = format!("`sibuna lb` has no option `{option}`.");
                return Err(mistake("unknown option", message, USAGE));
            }
        }
    }
    complete(&mut start, plain)?;
    if start.binds.is_empty() || start.servers.is_empty() {
        return Err(mistake(
            "missing address",
            "`sibuna lb` needs at least one `--bind` and one `--server`.".to_owned(),
            "sibuna lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80",
        ));
    }
    Ok(if print { Request::Print(start, format) } else { Request::Serve(start) })
}

fn protocol(value: &str) -> Result<QuickProtocol, Mistake> {
    match value {
        "http" => Ok(QuickProtocol::Http),
        "tcp" => Ok(QuickProtocol::Tcp),
        "udp" => Ok(QuickProtocol::Udp),
        _ => Err(mistake(
            "invalid protocol",
            format!("`{value}` is not a protocol of the edge."),
            "Use `--proto http`, `--proto tcp` or `--proto udp`.",
        )),
    }
}

fn printed(value: &str) -> Result<Format, Mistake> {
    match value {
        "jlv" => Ok(Format::Jlv),
        "json" => Ok(Format::Json),
        _ => Err(mistake(
            "invalid format",
            format!("`{value}` is not a configuration format."),
            "Use `--format jlv` or `--format json`.",
        )),
    }
}

/// Prints a diagnostic to standard error and returns the failure status.
fn fail(title: &str, message: &str, hint: &str) -> ExitCode {
    let mut text = String::new();
    let _ = diagnostic::render(&mut text, title, message, hint);
    eprint!("{text}");
    ExitCode::FAILURE
}

/// Runs `sibuna lb` with the arguments after `lb`.
pub(super) fn run(args: &[String], secret: Option<&str>) -> ExitCode {
    let start = match parse(args) {
        Ok(Request::Help) => {
            eprintln!("Usage: {USAGE}");
            if !cfg!(feature = "jlv") {
                eprintln!("\nThis build loads JSON files only, so --print-config prints JSON.");
            }
            return ExitCode::SUCCESS;
        }
        Ok(Request::Print(start, format)) => return print(&start, format),
        Ok(Request::Serve(start)) => start,
        Err(error) => return fail(error.title, &error.message, &error.hint),
    };
    let served = start.config().and_then(|config| {
        let http = super::http::Prepared::load(&config)?;
        eprintln!("{}", summary(&start));
        super::serve(Source::quick_start(), super::Revision { config, http }, secret)
    });
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            super::failure::report(None, &error);
            ExitCode::FAILURE
        }
    }
}

/// Checks the topology and prints it, so that a printed file is one the daemon accepts.
fn print(start: &QuickStart, format: Format) -> ExitCode {
    use std::io::Write as _;

    if let Err(error) = start.config() {
        return fail(
            "quick start refused",
            &format!("The edge rejects this topology: {error}."),
            "Correct the options and print again.",
        );
    }
    let text = match format {
        Format::Jlv => start.jlv(),
        Format::Json => start.json(),
    };
    match std::io::stdout().lock().write_all(text.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

/// One line that says what the quick start serves and how to change the firewall.
fn summary(start: &QuickStart) -> String {
    let protocol = match start.protocol {
        QuickProtocol::Http => "HTTP",
        QuickProtocol::Tcp => "TCP",
        QuickProtocol::Udp => "UDP",
    };
    let count = start.servers.len();
    let plural = if count == 1 { "" } else { "s" };
    let mut line =
        format!("Sibuna lb: {protocol} to {count} server{plural}, no configuration file");
    if start.protocol == QuickProtocol::Http {
        line.push_str(&format!(", firewall {}", start.surface));
        if start.surface == "off" {
            line.push_str(" (--firewall gate or shield turns it on)");
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(line: &str) -> Result<Request, Mistake> {
        let args: Vec<String> = line.split(' ').map(str::to_owned).collect();
        parse(&args)
    }

    #[test]
    fn options_fill_the_quick_start() {
        let line = "--bind :8080 --bind [::1]:8081 --server 10.0.0.1:80 --server 10.0.0.2:80 \
                    --health /healthz --firewall gate --admin /tmp/a.sock --tls site.pem";
        let Ok(Request::Serve(start)) = request(line) else { panic!("expected a topology") };
        let expected = QuickStart {
            binds: vec!["0.0.0.0:8080".parse().unwrap(), "[::1]:8081".parse().unwrap()],
            servers: vec!["10.0.0.1:80".parse().unwrap(), "10.0.0.2:80".parse().unwrap()],
            protocol: QuickProtocol::Http,
            tls: Some("site.pem".to_owned()),
            health: Some("/healthz".to_owned()),
            surface: "gate".to_owned(),
            admin_socket: Some("/tmp/a.sock".to_owned()),
            automatic: sibuna_lb::QuickAutomatic::default(),
        };
        assert_eq!(start, expected);
    }

    #[test]
    fn tls_auto_needs_only_a_domain_and_a_server() {
        let line = "--tls auto --domain example.org --domain www.example.org --server 10.0.0.1:80";
        let Ok(Request::Serve(start)) = request(line) else { panic!("expected a topology") };
        assert_eq!(start.tls, None);
        assert_eq!(start.binds, ["0.0.0.0:443".parse().unwrap()]);
        assert_eq!(start.automatic.domains, ["example.org", "www.example.org"]);
        assert_eq!(start.automatic.http_binds, ["0.0.0.0:80".parse().unwrap()]);
        let line = "--tls auto --domain example.org --server 10.0.0.1:80 --bind [::1]:8443 \
                    --http :8080 --acme-directory letsencrypt-staging --acme-email a@example.org \
                    --acme-storage /tmp/acme";
        let Ok(Request::Serve(start)) = request(line) else { panic!("expected a topology") };
        assert_eq!(start.automatic.http_binds, ["0.0.0.0:8080".parse().unwrap()]);
        assert_eq!(start.automatic.directory.as_deref(), Some("letsencrypt-staging"));
        assert_eq!(start.automatic.email.as_deref(), Some("a@example.org"));
        assert_eq!(start.automatic.storage.as_deref(), Some("/tmp/acme"));
        let off = "--tls auto --domain example.org --server 10.0.0.1:80 --http off";
        let Ok(Request::Serve(start)) = request(off) else { panic!("expected a topology") };
        assert!(start.automatic.http_binds.is_empty());
        let title = |line: &str| request(line).unwrap_err().title;
        assert_eq!(title("--tls auto --server 10.0.0.1:80"), "missing domain");
        assert_eq!(title("--bind :80 --domain a.example --server 10.0.0.1:80"), "missing option");
        let tcp = "--tls auto --domain a.example --server 10.0.0.1:80 --proto tcp";
        assert_eq!(title(tcp), "invalid protocol");
    }

    #[test]
    fn printing_selects_a_format() {
        let line = "--bind :80 --server 10.0.0.1:80 --proto tcp --print-config";
        let Ok(Request::Print(start, format)) = request(line) else { panic!("expected print") };
        assert_eq!((start.protocol, format), (QuickProtocol::Tcp, DEFAULT_FORMAT));
        let json = request(&format!("{line} --format json"));
        assert!(matches!(json, Ok(Request::Print(_, Format::Json))));
        assert_eq!(request("--help"), Ok(Request::Help));
    }

    #[test]
    fn mistakes_are_named() {
        let title = |line: &str| request(line).unwrap_err().title;
        assert_eq!(title("--bind :80"), "missing address");
        assert_eq!(title("--server 10.0.0.1:80"), "missing address");
        assert_eq!(title("--bind :80 --server web.example:80"), "invalid address");
        assert_eq!(title("--bind :80 --server :80"), "invalid address");
        assert_eq!(title("--bind :80 --server"), "missing value");
        assert_eq!(title("--bind :80 --server 10.0.0.1:80 --verbose"), "unknown option");
        assert_eq!(title("--bind :80 --server 10.0.0.1:80 --proto sctp"), "invalid protocol");
        assert_eq!(title("--bind :80 --server 10.0.0.1:80 --format yaml"), "invalid format");
    }
}
