//! The one-pool topology of `sibuna lb` (SID 0018), written as the document a file would
//! hold. The quick start has no builder of its own: [`QuickStart::config`] parses the JSON
//! form with [`Config::parse`], so the printed file and the served topology cannot differ.

use std::fmt::Write;
use std::io;
use std::net::SocketAddr;

use crate::Config;

/// The protocol of the quick-start frontend and of its pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QuickProtocol {
    /// Requests are parsed and balanced one by one.
    #[default]
    Http,
    /// Connections are relayed as bytes.
    Tcp,
    /// Datagrams are relayed per client address.
    Udp,
}

/// One frontend named `web` in front of one pool named `app`. Fill the fields and call
/// [`QuickStart::config`], [`QuickStart::jlv`] or [`QuickStart::json`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickStart {
    /// The listener addresses, at least one.
    pub binds: Vec<SocketAddr>,
    /// The server addresses, at least one. Each server is named by its address.
    pub servers: Vec<SocketAddr>,
    /// The protocol of the listeners and the servers.
    pub protocol: QuickProtocol,
    /// A combined PEM file, or a directory of them, to terminate TLS with.
    pub tls: Option<String>,
    /// The health probe: an absolute path for an HTTP probe, or `tcp` for a connect.
    pub health: Option<String>,
    /// The HTTP surface: `off`, `gate` or `shield`.
    pub surface: String,
    /// The path of the admin socket.
    pub admin_socket: Option<String>,
}

impl Default for QuickStart {
    /// HTTP without the firewall, no TLS, no probe and no admin socket.
    fn default() -> Self {
        Self {
            binds: Vec::new(),
            servers: Vec::new(),
            protocol: QuickProtocol::Http,
            tls: None,
            health: None,
            surface: "off".to_owned(),
            admin_socket: None,
        }
    }
}

/// A value of the document, with the member order we print.
enum Node {
    Text(String),
    List(Vec<Node>),
    Map(Vec<(&'static str, Node)>),
    /// A JLV expression, written as it is.
    Code(String),
}

fn text(value: impl Into<String>) -> Node {
    Node::Text(value.into())
}

impl QuickStart {
    /// Parses the JSON form as a file is parsed. Fails with the diagnostic of the
    /// topology checks, for example for a missing server or an HTTP probe on a TCP pool.
    pub fn config(&self) -> io::Result<Config> {
        Config::parse(self.json().as_bytes())
    }

    /// The topology as a JSON document, one top-level member per line.
    pub fn json(&self) -> String {
        let servers = self.servers.iter().map(|addr| text(addr.to_string())).collect();
        let mut out = String::from("{\n");
        let members = self.document(Node::List(servers));
        for (index, (key, value)) in members.iter().enumerate() {
            let comma = if index + 1 < members.len() { "," } else { "" };
            let _ = write!(out, "  \"{key}\": ");
            write_node(&mut out, value, Syntax::Json);
            let _ = writeln!(out, "{comma}");
        }
        out.push_str("}\n");
        out
    }

    /// The topology as a JLV module with the function `edge`. Three or more servers on
    /// one port are generated from the list of their hosts.
    pub fn jlv(&self) -> String {
        let mut out = String::from(
            "// Written by `sibuna lb --print-config`. Check it with `sibuna check -f edge.jlv`.\n\
             fn edge() -> Map<Value> {\n",
        );
        let servers = match self.shared_port() {
            Some(port) => {
                let hosts = self.servers.iter().map(|addr| text(host(*addr))).collect();
                out.push_str("    let hosts = ");
                write_node(&mut out, &Node::List(hosts), Syntax::Jlv);
                out.push('\n');
                Node::Code(format!("[for host in hosts: \"${{host}}:{port}\"]"))
            }
            None => Node::List(self.servers.iter().map(|addr| text(addr.to_string())).collect()),
        };
        out.push_str("    return {\n");
        for (key, value) in self.document(servers) {
            let _ = write!(out, "        {key}: ");
            write_node(&mut out, &value, Syntax::Jlv);
            out.push_str(",\n");
        }
        out.push_str("    }\n}\n");
        out
    }

    /// The port that at least three servers have in common, when all have it.
    fn shared_port(&self) -> Option<u16> {
        let port = self.servers.first()?.port();
        (self.servers.len() >= 3 && self.servers.iter().all(|addr| addr.port() == port))
            .then_some(port)
    }

    /// The top-level members. Keys with their default value are left out.
    fn document(&self, servers: Node) -> Vec<(&'static str, Node)> {
        let protocol = match self.protocol {
            QuickProtocol::Http => None,
            QuickProtocol::Tcp => Some("tcp"),
            QuickProtocol::Udp => Some("udp"),
        };
        let mut members = Vec::new();
        if let Some(path) = &self.admin_socket {
            members.push(("global", Node::Map(vec![("admin_socket", text(path))])));
        }
        if protocol.is_none() {
            members.push(("http", Node::Map(vec![("surface", text(&self.surface))])));
        }
        let mut web = Vec::new();
        let mut app = Vec::new();
        if let Some(protocol) = protocol {
            web.push(("proto", text(protocol)));
            app.push(("mode", text(protocol)));
        }
        web.push(("binds", Node::List(self.binds.iter().map(|b| text(b.to_string())).collect())));
        if let Some(path) = &self.tls {
            web.push(("tls", Node::Map(vec![("crt", text(path))])));
        }
        match self.health.as_deref() {
            None => {}
            Some("tcp") => app.push(("health_check", Node::Map(vec![("kind", text("tcp"))]))),
            Some(path) => {
                let probe = vec![("kind", text("http")), ("path", text(path))];
                app.push(("health_check", Node::Map(probe)));
            }
        }
        app.push(("servers", servers));
        members.push(("frontends", Node::Map(vec![("web", Node::Map(web))])));
        members.push(("backends", Node::Map(vec![("app", Node::Map(app))])));
        members
    }
}

/// The address without its port: `10.0.0.1` or `[2001:db8::1]`.
fn host(addr: SocketAddr) -> String {
    let text = addr.to_string();
    let end = text.rfind(':').unwrap_or(text.len());
    text[..end].to_owned()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Syntax {
    Json,
    Jlv,
}

/// Writes a value on one line.
fn write_node(out: &mut String, node: &Node, syntax: Syntax) {
    match node {
        Node::Text(value) => write_text(out, value, syntax),
        Node::Code(code) => out.push_str(code),
        Node::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_node(out, item, syntax);
            }
            out.push(']');
        }
        Node::Map(members) => {
            out.push_str(if syntax == Syntax::Jlv { "{ " } else { "{" });
            for (index, (key, value)) in members.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let _ = match syntax {
                    Syntax::Json => write!(out, "\"{key}\": "),
                    Syntax::Jlv => write!(out, "{key}: "),
                };
                write_node(out, value, syntax);
            }
            out.push_str(if syntax == Syntax::Jlv { " }" } else { "}" });
        }
    }
}

/// Writes a string literal. JLV reads `${` as an interpolation, so it is written `$${`.
fn write_text(out: &mut String, value: &str, syntax: Syntax) {
    if syntax == Syntax::Json {
        let _ = sibuna_json::write_string(out, value);
        return;
    }
    out.push('"');
    let mut previous = '\0';
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '{' if previous == '$' => out.push_str("${"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
        previous = character;
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quick(servers: &[&str]) -> QuickStart {
        QuickStart {
            binds: vec!["0.0.0.0:8080".parse().unwrap()],
            servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
            ..QuickStart::default()
        }
    }

    #[test]
    fn the_smallest_module_has_three_members() {
        let module = quick(&["10.0.0.1:80", "10.0.0.2:80"]).jlv();
        assert!(module.contains("        http: { surface: \"off\" },\n"), "{module}");
        assert!(module.contains("        frontends: { web: { binds: [\"0.0.0.0:8080\"] } },\n"));
        assert!(module.contains(
            "        backends: { app: { servers: [\"10.0.0.1:80\", \"10.0.0.2:80\"] } },\n"
        ));
        assert!(module.ends_with("    }\n}\n"));
    }

    #[test]
    fn three_servers_on_one_port_become_a_comprehension() {
        let module = quick(&["10.0.0.1:80", "10.0.0.2:80", "[2001:db8::1]:80"]).jlv();
        assert!(
            module.contains("let hosts = [\"10.0.0.1\", \"10.0.0.2\", \"[2001:db8::1]\"]\n"),
            "{module}"
        );
        assert!(module.contains("servers: [for host in hosts: \"${host}:80\"]"), "{module}");
        let mixed = quick(&["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:81"]).jlv();
        assert!(!mixed.contains("hosts"), "{mixed}");
    }

    #[test]
    fn the_json_form_is_accepted_by_the_file_parser() {
        let mut start = quick(&["10.0.0.1:80", "10.0.0.2:80"]);
        start.health = Some("/healthz".to_owned());
        start.surface = "gate".to_owned();
        start.admin_socket = Some("/run/sibuna/edge.sock".to_owned());
        let config = start.config().unwrap();
        assert_eq!(config.admin_socket(), Some("/run/sibuna/edge.sock"));
        assert!(config.http().is_some_and(|http| http.firewall && !http.shield));
        for protocol in [QuickProtocol::Tcp, QuickProtocol::Udp] {
            let mut start = quick(&["10.0.0.1:53"]);
            start.binds = vec!["192.0.2.1:53".parse().unwrap()];
            start.protocol = protocol;
            assert!(start.json().contains("\"proto\": "));
            start.config().unwrap();
        }
    }

    #[test]
    fn mistakes_get_the_diagnostics_of_the_file() {
        let reason = |start: QuickStart| start.config().err().unwrap().to_string();
        assert!(reason(quick(&[])).contains("servers"));
        let mut probe = quick(&["10.0.0.1:80"]);
        probe.protocol = QuickProtocol::Tcp;
        probe.health = Some("/healthz".to_owned());
        assert!(reason(probe).contains("HTTP probes require an HTTP pool"));
        let mut surface = quick(&["10.0.0.1:80"]);
        surface.surface = "loud".to_owned();
        assert!(reason(surface).contains("off, gate or shield"));
    }

    #[test]
    fn jlv_text_escapes_quotes_and_interpolations() {
        let mut out = String::new();
        write_text(&mut out, "a\"b\\c${d}", Syntax::Jlv);
        assert_eq!(out, r#""a\"b\\c$${d}""#);
    }
}
