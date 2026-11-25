//! The admin protocol of SID 0018 without its socket: one command line in, one answer out.
//!
//! A line has at most [`MAX_LINE`] bytes of printable ASCII. The answer begins with `ok`
//! or with `error CODE TITLE`. After an error the second line explains and the third
//! line begins with `Hint:`. Nothing here performs I/O.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sibuna_lb::{Change, MeshCommand, RuntimeError, ServerState, ServerStatus};

/// The longest command line, without its line feed.
pub(super) const MAX_LINE: usize = 512;

/// What the commands are, for the answer to `help` and for hints.
pub(super) const USAGE: &str = "\
show servers
show info
show stats
show certs
show ca
set server POOL/NAME state ready|drain [local]
set server POOL/NAME weight N [local]
add server POOL/NAME IP:PORT [weight N] [local]
del server POOL/NAME [local]
del ban ADDRESS [local]
reload
help
";

/// One parsed command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Command {
    ShowServers,
    ShowInfo,
    ShowStats,
    /// The certificates of automatic HTTPS (SID 0021).
    ShowCerts,
    /// The root certificate of the local authority (SID 0021).
    ShowCa,
    Help,
    Reload,
    State {
        pool: String,
        name: String,
        state: ServerState,
    },
    Weight {
        pool: String,
        name: String,
        weight: u32,
    },
    Add {
        pool: String,
        name: String,
        addr: SocketAddr,
        weight: u32,
    },
    Del {
        pool: String,
        name: String,
    },
    /// Lifts the ban of the client at this address (SID 0022).
    DelBan {
        client: std::net::IpAddr,
    },
    /// A change to a server that stays on this node. Without the word `local` a mesh
    /// carries the change to the peers (SID 0022).
    Local(Box<Command>),
}

impl Command {
    /// Whether the command changes what is served. Such a command is logged.
    pub fn changes(&self) -> bool {
        !matches!(
            self,
            Self::ShowServers
                | Self::ShowInfo
                | Self::ShowStats
                | Self::ShowCerts
                | Self::ShowCa
                | Self::Help
        )
    }
}

/// An admin failure with a code that the socket alone produces.
pub(super) fn failure(
    code: &'static str,
    title: &'static str,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> RuntimeError {
    RuntimeError { code, title, message: message.into(), hint: hint.into() }
}

fn unknown(line: &str) -> RuntimeError {
    failure(
        "ADM002",
        "UNKNOWN COMMAND",
        format!("`{line}` is not a command."),
        "Run `help` to list the commands, for example `set server app/web1 state drain`.",
    )
}

/// Splits `POOL/NAME` at the first slash.
fn target(word: &str) -> Result<(String, String), RuntimeError> {
    match word.split_once('/') {
        Some((pool, name)) if !pool.is_empty() && !name.is_empty() => {
            Ok((pool.to_owned(), name.to_owned()))
        }
        _ => Err(RuntimeError::invalid(
            format!("`{word}` does not name a server."),
            "Write the pool, a slash and the server, as in `app/web1`.",
        )),
    }
}

fn weight(word: &str) -> Result<u32, RuntimeError> {
    word.parse().map_err(|_| {
        RuntimeError::invalid(
            format!("`{word}` is not a weight."),
            "A weight is a whole number from 1 to 65535.",
        )
    })
}

fn state(word: &str) -> Result<ServerState, RuntimeError> {
    match word {
        "ready" => Ok(ServerState::Ready),
        // HAProxy's `maint` has no meaning of its own here (SID 0018).
        "drain" | "maint" => Ok(ServerState::Drain),
        _ => Err(RuntimeError::invalid(
            format!("`{word}` is not a server state."),
            "The states are `ready` and `drain`.",
        )),
    }
}

fn address(word: &str) -> Result<SocketAddr, RuntimeError> {
    word.parse().map_err(|_| {
        RuntimeError::invalid(
            format!("`{word}` is not a numeric address with a port."),
            "Write an IP address and a port, such as 10.0.0.3:80 or [2001:db8::3]:80.",
        )
    })
}

/// Parses one line. Fails with `ADM002` for unknown words and `ADM005` for a bad value.
pub(super) fn parse(line: &str) -> Result<Command, RuntimeError> {
    let mut words = [""; 8];
    let mut count = 0;
    for word in line.split_ascii_whitespace() {
        if count == words.len() {
            return Err(unknown(line));
        }
        words[count] = word;
        count += 1;
    }
    // The last word `local` keeps a change to a server on this node.
    let changes_server = matches!(words[0], "set" | "add" | "del");
    let local = changes_server && count > 1 && words[count - 1] == "local";
    count -= usize::from(local);
    let command = match &words[..count] {
        ["show", "servers"] => Ok(Command::ShowServers),
        ["show", "info"] => Ok(Command::ShowInfo),
        ["show", "stats"] => Ok(Command::ShowStats),
        ["show", "certs"] => Ok(Command::ShowCerts),
        ["show", "ca"] => Ok(Command::ShowCa),
        ["help"] => Ok(Command::Help),
        ["reload"] => Ok(Command::Reload),
        ["set", "server", server, "state", word] => {
            let (pool, name) = target(server)?;
            Ok(Command::State { pool, name, state: state(word)? })
        }
        ["set", "server", server, "weight", word] => {
            let (pool, name) = target(server)?;
            Ok(Command::Weight { pool, name, weight: weight(word)? })
        }
        ["add", "server", server, addr] => {
            let (pool, name) = target(server)?;
            Ok(Command::Add { pool, name, addr: address(addr)?, weight: 1 })
        }
        ["add", "server", server, addr, "weight", word] => {
            let (pool, name) = target(server)?;
            Ok(Command::Add { pool, name, addr: address(addr)?, weight: weight(word)? })
        }
        ["del", "ban", client] => match client.parse() {
            Ok(client) => Ok(Command::DelBan { client }),
            Err(_) => Err(RuntimeError::invalid(
                format!("`{client}` is not an address."),
                "Name the client by its IPv4 or IPv6 address, as the access log shows it.",
            )),
        },
        ["del", "server", server] => {
            let (pool, name) = target(server)?;
            Ok(Command::Del { pool, name })
        }
        _ => Err(unknown(line)),
    }?;
    Ok(if local { Command::Local(Box::new(command)) } else { command })
}

/// Checks the bytes of a received line and removes a trailing carriage return. Fails
/// with `ADM001` for a byte outside printable ASCII.
pub(super) fn line(bytes: &[u8]) -> Result<&str, RuntimeError> {
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    let printable = bytes.iter().all(|byte| (0x20..=0x7e).contains(byte));
    match std::str::from_utf8(bytes) {
        Ok(text) if printable => Ok(text),
        _ => Err(malformed("The command holds a byte outside printable ASCII.")),
    }
}

/// The `ADM001` failure with the given explanation.
pub(super) fn malformed(message: &str) -> RuntimeError {
    failure(
        "ADM001",
        "MALFORMED COMMAND",
        message,
        format!("Send one line of at most {MAX_LINE} printable ASCII bytes, then a line feed."),
    )
}

/// Encodes an answer for the socket.
pub(super) fn encode(answer: &Result<String, RuntimeError>) -> String {
    match answer {
        Ok(body) => format!("ok\n{body}"),
        Err(error) => {
            format!(
                "error {} {}\n{}\nHint: {}\n",
                error.code, error.title, error.message, error.hint
            )
        }
    }
}

/// An answer as the client reads it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Answer<'a> {
    /// The command succeeded. The text is its result, possibly empty.
    Done(&'a str),
    /// The command failed.
    Failed { code: &'a str, title: &'a str, message: &'a str, hint: &'a str },
}

/// Decodes an answer. Returns `None` for text that is no answer of this protocol.
pub(super) fn decode(text: &str) -> Option<Answer<'_>> {
    let (first, rest) = text.split_once('\n')?;
    if first == "ok" {
        return Some(Answer::Done(rest));
    }
    let (code, title) = first.strip_prefix("error ")?.split_once(' ')?;
    let (message, hint) = rest.split_once('\n')?;
    let hint = hint.strip_prefix("Hint: ")?.trim_end_matches('\n');
    Some(Answer::Failed { code, title, message, hint })
}

/// What a command changed on a server, for the column `changed`.
fn changed(server: &ServerStatus) -> String {
    let marks = [
        (server.added, "added"),
        (server.state == ServerState::Drain, "state"),
        (server.reweighted, "weight"),
    ];
    let set: Vec<&str> = marks.iter().filter(|(on, _)| *on).map(|(_, mark)| *mark).collect();
    if set.is_empty() { "-".to_owned() } else { set.join(",") }
}

/// Writes the table of `show servers`: a header and one aligned line per server.
pub(super) fn render_servers(servers: &[ServerStatus]) -> String {
    let header = [
        "pool", "name", "address", "state", "weight", "flows", "health", "ejected", "ramp",
        "changed",
    ];
    let mut rows = vec![header.map(str::to_owned)];
    for server in servers {
        let health = match server.healthy {
            None => "-",
            Some(true) => "up",
            Some(false) => "down",
        };
        rows.push([
            server.pool.clone(),
            server.name.clone(),
            server.addr.to_string(),
            server.state.word().to_owned(),
            server.weight.to_string(),
            server.flows.to_string(),
            health.to_owned(),
            // The time passive health still keeps the server out, rounded up.
            server.ejected.map_or("-".to_owned(), |left| format!("{}s", left.as_secs() + 1)),
            server.ramp.map_or("-".to_owned(), |percent| format!("{percent}%")),
            changed(server),
        ]);
    }
    let mut widths = [0; 10];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let mut out = String::new();
    for row in &rows {
        for (index, (cell, width)) in row.iter().zip(widths).enumerate() {
            let _ = if index + 1 < row.len() {
                write!(out, "{cell:<width$} ")
            } else {
                writeln!(out, "{cell}")
            };
        }
    }
    out
}

/// A token bucket for commands: a burst of 20, refilled at 10 per second.
pub(super) struct Bucket {
    /// Thousandths of a command.
    credit: u64,
    filled: Instant,
}

impl Bucket {
    const BURST: u64 = 20_000;
    const PER_MILLISECOND: u64 = 10;

    /// A full bucket.
    pub fn new(now: Instant) -> Self {
        Self { credit: Self::BURST, filled: now }
    }

    /// Takes one command's worth of credit. Returns false when the rate is exhausted.
    pub fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.filled).min(Duration::from_secs(60));
        let gained = elapsed.as_millis() as u64 * Self::PER_MILLISECOND;
        self.credit = (self.credit + gained).min(Self::BURST);
        self.filled = now;
        if self.credit < 1000 {
            return false;
        }
        self.credit -= 1000;
        true
    }
}

/// The change to a server that `command` asks for, as the mesh carries it. `None` for
/// a command that changes no server, and for the removal of a server that is not among
/// `servers`: a removal names the address it removes.
pub(super) fn mesh_command(command: &Command, servers: &[ServerStatus]) -> Option<MeshCommand> {
    let (pool, name, change) = match command {
        Command::State { pool, name, state } => {
            (pool, name, Change::State { drained: *state == ServerState::Drain })
        }
        Command::Weight { pool, name, weight } => (pool, name, Change::Weight(*weight)),
        Command::Add { pool, name, addr, weight } => {
            (pool, name, Change::Member { addr: *addr, weight: *weight, present: true })
        }
        Command::Del { pool, name } => {
            let server = servers.iter().find(|s| s.pool == *pool && s.name == *name)?;
            (pool, name, Change::Member { addr: server.addr, weight: 0, present: false })
        }
        _ => return None,
    };
    Some(MeshCommand { pool: pool.clone(), name: name.clone(), change })
}

/// The admin line that states `command`, for the log.
pub(super) fn render_command(command: &MeshCommand) -> String {
    let server = format!("{}/{}", command.pool, command.name);
    match command.change {
        Change::State { drained: true } => format!("set server {server} state drain"),
        Change::State { drained: false } => format!("set server {server} state ready"),
        Change::Weight(weight) => format!("set server {server} weight {weight}"),
        Change::Member { addr, weight, present: true } => {
            format!("add server {server} {addr} weight {weight}")
        }
        Change::Member { present: false, .. } => format!("del server {server}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_parses() {
        let server = |pool: &str, name: &str| (pool.to_owned(), name.to_owned());
        assert_eq!(parse("show servers"), Ok(Command::ShowServers));
        assert_eq!(parse("  show   info "), Ok(Command::ShowInfo));
        assert_eq!(parse("show stats"), Ok(Command::ShowStats));
        assert_eq!(parse("show certs"), Ok(Command::ShowCerts));
        assert_eq!(parse("show ca"), Ok(Command::ShowCa));
        assert_eq!(parse("reload"), Ok(Command::Reload));
        let (pool, name) = server("app", "10.0.0.1:80");
        let drain = Command::State { pool, name, state: ServerState::Drain };
        assert_eq!(parse("set server app/10.0.0.1:80 state drain"), Ok(drain.clone()));
        assert_eq!(parse("set server app/10.0.0.1:80 state maint"), Ok(drain));
        let (pool, name) = server("app", "a/b");
        assert_eq!(
            parse("set server app/a/b weight 7"),
            Ok(Command::Weight { pool, name, weight: 7 })
        );
        let addr = "[2001:db8::3]:80".parse().unwrap();
        let (pool, name) = server("app", "blue");
        let add = Command::Add { pool, name, addr, weight: 3 };
        assert_eq!(parse("add server app/blue [2001:db8::3]:80 weight 3"), Ok(add));
        let (pool, name) = server("app", "blue");
        let del = Command::Del { pool, name };
        assert_eq!(parse("del server app/blue"), Ok(del.clone()));
        assert_eq!(parse("del server app/blue local"), Ok(Command::Local(Box::new(del))));
        let lift = Command::DelBan { client: "2001:db8::7".parse().unwrap() };
        assert_eq!(parse("del ban 2001:db8::7"), Ok(lift.clone()));
        assert_eq!(parse("del ban 2001:db8::7 local"), Ok(Command::Local(Box::new(lift))));
        assert!(parse("del ban example.org").is_err());
        assert!(parse("show servers local").is_err());
        assert!(parse("reload local").is_err());
    }

    #[test]
    fn bad_lines_get_a_code_and_a_hint() {
        let code = |line: &str| parse(line).unwrap_err().code;
        assert_eq!(code(""), "ADM002");
        assert_eq!(code("shutdown now"), "ADM002");
        assert_eq!(code("a b c d e f g h i"), "ADM002");
        assert_eq!(code("set server app state drain"), "ADM005");
        assert_eq!(code("set server /a state drain"), "ADM005");
        assert_eq!(code("set server app/a state up"), "ADM005");
        assert_eq!(code("set server app/a weight -1"), "ADM005");
        assert_eq!(code("set server app/a weight 99999999999"), "ADM005");
        assert_eq!(code("add server app/a web.example:80"), "ADM005");
        assert_eq!(line(b"show \x00info").unwrap_err().code, "ADM001");
        assert_eq!(line("d\u{e9}l".as_bytes()).unwrap_err().code, "ADM001");
        assert_eq!(line(b"reload\r"), Ok("reload"));
        assert!(!parse("nonsense").unwrap_err().hint.is_empty());
    }

    #[test]
    fn answers_survive_the_wire() {
        assert_eq!(decode(&encode(&Ok(String::new()))), Some(Answer::Done("")));
        assert_eq!(decode(&encode(&Ok("a\nb\n".to_owned()))), Some(Answer::Done("a\nb\n")));
        let error = parse("set server app/a state up").unwrap_err();
        let wire = encode(&Err(error.clone()));
        let expected = Answer::Failed {
            code: "ADM005",
            title: "INVALID VALUE",
            message: &error.message,
            hint: &error.hint,
        };
        assert_eq!(decode(&wire), Some(expected));
        assert_eq!(decode("HTTP/1.1 400 Bad Request\r\n"), None);
        assert_eq!(decode(""), None);
    }

    #[test]
    fn the_table_marks_what_changed() {
        let server = |name: &str, state, added, reweighted: bool| ServerStatus {
            pool: "app".to_owned(),
            name: name.to_owned(),
            addr: "10.0.0.1:80".parse().unwrap(),
            state,
            weight: 2,
            flows: 4,
            healthy: Some(true),
            backup: false,
            added,
            reweighted,
            // The first server is ejected for 6.2 more seconds, the second ramps.
            ejected: reweighted.then_some(Duration::from_millis(6200)),
            ramp: added.then_some(40),
        };
        let table = render_servers(&[
            server("a", ServerState::Drain, false, true),
            server("blue", ServerState::Ready, true, false),
            server("c", ServerState::Ready, false, false),
        ]);
        let lines: Vec<&str> = table.lines().collect();
        let head = "pool name address     state weight flows health ejected ramp changed";
        assert_eq!(lines[0], head);
        assert_eq!(
            lines[1],
            "app  a    10.0.0.1:80 drain 2      4     up     7s      -    state,weight"
        );
        assert_eq!(lines[2], "app  blue 10.0.0.1:80 ready 2      4     up     -       40%  added");
        assert_eq!(lines[3], "app  c    10.0.0.1:80 ready 2      4     up     -       -    -");
    }

    #[test]
    fn the_bucket_allows_a_burst_and_then_ten_per_second() {
        let start = Instant::now();
        let mut bucket = Bucket::new(start);
        assert!((0..20).all(|_| bucket.take(start)));
        assert!(!bucket.take(start));
        let later = start + Duration::from_millis(250);
        assert!(bucket.take(later));
        assert!(bucket.take(later));
        assert!(!bucket.take(later));
        let idle = later + Duration::from_secs(3600);
        assert_eq!((0..30).filter(|_| bucket.take(idle)).count(), 20);
    }
}
