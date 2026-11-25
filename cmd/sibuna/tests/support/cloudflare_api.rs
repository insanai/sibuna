//! A server that speaks the part of the Cloudflare API, version 4, that the DNS-01
//! provider uses (SID 0021). It listens on a loopback port. The records it holds go
//! into the table of the DNS server of the test, so the test authority finds them.
//!
//! ```text
//!   GET    /client/v4/zones?name=Z
//!   POST   /client/v4/zones/ID/dns_records
//!   GET    /client/v4/zones/ID/dns_records?type=TXT&name=N
//!   DELETE /client/v4/zones/ID/dns_records/RECORD
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sibuna_acme::dns::server::{Entry, Table};

/// One TXT record of the API.
#[derive(Clone, Debug)]
struct Record {
    id: String,
    zone: String,
    name: String,
    /// The content as the API holds it: inside double quotes.
    content: String,
}

/// What the test sets and reads.
pub struct Api {
    /// The base URL for `global.acme.dns.cloudflare.api`.
    pub url: String,
    /// The token that the API accepts.
    pub token: String,
    /// The zones of the account: name and identifier.
    pub zones: Vec<(&'static str, &'static str)>,
    /// The method and the target of every request, in order.
    pub calls: Mutex<Vec<String>>,
    /// The requests that came with another token, or with none.
    pub denied: Mutex<usize>,
    records: Mutex<Vec<Record>>,
    table: Arc<Mutex<Table>>,
}

fn failure(code: u32, message: &str) -> String {
    let errors = format!(r#"[{{"code":{code},"message":"{message}"}}]"#);
    format!(r#"{{"success":false,"errors":{errors},"messages":[],"result":null}}"#)
}

fn success(result: &str) -> (u16, String) {
    (200, format!(r#"{{"success":true,"errors":[],"messages":[],"result":{result}}}"#))
}

/// The value of the member `key` of a flat JSON object whose strings have no escape
/// other than `\"`.
fn member(body: &str, key: &str) -> Option<String> {
    let start = body.find(&format!("\"{key}\":\""))? + key.len() + 4;
    let mut value = String::new();
    let mut letters = body[start..].chars();
    loop {
        match letters.next()? {
            '\\' => value.push(letters.next()?),
            '"' => return Some(value),
            letter => value.push(letter),
        }
    }
}

/// The value of the parameter `key` of a query string.
fn parameter<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
}

impl Api {
    /// Starts the API on a free loopback port. `table` is that of the DNS server.
    pub fn start(
        token: &str,
        zones: &[(&'static str, &'static str)],
        table: Arc<Mutex<Table>>,
    ) -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = Arc::new(Self {
            url: format!("http://{}/client/v4", listener.local_addr().unwrap()),
            token: token.to_owned(),
            zones: zones.to_vec(),
            calls: Mutex::default(),
            denied: Mutex::default(),
            records: Mutex::default(),
            table,
        });
        let serving = Arc::clone(&api);
        std::thread::spawn(move || {
            for socket in listener.incoming().flatten() {
                let api = Arc::clone(&serving);
                std::thread::spawn(move || api.serve(socket));
            }
        });
        api
    }

    /// The records that the API holds now: name and content without its quotes.
    pub fn records(&self) -> Vec<(String, String)> {
        let records = self.records.lock().unwrap();
        records
            .iter()
            .map(|record| (record.name.clone(), record.content.trim_matches('"').to_owned()))
            .collect()
    }

    /// Reads one request and answers it.
    fn serve(&self, mut socket: TcpStream) {
        let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        let mut first = String::new();
        if reader.read_line(&mut first).unwrap_or(0) == 0 {
            return;
        }
        let (mut length, mut bearer) = (0, String::new());
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 2 {
            if let Some((name, value)) = line.split_once(':') {
                match name.to_ascii_lowercase().as_str() {
                    "content-length" => length = value.trim().parse().unwrap_or(0),
                    "authorization" => bearer = value.trim().to_owned(),
                    _ => {}
                }
            }
            line.clear();
        }
        let mut body = vec![0; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let mut words = first.split_whitespace();
        let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        self.calls.lock().unwrap().push(format!("{method} {target}"));
        let (status, answer) = if bearer == format!("Bearer {}", self.token) {
            self.answer(method, target, &String::from_utf8_lossy(&body))
        } else {
            *self.denied.lock().unwrap() += 1;
            (403, failure(10_000, "Authentication error"))
        };
        let head = format!(
            "HTTP/1.1 {status} Answer\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            answer.len()
        );
        let _ = socket.write_all(head.as_bytes());
        let _ = socket.write_all(answer.as_bytes());
    }

    fn answer(&self, method: &str, target: &str, body: &str) -> (u16, String) {
        let Some(path) = target.strip_prefix("/client/v4/zones") else {
            return (404, failure(7003, "No route for that URI"));
        };
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        match (method, parts.as_slice()) {
            ("GET", []) => {
                let asked = parameter(query, "name").unwrap_or("");
                let found: Vec<String> = self
                    .zones
                    .iter()
                    .filter(|(name, _)| *name == asked)
                    .map(|(name, id)| format!(r#"{{"id":"{id}","name":"{name}"}}"#))
                    .collect();
                success(&format!("[{}]", found.join(",")))
            }
            (_, [zone, ..]) if !self.zones.iter().any(|(_, id)| id == zone) => {
                (404, failure(7003, "Could not route to the zone"))
            }
            ("POST", [zone, "dns_records"]) => self.create(zone, body),
            ("GET", [zone, "dns_records"]) => self.list(zone, query),
            ("DELETE", [_, "dns_records", id]) => self.delete(id),
            _ => (404, failure(7003, "No route for that URI")),
        }
    }

    fn create(&self, zone: &str, body: &str) -> (u16, String) {
        let fields = (member(body, "type"), member(body, "name"), member(body, "content"));
        let (Some(kind), Some(name), Some(content)) = fields else {
            return (400, failure(9005, "Content for the record is invalid"));
        };
        if kind != "TXT" || !body.contains("\"ttl\":120") {
            return (400, failure(9005, "Expected a TXT record with a TTL of 120"));
        }
        let mut records = self.records.lock().unwrap();
        if records.iter().any(|record| record.name == name && record.content == content) {
            return (400, failure(81_058, "An identical record already exists."));
        }
        let id = format!("rec{:04}", records.len() + 1);
        let value = content.trim_matches('"').to_owned();
        self.table.lock().unwrap().add(&name, Entry::Txt(value));
        records.push(Record { id: id.clone(), zone: zone.to_owned(), name, content });
        success(&format!(r#"{{"id":"{id}"}}"#))
    }

    fn list(&self, zone: &str, query: &str) -> (u16, String) {
        let name = parameter(query, "name").unwrap_or("");
        if parameter(query, "type") != Some("TXT") {
            return (400, failure(9005, "Expected the type TXT"));
        }
        let records = self.records.lock().unwrap();
        let found: Vec<String> = records
            .iter()
            .filter(|record| record.zone == zone && record.name == name)
            .map(|record| {
                let content = record.content.replace('"', "\\\"");
                format!(
                    r#"{{"id":"{}","type":"TXT","name":"{}","content":"{content}","ttl":120}}"#,
                    record.id, record.name
                )
            })
            .collect();
        success(&format!("[{}]", found.join(",")))
    }

    fn delete(&self, id: &str) -> (u16, String) {
        let mut records = self.records.lock().unwrap();
        let Some(at) = records.iter().position(|record| record.id == id) else {
            return (404, failure(81_044, "Record does not exist."));
        };
        let gone = records.remove(at);
        let entry = (gone.name.clone(), Entry::Txt(gone.content.trim_matches('"').to_owned()));
        self.table.lock().unwrap().records.retain(|found| *found != entry);
        success(&format!(r#"{{"id":"{id}"}}"#))
    }
}
