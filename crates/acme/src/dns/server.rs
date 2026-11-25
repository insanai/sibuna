//! A small authoritative DNS server for tests. It answers from a table over UDP and
//! TCP, and takes dynamic updates of TXT records, signed with TSIG when it has a key.
//!
//! The module exists with the feature `test-server` only. It is no server for the
//! Internet: it reads a question and trusts the table.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use super::tsig::{self, TsigKey};
use super::wire::{self, CLASS_IN, CLASS_NONE, Data, Message, TYPE_CNAME, TYPE_TSIG, TYPE_TXT};
use super::{unix_now, wire::HEADER};

/// How long a thread of the server waits before it looks at the stop flag.
const TICK: Duration = Duration::from_millis(20);
/// The opcode of a dynamic update.
const OPCODE_UPDATE: u8 = 5;
/// The response codes the server sends besides 0.
const NXDOMAIN: u8 = 3;
const REFUSED: u8 = 5;
const NOTAUTH: u8 = 9;

/// The data of one record of the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// The start of a zone.
    Soa,
    /// A name server of a zone.
    Ns(String),
    /// An alias.
    Cname(String),
    /// An address.
    A(Ipv4Addr),
    /// A text.
    Txt(String),
}

impl Entry {
    fn kind(&self) -> u16 {
        match self {
            Self::Soa => wire::TYPE_SOA,
            Self::Ns(_) => wire::TYPE_NS,
            Self::Cname(_) => TYPE_CNAME,
            Self::A(_) => wire::TYPE_A,
            Self::Txt(_) => TYPE_TXT,
        }
    }

    fn data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        match self {
            // Two root names and five numbers of 32 bits.
            Self::Soa => data.resize(22, 0),
            Self::Ns(target) | Self::Cname(target) => {
                let _ = wire::write_name(&mut data, target);
            }
            Self::A(address) => data.extend_from_slice(&address.octets()),
            Self::Txt(text) => {
                data.push(text.len().min(255) as u8);
                data.extend_from_slice(&text.as_bytes()[..text.len().min(255)]);
            }
        }
        data
    }
}

/// What the server knows and what it saw.
#[derive(Debug, Default)]
pub struct Table {
    /// The records: the owner in lower case without a final dot, and the data.
    pub records: Vec<(String, Entry)>,
    /// The key that every update must be signed with.
    pub key: Option<TsigKey>,
    /// A file of more TXT records, one `OWNER VALUE` per line, read for every question.
    /// A hook program of a test writes it.
    pub txt_file: Option<PathBuf>,
    /// Cut every answer over UDP, so that the client asks again over TCP.
    pub truncate_udp: bool,
    /// Answer no question for a TXT record, as a dead server.
    pub silent: bool,
    /// The updates that were applied: owner, value, and whether it was a delete.
    pub updates: Vec<(String, String, bool)>,
    /// How many questions were answered over TCP.
    pub tcp_count: u32,
}

impl Table {
    /// Adds a record.
    pub fn add(&mut self, owner: &str, entry: Entry) {
        self.records.push((owner.trim_end_matches('.').to_ascii_lowercase(), entry));
    }

    /// The TXT values at `owner`, from the table and from the file.
    pub fn texts(&self, owner: &str) -> Vec<String> {
        self.all()
            .into_iter()
            .filter_map(|(name, entry)| match entry {
                Entry::Txt(text) if name == owner => Some(text),
                _ => None,
            })
            .collect()
    }

    fn all(&self) -> Vec<(String, Entry)> {
        let mut records = self.records.clone();
        let file = self.txt_file.as_ref().and_then(|path| std::fs::read_to_string(path).ok());
        for line in file.as_deref().unwrap_or_default().lines().take(256) {
            if let Some((owner, value)) = line.trim().split_once(' ') {
                let owner = owner.trim_end_matches('.').to_ascii_lowercase();
                records.push((owner, Entry::Txt(value.to_owned())));
            }
        }
        records
    }
}

fn header(request: &[u8], rcode: u8, answers: u16) -> Vec<u8> {
    let mut out = request[..HEADER].to_vec();
    // Response, authoritative, the opcode of the request, the response code.
    out[2] = 0x84 | (request[2] & 0x78);
    out[3] = rcode;
    out[4..6].copy_from_slice(&[0, 1]);
    out[6..8].copy_from_slice(&answers.to_be_bytes());
    out[8..12].copy_from_slice(&[0; 4]);
    out
}

/// The answer to a question: the records at the name, through its aliases.
fn answer(table: &Table, request: &[u8], message: &Message, question_end: usize) -> Vec<u8> {
    let Some((asked, kind)) = &message.question else { return header(request, REFUSED, 0) };
    let records = table.all();
    let mut found = Vec::new();
    let mut name = asked.clone();
    let mut exists = false;
    for _ in 0..8 {
        let here = records.iter().filter(|(owner, _)| *owner == name);
        let (aliases, others): (Vec<_>, Vec<_>) =
            here.partition(|(_, entry)| entry.kind() == TYPE_CNAME);
        exists |= !aliases.is_empty() || !others.is_empty();
        found.extend(others.into_iter().filter(|(_, entry)| entry.kind() == *kind).cloned());
        match aliases.first() {
            Some((owner, Entry::Cname(target))) => {
                found.push((owner.clone(), Entry::Cname(target.clone())));
                if *kind == TYPE_CNAME {
                    break;
                }
                name.clone_from(target);
            }
            _ => break,
        }
    }
    let rcode = if exists { 0 } else { NXDOMAIN };
    let mut out = header(request, rcode, found.len() as u16);
    out.extend_from_slice(&request[HEADER..question_end]);
    for (owner, entry) in &found {
        let data = entry.data();
        let _ = wire::write_name(&mut out, owner);
        out.extend_from_slice(&entry.kind().to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    }
    out
}

/// The time a signed request was signed at, when its signature is that of `key`.
fn signed_time(request: &[u8], message: &Message, key: &TsigKey) -> Option<([u8; 32], u64)> {
    let record = message.records.last().filter(|record| record.kind == TYPE_TSIG)?;
    let Data::Other(data) = &record.data else { return None };
    let (_, at) = wire::read_name(data, 0)?;
    let mut time = [0; 8];
    time[2..].copy_from_slice(data.get(at..at + 6)?);
    let time = u64::from_be_bytes(time);
    let mut unsigned = request[..record.start].to_vec();
    let additional = u16::from_be_bytes([request[10], request[11]]).checked_sub(1)?;
    unsigned[10..12].copy_from_slice(&additional.to_be_bytes());
    let mac = tsig::sign(&mut unsigned, key, time).ok()?;
    (unsigned == request && unix_now().abs_diff(time) <= 300).then_some((mac, time))
}

/// Applies an update of TXT records and returns the answer.
fn update(table: &mut Table, request: &[u8], message: &Message, question_end: usize) -> Vec<u8> {
    let reply = |rcode| {
        let mut out = header(request, rcode, 0);
        out.extend_from_slice(&request[HEADER..question_end]);
        out
    };
    let signature = match &table.key {
        None => None,
        Some(key) => match signed_time(request, message, key) {
            Some((mac, _)) => Some((key.clone(), mac)),
            None => return reply(NOTAUTH),
        },
    };
    let zone = message.question.as_ref().map(|(zone, _)| zone.clone()).unwrap_or_default();
    let known = table.records.iter().any(|(owner, entry)| *owner == zone && *entry == Entry::Soa);
    if !known {
        return reply(REFUSED);
    }
    for record in &message.records {
        let Data::Txt(text) = &record.data else { continue };
        let value = String::from_utf8_lossy(text).into_owned();
        let inside = record.name == zone || record.name.ends_with(&format!(".{zone}"));
        if !inside {
            return reply(REFUSED);
        }
        let entry = (record.name.clone(), Entry::Txt(value.clone()));
        match record.class {
            CLASS_IN => table.records.push(entry),
            CLASS_NONE => table.records.retain(|found| *found != entry),
            _ => continue,
        }
        table.updates.push((record.name.clone(), value, record.class == CLASS_NONE));
    }
    let mut out = reply(0);
    if let Some((key, mac)) = signature {
        let _ = tsig::sign_answer(&mut out, &key, unix_now(), &mac);
    }
    out
}

/// The answer to one request, or `None` for bytes that are no request.
fn respond(table: &Mutex<Table>, request: &[u8], over_tcp: bool) -> Option<Vec<u8>> {
    let message = wire::parse(request)?;
    let (_, name_end) = wire::read_name(request, HEADER)?;
    let question_end = name_end + 4;
    let mut table = table.lock().unwrap_or_else(PoisonError::into_inner);
    let is_text = message.question.as_ref().is_some_and(|(_, kind)| *kind == TYPE_TXT);
    if table.silent && is_text {
        return None;
    }
    if !over_tcp && table.truncate_udp {
        let mut out = header(request, 0, 0);
        out[2] |= 0x02;
        out.extend_from_slice(&request[HEADER..question_end]);
        return Some(out);
    }
    table.tcp_count += u32::from(over_tcp);
    if (request[2] >> 3) & 0x0f == OPCODE_UPDATE {
        return Some(update(&mut table, request, &message, question_end));
    }
    Some(answer(&table, request, &message, question_end))
}

/// A running server. Dropping it stops its two threads.
#[derive(Debug)]
pub struct Server {
    /// The address of the server, the same for UDP and TCP.
    pub address: SocketAddr,
    /// The table. Lock it to change what the server answers and to see what it saw.
    pub table: Arc<Mutex<Table>>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Server {
    /// Starts a server at `address` of the loopback interface. A port of 0 asks for a
    /// free one, the same for UDP and TCP. TCP is bound first: tests that run beside
    /// this one take and release TCP ports all the time, and UDP ports hardly ever. The
    /// call tries other ports when the second socket finds its port taken.
    pub fn start(address: SocketAddr) -> io::Result<Self> {
        let mut last = io::Error::other("no port");
        for _ in 0..64 {
            let tcp = match TcpListener::bind(address) {
                Ok(tcp) => tcp,
                Err(error) => {
                    last = error;
                    continue;
                }
            };
            let bound = tcp.local_addr()?;
            match UdpSocket::bind(bound) {
                Ok(udp) => return Self::serve(udp, tcp, bound),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Starts a server at a free port of `127.0.0.1`.
    pub fn start_local() -> io::Result<Self> {
        Self::start(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
    }

    fn serve(udp: UdpSocket, tcp: TcpListener, address: SocketAddr) -> io::Result<Self> {
        udp.set_read_timeout(Some(TICK))?;
        tcp.set_nonblocking(true)?;
        let table = Arc::new(Mutex::new(Table::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (shared, stopped) = (Arc::clone(&table), Arc::clone(&stop));
        let over_udp = std::thread::spawn(move || {
            let mut buffer = [0; 4096];
            while !stopped.load(Ordering::Relaxed) {
                let Ok((length, peer)) = udp.recv_from(&mut buffer) else { continue };
                if let Some(answer) = respond(&shared, &buffer[..length], false) {
                    let _ = udp.send_to(&answer, peer);
                }
            }
        });
        let (shared, stopped) = (Arc::clone(&table), Arc::clone(&stop));
        let over_tcp = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = tcp.accept() else {
                    std::thread::sleep(TICK);
                    continue;
                };
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut prefix = [0; 2];
                if stream.read_exact(&mut prefix).is_err() {
                    continue;
                }
                let mut request = vec![0; usize::from(u16::from_be_bytes(prefix))];
                if stream.read_exact(&mut request).is_err() {
                    continue;
                }
                if let Some(answer) = respond(&shared, &request, true) {
                    let mut framed = (answer.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&answer);
                    let _ = stream.write_all(&framed);
                }
            }
        });
        Ok(Self { address, table, stop, threads: vec![over_udp, over_tcp] })
    }

    /// Runs `change` with the table locked.
    pub fn with<T>(&self, change: impl FnOnce(&mut Table) -> T) -> T {
        change(&mut self.table.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
