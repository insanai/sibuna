//! One file for every node of a mesh (SID 0023).
//!
//! `reload cluster` on one node reloads that node and then sends its file to every
//! peer. A peer that states `mesh.accept_config` checks the file, puts it in the place
//! of its own and reloads.
//!
//! ```text
//!   node A                                   node B (accept_config)
//!   reload cluster
//!     check and reload own file
//!     connect TCP B:mesh port  ------------> source address in the roster?
//!     SEC1 | stamp | length | file | tag --> tag right? stamp fresh and newer?
//!                                            write FILE.incoming, check it
//!                                            same mesh nodes? rename over FILE
//!     "ok" or "refused REASON" <------------ leave the revision for the worker
//! ```
//!
//! The tag is a keyed BLAKE3 hash under a key derived from the mesh key. The file is
//! not encrypted: a topology holds paths of secrets, not secrets.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sibuna_crypto::{blake3, ct};
use sibuna_lb::MeshConfig;

use super::watch::Source;
use super::{Pending, note};

/// The first bytes of a pushed file.
const MAGIC: &[u8; 4] = b"SEC1";
/// The bytes before the file: the magic, the stamp and the length.
const HEADER: usize = 16;
/// The bytes of the tag after the file.
const TAG: usize = 32;
/// The largest file a node takes from a peer.
const MAX_FILE: usize = 1 << 20;
/// How long a node waits for a peer, to connect and for each read and write.
const TIMEOUT: Duration = Duration::from_secs(5);
/// How far the stamp of a file may lie from the clock of the receiver.
const SKEW_MS: u64 = 60_000;
/// The longest answer of a peer that we read.
const MAX_ANSWER: u64 = 1024;

/// The peers of this node and the key that signs a pushed file.
pub(super) struct Peers {
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    key: [u8; 32],
}

fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// The bytes on the wire for `file`, stamped with the Unix millisecond `stamp`.
fn seal(key: &[u8; 32], stamp: u64, file: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(HEADER + file.len() + TAG);
    wire.extend_from_slice(MAGIC);
    wire.extend_from_slice(&stamp.to_be_bytes());
    wire.extend_from_slice(&(file.len() as u32).to_be_bytes());
    wire.extend_from_slice(file);
    let tag = blake3::keyed_hash(key, &wire);
    wire.extend_from_slice(&tag);
    wire
}

/// Reads one sealed file from `stream`. Returns its stamp and its bytes, or why the
/// message was not one: a wrong magic, a length beyond the limit, a cut or a wrong tag.
fn open(key: &[u8; 32], stream: &mut impl Read) -> Result<(u64, Vec<u8>), String> {
    let cut = |_| "the message was cut".to_owned();
    let mut wire = vec![0; HEADER];
    stream.read_exact(&mut wire).map_err(cut)?;
    if &wire[..4] != MAGIC {
        return Err("the message is not a configuration".to_owned());
    }
    let stamp = u64::from_be_bytes(wire[4..12].try_into().unwrap_or_default());
    let length = u32::from_be_bytes(wire[12..16].try_into().unwrap_or_default()) as usize;
    if length > MAX_FILE {
        return Err(format!("the file is longer than {MAX_FILE} bytes"));
    }
    wire.resize(HEADER + length, 0);
    stream.read_exact(&mut wire[HEADER..]).map_err(cut)?;
    let mut tag = [0; TAG];
    stream.read_exact(&mut tag).map_err(cut)?;
    if !ct::eq(&tag, &blake3::keyed_hash(key, &wire)) {
        return Err("the tag is wrong: the mesh keys differ, or the message was altered".into());
    }
    Ok((stamp, wire.split_off(HEADER)))
}

/// Whether a file stamped `stamp` may replace one stamped `last` at the time `now`: it
/// is newer, and its stamp lies within [`SKEW_MS`] of the clock. An old message sent
/// again is therefore refused.
fn is_fresh(stamp: u64, last: u64, now: u64) -> bool {
    stamp > last && stamp.abs_diff(now) <= SKEW_MS
}

/// Where a received file waits for its check: beside `path`, with the same extension,
/// so that it is read in the same language.
fn incoming(path: &str) -> String {
    let file = std::path::Path::new(path);
    match file.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => {
            let stem = &path[..path.len() - extension.len() - 1];
            format!("{stem}.incoming.{extension}")
        }
        None => format!("{path}.incoming"),
    }
}

impl Peers {
    /// The peers that `spec` names, with the key derived from the mesh key `secret`.
    pub fn new(spec: &MeshConfig, secret: &[u8; 32]) -> Self {
        let key = blake3::derive_key("sibuna/edge-mesh/config/v1", secret);
        Self { listen: spec.listen(), peers: spec.peers().to_vec(), key }
    }

    /// Sends `file` to every peer at once and returns what each answered: nothing for
    /// a peer that took the file, or why it did not.
    pub fn push(&self, file: &[u8]) -> Vec<(SocketAddr, Result<(), String>)> {
        let wire = seal(&self.key, unix_ms(), file);
        std::thread::scope(|scope| {
            let sends: Vec<_> = self
                .peers
                .iter()
                .map(|peer| (*peer, scope.spawn(|| send(*peer, &wire))))
                .collect();
            let joined = sends.into_iter().map(|(peer, send)| {
                (peer, send.join().unwrap_or_else(|_| Err("the send failed".to_owned())))
            });
            joined.collect()
        })
    }

    /// Takes files from the peers on the TCP port of the mesh address, on a thread of
    /// its own, until the process ends. Fails when the port cannot be bound.
    pub fn accept(self: Arc<Self>, source: Arc<Source>, pending: Pending) -> io::Result<()> {
        let listener = TcpListener::bind(self.listen)?;
        let serve = move || {
            let mut last = 0;
            for stream in listener.incoming() {
                // A failed accept belongs to one peer. A short pause keeps a
                // persistent failure from spinning.
                let Ok(mut stream) = stream else {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                };
                let answer = match self.receive(&mut stream, &source, &pending, &mut last) {
                    Ok(()) => "ok\n".to_owned(),
                    Err(reason) => format!("refused {}\n", reason.replace('\n', " ")),
                };
                let _ = stream.write_all(answer.as_bytes());
            }
        };
        std::thread::Builder::new().name("sibuna-cluster".to_owned()).spawn(serve)?;
        Ok(())
    }

    /// Takes one file from a peer: authenticates it, checks it as a reload would, puts
    /// it in the place of this node's file and leaves the revision for the worker.
    fn receive(
        &self,
        stream: &mut TcpStream,
        source: &Source,
        pending: &Pending,
        last: &mut u64,
    ) -> Result<(), String> {
        let text = |error: io::Error| error.to_string();
        let peer = stream.peer_addr().map_err(text)?;
        if !self.peers.iter().any(|known| known.ip() == peer.ip()) {
            return Err(format!("{} is not a node of this mesh", peer.ip()));
        }
        stream.set_read_timeout(Some(TIMEOUT)).map_err(text)?;
        stream.set_write_timeout(Some(TIMEOUT)).map_err(text)?;
        let (stamp, file) = open(&self.key, stream)?;
        if !is_fresh(stamp, *last, unix_ms()) {
            return Err("the file is older than the one in use, or the clocks differ by \
                        more than a minute"
                .to_owned());
        }
        let Some(path) = source.path() else {
            return Err("this node was started by `sibuna lb` and has no file".to_owned());
        };
        let waiting = incoming(path);
        let checked = self.check(&waiting, &file);
        if let Err(reason) = checked.and_then(|()| fs::rename(&waiting, path).map_err(text)) {
            let _ = fs::remove_file(&waiting);
            return Err(reason);
        }
        *last = stamp;
        let revision = source.load().map_err(text)?;
        *pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(revision);
        note(format_args!("EDGE011: configuration received from {}", peer.ip()));
        Ok(())
    }

    /// Writes `file` at `waiting` and checks it: it must be a valid topology that names
    /// the mesh as this node knows it.
    fn check(&self, waiting: &str, file: &[u8]) -> Result<(), String> {
        let text = |error: io::Error| error.to_string();
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(waiting).and_then(|mut out| out.write_all(file)).map_err(text)?;
        let revision = super::load(waiting).map_err(text)?;
        let same = revision.config.mesh().is_some_and(|mesh| {
            mesh.listen() == self.listen && mesh.peers() == self.peers.as_slice()
        });
        if !same {
            return Err("the file names another mesh, or this node by another address. \
                        Hint: list every node under mesh.nodes, the same on all nodes"
                .to_owned());
        }
        Ok(())
    }
}

/// Sends the sealed file to one peer and reads its answer.
fn send(peer: SocketAddr, wire: &[u8]) -> Result<(), String> {
    let text = |error: io::Error| error.to_string();
    let mut stream = TcpStream::connect_timeout(&peer, TIMEOUT).map_err(text)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(text)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(text)?;
    stream.write_all(wire).map_err(text)?;
    let mut answer = String::new();
    stream.take(MAX_ANSWER).read_to_string(&mut answer).map_err(text)?;
    match answer.trim_end() {
        "ok" => Ok(()),
        "" => Err("the peer closed without an answer. It may not state mesh.accept_config".into()),
        other => Err(other.strip_prefix("refused ").unwrap_or(other).to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn a_sealed_file_opens_and_any_change_or_cut_is_refused() {
        let wire = seal(&KEY, 42, b"{\"a\":1}");
        assert_eq!(open(&KEY, &mut &wire[..]), Ok((42, b"{\"a\":1}".to_vec())));
        for index in 0..wire.len() {
            let mut altered = wire.clone();
            altered[index] ^= 1;
            assert!(open(&KEY, &mut &altered[..]).is_err(), "byte {index}");
            assert!(open(&KEY, &mut &wire[..index]).is_err(), "cut at {index}");
        }
        assert!(open(&[8; 32], &mut &wire[..]).is_err());
    }

    #[test]
    fn a_length_beyond_the_limit_is_refused_before_it_is_read() {
        let mut wire = seal(&KEY, 1, b"");
        wire[12..16].copy_from_slice(&(MAX_FILE as u32 + 1).to_be_bytes());
        let refusal = open(&KEY, &mut &wire[..]).unwrap_err();
        assert!(refusal.contains("longer"), "{refusal}");
    }

    #[test]
    fn only_a_newer_file_with_a_stamp_near_the_clock_is_fresh() {
        let now = 10_000_000;
        assert!(is_fresh(now, 0, now));
        assert!(is_fresh(now + SKEW_MS, now, now));
        assert!(!is_fresh(now, now, now), "the same message again");
        assert!(!is_fresh(now - 1, now, now), "an older message");
        assert!(!is_fresh(now - SKEW_MS - 1, 0, now), "a stale message after a restart");
        assert!(!is_fresh(now + SKEW_MS + 1, 0, now));
    }

    #[test]
    fn the_waiting_file_keeps_the_extension() {
        assert_eq!(incoming("/etc/sibuna/edge.jlv"), "/etc/sibuna/edge.incoming.jlv");
        assert_eq!(incoming("edge.json"), "edge.incoming.json");
        assert_eq!(incoming("/etc/sibuna/edge"), "/etc/sibuna/edge.incoming");
    }
}
