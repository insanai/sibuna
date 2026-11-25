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
//!                                            check the received bytes
//!                                            same mesh nodes? install FILE
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
/// The first bytes of a question for the digest of the file of a node.
const ASK: &[u8; 4] = b"SEQ1";
/// The bytes of a question: the magic, the stamp and the tag.
const QUESTION: usize = 12 + TAG;
/// The hexadecimal digits of a digest as we show it.
const DIGEST: usize = 16;
/// The bytes before the file: the magic, the stamp and the length.
const HEADER: usize = 16;
/// The bytes of the tag after the file.
const TAG: usize = 32;
/// The largest file a node takes from a peer.
const MAX_FILE: usize = sibuna_lb::Config::DOCUMENT_LIMITS.max_input_bytes;
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

/// The digest of a file as `show cluster` prints it: the first digits of its BLAKE3 hash.
pub(super) fn digest(file: &[u8]) -> String {
    let hash = blake3::hash(file);
    hash.iter().take(DIGEST / 2).map(|byte| format!("{byte:02x}")).collect()
}

/// A question for the digest, stamped with the Unix millisecond `stamp`.
fn question(key: &[u8; 32], stamp: u64) -> Vec<u8> {
    let mut wire = Vec::with_capacity(QUESTION);
    wire.extend_from_slice(ASK);
    wire.extend_from_slice(&stamp.to_be_bytes());
    let tag = blake3::keyed_hash(key, &wire);
    wire.extend_from_slice(&tag);
    wire
}

/// The tag of an answer to the question stamped `stamp`: it binds the digest to the
/// question, so an old answer cannot stand for a new one.
fn answer_tag(key: &[u8; 32], stamp: u64, digest: &str) -> String {
    let mut signed = stamp.to_be_bytes().to_vec();
    signed.extend_from_slice(digest.as_bytes());
    let tag = blake3::keyed_hash(key, &signed);
    tag.iter().take(16).map(|byte| format!("{byte:02x}")).collect()
}

/// Whether a file stamped `stamp` may replace one stamped `last` at the time `now`: it
/// is newer, and its stamp lies within [`SKEW_MS`] of the clock. An old message sent
/// again is therefore refused.
fn is_fresh(stamp: u64, last: u64, now: u64) -> bool {
    stamp > last && stamp.abs_diff(now) <= SKEW_MS
}

/// Replaces the destination only after the complete checked source is on disk.
fn install(path: &str, bytes: &[u8]) -> io::Result<super::watch::Stamp> {
    let mut nonce = [0; 12];
    crate::random::fill(&mut nonce)?;
    let temporary = std::path::Path::new(path)
        .with_file_name(format!(".sibuna-{}.tmp", sibuna_encoding::hex::encode(&nonce)));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out = options.open(&temporary)?;
    let result = out.write_all(bytes).and_then(|()| out.sync_all()).and_then(|()| out.metadata());
    drop(out);
    let result = result.and_then(|metadata| {
        fs::rename(&temporary, path)?;
        Ok(super::watch::Stamp::from_file(&metadata))
    });
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

impl Peers {
    /// The peers that `spec` names, with the key derived from the mesh key `secret`.
    pub fn new(spec: &MeshConfig, secret: &[u8; 32]) -> Self {
        let key = blake3::derive_key("sibuna/edge-mesh/config/v1", secret);
        Self { listen: spec.listen(), peers: spec.peers().to_vec(), key }
    }

    /// The mesh address of this node.
    pub fn listen(&self) -> SocketAddr {
        self.listen
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

    /// Asks every peer at once for the digest of its file. Returns the digest of each,
    /// or why it gave none.
    pub fn ask(&self) -> Vec<(SocketAddr, Result<String, String>)> {
        let stamp = unix_ms();
        let wire = question(&self.key, stamp);
        std::thread::scope(|scope| {
            let asks: Vec<_> = self
                .peers
                .iter()
                .map(|peer| (*peer, scope.spawn(|| self.ask_one(*peer, &wire, stamp))))
                .collect();
            let joined = asks.into_iter().map(|(peer, ask)| {
                (peer, ask.join().unwrap_or_else(|_| Err("the question failed".to_owned())))
            });
            joined.collect()
        })
    }

    fn ask_one(&self, peer: SocketAddr, wire: &[u8], stamp: u64) -> Result<String, String> {
        let answer = exchange(peer, wire)?;
        let mut words = answer.split_ascii_whitespace();
        match (words.next(), words.next(), words.next()) {
            (Some("digest"), Some(digest), Some(tag))
                if ct::eq(tag.as_bytes(), answer_tag(&self.key, stamp, digest).as_bytes()) =>
            {
                Ok(digest.to_owned())
            }
            (Some("digest"), ..) => Err("the answer is not signed with our mesh key".to_owned()),
            _ => Err(answer.strip_prefix("refused ").unwrap_or(&answer).to_owned()),
        }
    }

    /// Answers a question for the digest of this node's file.
    fn tell(&self, stream: &mut impl Read, source: &Source) -> Result<String, String> {
        let mut wire = [0; QUESTION];
        stream.read_exact(&mut wire).map_err(|_| "the message was cut".to_owned())?;
        let (signed, tag) = wire.split_at(12);
        if !ct::eq(tag, &blake3::keyed_hash(&self.key, signed)) {
            return Err("the tag is wrong: the mesh keys differ".to_owned());
        }
        let stamp = u64::from_be_bytes(signed[4..12].try_into().unwrap_or_default());
        if stamp.abs_diff(unix_ms()) > SKEW_MS {
            return Err("the clocks differ by more than a minute".to_owned());
        }
        let path = source.path().ok_or("this node has no file")?;
        let digest = digest(&super::read_file(path).map_err(|error| error.to_string())?);
        Ok(format!("digest {digest} {}\n", answer_tag(&self.key, stamp, &digest)))
    }

    /// Serves the peers on the TCP port of the mesh address, on a thread of its own,
    /// until the process ends: it tells the digest of this node's file, and with
    /// `take_files` it takes the file of a peer. Fails when the port cannot be bound.
    pub fn accept(
        self: Arc<Self>,
        source: Arc<Source>,
        pending: Pending,
        take_files: bool,
    ) -> io::Result<()> {
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
                let answer = self.serve(&mut stream, &source, &pending, &mut last, take_files);
                let answer = answer
                    .unwrap_or_else(|reason| format!("refused {}\n", reason.replace('\n', " ")));
                let _ = stream.write_all(answer.as_bytes());
            }
        };
        std::thread::Builder::new().name("sibuna-cluster".to_owned()).spawn(serve)?;
        Ok(())
    }

    /// Serves one connection of a peer: a question for the digest, or a file.
    fn serve(
        &self,
        stream: &mut TcpStream,
        source: &Source,
        pending: &Pending,
        last: &mut u64,
        take_files: bool,
    ) -> Result<String, String> {
        let text = |error: io::Error| error.to_string();
        let peer = stream.peer_addr().map_err(text)?;
        if !self.peers.iter().any(|known| known.ip() == peer.ip()) {
            return Err(format!("{} is not a node of this mesh", peer.ip()));
        }
        stream.set_read_timeout(Some(TIMEOUT)).map_err(text)?;
        stream.set_write_timeout(Some(TIMEOUT)).map_err(text)?;
        let mut magic = [0; 4];
        stream.read_exact(&mut magic).map_err(text)?;
        let mut message = magic.as_slice().chain(stream);
        if &magic == ASK {
            return self.tell(&mut message, source);
        }
        if !take_files {
            return Err("this node does not state mesh.accept_config".to_owned());
        }
        self.receive(&mut message, peer, source, pending, last).map(|()| "ok\n".to_owned())
    }

    /// Takes one file from a peer: authenticates it, checks it as a reload would, puts
    /// it in the place of this node's file and leaves the revision for the worker.
    fn receive(
        &self,
        stream: &mut impl Read,
        peer: SocketAddr,
        source: &Source,
        pending: &Pending,
        last: &mut u64,
    ) -> Result<(), String> {
        let text = |error: io::Error| error.to_string();
        let (stamp, file) = open(&self.key, stream)?;
        // A node that follows a database keeps the file of its host (SID 0028).
        if super::authority::follows(source) {
            return Err("this node follows a database and keeps its own file".to_owned());
        }
        if !is_fresh(stamp, *last, unix_ms()) {
            return Err("the file is older than the one in use, or the clocks differ by \
                        more than a minute"
                .to_owned());
        }
        let Some(path) = source.path() else {
            return Err("this node was started by `sibuna lb` and has no file".to_owned());
        };
        let revision = self.check(path, &file)?;
        let installed = install(path, &file).map_err(text)?;
        source.mark_loaded(Some(installed));
        *last = stamp;
        *pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(revision);
        note(format_args!("EDGE011: configuration received from {}", peer.ip()));
        Ok(())
    }

    /// Prepares the exact source that will be installed, using the node's file language.
    fn check(&self, path: &str, file: &[u8]) -> Result<super::Revision, String> {
        let document = super::evaluate(path, file.to_vec()).map_err(|e| e.to_string())?;
        let revision = super::revision(&document).map_err(|e| e.to_string())?;
        let same = revision.config.mesh().is_some_and(|mesh| {
            mesh.listen() == self.listen && mesh.peers() == self.peers.as_slice()
        });
        if !same {
            return Err("the file names another mesh, or this node by another address. \
                        Hint: list every node under mesh.nodes, the same on all nodes"
                .to_owned());
        }
        Ok(revision)
    }
}

/// Sends the sealed file to one peer and reads its answer.
fn send(peer: SocketAddr, wire: &[u8]) -> Result<(), String> {
    match exchange(peer, wire)?.as_str() {
        "ok" => Ok(()),
        other => Err(other.strip_prefix("refused ").unwrap_or(other).to_owned()),
    }
}

/// Sends one message to a peer and returns the line it answers.
fn exchange(peer: SocketAddr, wire: &[u8]) -> Result<String, String> {
    let text = |error: io::Error| error.to_string();
    let mut stream = TcpStream::connect_timeout(&peer, TIMEOUT).map_err(text)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(text)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(text)?;
    stream.write_all(wire).map_err(text)?;
    let mut answer = String::new();
    stream.take(MAX_ANSWER).read_to_string(&mut answer).map_err(text)?;
    if answer.trim_end().is_empty() {
        return Err("the peer closed without an answer".to_owned());
    }
    Ok(answer.trim_end().to_owned())
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
    fn an_answer_belongs_to_its_question_and_its_digest() {
        let tag = answer_tag(&KEY, 5, "00ff");
        assert_ne!(tag, answer_tag(&KEY, 6, "00ff"), "another question");
        assert_ne!(tag, answer_tag(&KEY, 5, "00fe"), "another digest");
        assert_ne!(tag, answer_tag(&[8; 32], 5, "00ff"), "another key");
        assert_eq!(digest(b"a").len(), DIGEST);
        assert_ne!(digest(b"a"), digest(b"b"));
        assert_eq!(question(&KEY, 5).len(), QUESTION);
    }
}
