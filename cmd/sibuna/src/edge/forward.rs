//! Turns peer forwarding on when the topology asks for it (SID 0026).

use std::fs::File;
use std::io::{self, Read};

use sibuna_lb::Edge;

/// Opens the forwarding port of `edge` when its topology has `mesh.forward`. With
/// `shared` a replacement process may bind the port too (`global.reuse_port`).
///
/// # Errors
///
/// The key file cannot be read or does not hold 32 bytes, no random bytes are to be
/// had, or the port cannot be bound. The edge then does not start.
pub(super) fn begin(edge: &mut Edge, shared: bool) -> io::Result<()> {
    let Some(path) = edge.forward_key_file().map(str::to_owned) else { return Ok(()) };
    let mut key = [0; 32];
    let mut file = File::open(&path)?;
    file.read_exact(&mut key)?;
    if file.read(&mut [0])? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mesh key must be 32 bytes"));
    }
    let mut boot = [0; 16];
    crate::random::fill(&mut boot)?;
    edge.begin_forwarding(&key, boot, shared)
}
