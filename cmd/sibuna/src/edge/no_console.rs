//! The place of the operator console (SID 0031) in a build without it: a build without
//! the `console` feature, or for a system without Unix sockets. A file with a `console`
//! section is refused at start, and at a reload.

use std::io;
use std::sync::Arc;
use std::sync::mpsc::Sender;

use sibuna_lb::{ConsoleOptions, Edge, Regime, Stats};

use super::admin;
use super::watch::Source;
use crate::access::Observe;

/// The side of the edge worker: nothing.
pub(super) struct Link;

/// What a console would read of the edge.
pub(super) struct Parts {
    pub stats: Arc<Stats>,
    pub observe: Arc<Observe>,
    pub source: Arc<Source>,
    pub jobs: Sender<admin::Job>,
    /// The ban table of the edge (SID 0034).
    pub defense: Arc<sibuna_lb::Defense>,
}

fn absent() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the console section needs a build with the console feature, on a Unix system",
    )
}

impl Link {
    /// Refuses a `console` section.
    pub fn start(options: Option<&ConsoleOptions>, parts: Parts) -> io::Result<Self> {
        drop((parts.stats, parts.observe, parts.source, parts.jobs, parts.defense));
        if options.is_some() { Err(absent()) } else { Ok(Self) }
    }

    /// Does nothing.
    pub fn set_regime(&mut self, _regime: Regime) {}

    /// Does nothing.
    pub fn turn(&self, _edge: &Edge, _reloads: u64) {}

    /// Refuses a `console` section.
    pub fn plan(&self, next: Option<&ConsoleOptions>) -> io::Result<Vec<u32>> {
        if next.is_some() { Err(absent()) } else { Ok(Vec::new()) }
    }

    /// Does nothing.
    pub fn apply(&self, _removed: &[u32], _next: Option<&ConsoleOptions>) {}
}
