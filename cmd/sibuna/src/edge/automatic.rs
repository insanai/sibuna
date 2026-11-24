//! Starts automatic HTTPS for the edge and carries it through a reload (SID 0021).
//!
//! The certificate thread starts once, with the daemon. A reload may add and remove
//! `auto` names. It cannot change `global.acme`, and it cannot start the thread.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use sibuna_ingress::{Automatic, Identity};
use sibuna_lb::AutomaticHttps;

/// Starts the certificate thread when the topology has `auto` names, and lets the TLS
/// listeners read its certificates. Fails only when the thread cannot be spawned.
pub(super) fn start(
    config: Option<AutomaticHttps>,
    identities: &BTreeMap<SocketAddr, Identity>,
) -> io::Result<Option<Arc<Automatic>>> {
    let Some(config) = config else { return Ok(None) };
    super::note(format_args!(
        "Sibuna edge: automatic HTTPS for {} name(s) from {}, storage {}",
        config.names.len(),
        config.options.directory,
        config.options.storage
    ));
    let automatic = Arc::new(Automatic::start(config, Arc::new(crate::acme::log))?);
    manage(&automatic, identities);
    Ok(Some(automatic))
}

fn manage(automatic: &Automatic, identities: &BTreeMap<SocketAddr, Identity>) {
    for identity in identities.values() {
        identity.manage(automatic);
    }
}

/// Whether a reload can go from the running state to `next` without a restart.
pub(super) fn compatible(running: Option<&Arc<Automatic>>, next: Option<&AutomaticHttps>) -> bool {
    match (running, next) {
        (Some(running), Some(next)) => *running.options() == next.options,
        // The names may all leave. The thread then has nothing to renew.
        (_, None) => true,
        (None, Some(_)) => false,
    }
}

/// Gives the names of a reloaded topology to the running thread, and lets the new
/// identities read its certificates.
pub(super) fn reload(
    running: Option<&Arc<Automatic>>,
    next: Option<AutomaticHttps>,
    identities: &BTreeMap<SocketAddr, Identity>,
) {
    let Some(running) = running else { return };
    manage(running, identities);
    match next {
        Some(next) => running.set_names(next.names, next.plain_frontend),
        None => running.set_names(Vec::new(), false),
    }
}
