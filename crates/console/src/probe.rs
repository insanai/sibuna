//! Data-plane probes (unit U6; Zig's `cluster_probe.zig`): every 5 seconds, `GET
//! /__sibuna/health` and `/__sibuna/metrics` of each configured `--console-probe` target,
//! 2 seconds per probe, plain HTTP to numeric addresses only.

use sibuna_console_protocol::nodes::Probe;

use crate::shared::{Setup, Shared};

/// The latest verdict of every configured probe.
#[derive(Debug, Default)]
pub struct Probes {}

impl Probes {
    /// Returns the probes of the configuration, all unprobed.
    pub fn new(setup: &Setup<'_>) -> Probes {
        let _ = setup;
        Probes {}
    }

    /// Replaces the contents of `out` with the latest verdict of each configured probe, in
    /// configuration order (at most eight).
    pub fn snapshot(&self, out: &mut Vec<Probe>) {
        out.clear();
    }
}

/// The probe thread's body: returns when the console stops.
pub fn run(shared: &Shared) {
    let _ = shared;
}
