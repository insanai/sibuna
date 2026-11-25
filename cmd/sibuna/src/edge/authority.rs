//! Persistent mode (SID 0028): the file of the node owns what belongs to its host, and
//! a database owns the published topology.
//!
//! ```text
//!   signal, watcher, admin `reload`          thread `edge-authority`        edge worker
//!   -----------------------------          -----------------------        -----------
//!   Source::load                             wait: NOTIFY, poll or a wake
//!     file + candidate, check                head(), revision(N), whole
//!     refused? file + served revision        file + revision N, check
//!     leave it in `pending`  ------------->  leave it in `pending`  ----->  reload
//!                                            cache, report  <-------------  settle:
//!                                                                           applied, or
//!                                                                           refused
//! ```
//!
//! The worker never waits for the database. A revision that does not check, and a
//! database that does not answer, change nothing that is served.

#[cfg(feature = "storage")]
mod cli;
#[cfg(feature = "storage")]
mod follower;

#[cfg(feature = "storage")]
pub(super) use cli::run;
#[cfg(feature = "storage")]
pub(super) use follower::{
    Slot, Stamp, cluster, describe, failure, follow, follows, is_node_file, load,
};

#[cfg(not(feature = "storage"))]
pub(super) use absent::{
    Slot, Stamp, cluster, describe, failure, follow, follows, is_node_file, load, run,
};

/// A build without storage: no file is a node file, and the commands say why.
#[cfg(not(feature = "storage"))]
mod absent {
    use std::io;
    use std::process::ExitCode;
    use std::sync::Arc;

    use super::super::watch::Source;
    use super::super::{Pending, Revision};

    /// Nothing: this build has no persistent mode.
    #[derive(Default)]
    pub(in super::super) struct Slot;

    impl Slot {
        /// Always succeeds: a build without storage serves files only.
        pub fn serve_file(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Never made in this build.
    pub(in super::super) struct Stamp(std::convert::Infallible);

    impl Stamp {
        /// Nothing to settle.
        pub fn settle(self, _refusal: Option<&io::Error>) {}
    }

    /// A file with `authority` is read as a topology here, and its reader refuses the
    /// section by its name.
    pub(in super::super) fn is_node_file(_document: &[u8]) -> bool {
        false
    }

    /// Never called: no file is a node file in this build.
    pub(in super::super) fn load(
        _node_file: &[u8],
        _slot: &Slot,
        _check: &dyn Fn(&[u8]) -> io::Result<Revision>,
    ) -> io::Result<Revision> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "this build has no storage"))
    }

    /// Nothing to follow.
    pub(in super::super) fn follow(source: &Arc<Source>, _pending: &Pending) -> io::Result<()> {
        // The slot of a build without storage only ever says "file".
        source.authority().serve_file()
    }

    /// No failure is one of the authority.
    pub(in super::super) fn failure(_error: &io::Error) -> Option<(&'static str, &'static str)> {
        None
    }

    /// No source follows a database in this build.
    pub(in super::super) fn follows(_source: &Source) -> bool {
        false
    }

    /// No revisions to show.
    pub(in super::super) fn cluster(_source: &Source) -> Option<String> {
        None
    }

    /// No authority to describe.
    pub(in super::super) fn describe(_source: &Source) -> Option<String> {
        None
    }

    /// `sibuna authority` in a build without storage.
    pub(in super::super) fn run(_args: &[String]) -> ExitCode {
        let mut text = String::new();
        let _ = sibuna_core::diagnostic::render(
            &mut text,
            "no storage (DBA005)",
            "This build has no SQLite and no PostgreSQL, and so no database authority.",
            "Build with the feature `sqlite` or `postgres`.",
        );
        eprint!("{text}");
        ExitCode::FAILURE
    }
}
