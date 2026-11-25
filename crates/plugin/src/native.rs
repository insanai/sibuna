//! The native tier: hooks compiled into the daemon (SID 0030, "The native tier").

use crate::verdict::{Failure, Verdict};
use crate::view::{Edits, View};

/// A hook written in Rust and compiled into the daemon. Each thread that serves traffic
/// builds its own, so a hook may keep state without a lock. It is trusted code: it runs
/// without a budget, and it must not block.
///
/// Every method has a default that admits, so a hook implements the stages it uses.
pub trait Hook: Send {
    /// Judges a new connection or UDP mapping.
    ///
    /// # Errors
    ///
    /// A [`Failure`], which the failure rule turns into an outcome.
    fn on_connection(&mut self, view: &View<'_>) -> Result<Verdict, Failure> {
        let _ = view;
        Ok(Verdict::Admit)
    }

    /// Judges an admitted request. It may add request fields to `edits`.
    ///
    /// # Errors
    ///
    /// A [`Failure`], which the failure rule turns into an outcome.
    fn on_request(&mut self, view: &View<'_>, edits: &mut Edits) -> Result<Verdict, Failure> {
        let _ = (view, edits);
        Ok(Verdict::Admit)
    }

    /// Observes a request whose answer ended.
    ///
    /// # Errors
    ///
    /// A [`Failure`], which drops the sample.
    fn on_telemetry(&mut self, view: &View<'_>) -> Result<(), Failure> {
        let _ = view;
        Ok(())
    }
}

/// One entry of the daemon's table of native hooks, fixed at build time.
#[derive(Clone, Copy)]
pub struct Native {
    /// The name that `hook` in the configuration selects.
    pub name: &'static str,
    /// Builds the hook from its settings, or says why the settings are wrong.
    pub build: fn(&[(String, String)]) -> Result<Box<dyn Hook>, String>,
}

impl std::fmt::Debug for Native {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Native").field("name", &self.name).finish_non_exhaustive()
    }
}
