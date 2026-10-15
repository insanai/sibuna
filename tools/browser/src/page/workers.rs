//! Dedicated workers of a page: scripts that run before theirs, and their console output.
//!
//! The page auto-attaches to its child targets. For a worker we enable `Runtime`, so its
//! console messages and exceptions are collected with the page's. Once a worker script
//! is added, children start paused (`waitForDebuggerOnStart`) until we have run the
//! scripts; before that they are not paused, because the pause and the round trips it
//! needs delay the worker by tens of milliseconds, which distorts timings such as a
//! proof-of-work solve. Messages a worker logs before we attach may then be missed.

use std::time::Instant;

use sibuna_json::Value;

use super::Page;
use crate::cdp::{Params, field, string_at};
use crate::error::Error;

/// The most worker sessions tracked at once; further workers still run, unobserved.
const MAX_WORKERS: usize = 64;

/// Removes `WebAssembly` from a global scope, so a solver must use its fallback.
pub(crate) const REMOVE_WEBASSEMBLY: &str = "delete globalThis.WebAssembly;";

impl Page<'_> {
    /// Runs `source` in every dedicated worker the page starts from now on, before the
    /// worker's own script.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::call`], from asking Chromium to pause new workers.
    pub fn add_worker_script(&mut self, source: &str) -> Result<(), Error> {
        if self.worker_scripts.is_empty() {
            self.begin_auto_attach(true)?;
        }
        self.worker_scripts.push(source.to_owned());
        Ok(())
    }

    /// Removes the `WebAssembly` global from every later document and dedicated worker,
    /// before their scripts run, so code must take its JavaScript path.
    ///
    /// V8's `--noexpose_wasm` flag would be the obvious tool, but Chromium 155 ignores
    /// it (both `typeof WebAssembly` checks still see an object), and `--jitless`, which
    /// does remove WebAssembly, also slows every script to the interpreter's pace.
    ///
    /// # Errors
    ///
    /// The errors of [`Page::add_init_script`].
    pub fn disable_webassembly(&mut self) -> Result<(), Error> {
        self.add_init_script(REMOVE_WEBASSEMBLY)?;
        self.add_worker_script(REMOVE_WEBASSEMBLY)
    }

    /// Asks Chromium to attach to the page's children, pausing them until prepared when
    /// `pause` is set.
    pub(crate) fn begin_auto_attach(&mut self, pause: bool) -> Result<(), Error> {
        let params = Params::new()
            .bool("autoAttach", true)
            .bool("waitForDebuggerOnStart", pause)
            .bool("flatten", true);
        self.call("Target.setAutoAttach", &params)?;
        Ok(())
    }

    /// True when `session` belongs to a worker we observe.
    pub(crate) fn is_worker_session(&self, session: Option<&str>) -> bool {
        session.is_some_and(|id| self.workers.iter().any(|worker| worker == id))
    }

    /// Prepares a newly attached child target and lets it run.
    pub(crate) fn attach_child(&mut self, params: &Value<'_>) -> Result<(), Error> {
        let session = string_at(params, &["sessionId"]).to_owned();
        let kind = string_at(params, &["targetInfo", "type"]);
        if kind == "worker" && self.workers.len() < MAX_WORKERS {
            self.workers.push(session.clone());
            self.child_call(&session, "Runtime.enable", &Params::new())?;
            for index in 0..self.worker_scripts.len() {
                let source = self.worker_scripts.get(index).cloned().unwrap_or_default();
                let script = Params::new().string("expression", &source);
                self.child_call(&session, "Runtime.evaluate", &script)?;
            }
        }
        if field(params, &["waitingForDebugger"]).and_then(Value::as_bool) == Some(true) {
            self.child_call(&session, "Runtime.runIfWaitingForDebugger", &Params::new())?;
        }
        Ok(())
    }

    /// Forgets a worker session that ended.
    pub(crate) fn detach_child(&mut self, params: &Value<'_>) {
        let session = string_at(params, &["sessionId"]);
        self.workers.retain(|worker| worker != session);
    }

    /// A command to a child session. Events that arrive meanwhile stay queued for the
    /// caller's event loop, so handling an event never recurses into another.
    fn child_call(&mut self, session: &str, method: &str, params: &Params) -> Result<(), Error> {
        let deadline = Instant::now() + self.browser.options.command_timeout;
        match self.browser.connection.call(Some(session), method, params, deadline) {
            // A worker that ends while we prepare it is not an error of the page.
            Ok(_) | Err(Error::Command { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }
}
