//! The node command executor (unit U3; Zig's `console_node_commands.zig` and
//! `console_node_state.zig`): drain, resume and clear local bans.
//!
//! One command runs at a time. The intent (S30) commits first; authority and expiry are
//! checked again before the effect, which runs through [`crate::host::Node`]; then the
//! completion (S31) commits. A completion that cannot be recorded is kept in memory and
//! retried by the collector through [`Commands::retry`]; a clear never runs twice, because
//! a retry of a stored operation id returns its receipt instead of running it again. While
//! a completion is unrecorded no new command starts.
//!
//! ```text
//! request --> intent (S30) --> recheck authority, expiry --> effect --> completion (S31)
//!                | stored id: its receipt, no effect           | failed: kept, retried
//! ```
//!
//! The control revision counts applied commands since the console started (Zig's
//! `console_node.revision`); an operator names the revision it saw, so a command based on a
//! stale view is refused.
//!
//! # Changes from the Zig version
//!
//! - The storage owner's tick flushed the retained completion; here the collector calls
//!   [`Commands::retry`] with a background ticket, and a request flushes it first.
//! - A command that arrives while another one runs is refused with 503 `CONSOLENODE` at
//!   once instead of queueing behind it on the storage owner.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use sibuna_console_protocol::nodes::{Command, Kind, Receipt, State};
use sibuna_console_protocol::{Action, Text};
use sibuna_console_storage::nodes::{
    CommandState, Completed, Completion, Requested, complete_command, load_command,
    request_command,
};
use sibuna_console_storage::{Credential, Need, access};
use sibuna_encoding::hex;

use crate::http::RouteError;
use crate::shared::{Setup, Shared};
use crate::storage::{BackgroundTicket, StorageFailure};

/// What a node command needs: an operator's browser session with its CSRF digest.
const CONTROL: Need = Need::mutation(Action::ControlNode, None);

/// The failure code of node routes.
pub(crate) const CODE: &str = "CONSOLENODE";

/// A completion not yet recorded, with the receipt the operator was shown.
#[derive(Debug)]
struct Pending {
    receipt: Receipt,
    completion: Completion,
}

/// The executor's mutable state.
#[derive(Debug, Default)]
struct Progress {
    /// Applied commands since the console started.
    control_revision: u64,
    /// The completion awaiting its record.
    pending: Option<Pending>,
    /// The collector's outstanding retry of `pending`.
    retry: Option<BackgroundTicket<Completed>>,
}

/// The executor's state: the command in flight and completions awaiting their record.
#[derive(Debug)]
pub struct Commands {
    /// Held while a command runs; a second command is refused, not queued.
    running: Mutex<()>,
    state: Mutex<Progress>,
    started: Instant,
}

impl Default for Commands {
    fn default() -> Commands {
        Commands { running: Mutex::new(()), state: Mutex::default(), started: Instant::now() }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Every update of the state is a few assignments; a poisoned state is consistent.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Commands {
    /// Returns an idle executor.
    pub fn new(setup: &Setup<'_>) -> Commands {
        let _ = setup;
        Commands::default()
    }

    /// Returns the control revision: commands applied since the console started.
    pub fn control_revision(&self) -> u64 {
        lock(&self.state).control_revision
    }

    /// Returns true while a completion awaits its record.
    pub fn is_pending(&self) -> bool {
        lock(&self.state).pending.is_some()
    }

    /// Returns the milliseconds since the executor was built, at console start.
    pub fn uptime_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Returns the unrecorded receipt of operation `id`, if it is the pending one.
    pub fn pending_receipt(&self, id: &[u8; 16]) -> Option<Receipt> {
        let state = lock(&self.state);
        let pending = state.pending.as_ref()?;
        (pending.completion.id == *id).then(|| pending.receipt.clone())
    }

    /// Retries recording completions that could not be committed; called by the collector
    /// once per tick. Never blocks: it submits at most one background storage job and
    /// collects its result on a later call.
    pub fn retry(&self, shared: &Shared) {
        let mut state = lock(&self.state);
        let Some(completion) = state.pending.as_ref().map(|pending| pending.completion) else {
            state.retry = None;
            return;
        };
        match state.retry.as_mut().map(BackgroundTicket::try_take) {
            Some(None) => {}
            Some(Some(Ok(_))) => {
                state.retry = None;
                state.pending = None;
            }
            Some(Some(Err(_))) | None => {
                state.retry = shared
                    .storage
                    .submit_background(move |tx| {
                        Box::pin(async move { complete_command(tx, &completion).await })
                    })
                    .ok();
            }
        }
    }

    /// Records the pending completion now, for a request; returns true when nothing is
    /// pending any more.
    fn flush(&self, shared: &Shared) -> bool {
        let Some(completion) =
            lock(&self.state).pending.as_ref().map(|pending| pending.completion)
        else {
            return true;
        };
        let recorded = shared
            .storage
            .transact(move |tx| Box::pin(async move { complete_command(tx, &completion).await }));
        if recorded.is_err() {
            return false;
        }
        let mut state = lock(&self.state);
        if state.pending.as_ref().is_some_and(|pending| pending.completion == completion) {
            state.pending = None;
            state.retry = None;
        }
        true
    }

    /// Runs `command` for the operator `credential` names: intent, rechecks, effect,
    /// completion. Returns the receipt: of this run, or the stored one of a repeated
    /// operation id.
    ///
    /// Fails with 400 `CONSOLENODE` for another node, 409 for a stale boot or control
    /// revision or an operation id naming another command, 503 while another command runs
    /// or a completion cannot be recorded, and with the mapped storage refusal.
    pub fn execute(
        &self,
        shared: &Shared,
        credential: &Credential,
        command: &Command,
    ) -> Result<Receipt, RouteError> {
        let _running = self.running.try_lock().map_err(|_| RouteError::fail(503, CODE))?;
        if command.node != shared.identity.node_id {
            return Err(RouteError::fail(400, CODE));
        }
        if let Some(receipt) = self.pending_receipt(&command.id) {
            if !same_command(&receipt, command) {
                return Err(RouteError::fail(409, CODE));
            }
            let persisted = self.flush(shared);
            return Ok(Receipt { completion_persisted: persisted, ..receipt });
        }
        if !self.flush(shared) {
            return Err(RouteError::fail(503, CODE));
        }
        let receipt = match self.intent(shared, credential, command)? {
            Requested::Existing(receipt) => return Ok(receipt),
            Requested::Recorded(receipt) => receipt,
        };
        let authorized = self.recheck(shared, credential, command.expires);
        let completion = self.effect(shared, command, authorized);
        let receipt = Receipt {
            state: match completion.state {
                CommandState::Applied => State::Applied,
                _ => State::Rejected,
            },
            applied_revision: completion.applied_revision,
            cleared_entries: completion.cleared_entries,
            completed_at: Some(completion.completed_at),
            ..receipt
        };
        lock(&self.state).pending = Some(Pending { receipt: receipt.clone(), completion });
        let persisted = self.flush(shared);
        Ok(Receipt { completion_persisted: persisted, ..receipt })
    }

    /// Records the intent (S30), refusing a new command whose boot or control revision is
    /// stale; a stored operation id answers with its receipt instead.
    fn intent(
        &self,
        shared: &Shared,
        credential: &Credential,
        command: &Command,
    ) -> Result<Requested, RouteError> {
        let boot = shared.identity.boot;
        let control = self.control_revision();
        let (credential, command, now) = (credential.clone(), command.clone(), shared.now());
        shared
            .storage
            .transact(move |tx| {
                Box::pin(async move {
                    let stored = load_command(tx, &command.id).await?.is_some();
                    if !stored && (command.boot != boot || command.expected_revision != control) {
                        return Err(sibuna_console_storage::ConsoleStorageError::Conflict);
                    }
                    request_command(tx, &credential, &command, now).await
                })
            })
            .map_err(|failure| node_error(&failure))
    }

    /// Returns true when the credential still allows control and the command has not
    /// expired: a remote intent commit can span expiry or revocation, and no effect may use
    /// such an old grant.
    fn recheck(&self, shared: &Shared, credential: &Credential, expires: u64) -> bool {
        let (credential, now) = (credential.clone(), shared.now());
        let allowed = shared.storage.transact(move |tx| {
            Box::pin(async move { access::authorize_in(tx, &credential, CONTROL, now).await })
        });
        allowed.is_ok() && shared.now() < expires
    }

    /// Runs the local effect when `authorized` and returns the completion to record.
    fn effect(&self, shared: &Shared, command: &Command, authorized: bool) -> Completion {
        let mut completion = Completion {
            id: command.id,
            boot: command.boot,
            state: CommandState::Rejected,
            completed_at: 0,
            applied_revision: None,
            cleared_entries: None,
        };
        if authorized {
            match command.kind {
                Kind::Drain => shared.node.set_draining(true),
                Kind::Resume => shared.node.set_draining(false),
                Kind::ClearLocalBans => {
                    completion.cleared_entries = Some(shared.node.clear_local_bans(shared.now()));
                }
            }
            let revision = {
                let mut state = lock(&self.state);
                state.control_revision += 1;
                state.control_revision
            };
            completion.applied_revision = Some(revision);
            completion.state = CommandState::Applied;
            // Membership carries the control revision; the collector announces it soon.
            shared.live.request_announce(revision);
        }
        completion.completed_at = shared.now();
        completion
    }
}

/// Returns true when `receipt` records `command`: same node, boot, kind and revision.
fn same_command(receipt: &Receipt, command: &Command) -> bool {
    receipt.node == command.node
        && receipt.kind == command.kind
        && receipt.expected_revision == command.expected_revision
        && receipt.boot.as_str() == hex::encode(&command.boot)
}

/// Maps a node route's storage failure: refusals with Zig's statuses, everything else 503,
/// all as `CONSOLENODE`.
pub(crate) fn node_error(failure: &StorageFailure) -> RouteError {
    failure.route_error(CODE)
}

/// Returns `bytes` as 32 lowercase hex digits.
pub(crate) fn hex_id(bytes: &[u8; 16]) -> Text<32> {
    Text::from_string(hex::encode(bytes)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_match_the_command_they_record() {
        let command = Command { id: [1; 16], boot: [2; 16], node: 1, ..Command::default() };
        let receipt =
            Receipt { boot: hex_id(&[2; 16]), node: 1, kind: Kind::Drain, ..Receipt::default() };
        assert!(same_command(&receipt, &command));
        assert!(!same_command(&receipt, &Command { kind: Kind::Resume, ..command.clone() }));
        assert!(!same_command(&receipt, &Command { boot: [3; 16], ..command.clone() }));
        assert!(!same_command(&receipt, &Command { expected_revision: 1, ..command }));
        let commands = Commands::default();
        assert_eq!((commands.control_revision(), commands.is_pending()), (0, false));
        assert_eq!(commands.pending_receipt(&[1; 16]), None);
    }
}
