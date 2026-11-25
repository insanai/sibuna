//! Hooks for the Sibuna edge (SID 0030): code of the operator that judges traffic.
//!
//! A hook attaches to a frontend at a [`Stage`]. It reads a [`View`] of a flow or a
//! request and answers a [`Verdict`]. Three tiers run hooks, and all three sit behind
//! the same call:
//!
//! - **native**: a [`Hook`] compiled into the daemon. Trusted, no budget.
//! - **wasm**: a module run by the interpreter of [`wasm`], under fuel, a page budget
//!   and a bound on host calls.
//! - **agent**: another process on a Unix socket, behind a deadline, a bounded queue
//!   and a [`Breaker`].
//!
//! ```text
//!  configuration --> [Settings] --[Plan::load]--> [Plan] --[Slot::publish]--> [Slot]
//!                                 reads modules,   immutable,                   |
//!                                 validates        shared                       v
//!  request thread: [Local::run_request(slot, view)] --> [Decision]     one atomic load
//!                   owns its instances: Wasm memories,                 when nothing
//!                   agent connections, breakers                        is attached
//! ```
//!
//! A thread that serves traffic owns a [`Local`]. No lock is taken on the request path.
//! When an invocation fails, [`outcome`] decides: a hook denies unless its plugin says
//! `on_failure: "admit"`, and a telemetry hook only loses its sample.
//!
//! The crate uses the standard library only.

mod agent;
mod breaker;
mod native;
mod set;
mod spec;
mod verdict;
mod view;
pub mod wasm;
mod wasm_hook;

pub use agent::{
    FRAME_HEADER, Frame, FrameKind, MAX_FRAME, PROTOCOL_VERSION, read_frame, write_frame,
};
pub use breaker::{Breaker, BreakerLimits};
pub use native::{Hook, Native};
pub use set::{Decision, Local, Plan, PluginStatus, Slot};
pub use spec::{AgentSpec, Attach, Error, Kind, Settings, Spec, WasmSpec};
pub use verdict::{Failure, OnFailure, Stage, Verdict, chain, outcome};
pub use view::{
    Edits, Field, MAX_ADDED_BYTES, MAX_ADDED_FIELDS, Protocol, View, WIRE_FIXED, WIRE_VERSION,
    encode,
};
pub use wasm_hook::{ABI_VERSION, MIN_INPUT};
