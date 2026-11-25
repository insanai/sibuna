//! What the configuration says about plugins, as plain data, and the diagnostics of
//! loading them (SID 0030, "Configuration and reload").
//!
//! `sibuna-lb` reads the topology into these structures. [`crate::Plan::load`] checks
//! every bound and loads every module, so the bounds live in one place.

use std::fmt;

use crate::breaker::BreakerLimits;
use crate::verdict::{OnFailure, Stage};

/// The most plugins of one topology.
pub const MAX_PLUGINS: usize = 16;
/// The most hooks of one stage of one frontend.
pub const MAX_STAGE_HOOKS: usize = 8;

/// The plugins of a topology and where each frontend attaches them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// The plugins in the order of the file.
    pub plugins: Vec<Spec>,
    /// The frontends that attach hooks: the name and the lists.
    pub frontends: Vec<(String, Attach)>,
    /// The judges of parked connections.
    pub judges: JudgeOptions,
}

/// The threads that decide parked connections, for each caller that parks (SID 0030,
/// "Parking a connection").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JudgeOptions {
    /// The threads, 1 to 64.
    pub threads: u32,
    /// The cases that may wait for a thread, 1 to 4,096.
    pub queue: u32,
}

impl Default for JudgeOptions {
    fn default() -> Self {
        JudgeOptions { threads: 4, queue: 256 }
    }
}

impl Settings {
    /// True when no frontend attaches a hook.
    pub fn is_empty(&self) -> bool {
        self.frontends
            .iter()
            .all(|(_, attach)| Stage::ALL.iter().all(|s| attach.of(*s).is_empty()))
    }
}

/// One named plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    /// The name that frontends list.
    pub name: String,
    /// What a failure of the plugin means. See [`crate::outcome`].
    pub on_failure: OnFailure,
    /// The tier and its options.
    pub kind: Kind,
}

/// The tier of a plugin and its options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A hook compiled into the daemon.
    Native {
        /// The name of the hook in the daemon's table.
        hook: String,
        /// Its settings as pairs of key and value.
        settings: Vec<(String, String)>,
    },
    /// A WebAssembly module.
    Wasm(WasmSpec),
    /// A process on a Unix socket.
    Agent(AgentSpec),
}

impl Kind {
    /// The name of the tier.
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Native { .. } => "native",
            Kind::Wasm(_) => "wasm",
            Kind::Agent(_) => "agent",
        }
    }
}

/// The options of a Wasm plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmSpec {
    /// The path of the module file.
    pub module: String,
    /// The fuel of one invocation, 1,000 to 100,000,000.
    pub fuel_limit: u64,
    /// The most pages of memory of one instance, 1 to 256.
    pub memory_pages: u32,
    /// The most host calls of one invocation, at most 1,024.
    pub host_calls: u32,
}

impl Default for WasmSpec {
    fn default() -> Self {
        WasmSpec { module: String::new(), fuel_limit: 100_000, memory_pages: 4, host_calls: 16 }
    }
}

/// The options of an agent plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSpec {
    /// The path of the agent's Unix socket.
    pub socket: String,
    /// The longest wait for one answer in milliseconds, 1 to 1,000.
    pub deadline_ms: u64,
    /// The most calls of the node that wait for the agent at one time, and the most
    /// KiB of telemetry frames one thread holds back. 1 to 4,096.
    pub queue: u32,
    /// When the breaker of a thread opens and for how long.
    pub breaker: BreakerLimits,
}

impl Default for AgentSpec {
    fn default() -> Self {
        AgentSpec {
            socket: String::new(),
            deadline_ms: 5,
            queue: 64,
            breaker: BreakerLimits::default(),
        }
    }
}

/// The hooks of one frontend, by stage, as plugin names in the order they run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attach {
    /// The hooks of the connection stage.
    pub connection: Vec<String>,
    /// The hooks of the request stage.
    pub request: Vec<String>,
    /// The hooks of the telemetry stage.
    pub telemetry: Vec<String>,
}

impl Attach {
    /// The names attached at `stage`.
    pub fn of(&self, stage: Stage) -> &[String] {
        match stage {
            Stage::Connection => &self.connection,
            Stage::Request => &self.request,
            Stage::Telemetry => &self.telemetry,
        }
    }
}

/// Why a set of plugins did not load. The serving set stays in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The code, `HOOK001` to `HOOK009`.
    pub code: &'static str,
    /// The title of the diagnostic.
    pub title: &'static str,
    /// What happened, naming the plugin.
    pub message: String,
    /// How to repair it.
    pub hint: &'static str,
}

impl Error {
    pub(crate) fn unknown_plugin(frontend: &str, stage: Stage, name: &str) -> Error {
        Error {
            code: "HOOK001",
            title: "UNKNOWN PLUGIN",
            message: format!(
                "frontends.{frontend}.hooks.{} lists `{name}`, and `plugins` has no such name",
                stage.name()
            ),
            hint: "Define the plugin under `plugins`, or correct the name.",
        }
    }

    pub(crate) fn invalid(message: String) -> Error {
        Error {
            code: "HOOK002",
            title: "INVALID PLUGIN SETTINGS",
            message,
            hint: "The operations chapter lists every key of a plugin with its range.",
        }
    }

    pub(crate) fn unreadable(name: &str, path: &str, error: &std::io::Error) -> Error {
        Error {
            code: "HOOK003",
            title: "MODULE NOT READABLE",
            message: format!("plugins.{name}: cannot read `{path}`: {error}"),
            hint: "Check the path in `module` and that the daemon's user can read the file.",
        }
    }

    pub(crate) fn not_loaded(name: &str, reason: &dyn fmt::Display) -> Error {
        Error {
            code: "HOOK004",
            title: "MODULE NOT LOADED",
            message: format!("plugins.{name}: {reason}"),
            hint: "Build the module for wasm32-unknown-unknown without threads or SIMD. A \
                   module whose memory starts above `memory_pages` needs a smaller stack \
                   (`-zstack-size`) or a larger budget.",
        }
    }

    pub(crate) fn forbidden_import(name: &str, import: &str) -> Error {
        Error {
            code: "HOOK005",
            title: "FORBIDDEN IMPORT",
            message: format!("plugins.{name}: the module imports `{import}`"),
            hint: "A hook may import `sibuna.add_header` and `sibuna.now_ms` only. There is \
                   no WASI: build without `std`, or for a target without a system interface.",
        }
    }

    pub(crate) fn abi(name: &str, reason: &dyn fmt::Display) -> Error {
        Error {
            code: "HOOK006",
            title: "ABI MISMATCH",
            message: format!("plugins.{name}: {reason}"),
            hint: "Export `memory`, `sibuna_abi` (returns 1), `sibuna_input`, \
                   `sibuna_input_size` and one `sibuna_on_STAGE(len: i32) -> i32` for each \
                   stage the plugin is attached at.",
        }
    }

    pub(crate) fn unknown_native(name: &str, hook: &str, known: &str) -> Error {
        Error {
            code: "HOOK007",
            title: "UNKNOWN NATIVE HOOK",
            message: format!("plugins.{name}: this build has no hook `{hook}`. It has: {known}"),
            hint: "A native hook is compiled into the daemon. Correct `hook`, or use a Wasm \
                   module or an agent.",
        }
    }

    pub(crate) fn native_settings(name: &str, reason: &str) -> Error {
        Error {
            code: "HOOK008",
            title: "NATIVE HOOK REFUSED ITS SETTINGS",
            message: format!("plugins.{name}: {reason}"),
            hint: "Correct `settings` of the plugin.",
        }
    }

    #[cfg_attr(unix, allow(dead_code))]
    pub(crate) fn no_agents(name: &str) -> Error {
        Error {
            code: "HOOK009",
            title: "AGENTS NOT SUPPORTED",
            message: format!("plugins.{name}: an agent needs a Unix socket"),
            hint: "Use a Wasm module on this platform.",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}. Hint: {}", self.code, self.title, self.message, self.hint)
    }
}

impl std::error::Error for Error {}
