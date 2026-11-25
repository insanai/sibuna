//! The published set of hooks and one thread's instances of it (SID 0030).
//!
//! A [`Plan`] is built off the request path and never changes. A [`Slot`] publishes it,
//! as the policy engine is published: readers compare one generation number, and take
//! the slow path only when it moved. A [`Local`] belongs to one thread and owns every
//! mutable thing: Wasm memories, agent connections, breakers and scratch buffers.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

#[cfg(unix)]
use crate::agent::{AgentClient, AgentShared};
use crate::native::{Hook, Native};
use crate::spec::{Error, Kind, MAX_PLUGINS, MAX_STAGE_HOOKS, Settings, Spec};
use crate::verdict::{Failure, OnFailure, Stage, Verdict, outcome};
use crate::view::{Edits, View, encode};
use crate::wasm::MAX_MODULE_BYTES;
use crate::wasm_hook::{Compiled, WasmHook};

/// The most bytes of an encoded view that any tier accepts.
const MAX_VIEW: usize = 65_536;

/// The counters of one plugin, shared by all threads. Each is a relaxed atomic add.
#[derive(Debug, Default)]
struct Stats {
    calls: AtomicU64,
    admitted: AtomicU64,
    denied: AtomicU64,
    challenged: AtomicU64,
    failures: [AtomicU64; 4],
    dropped: AtomicU64,
    refused_fields: AtomicU64,
}

/// What `show hooks` and the metrics report for one plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginStatus {
    /// The name of the plugin.
    pub name: String,
    /// `native`, `wasm` or `agent`.
    pub tier: &'static str,
    /// The written choice of the plugin.
    pub on_failure: OnFailure,
    /// Invocations at every stage.
    pub calls: u64,
    /// Invocations that answered admit.
    pub admitted: u64,
    /// Invocations that answered deny.
    pub denied: u64,
    /// Invocations that answered challenge.
    pub challenged: u64,
    /// Invocations that failed, in the order of [`Failure::ALL`].
    pub failures: [u64; 4],
    /// Telemetry samples that were dropped.
    pub dropped: u64,
    /// Request fields that the plugin tried to add and that were refused.
    pub refused_fields: u64,
    /// Threads whose breaker for this agent is open.
    pub open_breakers: u32,
}

/// The tier of a loaded plugin, with what its instances share.
enum Tier {
    Native {
        build: fn(&[(String, String)]) -> Result<Box<dyn Hook>, String>,
        settings: Vec<(String, String)>,
    },
    Wasm(Arc<Compiled>),
    #[cfg(unix)]
    Agent(Arc<AgentShared>),
}

struct Plugin {
    name: Box<str>,
    on_failure: OnFailure,
    tier: Tier,
    stats: Arc<Stats>,
}

struct Frontend {
    name: Box<str>,
    /// The plugins of each stage by index, in the order of [`Stage::ALL`].
    chains: [Box<[u16]>; 3],
}

/// A loaded set of hooks: immutable, and shared by every thread.
#[derive(Default)]
pub struct Plan {
    plugins: Vec<Plugin>,
    frontends: Vec<Frontend>,
    stages: u8,
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("plugins", &self.plugins.len())
            .field("frontends", &self.frontends.len())
            .finish_non_exhaustive()
    }
}

fn stage_index(stage: Stage) -> usize {
    usize::from(stage.wire()) - 1
}

/// Checks the ranges of the options of `spec`.
fn check_ranges(spec: &Spec) -> Result<(), Error> {
    let name = &spec.name;
    let fail = |what: &str| Err(Error::invalid(format!("plugins.{name}: {what}")));
    match &spec.kind {
        Kind::Native { .. } => Ok(()),
        Kind::Wasm(wasm) => {
            if !(1_000..=100_000_000).contains(&wasm.fuel_limit) {
                return fail("fuel_limit must be 1000 to 100000000");
            }
            if !(1..=256).contains(&wasm.memory_pages) {
                return fail("memory_pages must be 1 to 256");
            }
            if wasm.host_calls > 1024 {
                return fail("host_calls must be at most 1024");
            }
            Ok(())
        }
        Kind::Agent(agent) => {
            if agent.socket.is_empty() {
                return fail("socket must name a path");
            }
            if !(1..=1000).contains(&agent.deadline_ms) {
                return fail("deadline must be 1ms to 1s");
            }
            if !(1..=4096).contains(&agent.queue) {
                return fail("queue must be 1 to 4096");
            }
            if agent.breaker.failures == 0 || !(1..=600_000).contains(&agent.breaker.open_ms) {
                return fail("breaker needs failures of at least 1 and open of 1ms to 10m");
            }
            Ok(())
        }
    }
}

/// Reads the module file of a Wasm plugin, at most [`MAX_MODULE_BYTES`] of it.
fn read_module(name: &str, path: &str) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let unreadable = |error: std::io::Error| Error::unreadable(name, path, &error);
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut bytes = Vec::new();
    file.take(MAX_MODULE_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(unreadable)?;
    Ok(bytes)
}

/// Loads the tier of `spec`, which is attached at the stages of the bit set `stages`.
fn load_tier(spec: &Spec, stages: u8, natives: &[Native]) -> Result<Tier, Error> {
    let name = &spec.name;
    match &spec.kind {
        Kind::Native { hook, settings } => {
            let Some(native) = natives.iter().find(|native| native.name == hook) else {
                let known: Vec<&str> = natives.iter().map(|native| native.name).collect();
                return Err(Error::unknown_native(name, hook, &known.join(", ")));
            };
            // Built once now, so that wrong settings refuse the reload.
            (native.build)(settings).map_err(|why| Error::native_settings(name, &why))?;
            Ok(Tier::Native { build: native.build, settings: settings.clone() })
        }
        Kind::Wasm(wasm) => {
            let bytes = read_module(name, &wasm.module)?;
            Compiled::load(name, &bytes, wasm, stages)
                .map(|compiled| Tier::Wasm(Arc::new(compiled)))
        }
        #[cfg(unix)]
        Kind::Agent(agent) => AgentShared::start(agent.clone())
            .map(Tier::Agent)
            .map_err(|error| Error::invalid(format!("plugins.{name}: {error}"))),
        #[cfg(not(unix))]
        Kind::Agent(_) => Err(Error::no_agents(name)),
    }
}

impl Plan {
    /// Loads every plugin of `settings`: checks ranges, reads and validates modules,
    /// builds each native hook once from the table `natives`. A plugin that no frontend
    /// attaches is checked too.
    ///
    /// # Errors
    ///
    /// The `HOOK` diagnostic of the first plugin that does not load. Nothing is
    /// published then.
    pub fn load(settings: &Settings, natives: &[Native]) -> Result<Plan, Error> {
        if settings.plugins.len() > MAX_PLUGINS {
            return Err(Error::invalid(format!("more than {MAX_PLUGINS} plugins")));
        }
        let mut frontends = Vec::new();
        let mut used = vec![0u8; settings.plugins.len()];
        for (frontend, attach) in &settings.frontends {
            let mut chains: [Box<[u16]>; 3] = Default::default();
            for stage in Stage::ALL {
                let names = attach.of(stage);
                if names.len() > MAX_STAGE_HOOKS {
                    let stage = stage.name();
                    return Err(Error::invalid(format!(
                        "frontends.{frontend}.hooks.{stage}: more than {MAX_STAGE_HOOKS} hooks"
                    )));
                }
                let mut chain = Vec::new();
                for name in names {
                    let found = settings.plugins.iter().position(|spec| spec.name == *name);
                    let index =
                        found.ok_or_else(|| Error::unknown_plugin(frontend, stage, name))?;
                    used[index] |= stage.bit();
                    chain.push(index as u16);
                }
                chains[stage_index(stage)] = chain.into();
            }
            frontends.push(Frontend { name: frontend.as_str().into(), chains });
        }
        let mut plugins = Vec::new();
        for (spec, stages) in settings.plugins.iter().zip(&used) {
            if plugins.iter().any(|known: &Plugin| *known.name == *spec.name) {
                return Err(Error::invalid(format!("plugins.{}: defined twice", spec.name)));
            }
            check_ranges(spec)?;
            plugins.push(Plugin {
                name: spec.name.as_str().into(),
                on_failure: spec.on_failure,
                tier: load_tier(spec, *stages, natives)?,
                stats: Arc::default(),
            });
        }
        let stages = used.iter().fold(0, |all, stages| all | stages);
        Ok(Plan { plugins, frontends, stages })
    }

    /// The bit set of the stages at which some frontend attaches a hook.
    pub fn stages(&self) -> u8 {
        self.stages
    }

    /// True when the frontend `name` attaches a hook at `stage`.
    pub fn attaches(&self, name: &str, stage: Stage) -> bool {
        self.chain(name, stage).is_some_and(|chain| !chain.is_empty())
    }

    fn chain(&self, frontend: &str, stage: Stage) -> Option<&[u16]> {
        let frontend = self.frontends.iter().find(|known| *known.name == *frontend)?;
        frontend.chains.get(stage_index(stage)).map(|chain| &**chain)
    }

    /// The counters of every plugin, in the order of the configuration.
    pub fn status(&self) -> Vec<PluginStatus> {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let status = |plugin: &Plugin| {
            let stats = &plugin.stats;
            let (tier, open_breakers) = match &plugin.tier {
                Tier::Native { .. } => ("native", 0),
                Tier::Wasm(_) => ("wasm", 0),
                #[cfg(unix)]
                Tier::Agent(shared) => ("agent", shared.open_breakers.load(Ordering::Relaxed)),
            };
            PluginStatus {
                name: plugin.name.to_string(),
                tier,
                on_failure: plugin.on_failure,
                calls: read(&stats.calls),
                admitted: read(&stats.admitted),
                denied: read(&stats.denied),
                challenged: read(&stats.challenged),
                failures: [0, 1, 2, 3].map(|index| read(&stats.failures[index])),
                dropped: read(&stats.dropped),
                refused_fields: read(&stats.refused_fields),
                open_breakers,
            }
        };
        self.plugins.iter().map(status).collect()
    }

    /// Takes over the counters of the plugins of `previous` that keep their name, so a
    /// reload does not restart them.
    fn adopt(&mut self, previous: &Plan) {
        for plugin in &mut self.plugins {
            if let Some(old) = previous.plugins.iter().find(|old| old.name == plugin.name) {
                plugin.stats = Arc::clone(&old.stats);
            }
        }
    }
}

/// Where the current [`Plan`] is published.
#[derive(Debug)]
pub struct Slot {
    current: RwLock<Arc<Plan>>,
    /// Advanced after every publication. Release on publish and acquire on read: a
    /// reader that sees a new generation also sees the plan stored before it.
    generation: AtomicU64,
    /// The stages with hooks, as bits. This is the one word that traffic without hooks
    /// reads.
    stages: AtomicU8,
}

impl Default for Slot {
    fn default() -> Self {
        Slot::new()
    }
}

impl Slot {
    /// A slot that publishes no hooks.
    pub fn new() -> Slot {
        Slot {
            current: RwLock::new(Arc::new(Plan::default())),
            generation: AtomicU64::new(1),
            stages: AtomicU8::new(0),
        }
    }

    /// Publishes `plan`. Each thread takes it at its next invocation. The counters of
    /// plugins that keep their name go on.
    pub fn publish(&self, mut plan: Plan) {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        plan.adopt(&current);
        let stages = plan.stages;
        *current = Arc::new(plan);
        self.generation.fetch_add(1, Ordering::Release);
        self.stages.store(stages, Ordering::Release);
    }

    /// True when some frontend attaches a hook at `stage`. One atomic load.
    #[inline]
    pub fn has(&self, stage: Stage) -> bool {
        self.stages.load(Ordering::Relaxed) & stage.bit() != 0
    }

    /// The current plan. This takes the read lock: use it off the request path.
    pub fn load(&self) -> Arc<Plan> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// One thread's instance of a plugin.
enum Instance {
    Native(Box<dyn Hook>),
    Wasm(WasmHook),
    #[cfg(unix)]
    Agent(AgentClient),
}

/// What a chain of hooks decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision<'a> {
    /// The verdict of the chain.
    pub verdict: Verdict,
    /// The plugin that refused; empty for an admission.
    pub hook: &'a str,
    /// The request fields to add, as lines ending in CRLF; empty unless admitted.
    pub added: &'a [u8],
}

impl Decision<'_> {
    /// The admission that adds nothing.
    pub const ADMIT: Decision<'static> =
        Decision { verdict: Verdict::Admit, hook: "", added: b"" };
}

/// One thread's instances of the published hooks, and its scratch space.
#[derive(Default)]
pub struct Local {
    generation: u64,
    plan: Option<Arc<Plan>>,
    instances: Vec<Option<Instance>>,
    encoded: Vec<u8>,
    edits: Edits,
}

impl std::fmt::Debug for Local {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Local").field("generation", &self.generation).finish_non_exhaustive()
    }
}

/// Builds this thread's instance of `plugin`.
fn instantiate(plugin: &Plugin) -> Result<Instance, Failure> {
    match &plugin.tier {
        Tier::Native { build, settings } => {
            build(settings).map(Instance::Native).map_err(|_| Failure::Trap)
        }
        Tier::Wasm(compiled) => {
            WasmHook::new(compiled).map(Instance::Wasm).map_err(|_| Failure::Trap)
        }
        #[cfg(unix)]
        Tier::Agent(shared) => Ok(Instance::Agent(AgentClient::new(Arc::clone(shared)))),
    }
}

/// The scratch space of one run of a chain.
struct Scratch<'a> {
    /// The wire form of the view, encoded when the first hook needs it.
    encoded: &'a mut Vec<u8>,
    state: Option<Result<(), Failure>>,
    edits: &'a mut Edits,
}

impl Scratch<'_> {
    fn encoded(&mut self, view: &View<'_>) -> Result<&[u8], Failure> {
        let encoded = &mut *self.encoded;
        (*self.state.get_or_insert_with(|| encode(view, encoded, MAX_VIEW)))?;
        Ok(self.encoded)
    }
}

/// Runs one hook on `view`.
fn invoke(
    plugin: &Plugin,
    instance: &mut Instance,
    view: &View<'_>,
    scratch: &mut Scratch<'_>,
) -> Result<Verdict, Failure> {
    match (instance, &plugin.tier) {
        (Instance::Native(hook), _) => match view.stage {
            Stage::Connection => hook.on_connection(view),
            Stage::Request => hook.on_request(view, scratch.edits),
            Stage::Telemetry => hook.on_telemetry(view).map(|()| Verdict::Admit),
        },
        (Instance::Wasm(hook), Tier::Wasm(compiled)) => {
            scratch.encoded(view)?;
            hook.invoke(compiled, view.stage, scratch.encoded, scratch.edits)
        }
        #[cfg(unix)]
        (Instance::Agent(client), _) => {
            scratch.encoded(view)?;
            match view.stage {
                Stage::Telemetry => client.sample(scratch.encoded).map(|()| Verdict::Admit),
                Stage::Request => client.decide(scratch.encoded, Some(scratch.edits)),
                Stage::Connection => client.decide(scratch.encoded, None),
            }
        }
        // An instance is built from its plugin, so the two always agree.
        (Instance::Wasm(_), _) => Err(Failure::Trap),
    }
}

/// Counts the end of one invocation.
fn count(stats: &Stats, stage: Stage, result: Result<Verdict, Failure>, refused: u32) {
    let bump = |counter: &AtomicU64| counter.fetch_add(1, Ordering::Relaxed);
    bump(&stats.calls);
    match result {
        Ok(Verdict::Admit) => bump(&stats.admitted),
        Ok(Verdict::Deny) => bump(&stats.denied),
        Ok(Verdict::Challenge) => bump(&stats.challenged),
        Err(failure) => {
            if stage == Stage::Telemetry {
                bump(&stats.dropped);
            }
            bump(&stats.failures[failure.index()])
        }
    };
    if refused > 0 {
        stats.refused_fields.fetch_add(u64::from(refused), Ordering::Relaxed);
    }
}

impl Local {
    /// The instances of a thread that has run nothing yet.
    pub fn new() -> Local {
        Local::default()
    }

    /// Brings the instances up to the plan that `slot` publishes. Costs one atomic load
    /// when nothing was published since the last run.
    fn refresh(&mut self, slot: &Slot) {
        let generation = slot.generation.load(Ordering::Acquire);
        if self.generation != generation || self.plan.is_none() {
            let plan = slot.load();
            self.generation = generation;
            self.instances.clear();
            self.instances.resize_with(plan.plugins.len(), || None);
            self.plan = Some(plan);
        }
    }

    /// Runs the hooks that the frontend `view.frontend` attaches at `view.stage`, in
    /// order, and returns what the chain decided. A failure becomes an outcome by the
    /// failure rule; the first outcome that is not an admission ends the chain. At the
    /// telemetry stage every hook runs and the decision is always an admission.
    ///
    /// Call [`Slot::has`] first: it answers without touching the thread's instances
    /// when no hook is attached at the stage.
    pub fn run(&mut self, slot: &Slot, view: &View<'_>) -> Decision<'_> {
        self.refresh(slot);
        let Local { plan, instances, encoded, edits, .. } = self;
        edits.clear();
        let Some(plan) = plan.as_deref() else { return Decision::ADMIT };
        let Some(chain) = plan.chain(view.frontend, view.stage) else { return Decision::ADMIT };
        let mut scratch = Scratch { encoded, state: None, edits };
        for &index in chain {
            let index = usize::from(index);
            let (Some(plugin), Some(place)) = (plan.plugins.get(index), instances.get_mut(index))
            else {
                continue;
            };
            let mark = scratch.edits.mark();
            let refused_before = scratch.edits.refused();
            let result = match place {
                Some(instance) => invoke(plugin, instance, view, &mut scratch),
                None => instantiate(plugin).and_then(|instance| {
                    invoke(plugin, place.insert(instance), view, &mut scratch)
                }),
            };
            if result != Ok(Verdict::Admit) {
                // Only an admission by verdict adds fields.
                scratch.edits.rewind(mark.0, mark.1);
            }
            let refused = scratch.edits.refused() - refused_before;
            count(&plugin.stats, view.stage, result, refused);
            let verdict = outcome(view.stage, plugin.on_failure, result);
            if verdict != Verdict::Admit {
                return Decision { verdict, hook: &plugin.name, added: b"" };
            }
        }
        Decision { verdict: Verdict::Admit, hook: "", added: edits.lines() }
    }
}
