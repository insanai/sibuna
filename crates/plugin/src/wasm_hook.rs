//! The Wasm tier: the ABI between a module and the host (SID 0030, "The ABI").
//!
//! ```text
//!  module exports                       host calls them
//!  ------------------------------------ -----------------------------------------
//!  memory                               writes the view at sibuna_input()
//!  sibuna_abi() -> i32                  once, expects 1
//!  sibuna_input() -> i32                once, the address of the input buffer
//!  sibuna_input_size() -> i32           once, its size
//!  sibuna_on_connection(len) -> i32     per flow:    0 admit, 1 deny, 2 challenge
//!  sibuna_on_request(len) -> i32        per request: the same codes
//!  sibuna_on_telemetry(len) -> i32      per ended request, the result is ignored
//!
//!  module imports (module "sibuna")
//!  ------------------------------------
//!  add_header(ptr: i32, len: i32) -> i32   0 taken, -1 refused
//!  now_ms() -> i64                         Unix time in milliseconds
//! ```
//!
//! A module that imports anything else does not load.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::spec::{Error, WasmSpec};
use crate::verdict::{Failure, Stage, Verdict};
use crate::view::{Edits, MAX_ADDED_BYTES};
use crate::wasm::{Budget, Export, Host, Instance, LoadError, Module, Trap, ValType};

/// The version that `sibuna_abi` must return.
pub const ABI_VERSION: u64 = 1;
/// The least size of the input buffer of a module.
pub const MIN_INPUT: u32 = 256;
/// The largest input buffer the host uses, whatever the module offers.
const MAX_INPUT: u32 = 65_536;

/// A host function a module may import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostFn {
    AddHeader,
    NowMs,
}

/// Why a module does not meet the ABI.
#[derive(Debug)]
pub(crate) enum AbiError {
    Missing(&'static str),
    Signature(&'static str),
    Version(u64),
    Buffer(&'static str),
    Trap(&'static str, Trap),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiError::Missing(name) => write!(f, "the module does not export `{name}`"),
            AbiError::Signature(name) => write!(f, "`{name}` has the wrong signature"),
            AbiError::Version(found) => {
                write!(f, "`sibuna_abi` returned {found}; this daemon speaks version 1")
            }
            AbiError::Buffer(what) => write!(f, "the input buffer {what}"),
            AbiError::Trap(name, trap) => write!(f, "`{name}` stopped at instantiation: {trap:?}"),
        }
    }
}

/// A module that passed validation and the checks of the ABI. Shared by every thread.
pub(crate) struct Compiled {
    module: Arc<Module>,
    spec: WasmSpec,
    imports: Vec<HostFn>,
    abi: u32,
    input: u32,
    input_size: u32,
    /// The export of each stage, in the order of [`Stage::ALL`].
    stages: [Option<u32>; 3],
}

const STAGE_EXPORTS: [&str; 3] =
    ["sibuna_on_connection", "sibuna_on_request", "sibuna_on_telemetry"];

/// The index of the exported function `name` when it takes `params` and returns `result`.
fn typed_export(
    module: &Module,
    name: &'static str,
    params: &[ValType],
    result: ValType,
) -> Result<u32, AbiError> {
    let index = module.exported_func(name).ok_or(AbiError::Missing(name))?;
    let ty = module.func_type(index).ok_or(AbiError::Missing(name))?;
    let matches = *ty.params == *params && ty.result == Some(result);
    if matches { Ok(index) } else { Err(AbiError::Signature(name)) }
}

/// Resolves the imports of `module` to host functions.
fn resolve_imports(name: &str, module: &Module) -> Result<Vec<HostFn>, Error> {
    let mut resolved = Vec::new();
    for import in module.imports() {
        let ty = module.func_type(resolved.len() as u32);
        let shape = ty.map(|ty| (&*ty.params, ty.result));
        let found = match (&*import.module, &*import.name, shape) {
            ("sibuna", "add_header", Some(([ValType::I32, ValType::I32], Some(ValType::I32)))) => {
                HostFn::AddHeader
            }
            ("sibuna", "now_ms", Some(([], Some(ValType::I64)))) => HostFn::NowMs,
            _ => {
                let full = format!("{}.{}", import.module, import.name);
                return Err(Error::forbidden_import(name, &full));
            }
        };
        resolved.push(found);
    }
    Ok(resolved)
}

impl Compiled {
    /// Loads the module `bytes` of the plugin `name`, which is attached at the stages of
    /// the bit set `stages`, and instantiates it once to check the ABI.
    ///
    /// # Errors
    ///
    /// The `HOOK004` to `HOOK006` diagnostic of a module that does not validate, imports
    /// what the host does not offer, or does not meet the ABI.
    pub fn load(name: &str, bytes: &[u8], spec: &WasmSpec, stages: u8) -> Result<Self, Error> {
        let module = Module::load(bytes).map_err(|error| match error {
            LoadError::Import(import) => Error::forbidden_import(name, &import),
            other => Error::not_loaded(name, &other),
        })?;
        let imports = resolve_imports(name, &module)?;
        let abi = |error: AbiError| Error::abi(name, &error);
        if module.export("memory") != Some(Export::Memory) {
            return Err(abi(AbiError::Missing("memory")));
        }
        let mut exports = [None; 3];
        for (slot, stage) in exports.iter_mut().zip(Stage::ALL) {
            if stages & stage.bit() != 0 {
                let export = STAGE_EXPORTS[stage.wire() as usize - 1];
                *slot = Some(
                    typed_export(&module, export, &[ValType::I32], ValType::I32).map_err(abi)?,
                );
            }
        }
        let compiled = Compiled {
            abi: typed_export(&module, "sibuna_abi", &[], ValType::I32).map_err(abi)?,
            input: typed_export(&module, "sibuna_input", &[], ValType::I32).map_err(abi)?,
            input_size: typed_export(&module, "sibuna_input_size", &[], ValType::I32)
                .map_err(abi)?,
            module: Arc::new(module),
            spec: spec.clone(),
            imports,
            stages: exports,
        };
        // One instance now, so that a module that cannot start refuses the reload.
        WasmHook::new(&compiled).map_err(|error| match error {
            Start::Load(error) => Error::not_loaded(name, &error),
            Start::Abi(error) => Error::abi(name, &error),
        })?;
        Ok(compiled)
    }
}

/// Why an instance did not start.
pub(crate) enum Start {
    Load(LoadError),
    Abi(AbiError),
}

/// The host side of an invocation: the functions a module may call.
struct Calls<'a> {
    imports: &'a [HostFn],
    /// Where `add_header` writes. `None` outside the request stage.
    edits: Option<&'a mut Edits>,
}

impl Host for Calls<'_> {
    fn call(&mut self, import: u32, args: &[u64], memory: &mut [u8]) -> Result<u64, Trap> {
        const REFUSED: u64 = 0xffff_ffff;
        match self.imports.get(import as usize) {
            Some(HostFn::NowMs) => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                Ok(u64::try_from(now.as_millis()).unwrap_or(u64::MAX))
            }
            Some(HostFn::AddHeader) => {
                let [start, length] = args else { return Err(Trap::Host) };
                let (start, length) = (*start as u32 as usize, *length as u32 as usize);
                let line = memory.get(start..start.saturating_add(length));
                let line = line.ok_or(Trap::MemoryBounds)?;
                let Some(edits) = self.edits.as_deref_mut() else { return Ok(REFUSED) };
                let taken = length <= MAX_ADDED_BYTES && edits.add_line(line);
                Ok(if taken { 0 } else { REFUSED })
            }
            None => Err(Trap::Host),
        }
    }
}

/// One thread's instance of a Wasm hook.
pub(crate) struct WasmHook {
    instance: Instance,
    /// The address and the usable size of the input buffer.
    input: usize,
    capacity: usize,
    /// The last invocation failed, so the next one starts from the initial image.
    dirty: bool,
}

impl WasmHook {
    /// Instantiates `compiled`, runs its start function and asks for its ABI version
    /// and input buffer, all under the fuel of one invocation.
    pub fn new(compiled: &Compiled) -> Result<Self, Start> {
        let instance = Instance::new(Arc::clone(&compiled.module), compiled.spec.memory_pages)
            .map_err(Start::Load)?;
        let mut hook = WasmHook { instance, input: 0, capacity: 0, dirty: false };
        hook.start(compiled).map_err(Start::Abi)?;
        Ok(hook)
    }

    fn start(&mut self, compiled: &Compiled) -> Result<(), AbiError> {
        let spec = &compiled.spec;
        let mut budget = Budget { fuel: spec.fuel_limit, host_calls: spec.host_calls };
        let mut host = Calls { imports: &compiled.imports, edits: None };
        let mut call = |name: &'static str, func: u32| {
            let result = self.instance.call(func, &[], &mut budget, &mut host);
            result.map(|bits| bits.unwrap_or(0) & 0xffff_ffff).map_err(|t| AbiError::Trap(name, t))
        };
        if let Some(start) = compiled.module.start_func() {
            call("the start function", start)?;
        }
        let version = call("sibuna_abi", compiled.abi)?;
        if version != ABI_VERSION {
            return Err(AbiError::Version(version));
        }
        let input = call("sibuna_input", compiled.input)?;
        let size = call("sibuna_input_size", compiled.input_size)?;
        if size < u64::from(MIN_INPUT) {
            return Err(AbiError::Buffer("is smaller than 256 bytes"));
        }
        if input + size > self.instance.memory().len() as u64 {
            return Err(AbiError::Buffer("lies outside the memory"));
        }
        self.input = input as usize;
        self.capacity = size.min(u64::from(MAX_INPUT)) as usize;
        self.dirty = false;
        Ok(())
    }

    /// Runs the hook of `stage` on the encoded view `encoded`. At the request stage the
    /// module may add fields to `edits`.
    ///
    /// # Errors
    ///
    /// [`Failure::Overload`] when the view does not fit the input buffer,
    /// [`Failure::Timeout`] when the fuel is spent, [`Failure::Trap`] for every other
    /// stop and for a return value outside the ABI.
    pub fn invoke(
        &mut self,
        compiled: &Compiled,
        stage: Stage,
        encoded: &[u8],
        edits: &mut Edits,
    ) -> Result<Verdict, Failure> {
        if self.dirty {
            self.instance.reset();
            self.start(compiled).map_err(|_| Failure::Trap)?;
        }
        let func = compiled.stages[stage.wire() as usize - 1].ok_or(Failure::Trap)?;
        if encoded.len() > self.capacity {
            return Err(Failure::Overload);
        }
        let buffer = self.instance.memory_mut().get_mut(self.input..self.input + encoded.len());
        buffer.ok_or(Failure::Trap)?.copy_from_slice(encoded);
        let spec = &compiled.spec;
        let mut budget = Budget { fuel: spec.fuel_limit, host_calls: spec.host_calls };
        let edits = (stage == Stage::Request).then_some(edits);
        let mut host = Calls { imports: &compiled.imports, edits };
        let length = encoded.len() as u64;
        let result = self.instance.call(func, &[length], &mut budget, &mut host);
        let verdict = match (result, stage) {
            (Ok(_), Stage::Telemetry) | (Ok(Some(0)), _) => Ok(Verdict::Admit),
            (Ok(Some(1)), _) => Ok(Verdict::Deny),
            (Ok(Some(2)), _) => Ok(Verdict::Challenge),
            (Ok(_), _) => Err(Failure::Trap),
            (Err(Trap::Fuel), _) => Err(Failure::Timeout),
            (Err(_), _) => Err(Failure::Trap),
        };
        // A stop in the middle of a write may leave state that a later invocation
        // would trust.
        self.dirty = verdict.is_err();
        verdict
    }

    /// The pages the instance holds, for the tests of the page budget.
    #[cfg(test)]
    pub fn pages(&self) -> u32 {
        self.instance.pages()
    }
}
