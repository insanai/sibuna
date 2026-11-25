//! A WebAssembly interpreter for hooks (SID 0030, "The Wasm tier").
//!
//! It runs the MVP of WebAssembly 1.0 and four later proposals that compilers emit by
//! default: sign extension, saturating conversions, `memory.copy` and `memory.fill`. It
//! has no JIT, no `unsafe` and no access to the host beyond the [`Host`] it is given.
//!
//! ```text
//!   bytes --[Module::load]--> Module --[Instance::new]--> Instance --[call]--> result
//!            decode, validate,          memory, globals,     fuel, frames,      or Trap
//!            translate to ops           page budget          host calls
//! ```
//!
//! Three things bound an invocation, and each is an error value when passed: the fuel
//! and the host calls of the [`Budget`], and the pages the instance was created with.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use sibuna_plugin::wasm::{Budget, Host, Instance, Module, Trap};
//!
//! struct NoHost;
//! impl Host for NoHost {
//!     fn call(&mut self, _: u32, _: &[u64], _: &mut [u8]) -> Result<u64, Trap> {
//!         Err(Trap::Host)
//!     }
//! }
//!
//! // (module (func (export "add") (param i32 i32) (result i32)
//! //   local.get 0 local.get 1 i32.add))
//! let bytes = [
//!     0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, // magic and version
//!     1, 7, 1, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, // one type: (i32, i32) -> i32
//!     3, 2, 1, 0, // one function of type 0
//!     7, 7, 1, 3, b'a', b'd', b'd', 0, 0, // export "add" = function 0
//!     10, 9, 1, 7, 0, 0x20, 0, 0x20, 1, 0x6a, 0x0b, // its body
//! ];
//! let module = Arc::new(Module::load(&bytes).unwrap());
//! let add = module.exported_func("add").unwrap();
//! let mut instance = Instance::new(module, 1).unwrap();
//! let mut budget = Budget { fuel: 100, host_calls: 0 };
//! let sum = instance.call(add, &[2, 40], &mut budget, &mut NoHost).unwrap();
//! assert_eq!(sum, Some(42));
//! assert_eq!(budget.fuel, 96);
//! ```

mod exec;
mod module;
mod numeric;
mod op;
mod reader;
mod validate;

pub use exec::{Budget, Host, Instance, MAX_FRAMES, MAX_STACK, Trap};
pub use module::{Export, FuncType, Import, MAX_MODULE_BYTES, Module, PAGE, ValType};
pub use reader::LoadError;
