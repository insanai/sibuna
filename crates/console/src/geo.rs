//! GeoIP in the console: the active generation ([`slot`], shared with the storage thread's
//! incident hook) and the importer (unit U6: [`import`], [`download`], [`embedded`]).

pub mod download;
pub mod embedded;
pub mod import;
pub mod slot;

pub use import::Importer;
pub use slot::{GeoSlot, SlotError};
