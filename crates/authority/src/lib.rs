//! A database as the authority for the topology of an edge (SID 0028).
//!
//! In persistent mode the file of a node owns what belongs to its host and a database
//! owns the published topology, as numbered revisions that never change.
//!
//! ```text
//!   operator                         database                      node
//!   --------                         --------                      ----
//!   source --publish--> document
//!   head() ; diff(head, document)
//!   commit(expected = head) ------>  revision N+1, or Conflict
//!                                    NOTIFY (PostgreSQL)  ------>  head() at a notification
//!                                                                  and at every poll
//!                                    revision(N+1), whole  ----->  compose with the file,
//!                                                                  check, serve, report
//!                                    edge_nodes  <---------------  applied = N+1
//! ```
//!
//! - [`publish`], [`compose`] and [`diff`] work on documents and perform no I/O.
//! - [`Store`] is the store of revisions. [`SqlStore`] keeps it in SQLite, for one host,
//!   or in PostgreSQL, for a cluster. [`MemoryStore`] keeps it in memory for tests.
//! - [`Following`] is the state of a node that follows the store.
//! - [`write_cache`] and [`read_cache`] keep the last served revision on disk.
//!
//! The one-call path of a command is [`SqlStore::new`], [`Store::head`] and
//! [`commit_settled`]. The crate knows the sections of a topology and not their
//! meaning: the caller checks a composition with the topology checker.

mod cache;
mod diff;
mod document;
mod error;
mod follow;
mod memory;
mod render;
mod settings;
mod sql;
mod store;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use cache::{read_cache, write_cache};
pub use diff::{Change, MAX_LINES, diff, render as render_diff};
pub use document::{
    Composition, LIMITS, LOCAL, PUBLISHED, Publication, SECTION, canonical, compose, digest,
    is_node_file, pretty, publish,
};
pub use error::Error;
pub use follow::{Following, Published, Reach, short};
pub use memory::MemoryStore;
pub use render::{render_history, render_nodes, utc};
pub use settings::{DEFAULT_POLL, LOCAL_NODE, Location, MAX_NODE, Settings};
pub use sql::{Access, CHANNEL, SCHEMA, SqlStore, Waker};
pub use store::{
    Draft, Entry, Head, MAX_DETAIL, MAX_HISTORY, MAX_NAME, MAX_NODES, MAX_NOTE, MAX_SOURCE,
    NodeReport, Origin, Revision, Store, Woken, clip, commit_settled,
};
