//! The wire contracts of the Sibuna console (SID 0007, SID 0008): the values that cross
//! between the console server, its storage owner, peer consoles and the WebAssembly
//! interface. The crate has no networking, storage or daemon dependencies and builds for
//! `wasm32-unknown-unknown` as well as natively.
//!
//! # Contents
//!
//! - Access: [`Role`], [`Action`], [`Principal`], [`tokens`], [`users`], [`auth`],
//!   [`kiosk`], [`audit`].
//! - Live statistics: [`StatsSnapshot`], [`dashboard`] (views, coverage and interval
//!   rates), [`incident_geo`], [`timeline`].
//! - History: [`minutes`] and [`minute_summary`] (traffic), [`challenges`],
//!   [`challenge_minutes`] and [`challenge_records`], [`rule_hits`] and
//!   [`rule_hit_history`], [`rankings`], [`ranking_storage`], [`rankings_archive`] (SBR1
//!   and SBR2) and [`ranking_history`], with the Space-Saving sketch in [`space_saving`].
//! - Incidents: [`events`], [`security`], [`incident_heads`], [`similarity`], and the JA4
//!   fingerprints of SID 0014 ([`ja4`]).
//! - The real-time protocol: [`subscriptions`] (commands and bounds), [`subscription_feed`]
//!   (owner-to-hub feeds), [`json_delta`] (set and remove deltas) and
//!   [`subscription_client`] (transactional reassembly of views).
//! - Management: [`nodes`], [`notifications`], [`settings`], [`retention`], [`pages`],
//!   [`policies`], [`workflows`], [`geo`], [`client_family`], [`Location`].
//! - The storage owner's mailbox: [`storage::Request`], [`storage::Response`] and
//!   [`storage::validate`].
//! - JSON: [`codec`], with [`codec::Encode`], [`codec::Decode`], [`codec::to_json`] and
//!   [`codec::from_json`].
//!
//! # Wire compatibility
//!
//! Every JSON encoder writes the bytes the Zig console wrote for the same value: browsers,
//! peers and stored rows depend on them. Counters that browsers must read exactly are
//! written as numbers below 2^53 and as decimal strings above ([`codec::counter`]);
//! other numbers, enumerations, optional fields and fixed arrays follow Zig's
//! `std.json.Stringify`. Decoders read with the rules of Zig's typed parse (see
//! [`codec`]), reject unknown keys, and enforce every capacity.
//!
//! The integration tests hold the evidence: `tests/golden.rs` checks 56 vectors written
//! by Zig 0.16 (byte-identical encoding, and decoding of Zig's bytes);
//! `tests/differential.rs` checks that 10,000 mutated commands, peer snapshots, archives
//! and document pairs, and 500 mutated subscription sessions, get the same verdicts and
//! the same re-encoded bytes from Zig and Rust; `tests/fuzz.rs` feeds every decoder
//! hundreds of thousands of mutants. The Zig programs that produced the vectors import
//! `libs/console-protocol/src/root.zig` and are kept outside this repository.
//!
//! # Changes from the Zig version
//!
//! The behaviour is the Zig library's; the representation is Rust's.
//!
//! - Zig's fixed `Bytes(N)` buffers became [`Text<N>`], an owned `String` that never holds
//!   more than `N` bytes, and `Vec<u8>` with checked bounds for binary payloads. The same
//!   capacities apply and oversized values are refused, never truncated. The overlapping
//!   copy and tail zeroing that `Bytes.set` needed have no counterpart. Validators no
//!   longer test lengths that the types already guarantee.
//! - Pages that Zig kept as a fixed array and a count are `Vec`s bounded by the same row
//!   limits; decoders refuse longer lists. Fixed arrays remain where the wire format has
//!   a fixed length (country slots, dashboard sources and flows, security ranks, display
//!   bins, histograms).
//! - Heap payloads that a receiver had to free (`releaseRequest`, `releaseResult`) are
//!   owned values and boxes, dropped with their message; the compile-time bound on the
//!   storage result's size is gone. `rankings_archive.decodeInto` and the caller-owned
//!   merge scratch existed to keep large values off the WebAssembly stack: archives are
//!   returned by value (their sketches live on the heap) and
//!   [`space_saving::Sketch::merge_into`] takes a reusable `Vec`.
//! - Allocator parameters are gone: [`json_delta`] and the [`subscription_client`] borrow
//!   their inputs and write into owned strings. A subscription view that outgrows its
//!   bound while being rewritten is [`subscription_client::ClientError::TooLarge`] (Zig
//!   said `WriteFailed`). The client zeroes its buffers on reset and on drop, as Zig's
//!   `secureZero` did.
//! - Space-Saving keys stay inline in fixed arrays: `add` runs once per traffic sample,
//!   and replacing a key in place keeps it allocation-free. A dense array of key hashes
//!   beside the counters makes lookups compare key bytes only on a hash match; the
//!   counters, their order and every result are unchanged.
//! - Accumulators are transactional: [`minute_summary::Window::add`],
//!   [`rule_hit_history::Window::add`], [`challenge_minutes::add`] and
//!   [`challenge_minutes::merge`] leave their target unchanged on error, where Zig could
//!   leave a partial update (its page-level `accept` functions were already atomic).
//! - Assertions on internal invariants became refusals: [`similarity::Best::add`] ignores
//!   a distance that is not a finite number from 0 to 2, [`rule_hit_history::bin_range`]
//!   returns `None` for an index past the bins, and [`minute_summary::value`] returns
//!   `None` when the request total overflows (a deviation is then unavailable).
//! - Decoders decide exactly whether a number is whole, where Zig rounded through `f128`;
//!   they refuse hexadecimal float strings, and numbers that are infinite or NaN as `f64`
//!   (Zig stored such a value and later wrote it as the invalid token `inf`). Parsing is
//!   bounded by [`sibuna_json::Limits`], including a nesting depth of 64.
//! - [`rankings_archive::MAX_BYTES`] is 48,536 bytes, the largest SBR2 archive. Zig's value
//!   was 48,528 bytes, because it counted the referrer section header as 4 bytes instead of
//!   12, so it refused a minute whose two sketches were both full (see that constant). The
//!   Zig test that expected `MAX_BYTES` for a paths-only archive was never run; its port
//!   checks the real length, 37,784 bytes.
//! - Peer snapshots have a streaming decoder, [`StatsSnapshot::from_json`], beside the
//!   tree decoder; it accepts and refuses exactly the same documents (the fuzz and
//!   differential tests compare both).
//! - Names follow Rust: `StorageRequest` and `StorageResult` are [`storage::Request`] and
//!   [`storage::Response`]; `events.Row.write` and the `jsonStringify` methods are
//!   [`codec::Encode`]; `Mapping.decode` is [`events::country::Mapping::from_wire`];
//!   `statusLabel` returns a static string instead of filling a buffer.
//!
//! # Performance
//!
//! Medians of seven batches on a Ryzen 9 5950X, Zig 0.16 `ReleaseFast` against this
//! crate in release mode, with the same inputs (`tests/bench.rs`):
//!
//! | operation                                          | Zig      | Rust     |
//! |----------------------------------------------------|----------|----------|
//! | delta between two 3.7 KB dashboard views           | 68 us    | 33 us    |
//! | encode a dashboard view                            | 5.2 us   | 4.4 us   |
//! | decode a 2.5 KB peer snapshot, parse included      | 11.4 us  | 10.2 us  |
//! | subscription client applies one delta frame        | 23 us    | 1.5 us   |
//! | Space-Saving sample into a full sketch             | 529 ns   | 126 ns   |
//! | merge two full Space-Saving sketches               | 153 us   | 53 us    |
//!
//! The snapshot row uses [`StatsSnapshot::from_json`], which reads parser events
//! directly; the generic [`codec::from_json`] builds a value tree first and takes 12.2 us,
//! of which 10.0 us is the tree. The Zig client was slow because every update zeroed the
//! unused tails of its two 64 KiB buffers.

mod access;
pub mod audit;
pub mod auth;
pub mod challenge_minutes;
pub mod challenge_records;
pub mod challenges;
pub mod client_family;
pub mod codec;
pub mod dashboard;
mod error;
pub mod events;
pub mod geo;
pub mod incident_geo;
pub mod incident_heads;
pub mod ja4;
pub mod json_delta;
pub mod kiosk;
mod location;
pub mod minute_summary;
pub mod minutes;
pub mod nodes;
pub mod notifications;
pub mod pages;
pub mod policies;
pub mod ranking_history;
pub mod ranking_storage;
pub mod rankings;
pub mod rankings_archive;
pub mod retention;
pub mod rule_hit_history;
pub mod rule_hits;
pub mod security;
pub mod settings;
pub mod similarity;
pub mod space_saving;
mod stats;
pub mod storage;
mod stream;
pub mod subscription_client;
pub mod subscription_feed;
pub mod subscriptions;
mod text;
pub mod timeline;
pub mod tokens;
pub mod users;
pub mod workflows;

pub use access::{
    Action, AuthUser, AuthorizationCheck, CredentialKind, Principal, Role, valid_username,
};
pub use error::{InvalidResponse, ValidationError};
pub use location::{InvalidLocation, Location};
pub use stats::{COUNTRY_SLOTS, CountryCount, ProxyMode, StatsSnapshot};
pub use subscriptions::Topic;
pub use text::{Text, TooLarge};

/// The protocol version.
pub const VERSION: u16 = 1;
/// The largest client message and inline storage document, in bytes.
pub const MAX_MESSAGE: usize = 4096;
/// The most rows one incidents page holds.
pub const MAX_PAGE_ROWS: u16 = 100;

/// A node control request (Zig's `ControlRequest`).
pub type ControlRequest = nodes::Command;
