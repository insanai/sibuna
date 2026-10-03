//! Zaxonlite: an embedded SQLite service replicated by the paxos-zig
//! Multi-Paxos library.
//!
//! The Paxos journal plus content-addressed payload store are the
//! authoritative durable state. The SQLite database image is a materialized
//! state machine rebuildable from the durable state anchor plus the
//! retained journal suffix.

const std = @import("std");

/// Human-readable library version.
pub const version = "0.7.0";

/// Fixed-size replicated command descriptor and its canonical wire codec.
pub const command = @import("command.zig");
/// The command value carried in every Paxos slot; names payloads by content hash.
pub const Command = command.Command;
/// The one concrete ReplicatedLog instantiation and its entry/write encodings.
pub const types = @import("types.zig");
/// The global ordered-history anchor over every chosen entry (ZDS 0011).
pub const history = @import("history.zig");
/// Alternating durable applied-state anchors for SQLite recovery (ZDS 0011).
pub const applied_anchor = @import("applied_anchor.zig");
/// Immutable journal v3 segments with sealed trailers (ZDS 0011).
pub const segment = @import("segment.zig");
/// The authoritative retained-segment manifest for journal v3 (ZDS 0011).
pub const manifest = @import("manifest.zig");
/// Conservative trim policy and the durable TRIM record (ZDS 0011).
pub const trim = @import("trim.zig");
/// Framed, checksummed, append-only protocol journal: the authoritative state.
pub const journal = @import("journal.zig");
/// Content-addressed, immutable transaction payload store (SHA-256 named).
pub const payload_store = @import("payload_store.zig");
/// Store for transaction payload bytes, installed with write-temp/sync/rename.
pub const PayloadStore = payload_store.PayloadStore;
/// Canonical evidence that a transferable checkpoint is tied to the stop
/// sign already chosen by Paxos; receivers confirm its digest with a quorum.
/// SQLite WAL frame capture and deterministic page-level apply.
pub const wal = @import("wal.zig");
/// Narrow SQLite C API bindings; the only module that touches the C header.
pub const sqlite = @import("sqlite.zig");
/// SQLite invariant authorizer: keeps application SQL inside the
/// replication contract (transaction ownership, reserved metadata,
/// capture pragmas) without sandboxing ordinary SQLite usage.
pub const guard = @import("guard.zig");
/// Prepared parameter values and the copied, bounded transaction builder.
pub const prepared = @import("prepared.zig");
/// Typed hybrid search: validated requests, the enforced candidate cap,
/// and the canonical fused CTE statements (ZDS 0009).
pub const search_api = @import("search_api.zig");
/// A typed hybrid-search request for `Node.search`.
pub const SearchRequest = search_api.Request;
/// One bound SQL parameter: null, integer, real, text, or blob.
pub const Value = prepared.Value;
/// Multi-statement builder committed as one replicated SQLite transaction.
pub const Transaction = prepared.Transaction;
/// Length-prefixed peer and client wire protocol frames.
pub const wire = @import("wire.zig");
/// Mutual PSK authentication and per-frame HMAC integrity for TCP streams.
pub const transport_auth = @import("transport_auth.zig");
/// Optional mutual TLS 1.3 transport (OpenSSL 3): per-node certificates
/// verified against a cluster CA, beside the PSK mode.
pub const tls = @import("tls.zig");
/// Provider-file paths for one production TCP certificate identity.
pub const TlsConfig = tls.Config;
/// One-time token persistence, CSR exchange, and atomic identity installation.
pub const enrollment = @import("enrollment.zig");
/// Configuration loading with CLI > environment > file precedence.
pub const configuration = @import("configuration.zig");
/// The canonical decided registry: consensus-decided membership, roles,
/// endpoints, the node-ID allocation fence, and the operation ring.
pub const registry = @import("registry.zig");
/// Elm-style operator diagnostics: boundary header, explanation, and hint.
pub const diagnostic = @import("diagnostic.zig");
/// Shared fsync policy and helpers: `full` (F_FULLFSYNC on macOS) or `os`.
pub const durability = @import("durability.zig");
/// The embedded node host: one data directory, journal, payloads, SQLite image.
pub const node = @import("node.zig");
/// Product node roles and their consensus/storage capabilities.
pub const roles = @import("roles.zig");
/// One in-process zaxonlite node bound to one data directory.
pub const Node = node.Node;
/// Options for `Node.open`: data directory, identity, membership, and role.
pub const OpenOptions = node.OpenOptions;
/// Node type: data-voter, witness, standby, read-replica, or gateway.
pub const Role = roles.Role;
/// Result of a committed write: change count, decided slot, replay marker.
pub const ExecResult = node.ExecResult;
/// Arena-owned query rows; the caller must call `deinit` to free them.
pub const QueryResult = node.QueryResult;

pub const TypedResult = node.TypedResult;

pub const WriteCapture = node.WriteCapture;

pub const StatementInfo = node.StatementInfo;
/// One tagged read statement of a `queryBatch` call.
pub const BatchQuery = node.BatchQuery;
/// Arena-owned tagged result sets, all from one WAL snapshot.
pub const BatchResult = node.BatchResult;
/// Hard cap on statements in one `queryBatch` call.
pub const batch_queries_max = node.batch_queries_max;
/// Which checked statement failed its expectation, and what was observed.
pub const CheckedFailure = node.CheckedFailure;
/// Per-statement verification for `execCheckedTransaction`.
pub const Expectation = prepared.Expectation;
/// One statement of a checked transaction: SQL, values, expectation.
pub const CheckedStatement = prepared.CheckedStatement;
/// Thread-safe facade: pooled read-only connections, a serialized write
/// executor, and a maintenance gate over one privately owned node.
pub const shared_node = @import("shared_node.zig");
pub const SharedNode = shared_node.SharedNode;
/// Facade tuning for `SharedNode.open`/`adopt`.
pub const SharedNodeOptions = shared_node.Options;
/// The `zaxon serve` transport host: one node behind a TCP endpoint.
pub const server = @import("server.zig");
/// JSON RPC client with leader-redirect following; used by the CLI and tests.
pub const client = @import("client.zig");
/// External-client remote pool over ClusterConnection (ZDS 0010 Gate B).
pub const remote = @import("remote.zig");
/// Stateless TCP gateway that routes clients to serving cluster backends.
pub const gateway = @import("gateway.zig");
/// Transport-owning embedded facade: an in-process cluster member with TCP.
pub const embedded = @import("embedded.zig");
/// In-process cluster member owning its listener, peers, and tick loop.
pub const Embedded = embedded.Embedded;
/// Static cluster membership entry for the embedded facade.
pub const EmbeddedMember = embedded.Member;
/// Options for `Embedded.open`: directory, identity, membership, and mTLS.
pub const EmbeddedOpenOptions = embedded.OpenOptions;

test {
    _ = @import("command.zig");
    _ = @import("types.zig");
    _ = @import("history.zig");
    _ = @import("applied_anchor.zig");
    _ = @import("segment.zig");
    _ = @import("manifest.zig");
    _ = @import("trim.zig");
    _ = @import("journal.zig");
    _ = @import("payload_store.zig");
    _ = @import("sqlite.zig");
    _ = @import("guard.zig");
    _ = @import("prepared.zig");
    _ = @import("search_api.zig");
    _ = @import("wal.zig");
    _ = @import("wire.zig");
    _ = @import("transport_auth.zig");
    _ = @import("tls.zig");
    _ = @import("enrollment.zig");
    _ = @import("configuration.zig");
    _ = @import("registry.zig");
    _ = @import("durability.zig");
    _ = @import("node.zig");
    _ = @import("shared_node.zig");
    _ = @import("roles.zig");
    _ = @import("server.zig");
    _ = @import("client.zig");
    _ = @import("remote.zig");
    _ = @import("gateway.zig");
    _ = @import("embedded.zig");
}

test "sqlite is linked and recent" {
    try std.testing.expectEqualStrings("0.7.0", version);
    try std.testing.expect(sqlite.libversionNumber() >= 3050000);
}
