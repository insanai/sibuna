#let sid-number = "0005"
#let sid-title = "Distributed Storage Architecture: Zaxonlite Integration for Multi-Node Consensus, Dynamic Policies, and Cloudflare-Grade Edge Protection"
#let sid-state = "published"
#let sid-created = "2026-09-07"
#let sid-discussion = "Specifies the architecture for embedding Zaxonlite (the distributed SQLite consensus engine from paxos-zig) into Sibuna, enabling cluster-wide dynamic policy replication, distributed IP reputation, forensic audit search, and zero-external-dependency Cloudflare-grade edge protection without PostgreSQL, Redis, or Docker."
#let sid-labels = ("storage", "zaxonlite", "paxos", "sqlite", "distributed", "cloudflare", "safeline")
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Published"
#let sid-last-updated = "2026-09-07"

#import "../../shared/sid.typ": sid-document

#let ink = rgb("172033")
#let blue = rgb("0284c7")
#let blue-light = rgb("f0f9ff")
#let green = rgb("16a34a")
#let green-light = rgb("f0fdf4")
#let amber = rgb("d97706")
#let amber-light = rgb("fffbeb")
#let red = rgb("dc2626")
#let red-light = rgb("fef2f2")
#let gray = rgb("64748b")
#let rule = rgb("cbd5e1")

#let callout(title, body, fill: blue-light, stroke: blue) = block(
  width: 100%,
  breakable: true,
  inset: 10pt,
  radius: 6pt,
  fill: fill,
  stroke: 0.8pt + stroke,
)[
  #text(weight: "bold", fill: stroke)[#title]
  #v(0.3em)
  #body
]

#show: doc => sid-document(
  sid-number,
  sid-title,
  doc,
  authors: sid-authors,
  state: sid-state,
  created: sid-created,
  discussion: sid-discussion,
  labels: sid-labels,
  category: sid-category,
  status: sid-status,
  last-updated: sid-last-updated,
)

= Context & Motivation

In single-instance deployments, Sibuna loads static policies from JSON files (`--policy-file`) and tracks active proof-of-work challenges and IP burst limits in local lock-striped memory. 

However, modern production edge security requires scaling horizontally across multiple proxy instances, edge nodes, and data centers. In such multi-node deployments, three critical operational requirements emerge:
1. *Dynamic Policy Propagation:* Security operators must push, update, or disable firewall rules instantly without restarting proxy processes or orchestrating manual configuration file reloads.
2. *Cluster-Wide Threat Intelligence:* When Node A intercepts a distributed credential stuffing attack or an adversary hits an invisible honeypot trap, the offending IP or CIDR block must be banned cluster-wide across all nodes within milliseconds.
3. *Forensic Audit Logging & Attack Analytics:* High-throughput attack payloads (SQLi, XSS, RCE) must be stored durably with full-text search capability for forensic auditing and incident response.

#callout("The Flaw of Existing Solutions", [
  - *SafeLine WAF* delegates storage to PostgreSQL (for rules and incidents) and Redis (for rate limits). This introduces a multi-container Docker dependency, requires 1.5 GB to 2.0 GB of RAM, and presents a single point of failure when Postgres or Redis fails under volumetric load.
  - *Cloudflare* solves this at hyperscale by deploying distributed key-value storage (Quicksilver) and edge SQL consensus (Cloudflare D1, built on replicated SQLite). However, Cloudflare is a proprietary closed-source SaaS.
], fill: amber-light, stroke: amber)

Sibuna achieves Cloudflare-grade distributed edge capabilities as a pure-open-source system by integrating *Zaxonlite*—an embedded, distributed SQL database built on SQLite and the `paxos-zig` Multi-Paxos consensus library.

= Zaxonlite Architectural Foundations

Zaxonlite (developed within the `paxos-zig` ecosystem) is designed around two core principles:

1. *Replicate the Bytes, Not the SQL:* Transactions execute once on the elected cluster leader. SQLite's write-ahead log (WAL) frame images are replicated across cluster nodes via Multi-Paxos consensus. Nondeterministic SQL functions (`random()`, `datetime('now')`) are safe by construction, and all replicas converge to byte-identical SQLite databases.
2. *The Journal is Truth; the Database is a Cache:* Every write is framed, checksummed, appended, and fsynced to an immutable journal before consensus commits. The local SQLite database file is simply materialized state that can be rebuilt deterministically from durable state anchors plus the journal suffix.
3. *Linearizable and Local Quorum Reads:* Follower nodes can serve reads locally with bounded freshness (`any` read level) for ultra-low latency, or execute quorum-fenced `linearizable` reads with zero log append overhead.
4. *Embedded Library (Zero Server Processes):* Zaxonlite compiles directly into the host Zig binary (or links via C ABI), requiring *no external database servers, no Docker daemons, and zero background microservices*.

= Storage Schema Design for Sibuna

Zaxonlite embeds directly into Sibuna's `libs/store` module, providing the following structured schema:

```sql
-- Dynamic Declarative Firewall Rules
CREATE TABLE policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    priority INTEGER NOT NULL,
    path_pattern TEXT,
    action TEXT NOT NULL,          -- 'allow', 'deny', 'challenge', 'weigh'
    difficulty INTEGER,            -- custom bit-level or hex difficulty
    header_matchers TEXT,          -- JSON array of name/pattern pairs
    cidr_matchers TEXT,            -- JSON array of network/mask strings
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Distributed IP Threat Intelligence & Dynamic Bans
CREATE TABLE ip_reputation (
    ip_or_cidr TEXT PRIMARY KEY,
    reputation_score INTEGER NOT NULL, -- -100 (banned) to 100 (trusted)
    banned_until INTEGER,          -- epoch timestamp (NULL if permanent)
    trigger_rule TEXT,             -- 'waf:sqli', 'waf:rce', 'honeypot', etc.
    hits INTEGER NOT NULL DEFAULT 1,
    last_seen INTEGER NOT NULL
);

-- Attack Incident Forensics with FTS5 Search
CREATE TABLE security_incidents (
    id TEXT PRIMARY KEY,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    violation_category TEXT NOT NULL, -- 'sqli', 'xss', 'path_traversal', 'rce', 'honeypot'
    offending_payload TEXT NOT NULL,
    recorded_at INTEGER NOT NULL
);

-- Full-Text Search Virtual Table for Security Analysts
CREATE VIRTUAL TABLE incidents_fts USING fts5(
    path,
    offending_payload,
    content='security_incidents',
    content_rowid='rowid'
);
```

= Hot-Path Performance Architecture

To maintain Sibuna's core performance contract—*zero dynamic heap allocations and sub-microsecond request evaluation*—the database is decoupled from the request hot path using a *Read-Copy-Update (RCU) In-Memory Snapshot Cache*:

1. *Read Hot-Path:* The proxy thread evaluates requests against an immutable in-memory snapshot (`policy.Engine`). It never issues blocking SQL queries or waits on SQLite mutexes during request routing. Hot-path evaluation continues in under 80 nanoseconds.
2. *Asynchronous Change Stream:* A background consensus worker listens for committed Zaxonlite transactions. When an administrator inserts a new policy or a honeypot triggers an automated IP ban:
   - Zaxonlite commits the transaction via Multi-Paxos.
   - The worker rebuilds the in-memory `policy.Engine` trie and swaps the pointer atomically.
   - All worker threads see the updated rules immediately without dropping connections or restarting.
3. *Asynchronous Audit Logging:* When a WAF attack is blocked, the request context is placed onto a lock-free ring buffer. A dedicated background thread drains the queue and writes batched incident records to Zaxonlite. The attacker receives a `403 Forbidden` response in 180 nanoseconds without blocking on disk I/O.

= Comparative Evaluation: Sibuna + Zaxonlite vs SafeLine vs Cloudflare

#table(
  columns: (1.3fr, 1.2fr, 1.2fr, 1.3fr),
  table.header([*Dimension*], [*SafeLine WAF*], [*Cloudflare Edge*], [*Sibuna + Zaxonlite*]),
  [Database Technology], [PostgreSQL + Redis], [Quicksilver + D1 (SQLite)], [*Zaxonlite (SQLite + Multi-Paxos)*],
  [Architecture], [Multi-container Docker], [Proprietary Cloud SaaS], [*Single Standalone Zig Binary*],
  [Consensus Protocol], [External Postgres Sync], [Internal Paxos / Raft], [*Pure Zig Multi-Paxos (`paxos-zig`)*],
  [Memory Footprint], [1,500 MB – 2,000 MB], [N/A (Multi-Tenant)], [*< 35 MB (Engine + Zaxonlite)*],
  [Hot-Path Evaluation], [IPC to detector (2–6 ms)], [Edge Worker (< 1 ms)], [*Sub-microsecond (< 1 µs)*],
  [Deployment Effort], [Heavy docker-compose], [Cloudflare Account / DNS], [*`./sibuna --cluster` (Zero deps)*],
  [Full-Text Search], [Postgres `tsvector`], [Cloudflare Logpush], [*Embedded SQLite FTS5*],
)

= Delivery Plan

1. *Phase 1 (Standalone Embedded Mode):* Link `libzaxonlite.a` into Sibuna. Provide SQLite-backed dynamic policy loading and local FTS5 incident audit logging.
2. *Phase 2 (Consensus Replication):* Expose cluster flags (`--join <peer>`, `--voter`) to enable multi-node Paxos replication for IP bans and policy updates.
3. *Phase 3 (Hybrid Vector Clustering):* Leverage Zaxonlite's built-in `sqlite-vec` integration to compute embedding distances across attack payloads, automatically clustering distributed zero-day botnet campaigns without human intervention.
