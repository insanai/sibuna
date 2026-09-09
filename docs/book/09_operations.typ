#import "theme.typ": *
#import "figures.typ": *

#part_page("IX", [Operations and Deployment], [
  We cover the two surfaces, every command-line flag, forward-auth recipes, policy files,
  persistent storage and clustering with Zaxonlite, and packaging.
])

== Surfaces and Configuration

#objectives([
  By the end of this chapter, you should be able to run Sibuna as a reverse proxy or a
  forward-auth validator, choose a surface, set the proof-of-work tier and difficulty, and
  manage the master secret.
])

=== Choosing a Surface

- *Gate* (`--gate`, alias `--no-waf`): proof-of-work admission, sessions, declarative rules,
  reputation, GCRA limits, bans.
- *Shield* (default, `--shield`): Gate plus the semantic firewall.
- *Distributed deployment* (an option for either surface): `--data-dir` (persistent policies, reputation, forensics) and, with a
  cluster build, `--cluster-*` flags for replication.

=== Command-Line Reference

#table(
  columns: (1.6fr, 0.8fr, 2fr),
  table.header([*Flag*], [*Default*], [*Meaning*]),
  [`--port, -p`], [`8080`], [Listening port],
  [`--host, -h`], [`0.0.0.0`], [Listening address],
  [`--upstream-host`], [`127.0.0.1`], [Origin host (reverse proxy mode)],
  [`--upstream-port, -u`], [`3000`], [Origin port],
  [`--mode, -m`], [`reverse_proxy`], [`reverse_proxy` or `forward_auth`],
  [`--workers, -w`], [CPU count], [Accept threads sharing the listening socket; each connection then gets its own thread],
  [`--max-connections`], [`1024`], [Connections served concurrently; further ones are answered `503`],
  [`--idle-timeout`], [`15`], [Seconds an idle connection may hold its thread before the reaper closes it],
  [`--trust-forwarded`], [off; on in forward-auth], [Honour `X-Forwarded-For` / `X-Real-IP` from the peer],
  [`--algorithm, -a`], [`posw`], [`posw` or `hashcash`],
  [`--difficulty, -d`], [`16`], [Work bits: Hashcash zero bits, or PoSW depth plus three],
  [`--posw-challenges`], [`16`], [Openings per sequential-work proof],
  [`--token-scheme`], [`mac`], [`mac` (keyed BLAKE3) or `ed25519`],
  [`--token-ttl`], [`86400`], [Session lifetime, seconds],
  [`--challenge-ttl`], [`300`], [Challenge lifetime, seconds],
  [`--secret-file, -s`], [random], [64 hex characters or 32 raw bytes; `SIBUNA_SECRET` also accepted],
  [`--cookie-name`], [`__sibuna_token`], [Session cookie name],
  [`--secure-cookie`], [off], [Add the `Secure` attribute],
  [`--gate` / `--shield`], [shield], [Surface selection],
  [`--rate-limit`], [`100`], [Requests per window per client (GCRA burst)],
  [`--rate-window`], [`10`], [Window in seconds],
  [`--ban-seconds`], [`3600`], [Honeypot ban duration],
  [`--policy-file, -P`], [none], [Declarative JSON policy],
  [`--data-dir, -D`], [none], [Zaxonlite data directory; enables persistent storage],
  [`--cluster-node`], [`0`], [This node's id; non-zero enables replication],
  [`--cluster-listen`], [none], [This node's `host:port` for peers],
  [`--cluster-peer`], [none], [`id@host:port[/role]`, repeatable],
  [`--cluster-secret-file`], [none], [Shared PSK for loopback development clusters],
  [`--cluster-tls-cert/key/ca`], [none], [Mutual TLS identity for production clusters],
  [`--storage-poll-ms`], [`500`], [Storage thread cadence],
  [`--verbose, -v`], [off], [Verbose logging],
)

#warning([The master secret], [
  Without `--secret-file` or `SIBUNA_SECRET` the daemon draws a random seed and prints
  "random (set --secret-file)". Tokens and challenges then die with the process, and a cluster
  whose nodes hold different seeds will reject each other's cookies. Generate one with
  `head -c 32 /dev/urandom | xxd -p -c 64 > /etc/sibuna/secret` and mode 0600.
])

== Console Preview

The console is composed into the daemon when storage is compiled in, but starts only with
`--console`. Use `-Dconsole=false` to compile it out; storage-off builds default it off too.
Bootstrap locally while the daemon is stopped:

```bash
sibuna init-admin admin --data-dir ./data
sibuna --data-dir ./data --console 127.0.0.1:19446
```

Open `http://127.0.0.1:19446/console/` and replace the generated temporary password. The
signed-in navigation provides the animated country globe, request and challenge statistics,
incident investigation, policy and inspection editors, users, scoped API tokens, audit and
serving-node controls. The authentication shell loads no globe geometry or telemetry.
Committed CSS and the Zig/Wasm interface ship with ordinary builds; npm is needed only when
regenerating style assets.

Policy previews build a private candidate including configured file rules. Saves compare the
expected revision; committed and locally applied revisions are distinct. Audit details retain
bounded decision changes and the effective acting role. Matcher values are redacted and old
records with missing context remain explicitly absent. Drain, resume and clear-local-bans
require a command preview. Inspect the durable receipt after a lost response before retrying;
a committed intent alone does not establish that the runtime effect finished.

For remote operation, use an HTTPS proxy and configure `--console-origin`,
`--console-behind-proxy`, explicit `--console-trusted-proxy` CIDRs, and
`--console-key-file`. The key file contains 64 hexadecimal characters, has owner-only
permissions and protects stored second-factor secrets; retain it across restarts separately
from the challenge seed. The configured HTTPS origin and proxy allowlist are mandatory for
off-loopback access.

The native CLI accesses the running console through the same authorization and storage
contracts. It reads credentials from private files, not command-line values:

```bash
sibuna console geoip update --month 2026-09 \
    --origin http://127.0.0.1:19446 --username admin \
    --password-file ./admin-password
```

Use an owner-only password file, complete password setup first, and add `--factor-file` for
an authenticator or recovery code when required. `geoip status` reads the active generation.
Updates download the free DB-IP country archive, validate bounded ranges, persist the new
generation and activate it locally. Failed updates preserve the previous generation. A CLI
timeout stops waiting; it does not cancel submitted storage work. DB-IP Lite requires
CC BY 4.0 attribution. Unknown addresses, sample loss and stale data remain visible; importing
country data does not create traffic or enrich already expired samples.

SID 0007 remains Proposed. Cluster management WebSockets, full peer coverage, notifications,
constrained page templates, kiosk sessions and the console performance impact gates remain
unfinished. The working local workflows do not establish those acceptance results.

== Deployment Topologies

#objectives([
  Deploy the autonomous reverse proxy and the forward-auth validator behind Nginx or Caddy.
])

=== Reverse Proxy

#book_figure([Request routing on the Shield surface], pipeline_flow())

```bash
sibuna --port 80 --upstream-host 127.0.0.1 --upstream-port 3000 \
       --secret-file /etc/sibuna/secret --difficulty 16 --algorithm posw
```

Admitted requests reach the origin with `X-Forwarded-For`, `X-Real-IP`, `X-Sibuna-Status`, and
`X-Sibuna-Rule` headers; hop-by-hop headers and any incoming forwarded-for value are stripped.

=== Forward Auth Behind an Ingress

In `--mode forward_auth` the daemon answers the ingress's subrequest with `200` (plus the audit
headers), `401` for a challenge, `403` for a denial, or `429` when rate limited. The ingress
must forward the client address; forward-auth mode trusts it by default.

```nginx
server {
    listen 443 ssl;
    location / {
        auth_request /__sibuna_auth;
        error_page 401 = @sibuna_challenge;
        proxy_pass http://127.0.0.1:3000;
    }
    location = /__sibuna_auth {
        internal;
        proxy_pass http://127.0.0.1:8080/;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header Cookie $http_cookie;
    }
    location @sibuna_challenge { proxy_pass http://127.0.0.1:8080; }
    location /__sibuna/ { proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Forwarded-For $remote_addr; }
}
```

```caddyfile
example.com {
    forward_auth localhost:8080 {
        uri /
        header_up X-Forwarded-For {remote_host}
    }
    handle /__sibuna/* { reverse_proxy localhost:8080 }
    reverse_proxy localhost:3000
}
```

The `/__sibuna/*` namespace (interstitial, challenge, verify, solver assets) must reach the
daemon directly in both recipes.

== Declarative Policy

#objectives([
  Write a policy file with rules, weights, thresholds, IP rules, and the WAF switch.
])

```json
{
  "default_action": "CHALLENGE",
  "waf": true,
  "thresholds": { "challenge_at": 10, "deny_at": 40, "bits_step": 5 },
  "ip_rules": { "10.0.0.0/8": "ALLOW", "192.0.2.0/24": "DENY", "2001:db8::/32": "DENY" },
  "rules": [
    { "name": "deny-cf-workers", "headers": { "CF-Worker": ".*" }, "action": "DENY" },
    { "name": "deny-amazonbot", "user_agent": "Amazonbot", "action": "DENY" },
    { "name": "api-with-key", "path": "/api/*", "headers": { "X-Api-Key": ".*" },
    "action": "ALLOW" },
    { "name": "protect-checkout", "path": "/checkout/*", "action": "CHALLENGE",
      "challenge": { "difficulty": 20, "algorithm": "posw" } },
    { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 },
    { "name": "internal-vpc", "remote_addresses": ["10.0.0.0/8", "fd00::/8"],
    "action": "ALLOW" }
  ]
}
```

`rules` replaces the built-in table when present; `ip_rules` feeds the reputation trie, which
scales to thousands of prefixes; `waf: false` selects the Gate surface from the file.

== Persistent Storage and Clustering

#objectives([
  Enable Zaxonlite storage, add a dynamic policy and a ban with SQL, query incident forensics,
  understand campaign clustering, and run a replicated cluster.
])

#book_figure([The storage architecture: workers never block on the database], storage_architecture())

`--data-dir /var/lib/sibuna` opens an embedded Zaxonlite node (journal, payload store, and
SQLite image in one directory) and starts the storage thread. On start and whenever the
`policies` or `ip_reputation` tables change, the thread rebuilds the spare engine slot from the
policy file plus the database and publishes it; requests never wait on SQL.

=== Schema

#table(columns: (1fr, 2.3fr),
  table.header([Table], [Purpose and key]),
  [`policies`], [Ordered dynamic rules, keyed by `id`.],
  [`ip_reputation`], [Scores, hit counts and expiry, keyed by address or prefix.],
  [`security_incidents`], [One bounded event record, keyed by issuer and sequence.],
  [`incidents_fts`], [Full-text index over paths and payloads.],
  [`incidents_vec`], [64-component embeddings for nearest-campaign lookup.],
  [`sibuna_meta`], [Policy revision and per-issuer incident commit receipts.],
)

The complete schema is `apps/sibuna/src/persistent.zig`. Runtime migrations and indexes are
part of the same storage transaction; an abbreviated printed schema is not an upgrade script.


=== Operating It

Use the `zaxon` CLI from the Zaxonlite release, or any SQLite client on the materialised
`current.db` for reads:

```sql
-- Add a dynamic rule; healthy nodes poll after committed changes.
INSERT INTO policies (id, name, priority, path_pattern, action, difficulty, algorithm,
  header_matchers, cidr_matchers, weight, enabled, created_at, updated_at)
VALUES ('p-checkout', 'protect-checkout', 10, '/checkout/*', 'CHALLENGE', 20, 'posw',
  '{"X-Api": "v2"}', '["10.0.0.0/8"]', 0, 1, unixepoch(), unixepoch());

-- Ban an address cluster-wide for a day.
INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until,
  trigger_rule, hits, last_seen)
VALUES ('198.51.100.7', -100, unixepoch() + 86400, 'analyst', 1, unixepoch());

-- Forensics: full-text search over recorded payloads.
SELECT s.id, s.client_ip, s.violation_category, s.path, s.campaign_id
FROM incidents_fts f JOIN security_incidents s ON s.id = f.rowid
WHERE incidents_fts MATCH 'union' ORDER BY rank LIMIT 20;
```

Scores at or below $-50$ become `deny` prefixes in the trie, scores at or above $50$ become
`allow`, and `banned_until` bounds the ban. Honeypot hits insert a $-100$ record automatically,
so a trap sprung on one node bans the address on all of them.

=== A Transaction Receipt Makes Retry Safe

The storage thread collects at most 32 pending records and builds one SQL transaction. The
transaction inserts incidents, updates the text and vector indexes, and applies honeypot
reputation changes. Each issuer has a monotonically increasing cursor in `sibuna_meta`.
Every data-changing statement is guarded by that cursor; the transaction advances it last.

#definition([Worked example: the acknowledgement disappears], [
  Suppose issuer 2 prepares sequences 101 through 132, ending at cursor 133. The leader commits
  all records and cursor 133, then disappears before replying. The storage thread retains the
  exact SQL and retries. The receipt already equals 133, so the guarded writes do nothing:
  neither incidents nor honeypot hit counts are doubled. If the original transaction rolled
  back, the old cursor remains and the retry applies all writes once.
])

A failed commit retains the pending batch in memory and increments
`incident_write_failures`. The tick still attempts policy polling. A full 512-record queue
counts `incidents_dropped`; it never blocks an HTTP response waiting for disk. The pending
batch adds space for 32 records. Process death before commit can lose queued data: this is a
bounded asynchronous forensic path, not a durable message queue at enqueue time.

#exercise("9.1", [Move the receipt update outside the data transaction. Construct one crash
schedule that duplicates a reputation effect and another that loses an incident.])

=== Campaign Clustering

Each incident payload is embedded as a 64-dimensional unit vector by the hashing trick over
byte trigrams (digits folded, case folded) and stored in `incidents_vec`. Before insertion the
transaction queries the vector table for the nearest existing incident, including earlier
records in the same batch; if its cosine distance
is below $0.35$ the new incident joins that incident's `campaign_id`, otherwise it starts a
campaign. Similarity is a heuristic: the regression examples group related SQL payloads, but that
is not a guarantee that every pair of attacks shares a campaign. No model runs and nothing is trained.

=== Clustering

Build with `-Dcluster=true` (links OpenSSL 3 for Zaxonlite's mutual TLS) and start each member
with the full static membership:

```bash
sibuna --data-dir /var/lib/sibuna --cluster-node 1 --cluster-listen 10.0.0.1:9901 \
       --cluster-peer 2@10.0.0.2:9901 --cluster-peer 3@10.0.0.3:9901 \
       --cluster-tls-cert n1.crt --cluster-tls-key n1.key --cluster-tls-ca ca.crt \
       --secret-file /etc/sibuna/secret
```

Every member must pass the identical member list and the same master secret. Writes go to the
elected leader and replicate as SQLite page images by Multi-Paxos; each node's storage thread
sees the committed change and rebuilds its engine. For local experiments a loopback cluster may
use `--cluster-secret-file` (a pre-shared key) instead of certificates.

=== Cluster Challenge Routing

Challenge keys are bound to `--cluster-node`; keep challenge issuance and verification on the
same member. Tokens use the shared seed and work on other members. Local rate quotas do not
become global quotas, and process restarts clear spent sets. See the distributed benchmark
results for loopback throughput, replicated ban propagation and one-member-loss coverage.

The storage transport authenticates each node certificate using the common name
`zaxon-node-<id>` (matching `--cluster-node`), signed by the configured CA. A certificate
with an arbitrary common name does not authenticate a storage member. The distributed
harness creates temporary CA-signed identities and exercises this mutual-TLS transport.

== Packaging

#objectives([
  Build the binary for a target, package it, and run it under systemd.
])

- `zig build -Doptimize=ReleaseFast` produces a binary with storage compiled in (it links
  libc for SQLite).
- `zig build -Doptimize=ReleaseFast -Dstorage=false` produces a fully static binary with no libc
  dependency, suitable for a `scratch` container image; `--data-dir` is then refused at start.
- `zig build -Dcluster=true` adds replication and requires OpenSSL 3 at build and run time.

```ini
[Unit]
Description=Sibuna Web Firewall
After=network.target

[Service]
User=sibuna
ExecStart=/usr/local/bin/sibuna --port 8080 --upstream-port 3000 \
  --secret-file /etc/sibuna/secret --data-dir /var/lib/sibuna
Restart=always
LimitNOFILE=65535
ProtectSystem=strict
ReadWritePaths=/var/lib/sibuna

[Install]
WantedBy=multi-user.target
```

#exercise([9.2], [
  Write the policy file and the `ip_reputation` rows needed so that a staging network
  (`10.20.0.0/16`) bypasses challenges, `/admin/*` demands 20 work bits of sequential work, and
  a partner scraper identified by `X-Partner-Key` is admitted at 30 requests per 10 seconds.
], hint: [Rate limits are global per client; use a rule for the partner and the daemon flags for the limit.])

#teach_back([
  Explain to an operator why adding a row to `policies` takes effect without a restart and
  without a request ever waiting, in terms of the storage thread and the engine slots.
])
