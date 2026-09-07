#import "theme.typ": *
#import "figures.typ": *

#part_page("IX", [Operations and Deployment], [
  We cover the three surfaces, every command-line flag, forward-auth recipes, policy files,
  persistent storage and clustering with Zaxonlite, and packaging.
])

= Surfaces and Configuration

#objectives([
  By the end of this chapter, you should be able to run Sibuna as a reverse proxy or a
  forward-auth validator, choose a surface, set the proof-of-work tier and difficulty, and
  manage the master secret.
])

== Choosing a Surface

- *Gate* (`--gate`, alias `--no-waf`): proof-of-work admission, sessions, declarative rules,
  reputation, bans. 295 ns per classification.
- *Shield* (default, `--shield`): Gate plus the semantic firewall and GCRA rate limits.
- *Edge*: Shield plus `--data-dir` (persistent policies, reputation, forensics) and, with a
  cluster build, `--cluster-*` flags for replication.

== Command-Line Reference

#table(
  columns: (1.6fr, 0.8fr, 2fr),
  table.header([*Flag*], [*Default*], [*Meaning*]),
  [`--port, -p`], [`8080`], [Listening port],
  [`--host, -h`], [`0.0.0.0`], [Listening address],
  [`--upstream-host`], [`127.0.0.1`], [Origin host (reverse proxy mode)],
  [`--upstream-port, -u`], [`3000`], [Origin port],
  [`--mode, -m`], [`reverse_proxy`], [`reverse_proxy` or `forward_auth`],
  [`--workers, -w`], [CPU count], [Accept threads sharing the listening socket],
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

= Deployment Topologies

#objectives([
  Deploy the autonomous reverse proxy and the forward-auth validator behind Nginx or Caddy.
])

== Reverse Proxy

#book_figure([Request routing on the Shield surface], pipeline_flow())

```bash
sibuna --port 80 --upstream-host 127.0.0.1 --upstream-port 3000 \
       --secret-file /etc/sibuna/secret --difficulty 16 --algorithm posw
```

Admitted requests reach the origin with `X-Forwarded-For`, `X-Real-IP`, `X-Sibuna-Status`, and
`X-Sibuna-Rule` headers; hop-by-hop headers and any incoming forwarded-for value are stripped.

== Forward Auth Behind an Ingress

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
    location /__sibuna/ { proxy_pass http://127.0.0.1:8080; proxy_set_header X-Forwarded-For $remote_addr; }
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

= Declarative Policy

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
    { "name": "api-with-key", "path": "/api/*", "headers": { "X-Api-Key": ".*" }, "action": "ALLOW" },
    { "name": "protect-checkout", "path": "/checkout/*", "action": "CHALLENGE",
      "challenge": { "difficulty": 20, "algorithm": "posw" } },
    { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 },
    { "name": "internal-vpc", "remote_addresses": ["10.0.0.0/8", "fd00::/8"], "action": "ALLOW" }
  ]
}
```

`rules` replaces the built-in table when present; `ip_rules` feeds the reputation trie, which
scales to thousands of prefixes; `waf: false` selects the Gate surface from the file.

= Persistent Storage and Clustering

#objectives([
  Enable Zaxonlite storage, add a dynamic policy and a ban with SQL, query incident forensics,
  understand campaign clustering, and run a replicated cluster.
])

#book_figure([The storage architecture: workers never block on the database], storage_architecture())

`--data-dir /var/lib/sibuna` opens an embedded Zaxonlite node (journal, payload store, and
SQLite image in one directory) and starts the storage thread. On start and whenever the
`policies` or `ip_reputation` tables change, the thread rebuilds the spare engine slot from the
policy file plus the database and publishes it; requests never wait on SQL.

== Schema

```sql
CREATE TABLE policies (id TEXT PRIMARY KEY, name TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 100,
  path_pattern TEXT, ua_pattern TEXT, action TEXT NOT NULL, difficulty INTEGER, algorithm TEXT,
  header_matchers TEXT, cidr_matchers TEXT, weight INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE ip_reputation (ip_or_cidr TEXT PRIMARY KEY, reputation_score INTEGER NOT NULL,
  banned_until INTEGER, trigger_rule TEXT, hits INTEGER NOT NULL DEFAULT 1, last_seen INTEGER NOT NULL);
CREATE TABLE security_incidents (id INTEGER PRIMARY KEY, node_id INTEGER NOT NULL, client_ip TEXT NOT NULL,
  user_agent TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, violation_category TEXT NOT NULL,
  offending_payload TEXT NOT NULL, campaign_id INTEGER, recorded_at INTEGER NOT NULL);
CREATE VIRTUAL TABLE incidents_fts USING fts5(path, offending_payload,
  content='security_incidents', content_rowid='id');
CREATE VIRTUAL TABLE incidents_vec USING vec0(item_id INTEGER PRIMARY KEY,
  embedding float[64] distance_metric=cosine, embedding_coarse bit[64]);
```

== Operating It

Use the `zaxon` CLI from the Zaxonlite release, or any SQLite client on the materialised
`current.db` for reads:

```sql
-- Add a dynamic rule; every node picks it up within --storage-poll-ms.
INSERT INTO policies (id, name, priority, path_pattern, action, difficulty, algorithm,
  header_matchers, cidr_matchers, weight, enabled, created_at, updated_at)
VALUES ('p-checkout', 'protect-checkout', 10, '/checkout/*', 'CHALLENGE', 20, 'posw',
  '{"X-Api": "v2"}', '["10.0.0.0/8"]', 0, 1, unixepoch(), unixepoch());

-- Ban an address cluster-wide for a day.
INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, trigger_rule, hits, last_seen)
VALUES ('198.51.100.7', -100, unixepoch() + 86400, 'analyst', 1, unixepoch());

-- Forensics: full-text search over recorded payloads.
SELECT s.id, s.client_ip, s.violation_category, s.path, s.campaign_id
FROM incidents_fts f JOIN security_incidents s ON s.id = f.rowid
WHERE incidents_fts MATCH 'union' ORDER BY rank LIMIT 20;
```

Scores at or below $-50$ become `deny` prefixes in the trie, scores at or above $50$ become
`allow`, and `banned_until` bounds the ban. Honeypot hits insert a $-100$ record automatically,
so a trap sprung on one node bans the address on all of them.

== Campaign Clustering

Each incident payload is embedded as a 64-dimensional unit vector by the hashing trick over
byte trigrams (digits folded, case folded) and stored in `incidents_vec`. Before insertion the
storage thread asks the vector table for the nearest existing incident; if its cosine distance
is below $0.35$ the new incident joins that incident's `campaign_id`, otherwise it starts a
campaign. Two SQL injections with different target columns land in one campaign; a honeypot hit
does not. No model runs and nothing is trained.

== Clustering

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

= Packaging

#objectives([
  Build the binary for a target, package it, and run it under systemd.
])

- `zig build -Doptimize=ReleaseFast` produces a 4.2 MB binary with storage compiled in (it links
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

#exercise([9.1], [
  Write the policy file and the `ip_reputation` rows needed so that a staging network
  (`10.20.0.0/16`) bypasses challenges, `/admin/*` demands 20 work bits of sequential work, and
  a partner scraper identified by `X-Partner-Key` is admitted at 30 requests per 10 seconds.
], hint: [Rate limits are global per client; use a rule for the partner and the daemon flags for the limit.])

#teach_back([
  Explain to an operator why adding a row to `policies` takes effect without a restart and
  without a request ever waiting, in terms of the storage thread and the engine slots.
])
