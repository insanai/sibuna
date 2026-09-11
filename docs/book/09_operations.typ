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

=== A Tour of the Console

The screenshots below come from the built console on one loopback node fed with synthetic
traffic (addresses from documentation ranges, a honeypot and injection probes), so every
number is illustrative. Each page answers one question stated in its title and carries the
product, the serving node, the page and the way back in the same place.

#book_figure([Sign-in. The public shell loads no globe geometry, GeoIP data or telemetry;
the second form exchanges a wall-display code for a read-only statistics session.],
image("images/console-sign-in.png"))

#book_figure([Statistics · Traffic. Tiles show retained closed-minute counts with a
deviation against the same window yesterday and a live 60-second sparkline; decision colours
(admitted green, challenged amber, denied red, banned dark red) are the same in every panel.],
image("images/console-traffic.png"))

#book_figure([Statistics · Security. One tile per module, findings over sixty equal buckets,
the live event feed, attack categories and attacked paths; values that are not recorded say
so instead of showing zero.],
image("images/console-security.png"))

#book_figure([Events. Each recorded incident opens inline with its evidence: the selected
local response, byte lengths, campaign candidate, and explicit “not recorded” entries for
the matched rule, score terms and JA4 fingerprint. Deny and allow actions open the IP
groups form with the address drafted.],
image("images/console-events.png"))

#book_figure([Challenges. Issued, submitted, accepted and rejected counts by cause, the
configured and most recently issued parameters, and the accepted solve-time histogram
partitioned by algorithm and parameter bin.],
image("images/console-challenges.png"))

#book_figure([Policies. The applied engine names its surface and node-local limits, then
lists rules in evaluation order with hits today, followed by the inspection mode matrix, the
request tester and IP groups.],
image("images/console-policies.png"))

#book_figure([Reviewing a rule edit before saving (dark theme). Only changed fields are
listed; confirming validates the whole candidate and creates a new revision.],
image("images/console-policy-review.jpg"))

#book_figure([Nodes. The serving node's status and commands, then every announced member
with its applied revision, log slots, replication lag and probe result.],
image("images/console-nodes.png"))

#book_figure([GeoIP. Provider, licence, active generation digest, load time and the import
form; a failed import never replaces the active generation.],
image("images/console-geoip.png"))

#book_figure([Settings. Notification destinations, denial-spike thresholds, retention with
an explicit acknowledgement per window, response-page templates and About.],
image("images/console-settings.png"))

#book_figure([Audit. Append-only history with actor and role, action, subject and a detail
view with redacted before and after summaries; refused sign-ins are recorded too.],
image("images/console-audit.png"))

The optional `--console-location <latitude,longitude>` declares this node's position, for
example `1.3521,103.8198` for a deployment in Singapore. The globe initially centers there;
Center Sibuna returns to that point after rotation. Country activity follows animated
great-circle arcs toward the node, with rear-hemisphere and flat-map dateline clipping.
Country positions are representative centroids, and arrows represent the observed sixty-second
window rather than individual connections. An unset server position stays explicitly unknown.
The configured marker remains visible through telemetry outages; stale traffic does not animate.

Policy previews build a private candidate including configured file rules. Saves compare the
expected revision and require confirmation of a field comparison. Historical reverts compare
against the current rule and create a new revision. Committed and locally applied revisions
are distinct. Audit details retain
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
sibuna console geoip update --version 2026-09-09 \
    --origin http://127.0.0.1:19446 --username admin \
    --password-file ./admin-password
```

Use an owner-only password file, complete password setup first, and add `--factor-file` for
an authenticator or recovery code when required. `geoip status` reads the active generation.
Updates download the selected provider's published files over HTTPS (the public-domain
`user-country` dataset by default, or DB-IP Lite with `--provider dbip --version YYYY-MM`),
verify the publisher's checksums, validate bounded ranges through `libs/geoip`, persist the
new generation and activate it locally. Failed updates preserve the previous generation. A
CLI timeout stops waiting; it does not cancel submitted storage work. DB-IP Lite requires
CC BY 4.0 attribution, shown only while its data is active. A build with `-Dgeoip-data`
embeds a validated snapshot until the first durable import. Unknown addresses, sample loss
and stale data remain visible; importing country data does not create traffic or enrich
already expired samples.

Cluster members announce themselves through the replicated membership table and appear on
every console's Nodes page; configure `--console-probe <node-id>=<http://ip:port>` for the
peers whose data-plane listeners this console should health-check and
`--console-advertise <origin>` for the link other consoles show. Direct live telemetry uses
`--console-peer <node-id>=<https://origin>` (repeatable, at most eight) and a dedicated
`--console-peer-key-file`. Both endpoints must list each other and use trusted HTTPS ingress.
The peer key is an owner-only file containing 64 hex characters, provisioned independently of
console encryption, challenge and consensus keys. `--console-peer-ca-file` optionally supplies
PEM trust anchors for a private management PKI; otherwise the client uses system roots.
Certificate hostname validation always applies. Key rotation requires coordinated restart.
The Nodes API and its subscription report receipt age, clock skew, boot changes and sampling
loss. Missing observations remain unavailable and disconnected values remain stale; received
statistics never become another node's own contribution. The dashboard's *Live traffic scope*
selects one node or combines the configured nodes. *Node coverage and locations* identifies
missing, stale and clock-skewed sources, observation times and configured destinations.
Country rankings show the uncertainty from omitted source rows. Arrows retain their receiving
node, and missing node locations are not invented. The combined rate stays unobserved when
any contributing source lacks a consecutive interval. Select one node to inspect its retained
seconds and current-minute path rankings. Remote queries use the authenticated peer connection;
missing peers stay unavailable and history cursors cannot cross a node restart. Minute history
keeps its own node selection and per-node rows.
The navigation and mobile header identify the serving console node independently of the
selected traffic source. Local commands remain per node. `zig build console-impact` runs the data-plane isolation matrix (`-- --quick` for
a smoke run) and writes `benchmarks/results/console-impact-latest.json`.

Traffic tiles open on the last 24 hours of retained closed-minute records for the selected
nodes. The period control also offers an hour, seven or ninety days, and live boot totals.
Yesterday deviations require complete matching coverage from every selected node. The globe
and sparklines still describe their separate live 60-second window. A retained scan refreshes
one minute after completion, keeping its previous values and age visible until replacement;
changing the source or period discards the old scope. Missing history never becomes zero.

*Compare retained traffic* displays two closed minute windows beside each other: the same
window yesterday, the preceding period, or a second node. Duration and end-offset controls
freeze both UTC ranges. Each action reads at most sixteen compact pages per side, with
96 stored records per page. This covers a 24-hour window without overlapping restarts in one
batch; Continue retains the same boundaries for longer scans. Complete coverage, incomplete coverage and missing history remain
explicit. Rate percentages require complete non-overlapping intervals in equal UTC windows,
normalized by observed milliseconds; a zero reference with new traffic shows “New”.
The primary Traffic period remains independent.
The minute format does not record historical proxy mode, so origin-response comparisons remain
unavailable rather than interpreting forward-auth zeros as observed responses.

*Compare retained path rankings* selects two closed windows or nodes. Node 0 includes all
retained nodes, including retired members. An action reads at most sixteen immutable archives,
checks their identities and checksums, and merges every counter before selecting display rows.
Archives seal after the 60-second late-sample window, so the newest closed minute may still
be pending. Continue preserves the original windows and cursor. Bounds describe sampled path prefixes,
not exact request totals. The page shows partial scans, truncation, retention boundaries and
reported queue loss; missing archives cannot establish zero traffic or complete coverage.

Security opens on the last 24 hours and uses sixty equal time buckets over the selected period.
Its aggregates run on the storage owner under a fixed SQLite step budget
(`--console-query-steps`, 100,000 to 50,000,000, default four million). Set it alongside
`--console`; invalid or repeated values are refused. This allowance applies to local embedded
queries. Cluster queries use Zaxonlite’s server-side ten-million-step bound instead; changing
this option does not change that RPC limit. Exhausted queries ask for a narrower period.
Step counts bound query work, not elapsed time. Charts share a scale;
expand Trend values for the UTC interval starts and exact grouped counts. These are retained
findings, so missing incident coverage cannot be interpreted as absence of attacks.

Wall displays use kiosk sessions. Under Account, an operator names the display and selects
Create display code. The display pastes the one-time code into the sign-in form within ten
minutes; its session is read-only, limited to statistics and expires within twelve hours.
The account page erases the displayed code on navigation or when hidden. Hiding does not
revoke an unused grant; the exchange deadline still applies. Codes never belong in URLs.
Traffic and Security share the display: Security shows aggregate module trends and request
outcomes without incident addresses or payload evidence. Automatic cycling is optional,
off initially and suspended with reduced motion, stale data or Pause.

Notification destinations (signed webhooks and syslog for denial spikes, bans, unreachable
members and leader changes) live under Settings; webhook secrets need `--console-key-file`.
Each destination has its own cooldown and three-attempt retry budget. Delivery audit records
show outcomes; completed queue history is bounded to seven days and 4,096 events. Webhooks
include a stable `Idempotency-Key` so receivers can suppress repeated effects after uncertain
network completion.
Syslog's UDP/TCP selection applies only to outbound notifications, independently of protected
web traffic. Manual tests record intent and completion in Audit and refresh the destination
outcome; an unconfirmed audit completion is shown explicitly before an operator retries.

Settings also controls retention: one to 90 days for minute history, one to seven for
rankings, one to 30 for incidents and one to 365 for audit. The upper values are the defaults;
rankings keep their 512 MiB quota. Saving a retention value requires confirmation because
cleanup permanently removes older records in bounded batches. Increasing the value later
does not restore deleted history. Stale edits are refused and successful changes appear in Audit.

Response pages (challenge, denied, rate limited, banned, overloaded) are editable under
Settings as bounded HTML with fixed placeholders; drafts preview in a sandboxed tab and
saved pages are served from the next policy snapshot.

Policy workflows on the Policies page: reorder managed rules, replay a draft against retained
inspection findings, manage IP groups and country blocks pinned to the active GeoIP
generation, and export or atomically import the managed set (also `sibuna console policies
export` and `sibuna console policies import --file <set.json>`).
Applied rules show recorded hits today, hourly sparklines and an accessible table. A hit is a
successful declarative matcher evaluation: matching WEIGH rules and the first terminal match
count; an earlier inspection or reputation decision may prevent evaluation. Private tests do
not increment these counters. *Compare rule hits* freezes two closed periods for one recorded
node. Revision history offers *Compare hits around this edit*, excluding the edit minute and
using equal available periods up to the chosen duration. Optional applied-revision filters
keep unrelated generations out of the comparison. Startup, cutover, missing writes and
retention leave visible coverage gaps; percentages require complete coverage on both sides.
Rule observations and hourly/daily summaries follow the minute-retention setting. An observed
change around an edit is a comparison, not evidence that the edit caused the traffic change.

Importing a later GeoIP generation does not automatically refresh existing country-derived
reputation rows. Preview the country action to compare added, retained and removed prefixes;
page through the reviewed diff before applying it. The replacement removes obsolete rows owned
by that country and preserves independently managed prefixes. A changed generation or policy
revision requires a fresh preview, and overlapping independent edits are refused. The Events page
contains retained WAF findings and honeypot incidents; it is not a complete access log.
With GeoIP loaded, the storage worker records each incident's country and generation in
the incident transaction. This is attribution at persistence, not a reconstructed request-time
location. Later imports leave recorded mappings unchanged. The country filter accepts an
uppercase two-letter code, `unknown` for an address absent from the loaded generation,
or `not_recorded` for an incident without mapping data. Source groups report mixed countries
or coverage explicitly. The globe's *View events* action keeps the selected node and opens
the country's retained incidents for the last hour.
The Statistics page's *Security* view combines live rate-limit, challenge and ban rates with
retained inspection and honeypot findings over one hour, one day, seven days or thirty days.
Category, source and path links open the normal incident workflow with the same node and a
fixed time boundary. Applying incident filters starts a new period. Findings include audit
records and are distinct from blocked-request totals; absent reputation and rule-hit attribution
is shown as not recorded. Event and audit filters keep labels with their controls, align the
Apply action separately and adapt their columns to the available content width.
One authenticated WebSocket survives navigation and carries statistics, incident summaries,
node status, policy revisions, challenges and audit summaries. New incident and audit records
wait behind *Load latest records* so the table stays in place while it is read. Policy updates
show current committed and applied revisions without replacing an open draft. Flow counters
update live; refresh a selected non-default challenge timing partition explicitly. Historical
queries, detail reads and mutations remain HTTP requests.

Page fragments can be bookmarked; Back and Forward reopen authenticated pages. The sidebar
also remembers theme and spacing choices in this browser, with System as the default theme.
SID 0007 remains Proposed. The interface is available, with ongoing review corrections
and acceptance work recorded in the SID. Earlier impact runs are inconclusive. The corrected
harness includes each dashboard's stream, rankings and retained-timeline queries; a full
acceptance run requires a production GeoIP snapshot and documented host conditions. Direct TLS
peer transport and the combined dashboard have separate coverage and freshness contracts;
interface review and browser acceptance remain tracked in SID 0007. The complete Wasm
application warns above 448 KiB and has a 512 KiB uncompressed ceiling. These project limits
leave room for console workflows; they do not replace browser loading and responsiveness
measurements or change the explicit 4 MiB linear-memory allocation.

#pagebreak(weak: true)

== Deployment Topologies

#objectives([
  Deploy the autonomous reverse proxy and the forward-auth validator behind Nginx or Caddy.
])

=== Reverse Proxy

#book_figure([Request routing on the Shield surface], pipeline_flow(), placement: none)

```bash
sibuna --port 80 --upstream-host 127.0.0.1 --upstream-port 3000 \
       --secret-file /etc/sibuna/secret --difficulty 16 --algorithm posw
```

Admitted requests reach the origin with `X-Forwarded-For`, `X-Real-IP`, `X-Sibuna-Status`, and
`X-Sibuna-Rule` headers; hop-by-hop headers and any incoming forwarded-for value are stripped.

HTTP/1.1 WebSocket upgrades pass through admission and policy checks before the origin's
handshake is accepted. Subprotocol and extension negotiation remains end-to-end; two fixed
16 KiB buffers relay bytes in both directions, including prefetched bytes and half-closes.
Upgraded sockets remain within the normal connection quota and shutdown registry, but use
`--websocket-idle-timeout` (300 seconds by default) independently of the HTTP idle deadline.
Traffic in either direction refreshes that bound. Frames after the handshake are not WAF
inspection inputs. HTTPS/WSS uses a TLS-terminating ingress in front of Sibuna's private
HTTP/1.1 listener; Sibuna does not terminate browser TLS itself.

The ingress can negotiate HTTP/2 with browsers and forward HTTP/1.1 to Sibuna. Native
HTTP/2 support in Sibuna is deferred to a later update; this arrangement does not provide
end-to-end HTTP/2 semantics for applications such as native gRPC.

Content-Length request bodies stream through fixed buffers, preserving bytes and MIME
headers. Multipart uploads retain boundaries, repeated field names, filenames and part types.
The WAF examines at most the first 8 KiB of the body: multipart metadata and non-file fields
remain text inspection inputs, while file payloads are opaque. Recognized binary top-level
MIME types (images except SVG, audio, video, PDF, ZIP, gzip, 7z, protobuf and octet-stream)
are opaque too. JSON, XML, SVG, URL-encoded forms and unknown types retain text inspection.
Ambiguous or malformed MIME metadata falls back to text inspection. Multipart parsing is
bounded to 32 parts and 2 KiB of headers per part within that same prefix.

This is upload compatibility, not file validation or malware scanning. The backend must
enforce accepted media types rather than trust a client's Content-Type declaration. Fields
after the inspection prefix, including those after a large uploaded file, are not inspected.
Compressed payloads are not decompressed for inspection. Uploads still pass admission, path,
query and header checks and remain subject to connection deadlines. Request transfer coding
is currently unsupported, so send Content-Length rather than chunked request bodies.
Clients waiting for `100-continue` receive it locally before sending the body; unsupported
expectations receive 417. The Expect header is consumed before forwarding to the backend.

=== Forward Auth Behind an Ingress

In `--mode forward_auth` the daemon answers the ingress's subrequest with `200` (plus the audit
headers), `401` for a challenge, `403` for a denial, or `429` when rate limited. The ingress
must forward the client address and original URL; forward-auth mode trusts them by default.
Bind this listener privately so only the ingress can connect. `X-Forwarded-Uri` (Caddy) or
`X-Original-URI` (Nginx), and `X-Forwarded-Method`, restore the application request for policy
evaluation. Duplicate or conflicting original-URL fields are rejected. Internal daemon routes
always use the actual request URI. Forward-auth does not inspect a body the ingress omits.

```nginx
map $http_upgrade $sibuna_connection_upgrade {
    default upgrade;
    '' close;
}
server {
    listen 443 ssl;
    location / {
        auth_request /__sibuna_auth;
        auth_request_set $sibuna_auth_status $upstream_status;
        auth_request_set $sibuna_retry_after $upstream_http_retry_after;
        auth_request_set $sibuna_status $upstream_http_x_sibuna_status;
        auth_request_set $sibuna_rule $upstream_http_x_sibuna_rule;
        auth_request_set $sibuna_rule_hash $upstream_http_x_sibuna_rule_hash;
        error_page 401 = @sibuna_challenge;
        error_page 500 = @sibuna_auth_error;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $sibuna_connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Sibuna-Status $sibuna_status;
        proxy_set_header X-Sibuna-Rule $sibuna_rule;
        proxy_set_header X-Sibuna-Rule-Hash $sibuna_rule_hash;
        proxy_read_timeout 300s;
        proxy_pass http://127.0.0.1:3000;
    }
    location = /__sibuna_auth {
        internal;
        proxy_pass http://127.0.0.1:8080/;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Uri "";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header Cookie $http_cookie;
    }
    location @sibuna_challenge {
        rewrite ^ /__sibuna/challenge break;
        proxy_pass http://127.0.0.1:8080;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location @sibuna_auth_error {
        add_header Retry-After $sibuna_retry_after always;
        if ($sibuna_auth_status = 429) { return 429; }
        return 503;
    }
    location /__sibuna/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

```caddyfile
example.com {
    handle /__sibuna/* {
        reverse_proxy localhost:8080
    }
    handle {
        forward_auth localhost:8080 {
            uri /
            header_up X-Forwarded-For {remote_host}
            header_up -X-Original-URI
            copy_headers X-Sibuna-Status X-Sibuna-Rule X-Sibuna-Rule-Hash
        }
        reverse_proxy localhost:3000
    }
}
```

The `/__sibuna/*` namespace (interstitial, challenge, verify, solver assets) must reach the
daemon directly in both recipes.
Caddy supplies original URI/method metadata itself. The exclusive `handle` blocks ensure
that challenge and verification routes do not enter the forward-auth precheck. Nginx requires
the explicit Upgrade/Connection headers shown above for application WebSockets.
The Nginx error handler renders the internal challenge route without making a second
authorization decision or consuming the upload body. Its auth module accepts only 2xx,
401 and 403 directly, so the example translates a rate-limited auth error back to 429
with Retry-After; other authorization failures remain closed with 503. Nginx supplies its
own 403 body, whereas Caddy forwards Sibuna's denial page. Both recipes replace incoming
Sibuna audit headers with the actual authorization response. Configure normal TLS certificates
and application upload/deadline limits at the ingress; the examples show the routing logic.

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
