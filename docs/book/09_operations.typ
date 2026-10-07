#import "theme.typ": *
#import "figures.typ": *

#part_page("IX", [Operations and Deployment], [
  Choose Gate or Shield, connect Sibuna to your application, and manage policies and rules.
  This chapter covers deployment, the console, storage, clustering and release packages.
])

== Surfaces and Configuration

=== Native Core Rule Set

Version 0.3.0 packages include SID 0010's native CRS connector. It is opt-in: `--no-crs`
remains the default. Start in Audit, review the findings for the application with the
selected rules and resource bounds, and only then select Enforce.

Check a release before enabling it. The command verifies the official archive with the
pinned signing key and compiles its rules privately. It can save the verified sources for
startup:

```sh
sibuna crs check --version 4.30.0 --output ./crs-candidate
sibuna --upstream-host 127.0.0.1 --upstream-port 3000 \
    --crs-mode audit --crs-dir ./crs-candidate
```

Add `--configuration <file>` to include up to 64 KiB of your own authorized rules. Choose
a new output directory; the command refuses an existing one. Checking and saving prepare a
candidate without changing a running daemon. Startup verifies the saved sources again.

With the default `--no-crs`, Sibuna opens no rule files and reserves no inspection pool.
Conflicting mode flags produce an error regardless of their order.

The full reverse-proxy profile inspects complete request bodies before sending them to the
origin. It inspects complete response bodies before sending them to the client. Default wire and decoded ceilings are 4 MiB for requests and 1 MiB for responses.
The shared work budget defaults to 128 million units; evaluation is linear in the input, and
paranoia level one charges roughly 1,800 units per byte of free-text arguments. Use
`--crs-request-limit`, `--crs-response-limit`, `--crs-work-budget` and `--crs-slots` to set
reviewed bounds. Eight full-size slots reserve at least 112.6 MiB for bodies, decoding and response heads.
Metadata and matcher storage need additional space. Spare reservation provides small slots
for uncompressed requests up to 64 KiB. A compressed request uses a full-size slot even when
its encoded `Content-Length` is small: decoded input retains the configured request ceiling.
Chunked requests also use full-size slots. Reservation consumes address space; pages become
resident as requests use them. A node with the defaults peaked near 140 MiB under the
benchmark load.

A request waits up to 50 ms for a free slot. `--crs-timeout` sets an absolute inspection
deadline of 1–300 seconds, with a default of 30. Progress does not extend that deadline.
Pool exhaustion after the wait returns 503, excessive uploads 413, and enforcing inspection
failure refuses delivery. JSON and XML bodies are parsed by Content-Type, as in ModSecurity's
recommended configuration; a body that fails to parse is an inspection failure.
The conservative profile also validates a declared content encoding on a bodyless request:
empty `Content-Encoding: deflate` is incomplete and returns 403 in Enforce. HTTP permits
bodyless framing; this is a stricter inspection policy, not a protocol requirement. Audit
permits that exchange according to its incomplete policy and records the coverage gap.

Forward auth observes ingress metadata rather than the origin body or response. Select
`--crs-profile headers` explicitly with `--mode forward_auth`; full body enforcement is
refused there. Existing bot admission and CRS protection are independent. Audit counts
would-deny findings while preserving deliverable traffic; Enforce applies denials. An
incomplete Audit evaluation is labelled incomplete, never counted as inspected.
Use `--crs-inbound-threshold` and `--crs-outbound-threshold` for explicit startup threshold
overrides, each 1–65,535. Omitted thresholds retain the candidate settings, normally 5 and 4.
These process options do not edit the saved candidate or its source revision. Increasing a
threshold changes which accumulated anomalies deny an exchange; review the application
before selecting it. These generation settings initialize each transaction; locally authorized
rules can subsequently adjust its threshold and paranoia variables.

Indefinite responses require a reviewed operator exception, for example:

```text
SecRule RESPONSE_HEADERS:Content-Type "@beginsWith text/event-stream" \
    "id:123456,phase:3,pass,setvar:tx.sibuna_stream_response=1"
```

The exception takes effect after response-header enforcement and declares missing body
coverage. Validated WebSockets inspect their handshake rather than tunnel frames. Both
release the CRS slot before their long-lived relay. The existing HTTP/WebSocket idle policy
then governs the connection. The internal metrics endpoint exposes separate CRS counters
for complete, headers, handshake, excluded-stream and incomplete coverage.

The console Events page retains saved CRS findings with their rule ID, phase, severity,
mode, signed release digest, applied revision, paranoia levels and inspection coverage.
Audit findings do not claim an enforced denial. A selected denial status describes the
inspection decision; it does not prove that the client received the response. Incomplete,
headers-only, local-response, handshake and excluded-stream coverage remain distinct.
The event does not store expanded messages, tags, matched values or body contents.
Open “Show CRS rule details” for message and tag templates and the rule's net changes to
anomaly-score buckets. Truncated templates and unknown numeric changes are labelled.
Repeated findings share the total for their top-level rule. CRS findings are not grouped
by payload similarity.
Schema 44 adds separately loaded rule details to the scalar findings introduced in
schema 41. Both commit with their incident and optional redacted heads. JSON
page exports include this metadata; the CSV export retains its existing incident columns.
Enable `--console-capture-heads` to inspect redacted request and observed origin heads.
The page distinguishes a local response from an unavailable or unobserved origin response.
The Nodes page reports the serving node's applied CRS release, mode, profile, source and
operator configuration digests, thresholds, paranoia levels and effective resource bounds.
Coverage counters describe exchanges observed since this process started. Their categories
can overlap: one exchange can be both incomplete and denied. Do not sum them as incident
totals. An older binary with no CRS status is shown separately from unconfigured CRS.
The local view records this node's observations; check the saved revision and other nodes
separately when confirming activation.

Administrators manage signed candidates on the *Core Rule Set* page. Prepare a release or
mode change, compare the candidate with the saved selection, then select it. Preparation
leaves protection unchanged. The page shows the saved revision and each node's record of applying it. Off releases the CRS inspection pool while other protection continues.
Rollback restores the previous signed source, operator rules and settings as a new revision.
Additional operator rules are limited to 64 KiB. Failed verification or exhausted bounds
retain the previous protection. Unsaved editor text is erased when leaving the page or
signing out; copy it before reloading a changed saved revision. A failed compilation shows
`CRSCOMPILE/<category>`, the source file and line, the rule ID when already resolved, and a
recovery hint. Source text is not copied into the error. Native checks and both update
commands report the same location; candidate failures remain available after a restart.

Native commands use the same authenticated service. Keep administrator credentials in a
private file; the CLI refuses insecure remote HTTP origins and credentials in arguments.
Use HTTPS for a remote console. A preparation command waits for verification and leaves
protection unchanged. Read its candidate ID and settings before selecting it:

```sh
sibuna crs status --origin https://console.example.org \
    --username admin --password-file ./console-password
sibuna crs mode --mode audit --revision 1 \
    --origin https://console.example.org \
    --username admin --password-file ./console-password
sibuna crs select --id <reviewed-candidate-id> --revision 1 \
    --origin https://console.example.org \
    --username admin --password-file ./console-password
```

`crs check` and `crs update` with `--origin` prepare a release, accepting `--version`,
`--configuration` and a bounded JSON `--settings` file. Omitted configuration preserves
the current operator rules. A settings file uses the same field names as the console. Unknown fields are rejected;
omitted fields take the documented defaults. Review the resulting candidate before selection. `crs rollback` prepares the exact previous source and settings; selection remains
separate. `crs discard --id <id> --revision <revision>` cancels an unused candidate.
An update without settings preserves the current resource controls, including a saved
16-million work budget from earlier builds. To adopt the 128-million default, edit Work budget
in the console candidate or supply a complete reviewed settings file, then select the verified
candidate. Changing a startup flag cannot override an existing saved selection.
All changes require the saved revision explicitly, including revision zero for an initial
selection. Query status after an uncertain response rather than assuming the change failed.
`--factor-file` supplies a required second factor and `--timeout` bounds the preparation
wait to 1–300 seconds. Each command closes its session when it finishes. `crs validate --directory <path>` verifies
and compiles a saved signed candidate without opening the console or storage.

Use a private request/response sample to test a saved signed candidate without starting a
listener or changing protection:

```sh
sibuna crs test --directory ./crs-candidate --case ./request.json --mode audit
```

The JSON sample has a required `request` and an optional `response`. Request fields include
`method`, `target`, `client`, `headers` (name/value pairs) and `entity`; response fields include
`status`, `headers`, `entity` and `ending` (`complete`, `handshake` or `streaming`). An entity
has either `body` text or `body_hex` binary bytes. Remove transfer framing first and retain
`Content-Encoding` when supplying compressed bytes. Each supplied entity is at most 64 KiB.
Unknown names, duplicate keys and malformed transport metadata are refused. The command
inherits saved thresholds, paranoia levels, profile and resource limits; `--mode` overrides
this private evaluation without editing the candidate. Without it, a saved Off candidate
reports disabled coverage.

The JSON report names the source digests and saved candidate revision. It shows coverage,
Audit and Enforce decisions, available blocking and detection scores, work used, and up to
64 compact findings. Additional findings are counted as omitted. Unlogged nonterminal matches
have a separate count; terminal decisions remain visible even when logging is suppressed.
Safe unexpanded message and tag prefixes, truncation counts and actual net bucket changes
are included in `details`. Scored roots without a retained finding total are counted
separately, so setup actions and failed chains cannot disappear from coverage.
Missing response data is labelled. Decoding and work failures report incomplete coverage.
The test contacts no origin and adds no traffic observations. It saves neither the sample
nor expanded matched values. Gate sessions, live rate limits and origin behavior require a
live request test.

The console's *Core Rule Set* page can test a verified candidate or the selected rules.
Open *Show rule details* in a completed result to browse two findings at a time. Details
belong to the session that ran the test. They expire after one idle minute; reading renews
that period up to fifteen minutes after completion. Run another test to replace expired
details. Live protection stays unchanged. Enter the request method, path, client IP,
headers and text or hexadecimal entity. A response is optional; its ending declares complete
content, a WebSocket handshake or streaming. The form bounds each entity to 16 KiB and
accepts up to 32 headers on each side. Results report actual coverage and scores, retain no
sample, and remain available to the issuing session for one minute. Leaving the page or
signing out removes its form and result. Active protection needs separate selection.

Authenticated CLI users can submit the same private sample using `crs test --origin <origin>
--username <admin> --password-file <private-file> --id <retained-candidate>
--revision <saved-revision> --case <json-file> [--mode off|audit|enforce]`. The command keeps its
session through polling and closes it afterwards. Authorization and the expected revision
are rechecked when execution begins and before a result completes. The redacted audit row
records the source and test intent; it contains no sample. A lost response or expired result
requires a new private test, never a selection retry.

Before selecting a candidate, the console compares its verified rules with the saved
selection. It reports added, removed, modified and reordered rules, unchanged totals,
configured target exclusions and conditional runtime exclusion entries. At most 64 changed
rules are shown; additional changes are counted. Selection stays disabled while comparison
is pending or stale. Settings and authenticated source digests are reviewed separately.
A comparison never contacts the origin or changes protection. The *Excluded protection*
panel pages through the current and candidate inventories. It names skipped fields and
rule-wide exclusions and identifies conditional controls. Long or binary names have labelled
previews, exact byte lengths and SHA-256 identities; inspect their full configured selectors.

CLI operators can request the same comparison:

```sh
sibuna crs review --origin http://127.0.0.1:9443 --username admin \
    --password-file ./console-password --id <candidate-id> --revision <saved-revision>
```

The CLI includes both complete exclusion inventories in its JSON result. It follows cursors
within the same session and honors query limits. For large inventories, `crs review --timeout 900`
permits up to fifteen minutes; other management commands retain their five-minute
maximum. No partial inventory is printed after a failed or timed-out read.

The comparison belongs to the session that requested it. Reading a page renews its
one-minute idle expiry, up to fifteen minutes after completion. Run an expired comparison
again without preparing or selecting another candidate. Before returning a result, the
service rechecks administrator access, retained sources and the saved revision. The audit records
`crs.review` intent without rule source or request content. If the selection changes, refresh
status and compare again before a separate `crs select` command.

Engine deployments can manage rules through a private local directory, without the console
or persistent application storage. Prepare and review a signed candidate first, then copy
its sources into a versioned local selection:

```sh
mkdir -m 700 ./crs-store
sibuna crs update --directory ./crs-store --from ./crs-candidate \
    --revision 0 --mode audit --crs-slots 2
sibuna --upstream-port 3000 --crs-reload --crs-dir ./crs-store
sibuna crs status --directory ./crs-store
sibuna crs mode --directory ./crs-store --revision 1 --mode enforce
```

The CLI requires an explicit revision for every change. `crs update` accepts a reviewed
`--from` directory or downloads a tagged `--version`; omission discovers the latest stable
release. A downloaded update preserves the current operator configuration when no new file
is supplied. An explicit candidate supplies its own reviewed configuration. Updates retain
current settings unless resource controls such as `--crs-profile`, `--crs-request-limit`,
`--crs-work-budget` or `--crs-slots` override them. `crs rollback --directory <store>
--revision <revision>` restores the previous source and settings as a new selection.
Changing modes retains operator rules and all resource controls.

The background task applies the saved selection before opening listeners. It follows later
selections without adding work to request handling. Its report separates the requested
selection from the last process instance and applied revision. Use health checks to confirm
that process is still running. A busy writer lock is a retryable refusal.
After an uncertain write, query status before retrying. Failed application keeps the current
running generation and reports failure; startup refuses corrupt selected sources. The store
retains current and previous generations and bounds staging to four generation directories.
Use a private directory on a local filesystem with working file locks and atomic rename.
Generated names and lock files belong to the store; keep unrelated files outside it.
Windows operators restrict the directory using ACLs. `--crs-reload` excludes the console and
cluster management owners and refuses process settings that would override the saved
selection. Forward auth requires a saved `headers` profile. `--crs-timeout` remains the
process inspection deadline, independent of the saved rule selection.

=== Release Packages and Licenses

Version 0.3.0 packages include persistent storage, the browser solver and the optional
management console. Linux x86-64 and ARM64 packages link musl statically; macOS packages
cover Intel and Apple Silicon, require macOS 15 or later, and are unsigned. Windows packages
contain a native x86-64 executable for Windows 10 / Server 2019 or later. Use Ctrl+C for
ordered shutdown and Windows ACLs to restrict credential and data files. Clustering requires
a separate `-Dcluster=true` source build with OpenSSL 3.

Download from #link("https://github.com/insanai/sibuna/releases")[GitHub Releases], verify the
archive against `SHA256SUMS`, extract it and run `sibuna --version`. Each package contains
license texts, dependency notices and a `sibuna.build.json` manifest identifying the commit,
target, compiler, build options and executable digest. The release workflow tests the actual
packaged executables before publication; these checks do not establish performance acceptance.

The engine is LGPL-3.0. The console, including its WebAssembly interface, is
AGPL-3.0; the default combined executable is distributed under AGPL-3.0.
Build the engine without the console using `-Dconsole=false`. `LICENSE` and `NOTICE` describe component boundaries and third-party exceptions. Full terms
are in `LICENSES/`. Every release tag includes the
corresponding source and build scripts, and the console links to that source. Companies
seeking a version under terms other than LGPL or AGPL can contact the authors, Vikrant
Rathore and Ronak Rathore, about alternative licensing. Third-party libraries remain
subject to their respective licenses.

#objectives([
  By the end of this chapter, you should be able to run Sibuna as a reverse proxy or a
  forward-auth validator, choose a surface, set the proof-of-work tier and difficulty, and
  manage the master secret.
])

=== Choosing a Surface

Both surfaces can ask an unverified client to complete a proof before the application handles
its request. The client creates the proof and Sibuna verifies it. Choose work settings that
make creation costlier than verification without overburdening your users. A valid session
reuses the completed work, avoiding a new proof for every request; a route can still require
a higher work level. This admission step helps reserve application resources for admitted
traffic. Inspection and rate limits address separate risks.

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
  [`--max-connections`], [`1024`], [Connections served concurrently; further ones are refused with a bounded `503` reply],
  [`--idle-timeout`], [`15`], [Idle period in seconds; origin reads refresh it. Uploads must deliver 16 KiB per period],
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
  [`--challenge-rate-limit`], [`30`], [Challenge issuances and verifications per window per client, separate from the request budget],
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

A request head must arrive within `--idle-timeout`. Each origin read refreshes the response
deadline, so a slow stream stays open while bytes arrive. A silent origin closes both sockets.
Uploads must deliver at least 16 KiB per idle period to limit slow-body attacks.

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
(admitted green, challenged amber, denied red, banned dark red) are the same in every panel.
Two further tiles are levels rather than counts: active ban entries on contributing nodes
and nodes healthy from this console's own probes, each with a sparkline of observed
snapshots. Below the timeline, sampled panels rank request paths and referring hosts and
count client operating systems, browsers and response status over the same one-in-64
samples; retained rankings compare the same dimensions across windows.],
image("images/console-traffic.png"))

#book_figure([Statistics · Security. One tile per module, findings over sixty equal buckets,
the live event feed, attack categories and attacked paths; values that are not recorded say
so instead of showing zero.],
image("images/console-security.png"))

#book_figure([Events. Each recorded incident opens inline with its evidence: the selected
local response, byte lengths, campaign candidate, and explicit “not recorded” entries for
the matched rule, score terms and JA4 fingerprint. With `--console-capture-heads` the
redacted request head (and, for audited admissions through the reverse proxy, the origin
response head) opens on request, rendered as UTF-8 or Latin-1, with the response condition
stated (captured, local, forward-auth unobserved, origin unavailable) and a copy-as-cURL
command; only listed header values are kept, and `--console-capture-header <name>` adds to
that list. Otherwise heads read as not recorded. Deny and allow actions open the IP groups
form with the address drafted.],
image("images/console-events.png"))

#book_figure([Challenges. Issued, submitted, accepted and rejected counts by cause, the
configured and most recently issued parameters, and the accepted solve-time histogram
partitioned by algorithm and parameter bin. A retained window (one hour, one day or seven days) sums durable
per-minute records and states how many minutes were recorded and complete; live totals
since this boot stay separate. Below them, adaptive-difficulty transitions and per-address
records (with deny and allow shortcuts) cover the same window, retained seven days.],
image("images/console-challenges.png"))

#book_figure([Policies. The applied engine names its surface and node-local limits, then
lists rules in evaluation order with hits today, followed by the inspection mode matrix, the
request tester and IP groups.],
image("images/console-policies.png"))

#book_figure([Reviewing a rule edit before saving (dark theme). Only changed fields are
listed; confirming validates the whole candidate and creates a new revision.],
image("images/console-policy-review.jpg"))

#book_figure([Nodes. The serving node's status and commands, with resident memory and CPU of
the last second and their sixty-second sparklines, then every announced member with its
applied revision, log slots, replication lag and probe result.],
image("images/console-nodes.png"))

#book_figure([GeoIP. Provider, licence, active generation digest, load time and the import
form; a failed import never replaces the active generation.],
image("images/console-geoip.png"))

#book_figure([Settings. Notification destinations, denial-spike thresholds, retention with
an explicit acknowledgement per window, response-page templates and About.],
image("images/console-settings.png"))

#book_figure([Audit. Append-only history with actor and role, action, subject and a detail
view with redacted before and after summaries; refused sign-ins are recorded too. Every
management mutation and authentication row records the client address that presented the
credential; rows the system writes on its own show it as not recorded. A policy record offers
*Revert this change*, which restores the document recorded before that revision as a new,
audited revision after a confirmation, and is refused if the rule set has moved on.],
image("images/console-audit.png"))

The optional `--console-location <latitude,longitude>` declares this node's position, for
example `1.3521,103.8198` for a deployment in Singapore. The globe initially centers there. *Center Sibuna* returns to that point after rotation. Country activity follows animated
great-circle arcs toward the node, with rear-hemisphere and flat-map dateline clipping.
Country markers use representative central positions. Arrows summarize the observed
sixty-second window; they do not trace individual connections. An unset server position stays explicitly unknown.
The configured marker remains visible through telemetry outages; stale traffic does not animate.

Policy previews build a private candidate that includes configured file rules. Before a
save, review the changed fields and confirm the expected revision. A historical revert
checks the current rule and creates a new revision. The saved revision and locally applied
revision are shown separately. Audit details record the changes and the role used to make them. Matcher values are redacted and old
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
Certificate hostname validation always applies. Use a DNS name in each management origin,
resolvable by its peers and listed in the certificate's DNS subject alternative names. The
pinned Zig 0.17 verifier also supports IP subject alternative names for numeric-IP origins.
An address must match the certificate's IP alternative name; DNS names must match a DNS
alternative name. Private certificates must also have the normal
CA constraints, key usages and authority identifiers. Key rotation requires coordinated restart.
The Nodes API and its subscription report receipt age, clock skew, boot changes and sampling
loss. Missing observations remain unavailable and disconnected values remain stale; received
statistics never become another node's own contribution. The dashboard's *Live traffic scope*
selects one node or combines the configured nodes. *Node coverage and locations* identifies
missing, stale and clock-skewed sources, observation times and configured destinations.
Country rankings show uncertainty when source rows are missing. Each arrow points to its
receiving node; unknown node locations stay unknown. A combined rate is unavailable until
every contributing source supplies a consecutive interval. Select one node to inspect its retained
seconds and current-minute path rankings. Remote queries use the authenticated peer connection;
missing peers stay unavailable and history cursors cannot cross a node restart. Minute history
keeps its own node selection and per-node rows.
The navigation and mobile header name the serving console node separately from the selected
traffic source. Local commands affect their named node.

`zig build console-impact` runs the data-plane isolation matrix (`-- --quick` for
a smoke run, `-- --mode reverse_proxy` against a local origin, `-- --capture-heads` to
store heads on the enabled consoles and add an audited-admission workload) and writes
`benchmarks/results/console-impact-latest.json` with the mode and capture setting in its
provenance.

Traffic tiles open on the last 24 hours of retained closed-minute records for the selected
nodes. The period control also offers an hour, seven or ninety days, and live boot totals.
Yesterday deviations require complete matching coverage from every selected node. The globe
and sparklines still describe their separate live 60-second window. A retained scan refreshes
one minute after completion, keeping its previous values and age visible until replacement;
changing the source or period discards the old scope. Missing history never becomes zero.

*Compare retained traffic* displays two closed minute windows beside each other: the same
window yesterday, the preceding period, or a second node. Duration and end-offset controls
freeze both UTC ranges. Each action reads at most sixteen compact pages per side, with
96 stored records per page. One batch covers 24 hours when no restart intervals overlap. Use Continue for a longer scan;
the original boundaries stay fixed. The page labels complete coverage, incomplete coverage
and missing history. Rate percentages require complete non-overlapping intervals in equal UTC windows,
normalized by observed milliseconds; a zero reference with new traffic shows “New”.
The primary Traffic period remains independent.
The minute format does not record historical proxy mode, so origin-response comparisons remain
unavailable rather than interpreting forward-auth zeros as observed responses.

*Compare retained path rankings* selects two closed windows or nodes. Node 0 includes all
retained nodes, including retired members. An action reads at most sixteen immutable archives,
checks their identities and checksums, and merges every counter before selecting display rows.
Archives become immutable after the 60-second late-sample window. The newest closed minute
may therefore still be pending. Continue keeps the original windows and cursor. The bounds
describe sampled path prefixes; they cannot establish exact request totals. The page shows partial scans, truncation, retention boundaries and
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
Applied rules show recorded hits today, hourly sparklines and an accessible table. A hit means the rule's conditions matched. Matching WEIGH rules and the first terminal
match count. An earlier inspection or reputation decision can prevent rule evaluation. Private tests do
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
With GeoIP loaded, the storage worker records each incident's country and generation when
saving the incident. The mapping uses data available at persistence, which may differ from
the data available when the request arrived. Later imports leave recorded mappings unchanged. The country filter accepts an
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
SID 0007 is Committed. The October Linux and Chrome reviews passed its page and management
workflows, including a cluster on three physical hosts. The connected peer transport and
combined dashboard retain their own coverage and freshness contracts.

#warning([Console performance acceptance], [
  The eight single-node and three-host impact matrices from 1 October 2026 are inconclusive.
  Their raw samples, coverage checks and verdicts remain in `benchmarks/results/`. They
  predate the later request-path and CRS changes and do not qualify v0.3.0. The September
  paired reading is an accepted historical exception, not a formal pass for this release.

  These containers cannot control CPU frequency or other activity on the physical host.
  That uncertainty does not establish why measured throughput differed. Run the full
  acceptance test on the deployment host with a production GeoIP snapshot and documented
  conditions. The test includes each dashboard's stream, rankings and retained timeline.
])

The complete Wasm application warns above 640 KiB and has a 768 KiB uncompressed ceiling.
Its linear-memory allocation is 6 MiB. These project bounds leave room for the console's
workflows; loading time and responsiveness still need browser measurements. SID 0007
records the interface and browser acceptance evidence.

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
The following limits describe the lightweight WAF; the native CRS profile has the separate
whole-body bounds described at the start of this chapter. The lightweight WAF examines at
most the first 8 KiB of the body: multipart metadata and non-file fields
remain text inspection inputs, while file payloads are opaque. Recognized binary top-level
MIME types (images except SVG, audio, video, PDF, ZIP, gzip, 7z, protobuf and octet-stream)
are opaque too. JSON, XML, SVG, URL-encoded forms and unknown types retain text inspection.
Ambiguous or malformed MIME metadata falls back to text inspection. Multipart parsing is
bounded to 32 parts and 2 KiB of headers per part within that same prefix.

This is upload compatibility, not file validation or malware scanning. The backend must
enforce accepted media types rather than trust a client's Content-Type declaration. Fields
after the inspection prefix, including those after a large uploaded file, are not inspected.
The lightweight WAF does not decompress payloads for inspection. Uploads still pass admission, path,
query and header checks and remain subject to connection deadlines. Chunked request bodies
are decoded inside the connection buffer before inspection (SID 0009). A body that ends
within the buffer reaches the backend with Content-Length. A longer one is re-chunked by
Sibuna, one chunk per read, so the backend never sees the client's chunk sizes, extensions
or trailers. A chunk line with a lone CR or LF, whitespace around the size, a malformed
extension or more than 4 KiB is refused with 400. So is a trailer section over 16 KiB.
`Transfer-Encoding` with another coding receives 501. Backends that cannot parse chunked
requests still receive Content-Length for bodies under about 44 KiB.
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
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-Method $request_method;
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
daemon directly in both recipes. The nginx error page passes the original URI and method so the
interstitial carries the requirement the authorization decided; without them the page still
works, and issuance falls back to evaluating the URL the browser reports.
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

The loader refuses the whole file if a key is unknown, an action is misspelled, an address
is malformed or a number is out of range. The diagnostic names the rule and field, and
startup stops. A command line with an unknown option or an out-of-range value is
refused the same way.
`rules` replaces the built-in table when present; `ip_rules` feeds the reputation trie, which
scales to thousands of prefixes; `waf: false` selects the Gate surface from the file.

== Persistent Storage and Clustering

#objectives([
  Enable Zaxonlite storage, add a dynamic policy and a ban with SQL, query incident forensics,
  understand campaign clustering, and run a replicated cluster.
])

#book_figure([Storage runs separately from request workers], storage_architecture())

`--data-dir /var/lib/sibuna` opens an embedded Zaxonlite node (journal, payload store, and
SQLite image in one directory) and starts the storage thread. On start and whenever the
`policies` or `ip_reputation` tables change, the thread rebuilds the spare engine slot from the
policy file and database, then publishes it. Request workers read the published engine
without querying SQL.

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
so members apply the ban after the reputation change commits and propagates.

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
counts `incidents_dropped` instead of making the request wait for disk. The pending batch
holds another 32 records. A process crash before commit can lose queued records. Enqueueing
is asynchronous; durability begins when the storage transaction commits.

#exercise("9.1", [Move the receipt update outside the data transaction. Construct one crash
schedule that duplicates a reputation effect and another that loses an incident.])

=== Campaign Clustering

The grouping algorithm hashes three-byte sequences from each payload into a 64-component
unit vector. It folds case and digits and stores the result in `incidents_vec`. Before an
insert, the transaction finds the nearest existing vector, including earlier records in
that batch. A cosine distance below $0.35$ joins the existing incident's `campaign_id`;
otherwise the incident starts a new campaign.

This grouping is a heuristic. The regression examples group related SQL payloads, but a
shared campaign does not prove a shared attacker. The algorithm uses no trained model.

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

- `zig build -Doptimize=fast` produces a binary with storage compiled in (it links
  libc for SQLite).
- `zig build -Doptimize=fast -Dstorage=false` produces a fully static binary with no libc
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
