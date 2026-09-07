#let sid-number = "0007"
#let sid-title = "The Sibuna Console: A Real-Time Management Interface for Nodes and Clusters in Pure Zig"
#let sid-state = "discussion"
#let sid-created = "2026-09-08"
#let sid-discussion = "Specifies a SafeLine-class management console for Sibuna: a separate pure-Zig module started from the Sibuna CLI that serves a real-time web interface over the standard library's HTTP server and WebSockets, renders its pages from a WebAssembly module styled with daisyUI 5, keeps authentication, statistics, audit, and a GeoIP database in the embedded Zaxonlite store, manages one node or a replicated cluster, and is bound by a measured contract never to slow the data plane."
#let sid-labels = ("console", "management", "websocket", "ui", "zaxonlite", "geoip", "cluster",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Proposed"
#let sid-last-updated = "2026-09-08"

#import "../../shared/sid.typ": sid-document
#import "@preview/cetz:0.5.2" as cetz
#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge

#let blue = rgb("0284c7")
#let blue-light = rgb("f0f9ff")
#let green = rgb("16a34a")
#let green-light = rgb("f0fdf4")
#let amber = rgb("d97706")
#let amber-light = rgb("fffbeb")
#let red = rgb("b91c1c")
#let gray = rgb("64748b")
#let rule = rgb("cbd5e1")
#let ink = rgb("1e293b")

#let callout(title, body, fill: blue-light, stroke: blue) = block(
  width: 100%, breakable: true, inset: 10pt, radius: 6pt, fill: fill, stroke: 0.8pt + stroke,
)[
  #text(weight: "bold", fill: stroke)[#title]
  #v(0.3em)
  #body
]

#let phase(name, body, state: "planned") = block(
  width: 100%, breakable: true, inset: 10pt, radius: 6pt, stroke: 0.7pt + rule,
)[
  #text(weight: "bold", fill: blue)[#name]
  #h(6pt)
  #box(inset: (x: 5pt, y: 2pt), radius: 3pt, fill: if state == "delivered" { green-light } else { amber-light })[
    #text(size: 8.5pt, weight: "bold", fill: if state == "delivered" { green } else { amber })[#state]
  ]
  #v(0.2em)
  #body
]

#let invariant(id, body) = block(width: 100%, inset: (left: 8pt, y: 3pt), stroke: (left: 2pt + green))[
  #text(weight: "bold", fill: green)[#id]#h(6pt)#body
]

// Drawings are laid out as frames so the experimental HTML bundle embeds them as SVG.
#let fig(body) = context { if target() == "html" { html.frame(body) } else { body } }

#let figure-box(caption, body) = figure(
  align(center, fig(body)),
  caption: text(size: 9pt, fill: gray)[#caption],
)

// ---------------------------------------------------------------- wireframe primitives
// A wireframe is a canvas in millimetres with y measured from the top edge.
#let wire(width, height, draw) = cetz.canvas(length: 1mm, {
  import cetz.draw: *
  rect((0, 0), (width, height), stroke: 0.7pt + ink, fill: white)
  draw(height)
})

#let panel(H, x, y, w, h, label, bg: none, size: 6.5pt, weight: "regular") = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.4pt + gray, fill: bg)
  if label != none {
    content((x + 1.5, H - y - 1.6), anchor: "west", text(size: size, weight: weight, fill: ink)[#label])
  }
}

#let tile(H, x, y, w, h, number, label) = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.4pt + gray, fill: blue-light)
  content((x + 1.5, H - y - 4), anchor: "west", text(size: 9pt, weight: "bold", fill: blue)[#number])
  content((x + 1.5, H - y - h + 2), anchor: "west", text(size: 5.5pt, fill: gray)[#label])
}

#let bar_row(H, x, y, w, label) = {
  import cetz.draw: *
  content((x, H - y), anchor: "west", text(size: 5.5pt, fill: ink)[#label])
  rect((x + 22, H - y - 1), (x + 22 + w, H - y + 1), stroke: none, fill: blue)
}

#let line_chart(H, x, y, w, h, series: 1) = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.4pt + gray)
  for s in range(series) {
    let pts = ()
    for k in range(25) {
      let t = k / 24
      let v = 0.35 + 0.25 * calc.sin(t * 720deg + s * 90deg) + 0.15 * calc.sin(t * 2200deg + s * 40deg) - s * 0.12
      pts.push((x + 2 + t * (w - 4), H - y - h + 2 + v * (h - 4)))
    }
    line(..pts, stroke: 0.7pt + (blue, green, red).at(s))
  }
}

#let donut(H, x, y, r) = {
  import cetz.draw: *
  let cx = x + r
  let cy = H - y - r
  arc((cx, cy), start: 0deg, stop: 200deg, radius: r, anchor: "origin", stroke: 2.2pt + blue)
  arc((cx, cy), start: 200deg, stop: 290deg, radius: r, anchor: "origin", stroke: 2.2pt + green)
  arc((cx, cy), start: 290deg, stop: 360deg, radius: r, anchor: "origin", stroke: 2.2pt + amber)
}

#let table_rows(H, x, y, w, n, cols) = {
  import cetz.draw: *
  let rh = 3.6
  rect((x, H - y - rh), (x + w, H - y), stroke: 0.3pt + gray, fill: rgb("f1f5f9"))
  let cx = x + 1.5
  for c in cols {
    content((cx, H - y - rh / 2), anchor: "west", text(size: 5pt, weight: "bold", fill: ink)[#c.at(0)])
    cx += c.at(1)
  }
  for i in range(n) {
    let yy = y + rh * (i + 1)
    line((x, H - yy - rh), (x + w, H - yy - rh), stroke: 0.25pt + rule)
    let cx = x + 1.5
    for c in cols {
      rect((cx, H - yy - rh + 1.1), (cx + c.at(1) * 0.55, H - yy - rh + 2.3), stroke: none, fill: rgb("e2e8f0"))
      cx += c.at(1)
    }
  }
}

#let shell(H, W, active) = {
  import cetz.draw: *
  // top bar
  rect((0, H - 8), (W, H), stroke: 0.4pt + gray, fill: rgb("f8fafc"))
  content((3, H - 4), anchor: "west", text(size: 7pt, weight: "bold", fill: blue)[SIBUNA])
  content((W - 3, H - 4), anchor: "east", text(size: 5.5pt, fill: ink)[cluster: edge-eu · 3/3 healthy  ·  admin ▾  ·  ◐])
  // sidebar
  rect((0, 0), (26, H - 8), stroke: 0.4pt + gray, fill: rgb("f8fafc"))
  let items = ("Statistics", "Attack events", "Challenges", "Policy", "Nodes", "GeoIP", "Settings", "Audit")
  for (i, item) in items.enumerate() {
    let yy = H - 8 - 7 - i * 6.5
    if item == active {
      rect((1, yy - 2.6), (25, yy + 2.6), stroke: none, fill: blue-light, radius: 1)
    }
    content((3, yy), anchor: "west", text(size: 6pt, weight: if item == active { "bold" } else { "regular" }, fill: if item == active { blue } else { ink })[#item])
  }
}

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

= Abstract

Sibuna is operated today through command-line flags, a JSON policy file, and SQL against the
embedded Zaxonlite database. Operators of a comparable product, SafeLine, get a web console: a
statistics overview with live traffic and attack charts, an attack-event browser with payload
detail, per-site protection settings, rule editors, IP groups, and system settings. This
record specifies the Sibuna Console: a separate pure-Zig module, compiled into the same binary
and started from the Sibuna command line, that provides that class of interface for one node
or a replicated cluster. The console serves HTTP and WebSockets with the Zig standard library,
renders every page from a WebAssembly module written in Zig and styled with daisyUI 5 through
first-party components, streams statistics and events in real time, and keeps users,
sessions, audit records, minute-level statistics, and a GeoIP country database in the same
Zaxonlite store the data plane already replicates. Its defining constraint is an isolation
contract: the console may read the data plane's counters and its database, and it may write
the database, but it never enters a request thread, never allocates on one, and never holds a
lock a worker needs; a benchmark gate measures that the console's presence changes data-plane
throughput and tail latency by less than one percent.

= Introduction and Motivation

SID 0002 defines the Gate and Shield surfaces, SID 0003 the declarative policy, SID 0004 the
inspection engine, and SID 0005 the storage layer with dynamic policies, replicated
reputation, and forensic incident search. SID 0005 closed with an open item: "an
authenticated HTTP administration API for policies and incident search." Every operator
question since has pointed at the same gap. How much traffic did the gate challenge in the
last hour, and how many challenges were solved? Which addresses were banned on which node,
and did the ban propagate? Which rule fired for a denied request, and what did the payload
look like? Is node 2 the leader, and is it healthy? The answers exist in Prometheus counters,
the `security_incidents` table, and node logs, but assembling them needs three tools and a
schema in one's head.

SafeLine's console is the reference for what operators expect from a self-hosted application
firewall. Its front page, "Statistics", shows request and interception counts for a period,
a traffic timeline, attack-type and source breakdowns, and a map; "Attack Events" lists
blocked requests with an expandable detail; "Applications" configures protected sites;
"Protection" holds rules, rate limits, the anti-bot challenge, and IP groups; "Settings" holds
users, notifications, and system options. This record adopts that information architecture
where Sibuna has the same concept, replaces it where Sibuna's model differs (there are no
per-site upstreams; there are surfaces, policies, and nodes), and adds what SafeLine does not
have: a challenge funnel, cluster membership, and campaign clustering.

#callout([Reference material], [
  SafeLine's console was studied from its public documentation, README screenshots, and
  published walkthroughs (September 2026). The hosted demonstration at
  `demo.waf.chaitin.com` could not be opened from the authoring environment because no
  browser session was available; page names and panel contents below are taken from the
  documentation, and no SafeLine markup, stylesheet, or code is reproduced or referenced.
], fill: amber-light, stroke: amber)

The design follows the approach the zenfmt project uses for its server interface: a bounded
service kernel over the standard library, an application layer that composes routing,
authentication, and handlers as straight-line code, a WebAssembly interface module in Zig
that owns every page and all interface state, a fixed JavaScript glue that only moves events
in and commands out, and vendored daisyUI styling. Sibuna's console is larger than zenfmt's
(eight pages, live streams, a cluster) so the module structure below is deliberately more
granular, and the transport is WebSockets rather than server-sent events because the
interface also sends commands (subscribe, filter, acknowledge) on the same connection.

= Terminology and Scope

- *Data plane*: the Sibuna daemon's request path (accept, parse, classify, verify, proxy),
  its worker and connection threads, and its lock-free tables.
- *Storage thread*: the existing thread of SID 0005 that owns the Zaxonlite node and rebuilds
  engine slots.
- *Console*: the management application specified here: its listener, threads, module, and
  tables.
- *Kernel*: the console's bounded HTTP and WebSocket service layer (`libs/serve`).
- *Interface module*: the `wasm32-freestanding` Zig module that renders pages in the browser.
- *Glue*: the fixed JavaScript file that loads the module, opens the WebSocket, forwards
  events, and executes commands.
- *Topic*: a named real-time stream (`stats`, `events`, `nodes`, `policy`, `challenges`).
- *Node*: one Sibuna process; *cluster*: the Zaxonlite member set of SID 0005.

In scope: everything needed to observe and manage one node or a cluster from a browser and a
JSON API. Out of scope: TLS termination for the console (an ingress terminates it, as for the
data plane), per-site upstream routing (Sibuna proxies one origin per process), payment or
licensing, and mobile-native clients.

= Goals and Non-Goals

== Goals

- One binary, one command: `sibuna --console 127.0.0.1:9443` starts the console beside the
  data plane; `-Dconsole=false` compiles it out entirely.
- Parity with the SafeLine console's information architecture for statistics, events, rules,
  IP groups, and settings, expressed in Sibuna's own concepts.
- Real-time by default: the overview and the event list update within one second of the data
  plane's counters and within one storage tick of a committed incident.
- Cluster-aware: one console shows every member; policy and reputation edits made on any node
  reach every node through the replicated tables of SID 0005.
- Pure Zig: the kernel, the application, and the interface module are Zig; the only
  JavaScript is the fixed glue; the only CSS is daisyUI 5 plus first-party components.
- The isolation contract of section 6.2, with a measured gate.
- Every build product, including the stylesheet built by npm, is produced by `zig build`.

== Non-Goals

- A general dashboard framework or plugin system.
- Replacing Prometheus: the console reads the same counters and leaves `/__sibuna/metrics`
  untouched.
- Editing the JSON policy *file*: the console edits the replicated `policies` table, which
  precedes file rules by design (SID 0003); the file remains the bootstrap.
- Geo-blocking as a data-plane feature. GeoIP enriches events and statistics in the console
  and can feed `ip_reputation` rows through an explicit operator action; the request path
  never consults it.

= Architecture Overview

#let fit-diagram() = diagram(
  spacing: (9mm, 8mm),
  node-corner-radius: 3pt,
  edge-stroke: 0.7pt + gray,
  node((0,0), [`apps/sibuna` #linebreak() CLI, daemon, storage thread], fill: blue-light, stroke: 0.8pt + blue, inset: 7pt),
  node((2,0), [`libs/console` #linebreak() app: routes, auth, telemetry, hub, geoip, cluster], fill: green-light, stroke: 0.8pt + green, inset: 7pt),
  node((2,1), [`libs/serve` #linebreak() kernel: listener, slots, HTTP, WebSocket, assets], fill: green-light, stroke: 0.8pt + green, inset: 7pt),
  node((3.2,0), [`apps/console-ui` #linebreak() wasm32 interface module], fill: amber-light, stroke: 0.8pt + amber, inset: 7pt),
  node((0,1), [`libs/store`, `libs/policy` #linebreak() `libs/crypto`, `libs/net`], fill: blue-light, stroke: 0.8pt + blue, inset: 7pt),
  node((1,2), [Zaxonlite #linebreak() replicated SQLite], fill: rgb("f5f3ff"), stroke: 0.8pt + rgb("7c3aed"), inset: 7pt),
  edge((0,0), (0,1), "-|>"),
  edge((0,0), (2,0), "-|>", [starts; counters]),
  edge((2,0), (2,1), "-|>"),
  edge((2,0), (3.2,0), "-|>", [embeds]),
  edge((2,0), (1,2), "-|>", [SQL]),
  edge((0,0), (1,2), "-|>", [SQL]),
  edge((2,0), (0,0), "--|>", [atomic loads], bend: 30deg),
)

#figure-box([Modules and their dependencies. Solid arrows are imports; the dashed arrow is the
only path from the console into the data plane, and it is read-only.],
scale(72%, reflow: true, fit-diagram()))


== Modules and directories

#table(
  columns: (1.2fr, 2.6fr),
  table.header([*Path*], [*Contents*]),
  [`libs/serve/src/`], [`kernel.zig` (listener, connection slots, deadlines, drain), `router.zig` (comptime route table), `context.zig` (request context, response helpers), `websocket.zig` (upgrade, frame loop, per-connection send queue), `assets.zig` (embedded files with content-addressed paths), `json.zig` (bounded writer and reader), `ratelimit.zig`, `log.zig`],
  [`libs/console/src/`], [`app.zig` (composition and `handle`), `auth.zig` (Argon2id, sessions, roles, tokens, CSRF), `api/` (`stats.zig`, `events.zig`, `policy.zig`, `reputation.zig`, `nodes.zig`, `challenges.zig`, `settings.zig`, `users.zig`, `audit.zig`, `geoip.zig`), `telemetry/` (`sampler.zig`, `minutes.zig`, `funnel.zig`), `hub.zig` (topics, ring, subscribers), `geoip/` (`loader.zig`, `ranges.zig`, `lookup.zig`), `cluster/` (`members.zig`, `probe.zig`), `schema.zig`, `retention.zig`],
  [`apps/console-ui/src/`], [`main.zig` (ABI, state, event dispatch), `render/` (one file per page, plus `components.zig` for the `sb-*` components and `charts.zig` for SVG), `protocol.zig` (frames shared with `libs/console` by import), `main_test.zig` (golden renders)],
  [`apps/console-ui/web/`], [`shell.html`, `glue.js`, `tailwind.css` (source), `package.json`, `assets/console.css` (built, committed with digest), `assets/world-110m.svg` (committed)],
  [`apps/sibuna/src/console_start.zig`], [Flag parsing for `--console*`, the `sibuna console` subcommands, thread start and stop],
)

The three console libraries import `core`, `crypto`, `policy`, and `store` for types they
share with the data plane (rule structures, address parsing, the incident record), and import
nothing from `apps/sibuna`. The daemon imports `console` and passes it three things at start:
a pointer to its `Metrics`, a pointer to the storage layer's database handle factory, and the
`AppState` publication hook used to rebuild engines (already exercised by the storage thread).

== Process model and the isolation contract

The console runs on its own listener, its own bounded thread pool, and its own allocator
arena. It shares three things with the data plane: the process, the Zaxonlite database, and
the `Metrics` counters. The contract is stated as invariants and each has a test.

#invariant([I1], [No console code executes on a data-plane worker or connection thread. The
  daemon's `dispatch` has no console branch; console routes live on the console listener.])
#invariant([I2], [The console reads data-plane state only through atomic loads of `Metrics`
  and through SQL against the database. It never takes a shard spinlock, an engine slot, or
  the incident ring's consumer side.])
#invariant([I3], [The console writes data-plane state only through the database. A policy or
  reputation change is a committed row; the storage thread's existing tick observes the
  revision and publishes a rebuilt engine exactly as SID 0005 specifies.])
#invariant([I4], [Console memory is bounded at start: the connection slots, the WebSocket ring,
  the subscriber table, the sampler's minute buffers, and the GeoIP range array have fixed
  capacities recorded in `console.Budget`, and the sum is printed in the startup banner.])
#invariant([I5], [Console CPU is bounded by construction: the sampler runs at 4 Hz, broadcasts
  are coalesced to 1 Hz per topic, event fan-out is capped at 64 records per second per
  subscriber, and the GeoIP loader runs at a low priority in one thread with a bounded batch.])
#invariant([I6], [A console failure (panic in a handler, database error, exhausted slots) is
  contained: handlers return errors that become responses, the listener thread restarts the
  accept loop, and the data plane is unaffected. The reverse holds too: with the console
  compiled out (`-Dconsole=false`) the daemon has no code path that references it.])

The measured form of the contract is the gate in section 17: `benchmarks/tools.py` gains a
`--console` case that runs the admitted workload with no console, with the console idle, and
with eight live dashboards subscribed to every topic; the three medians must lie within one
percent of each other and the p99 within ten percent.

== Startup from the command line

```
sibuna --console 127.0.0.1:9443 --data-dir /var/lib/sibuna --secret-file /etc/sibuna/secret
sibuna --console 0.0.0.0:9443 --console-behind-proxy --console-cookie-secure ...
sibuna console init-admin --data-dir /var/lib/sibuna         # first user, prints a one-time password
sibuna console add-user --role viewer alice --data-dir ...
sibuna console geoip update --data-dir ...                    # fetch and load the country database
sibuna console token create --role operator ci --data-dir ... # API token for automation
```

`--console` requires `--data-dir`: users, sessions, and statistics live in the database, and a
console without persistence would lose its administrator on restart. The console listens on
loopback by default; binding elsewhere without `--console-behind-proxy` (which turns on
`Secure` cookies and trusts `X-Forwarded-For` from the ingress) prints a warning naming the
risk. In a cluster every member may run a console; each shows the whole cluster, because the
tables it reads are replicated, and each probes the others' health endpoints directly.

= The Serve Kernel

`libs/serve` is a bounded service kernel over `std.http.Server` and `std.Io`. It is the
console's HTTP substrate and is written to be reusable by a future service; it knows nothing
about firewalls.

- *Listener and slots.* One acceptor thread; `max_slots` (default 64, at most 256) connection
  threads with fixed 16 KB receive and send buffers. A head larger than the receive buffer is
  `431`; a full slot table is `503` with `Retry-After`. Deadlines (head 10 s, idle 60 s, body
  30 s) are enforced by a watchdog thread that shuts down expired sockets, the same mechanism
  the daemon's idle reaper uses, because the threaded `std.Io` exposes no per-read timeout.
- *HTTP.* `std.http.Server.receiveHead` parses the request; `Request.respond` and
  `respondStreaming` write responses. Bodies are limited to 1 MB except the policy import
  route (8 MB). Every response carries `Cache-Control`, `Content-Security-Policy`
  (`default-src 'self'; connect-src 'self' wss:`; no inline script; styles from the embedded
  sheet only), `X-Content-Type-Options`, `Referrer-Policy`, and `X-Frame-Options`.
- *WebSocket.* `Request.upgradeRequested` and `respondWebSocket` from the standard library
  perform the handshake; the kernel's `websocket.zig` owns the frame loop on the connection
  thread: it reads small text messages (at most 4 KB, the standard library's
  `readSmallMessage` bound), answers pings, and writes outbound frames from a per-connection
  bounded queue filled by the hub. Messages larger than the input buffer close the socket
  with status 1009.
- *Assets.* Embedded files (`shell.html`, `glue.js`, `console.css`, the interface module,
  `world-110m.svg`) are served under `/console/assets/<sha256-prefix>/<name>` with
  `Cache-Control: immutable`; the shell's placeholders resolve at start to those paths, so a
  new build never serves a stale module from a browser cache.
- *Router.* A comptime table of `(method, pattern, role, handler)`; patterns are literal
  segments with at most two `{param}` segments; matching is a bounded loop with no
  allocation. Unknown paths under `/console/` return the shell so the interface module can
  route client-side; unknown paths under `/console/api/` return a JSON `404`.
- *Rate limits.* Token buckets keyed by client address for login (5 per minute) and by
  session for mutations (60 per minute); reads are unlimited within the slot budget.

= Authentication and Authorization

- *Passwords* are hashed with Argon2id at the OWASP interactive parameters (`t=2`,
  `m=19 MiB`, `p=1`) and stored as PHC strings; verification runs on the console's thread,
  never the data plane's, and the login route is rate limited so the 19 MiB cost cannot be
  weaponised against the console host.
- *Sessions* are 256-bit random tokens stored only as SHA-256 digests in `console_sessions`
  with an absolute lifetime (12 h) and an idle lifetime (30 min), delivered in an `HttpOnly;
  SameSite=Strict; Path=/console` cookie, `Secure` when behind a proxy. A session records the
  client address and User-Agent; a mismatch invalidates it, the same binding the data plane
  applies to its own tokens.
- *Roles* form the order `viewer < operator < administrator`. Viewers read; operators edit
  policy, reputation, and bans; administrators manage users, tokens, GeoIP, retention, and
  settings. Every route declares its minimum role in the router table.
- *Cross-site request forgery* is prevented by the strict cookie plus a double-submit token:
  the interface module receives a CSRF token at login and sends it in `X-Console-CSRF` on
  every mutation; the WebSocket upgrade is accepted only when `Origin` matches the console's
  own host.
- *API tokens* for automation are opaque 256-bit values with a printable id, a role, and an
  optional expiry, presented as `Authorization: Bearer`; they are hashed like sessions.
- *Audit.* Every mutation writes one `console_audit` row (actor, role, action, subject,
  before and after summaries, address) in the same transaction as the change.
- *Bootstrap.* With no users in the database the console serves only the setup page, which
  accepts the one-time password printed by `sibuna console init-admin` and forces a change.

= The Telemetry Pipeline

The console's numbers come from three sources, none of which touches a worker thread.

== The sampler

A console thread wakes every 250 ms, loads every `Metrics` counter with `.monotonic` atomics,
computes deltas against the previous sample, and appends one record to a per-node ring of
3,600 one-second buckets (an hour). Once a minute it folds the last sixty seconds into a
`traffic_minutes` row: requests, allowed, denied, challenged, challenges issued, solutions
accepted and rejected, rate limited, banned, proxied, upstream errors, overloaded, incidents
persisted and dropped, and the node's resident set and CPU seconds read from the operating
system. Rows are keyed by node id and minute, so in a cluster every console sees every node's
minutes after replication, and a node that restarts leaves a gap rather than a corrupt
series.

== The incident tap

Incidents already flow through the storage thread into `security_incidents` (SID 0005). The
console does not add a second consumer to the incident ring (I2); instead its event feeder
polls the table once per storage tick (`--storage-poll-ms`, 500 ms by default) with a cursor
on the node-scoped id, enriches new rows with GeoIP and the campaign id, and publishes them
to the `events` topic. The latency from denial to dashboard is therefore one storage tick plus
one poll, about one second at defaults; the trade is deliberate, since a direct tap would
require a second bounded ring drained on the hot path's schedule.

== The challenge funnel

Sibuna has a measure SafeLine does not: the funnel from challenges issued, to solutions
submitted, to accepted, to rejected by cause (double spend, fingerprint mismatch, expired,
wrong difficulty), and the distribution of solve times reported by the interstitial. The
`funnel.zig` aggregator derives issued and accepted from the counters and the rejection
causes from a small histogram the daemon already keeps per `explainProofError` outcome; solve
times require one addition to the data plane, a 16-bucket logarithmic histogram of the
`elapsed_ms` field the worker posts with its solution, updated with one atomic add per
accepted solution. That single addition is the only data-plane change this record requests.

== Cluster aggregation

Statistics pages show the cluster total and a per-node breakdown. Totals are sums over
`traffic_minutes` for the selected period; the live tiles sum the latest one-second bucket
from every node's sampler, which reaches other consoles through the `nodes` topic rather
than the database (a node publishes its live bucket to its peers' consoles over the same
WebSocket protocol, node-to-node, with the cluster pre-shared key or client certificate).

= The Real-Time Protocol

One WebSocket per browser tab at `/console/ws`, opened after login. Frames are JSON text.

#table(
  columns: (1fr, 1.2fr, 2.4fr),
  table.header([*Direction*], [*Frame*], [*Meaning*]),
  [client → server], [`{"op":"sub","topic":"stats","args":{"window":"1h"}}`], [Subscribe; the server replies with a snapshot then deltas],
  [client → server], [`{"op":"unsub","topic":"events"}`], [Stop a stream],
  [client → server], [`{"op":"filter","topic":"events","args":{"node":2,"category":"waf:sqli"}}`], [Replace the server-side filter for a stream],
  [client → server], [`{"op":"ping"}`], [Application heartbeat (the transport ping is separate)],
  [server → client], [`{"topic":"stats","seq":8812,"snapshot":true,"data":{...}}`], [Full state on subscribe or after a gap],
  [server → client], [`{"topic":"stats","seq":8813,"data":{"t":1757…,"req":1832,"deny":12,…}}`], [One-second delta, coalesced at 1 Hz],
  [server → client], [`{"topic":"events","seq":91,"data":[{...},{...}]}`], [Batch of new incidents, at most 64 per second],
  [server → client], [`{"topic":"events","dropped":37}`], [The subscriber fell behind; the client requests a snapshot],
  [server → client], [`{"error":"unauthorized"}`], [Session expired; the client returns to login],
)

The hub keeps one bounded ring per topic (1,024 entries of at most 2 KB) and a cursor per
subscriber; publishing never blocks and never allocates, and a slow consumer sees a `dropped`
count rather than growing memory (the design of zenfmt's event hub, with a ring per topic).
Fan-out runs on the hub thread, which writes into each connection's bounded send queue; a
queue that is full drops the oldest delta for that connection and marks it, so a stalled
tab costs one queue and nothing else. Subscribers are capped at 64 per console; the 65th
receives a `503` at upgrade.

#let sequence() = cetz.canvas(length: 1mm, {
  import cetz.draw: *
  let lanes = (("Browser", 12), ("Console", 52), ("Zaxonlite", 92), ("Storage thread (every node)", 138))
  for (name, x) in lanes {
    rect((x - 11, 0), (x + 11, 7), stroke: 0.5pt + gray, fill: blue-light)
    content((x, 3.5), text(size: 6pt, weight: "bold", fill: ink)[#name])
    line((x, 0), (x, -76), stroke: (paint: gray, thickness: 0.4pt, dash: "dashed"))
  }
  let msg(y, a, b, label, dashed: false) = {
    let xa = lanes.at(a).at(1)
    let xb = lanes.at(b).at(1)
    line((xa, -y), (xb, -y), mark: (end: "straight"), stroke: (paint: ink, thickness: 0.5pt, dash: if dashed { "dashed" } else { "solid" }))
    content(((xa + xb) / 2, -y + 2.2), text(size: 5.5pt, fill: ink)[#label])
  }
  msg(9, 0, 1, [POST /console/api/session])
  msg(16, 1, 2, [SELECT user; verify Argon2id; INSERT session])
  msg(23, 1, 0, [200 + session cookie + CSRF token], dashed: true)
  msg(30, 0, 1, [GET /console/ws (Upgrade, same origin)])
  msg(37, 1, 0, [snapshot, then 1 Hz stats deltas], dashed: true)
  msg(44, 0, 1, [PUT /console/api/policies/p1 (X-Console-CSRF)])
  msg(51, 1, 2, [UPDATE policies; INSERT console_audit (one transaction)])
  msg(58, 2, 3, [replicated commit; revision changed])
  msg(65, 3, 3, [tick: rebuild spare engine; publish], dashed: true)
  msg(72, 3, 1, [`policy` topic: rule p1 active on node n], dashed: true)
})

#figure-box([One browser session: login, upgrade, subscribe, live deltas, a mutation, and the
policy rebuild it causes on every node.], sequence())

= Data Model

All console tables live in the same Zaxonlite database as SID 0005 and replicate with it.
Migrations are numbered in `schema.zig` and run in one transaction at console start.

#table(
  columns: (1fr, 2.8fr),
  table.header([*Table*], [*Columns and purpose*]),
  [`console_users`], [`id`, `name` (unique), `role`, `password_phc`, `must_change`, `disabled`, `created_at`, `updated_at`],
  [`console_sessions`], [`digest` (primary), `user_id`, `role`, `client_ip`, `user_agent_hash`, `csrf`, `issued_at`, `last_seen`, `expires_at`; expired rows are purged by retention],
  [`console_tokens`], [`id` (printable), `digest`, `label`, `role`, `created_by`, `created_at`, `expires_at`, `disabled`],
  [`console_audit`], [`id`, `at`, `actor`, `role`, `action`, `subject`, `before`, `after`, `client_ip`; append-only],
  [`console_settings`], [`key`, `value`, `updated_at`, `updated_by`; retention days, GeoIP source, notification webhooks],
  [`traffic_minutes`], [`node_id`, `minute` (epoch/60), the counters of section 8.1, `rss_kib`, `cpu_seconds`; primary key (`node_id`, `minute`)],
  [`challenge_minutes`], [`node_id`, `minute`, `issued`, `accepted`, `rejected_double_spend`, `rejected_fingerprint`, `rejected_expired`, `rejected_difficulty`, `solve_ms_buckets` (16 integers as JSON)],
  [`geoip_ranges`], [`start` (16-byte address as blob), `end`, `country` (ISO 3166-1 alpha-2); one row per range from the source CSV],
  [`geoip_meta`], [`source`, `licence`, `published`, `loaded_at`, `ranges`, `sha256`],
  [`nodes`], [`node_id`, `address`, `console_url`, `version`, `first_seen`, `last_seen`; written by each node at start and every minute],
)

Existing tables are read, and two are written: `policies` (rule editor) and `ip_reputation`
(ban and allow actions, GeoIP-derived blocks), both exactly as the storage thread already
expects them, so the rebuild path of SID 0005 needs no change.

= GeoIP

The console enriches addresses with a country, for the events table, the top-countries chart,
and the map. The source is an open database with a permissive licence: the DB-IP
"IP to Country Lite" CSV (Creative Commons Attribution 4.0, monthly), with MaxMind GeoLite2
Country as a configurable alternative for operators who have an account. The licence text
and attribution are shown on the GeoIP settings page and in the footer, as both licences
require.

- *Loader.* `sibuna console geoip update` (or the settings page) downloads the CSV over
  HTTPS with the standard library's client, verifies the size and the published SHA-256
  when the source provides one, parses ranges in a streaming pass, and inserts them in
  batches of 2,000 rows inside a transaction per batch on the console thread at low
  priority, replacing the previous set atomically by loading into `geoip_ranges_next` and
  renaming. About 300,000 ranges load in well under a minute on the reference host and
  replicate to the cluster like any other rows, so one update serves every node.
- *Lookup.* At start and after each load the console reads the ranges into a sorted
  in-memory array of `(start, end, country)` with 16-byte addresses (IPv4 mapped), about
  10 MB for the full set, and answers a lookup by binary search in under a microsecond.
  Lookups run on the event feeder thread and the API threads only (I2).
- *Privacy.* Only the country code is stored with an event; the console never stores city
  or coordinates, and the map is coloured by count per country.
- *Actions.* An operator can turn a country into `ip_reputation` rows (deny or challenge for
  every range of that country) with one audited action; the data plane then applies them
  through its trie exactly as any other reputation row, which keeps geo-blocking a policy
  decision made by a person rather than a data-plane lookup.

= Cluster Management

The `nodes` page shows every member known from the `nodes` table and the cluster
configuration: id, address, role (leader or follower, read from the Zaxonlite node status the
storage thread already logs), version, uptime, last replicated commit, the sampler's live
request rate, resident memory, CPU, and the health of its data-plane listener. Health is
probed by each console directly (`GET /__sibuna/health` and `/__sibuna/metrics` every
5 seconds, bounded to 2 s per probe) so a console can show a member whose storage has
failed but whose data plane still serves from its last snapshot, the failure mode SID 0005
documents.

Operations offered per node: drain (set a flag the node's accept loop reads, so it answers
`503` to new connections while finishing current ones, for maintenance), clear local bans,
and open that node's own console. Cluster-wide operations are edits of replicated tables and
need no per-node action: a rule saved on any console is a `policies` row; a ban is an
`ip_reputation` row; both propagate in the ban-propagation time measured in Part VIII of the
book (about 100 ms on loopback). The page also shows the two facts an operator must know
from SID 0005: challenge verification is issuer-bound (sticky routing is needed), and rate
limits are per node.

= The Interface Module

The interface follows the zenfmt approach: a `wasm32-freestanding` Zig module owns every
page, all interface state, and every fragment of markup; the glue owns the browser. The glue
loads the module, opens the WebSocket, forwards browser events and WebSocket frames into the
module as length-prefixed JSON, and executes the returned command list: `patch` (replace an
element's inner HTML), `attr`, `class`, `focus`, `navigate` (push state), `fetch` (issue an
API request the module described and post the result back), `ws` (send a frame), `download`,
`theme`. No markup, route, or form logic lives in JavaScript, so the golden tests compile the
same module natively and assert rendered HTML strings.

- *Rendering.* Pages render into a fixed 512 KB output buffer with a bounded HTML writer that
  escapes by construction. A page re-renders only the panels whose inputs changed (each panel
  is a function of a slice of state with an explicit version), so a one-second stats delta
  patches four tiles and one chart, not the document.
- *Charts* are inline SVG produced by `charts.zig`: a stacked area timeline (allowed,
  challenged, denied), sparklines, horizontal bars, a donut, a histogram, and the choropleth
  over the committed `world-110m.svg` (country paths keyed by ISO code, coloured by a class
  the module sets). Drawing a 3,600-point timeline is a single string build of about 40 KB;
  no charting library is loaded, and no canvas is used, so the charts print, zoom, and are
  accessible through titles.
- *Components.* daisyUI 5 supplies the primitives (`btn`, `card`, `table`, `drawer`,
  `badge`, `tabs`, `toast`, `modal`, `stat`). First-party `sb-*` components compose them
  with fixed markup and are the only elements the render functions emit: `sb-shell`,
  `sb-tile`, `sb-timeline`, `sb-table` (virtualised rows, sortable, with a filter bar),
  `sb-drawer` (event detail), `sb-form` (schema-driven, with validation messages in the
  daemon's Elm-style diagnostic voice), `sb-flag`, `sb-node-card`, `sb-diff`.
- *Themes.* daisyUI's `light` and `dark` themes selected by `data-theme`, following the
  system preference by default and remembered per browser.
- *Budget.* The module is compiled at `ReleaseSmall` with a 300 KB size gate, 4 MB initial
  memory, and no allocator on the event path beyond a bump arena reset per event.

== Pages

#table(
  columns: (0.9fr, 3fr),
  table.header([*Page*], [*Panels*]),
  [Setup and login], [First-run password change; login form; session expiry notices.],
  [Statistics], [Period selector (live, 1 h, 24 h, 7 d, 30 d); tiles (requests, admitted, challenged, denied, banned addresses, nodes healthy); live timeline; attack-type donut; top source addresses; top countries with map; per-node breakdown table.],
  [Attack events], [Live table with filter bar (node, category, rule, address, country, path, period); detail drawer (request head, decoded payload with matched structure highlighted, rule and score, campaign and its members, GeoIP, actions: ban, allow, add to group, copy as curl).],
  [Challenges], [Funnel (issued, submitted, accepted, rejected by cause); solve-time histogram by algorithm and difficulty; adaptive-difficulty bump timeline; JavaScript-fallback share; per-rule challenge parameters.],
  [Policy], [Ordered rules table with drag ordering, enable toggle, surface (Gate or Shield), thresholds; rule editor (form and JSON), pattern tester ("would this request be admitted, challenged, or denied, and by which rule"), import and export of the JSON file grammar; IP groups (reputation prefixes with score, expiry, trigger, source); GeoIP block builder.],
  [Nodes], [Member cards with role, health, version, sparklines; per-node drain and clear-bans; replication lag; the sticky-routing and local-limit notices.],
  [GeoIP], [Source, licence, published date, ranges loaded, last update, update button, attribution text.],
  [Settings], [Users and roles; API tokens; retention (minutes, incidents, audit); notification webhooks (deny spike, ban, node unhealthy, leader change); console binding and proxy facts (read-only).],
  [Audit], [Append-only log with actor, action, subject, before and after, filterable and exportable.],
)

= Wireframes

The drawings fix layout and information density, not visual style; daisyUI supplies the
style. Every panel named here maps to one `sb-*` component and one render function.

#figure-box([The shell: top bar with cluster status and the account menu, a fixed sidebar of the
eight pages, and the page body. The sidebar collapses to icons below 1,024 px.],
wire(170, 96, H => {
  shell(H, 170, "Statistics")
  panel(H, 28, 10, 140, 84, [page body], bg: rgb("fcfcfd"))
}))

#figure-box([Login and first-run setup. The setup variant replaces the password field with the
one-time password and a new-password pair, and forces a change.],
wire(170, 80, H => {
  import cetz.draw: *
  panel(H, 55, 10, 60, 60, none)
  content((85, H - 16), text(size: 7pt, weight: "bold", fill: blue)[SIBUNA CONSOLE])
  panel(H, 60, 22, 50, 8, [user name])
  panel(H, 60, 33, 50, 8, [password])
  panel(H, 60, 45, 50, 8, [Sign in], bg: blue-light, weight: "bold")
  content((85, H - 60), text(size: 5pt, fill: gray)[edge-eu · node 1 · v0.3.0 · GeoIP by DB-IP (CC BY 4.0)])
  content((85, H - 74), text(size: 5pt, fill: gray)[Five attempts per minute per address · sessions expire after 30 idle minutes])
}))

#figure-box([Statistics, the landing page. Tiles update every second; the timeline shows the
selected period with the live second at the right edge; the map colours countries by denied
requests.],
wire(170, 125, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Statistics])
  panel(H, 120, 9.5, 48, 5, [live · 1h · 24h · 7d · 30d], size: 5pt)
  let tiles = (("1.28 M", "requests 24 h"), ("1.19 M", "admitted"), ("64 k", "challenged"), ("21 k", "denied"), ("312", "banned addresses"), ("3 / 3", "nodes healthy"))
  for (i, t) in tiles.enumerate() {
    tile(H, 28 + i * 23.5, 16, 22, 13, t.at(0), t.at(1))
  }
  panel(H, 28, 32, 92, 40, [requests per second · allowed / challenged / denied (stacked)], size: 5.5pt)
  line_chart(H, 30, 38, 88, 32, series: 3)
  panel(H, 123, 32, 45, 40, [attack types], size: 5.5pt)
  donut(H, 128, 40, 11)
  for (i, l) in ("sqli 48%", "xss 22%", "traversal 17%", "rce 9%", "honeypot 4%").enumerate() {
    content((153, H - 41 - i * 5), anchor: "west", text(size: 5pt, fill: ink)[#l])
  }
  panel(H, 28, 75, 60, 46, [top source addresses], size: 5.5pt)
  table_rows(H, 29, 80, 58, 7, (([address], 20), ([country], 12), ([denied], 12), ([action], 12)))
  panel(H, 91, 75, 77, 46, [top countries · denied requests], size: 5.5pt)
  for (i, c) in (("CN", 40), ("US", 31), ("RU", 22), ("BR", 15), ("DE", 9), ("IN", 7)).enumerate() {
    bar_row(H, 93, 83 + i * 5, c.at(1), c.at(0))
  }
  panel(H, 128, 80, 38, 38, none, bg: rgb("f8fafc"))
  content((147, H - 99), text(size: 5pt, fill: gray)[world map (choropleth)])
}))

#figure-box([Attack events with the detail drawer open. The table is virtualised and streams new
rows at the top while a filter is active; the drawer shows the decoded payload with the
matched structure highlighted and offers the audited actions.],
wire(170, 120, H => {
  import cetz.draw: *
  shell(H, 170, "Attack events")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Attack events])
  panel(H, 28, 15, 90, 6, [node ▾  category ▾  rule ▾  address  country ▾  path  period ▾  ● live], size: 5pt)
  table_rows(H, 28, 23, 90, 22, (([time], 14), ([node], 8), ([source], 18), ([cat.], 12), ([rule], 14), ([path], 14), ([action], 8)))
  panel(H, 121, 10, 47, 108, none, bg: rgb("fcfcfd"))
  content((123, H - 14), anchor: "west", text(size: 6pt, weight: "bold")[waf:sqli · node 2 · 12:41:07])
  panel(H, 123, 18, 43, 12, [source 198.51.100.7 · CN · campaign 41 (3)], size: 5pt)
  panel(H, 123, 32, 43, 22, [GET /search?q=%27%20OR%201%3D1-- #linebreak() decoded: ' OR 1=1-- #linebreak() quote · keyword OR · tautology 1=1], size: 5pt)
  panel(H, 123, 56, 43, 18, [request head (User-Agent, Accept, …)], size: 5pt)
  panel(H, 123, 76, 43, 16, [similar incidents (vector search) · 3 rows], size: 5pt)
  panel(H, 123, 95, 20, 7, [Ban 24 h], bg: rgb("fef2f2"), weight: "bold", size: 5.5pt)
  panel(H, 145, 95, 21, 7, [Allow], size: 5.5pt)
  panel(H, 123, 104, 43, 7, [Add to group ▾ · Copy as curl], size: 5.5pt)
}))

#figure-box([Policy: the ordered rules table and the editor. The tester on the right evaluates a
synthetic request against the current policy through the same engine code and names the
rule that decided.],
wire(170, 120, H => {
  import cetz.draw: *
  shell(H, 170, "Policy")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Policy · surface: Shield ▾ · thresholds: 10 / 40 / 5])
  panel(H, 28, 15, 90, 6, [+ New rule   Import JSON   Export   Rules 12 · file rules 4 (read-only)], size: 5pt)
  table_rows(H, 28, 23, 90, 12, (([≡], 4), ([name], 22), ([match], 30), ([action], 12), ([difficulty], 12), ([on], 8)))
  panel(H, 121, 10, 47, 62, none, bg: rgb("fcfcfd"))
  content((123, H - 14), anchor: "west", text(size: 6pt, weight: "bold")[Edit rule · protect-checkout])
  for (i, f) in ("name", "path pattern", "user agent", "headers (4)", "CIDRs (8)", "action ▾ · weight", "challenge: 20 bits · posw").enumerate() {
    panel(H, 123, 18 + i * 6.5, 43, 5.5, [#f], size: 5pt)
  }
  panel(H, 123, 64, 20, 6, [Save], bg: blue-light, weight: "bold", size: 5.5pt)
  panel(H, 145, 64, 21, 6, [JSON view], size: 5.5pt)
  panel(H, 121, 75, 47, 43, none, bg: rgb("fcfcfd"))
  content((123, H - 79), anchor: "west", text(size: 6pt, weight: "bold")[Test a request])
  panel(H, 123, 83, 43, 5.5, [GET /checkout/pay  UA: Mozilla/5.0 …], size: 5pt)
  panel(H, 123, 90, 43, 5.5, [X-Api-Key: … · 203.0.113.9], size: 5pt)
  panel(H, 123, 97, 43, 9, [CHALLENGE · rule protect-checkout #linebreak() 20 work bits · posw · score 0], bg: amber-light, size: 5pt)
  panel(H, 123, 108, 43, 6, [Evaluate], bg: blue-light, weight: "bold", size: 5.5pt)
}))

#figure-box([Nodes: one card per member with role, health, version, and sparklines, and the two
facts an operator must know about cluster semantics.],
wire(170, 100, H => {
  import cetz.draw: *
  shell(H, 170, "Nodes")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Nodes · edge-eu · leader: node 2 · last commit 4,118 · lag 0])
  for (i, n) in (("node 1 · 10.0.0.1 · follower", "healthy · v0.3.0 · up 3d 4h"), ("node 2 · 10.0.0.2 · leader", "healthy · v0.3.0 · up 3d 4h"), ("node 3 · 10.0.0.3 · follower", "storage degraded · serving last snapshot")).enumerate() {
    let x = 28 + i * 47
    panel(H, x, 16, 45, 60, none, bg: rgb("fcfcfd"))
    content((x + 2, H - 20), anchor: "west", text(size: 5.5pt, weight: "bold")[#n.at(0)])
    content((x + 2, H - 25), anchor: "west", text(size: 5pt, fill: if i == 2 { red } else { green })[#n.at(1)])
    line_chart(H, x + 2, 28, 41, 14, series: 1)
    content((x + 2, H - 46), anchor: "west", text(size: 5pt, fill: ink)[2,140 req/s · 21 MiB · 0.9 core])
    content((x + 2, H - 51), anchor: "west", text(size: 5pt, fill: ink)[bans 312 · challenges 64 k · denied 21 k])
    panel(H, x + 2, 56, 19, 6, [Drain], size: 5pt)
    panel(H, x + 23, 56, 20, 6, [Clear bans], size: 5pt)
    panel(H, x + 2, 64, 41, 6, [Open console ↗], size: 5pt)
  }
  panel(H, 28, 80, 140, 14, [Challenge verification is issuer-bound: route a solver's fetch and verify to the same node. Rate limits and spent sets are per node.], bg: amber-light, size: 5pt)
}))

#figure-box([Settings: users and roles, API tokens, retention, notifications, GeoIP.],
wire(170, 100, H => {
  import cetz.draw: *
  shell(H, 170, "Settings")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Settings])
  panel(H, 28, 15, 140, 5.5, [Users · API tokens · Retention · Notifications · GeoIP · About], size: 5pt)
  table_rows(H, 28, 24, 90, 6, (([user], 26), ([role], 18), ([last login], 24), ([state], 14), ([], 8)))
  panel(H, 121, 24, 47, 34, none, bg: rgb("fcfcfd"))
  content((123, H - 28), anchor: "west", text(size: 6pt, weight: "bold")[Add user])
  for (i, f) in ("name", "role: viewer ▾", "temporary password").enumerate() {
    panel(H, 123, 32 + i * 6.5, 43, 5.5, [#f], size: 5pt)
  }
  panel(H, 123, 52, 20, 5.5, [Create], bg: blue-light, weight: "bold", size: 5.5pt)
  panel(H, 28, 62, 68, 32, [Retention #linebreak() minutes 90 d · incidents 30 d · audit 365 d], size: 5pt)
  panel(H, 99, 62, 69, 32, [GeoIP #linebreak() DB-IP Lite · 2026-09 · 318,402 ranges · loaded 2026-09-08 #linebreak() Update now · attribution shown in footer], size: 5pt)
}))

= The Build Pipeline

`build.zig` gains a `console` concern (`build/console.zig`, following zenfmt's one-file-per-
concern layout), wired by the existing `AppModules` helper.

#table(
  columns: (1.2fr, 2.6fr),
  table.header([*Step*], [*What it does*]),
  [`-Dconsole` (default true)], [Compiles `libs/serve`, `libs/console`, and the interface module into the daemon; `-Dconsole=false` removes every console symbol and the `--console` flags.],
  [`console-ui` (implicit)], [Compiles `apps/console-ui/src/main.zig` for `wasm32-freestanding` at `ReleaseSmall`, asserts the 300 KB budget, and embeds the bytes.],
  [`zig build console-assets`], [Runs `npm ci` and `npm run build` in `apps/console-ui/web/` through `b.addSystemCommand`, producing `assets/console.css` from `tailwind.css` with Tailwind 4 and the daisyUI 5 plugin, scanning `apps/console-ui/src/render/*.zig` for class names so unused daisyUI components are pruned. The step then writes `assets/MANIFEST.md` with the SHA-256 of every asset.],
  [Digest gate (in `zig build test`)], [A unit test in `libs/console/src/assets_test.zig` recomputes the digests of the committed assets and compares them with `MANIFEST.md`, so an edited source without a rebuilt sheet fails the suite. A plain `zig build` therefore needs no npm; only `console-assets` does, and CI runs it and checks the tree is clean.],
  [`zig build console-test`], [Golden tests of the interface module compiled natively (rendered HTML per page and per event), protocol round-trip tests, and the kernel's HTTP and WebSocket tests with an in-process client.],
  [`zig build console-e2e`], [Boots a daemon with `--console` on loopback, runs setup, login, a WebSocket subscription, a policy edit, and asserts the engine rebuild and the audit row; part of `zig build test`.],
  [`zig build console-impact`], [The isolation gate of section 6.2 through `benchmarks/tools.py --console`.],
)

`package.json` pins `tailwindcss` 4 and `daisyui` 5 exactly and has no other dependency;
`package-lock.json` is committed. npm runs only inside `console-assets`, never in the default
graph, so a contributor without Node can build, test, and run the daemon and the console with
the committed stylesheet.

= Security Considerations

- The console is an administrative surface and is bound to loopback by default; exposure
  requires an explicit address and, off a trusted network, `--console-behind-proxy` with TLS
  at the ingress. The data plane's own listener never serves console routes (I1), so a
  console vulnerability cannot be reached through the protected site.
- All state-changing routes require a session or token with an adequate role, the CSRF header,
  and are rate limited; all are audited. Password hashing cost is bounded by the login rate
  limit; session digests mean a database read exposure does not yield usable sessions.
- The interface module renders through an escaping writer; the content security policy
  forbids inline script and remote resources; the WebSocket accepts only same-origin
  upgrades; the shell sets `X-Frame-Options: DENY`.
- The policy tester evaluates through the real engine code but on the console thread against
  a private engine instance built from the current tables, never against the live slot.
- GeoIP data is a country only; the loader verifies transport integrity and the source's
  digest, and the loaded set replaces the previous one atomically.
- The `drain` operation is the only console action that touches a data-plane flag; it is an
  atomic boolean the accept loop reads once per accept, and it is audited.

= Performance Budget

#table(
  columns: (1.6fr, 1fr, 2fr),
  table.header([*Quantity*], [*Bound*], [*Mechanism*]),
  [Console resident memory, idle], [≤ 24 MiB above the daemon], [Fixed slots and rings; GeoIP array ≈ 10 MB is the largest item and is optional],
  [Console CPU, idle], [≤ 2 % of one core], [4 Hz sampler, 1 Hz coalescing, 5 s probes],
  [Data-plane throughput with 8 live dashboards], [within 1 % of no console], [I1, I2, I5; measured by `console-impact`],
  [Data-plane p99 with 8 live dashboards], [within 10 %], [Same],
  [Statistics delta latency], [≤ 1.25 s], [Sampler period plus 1 Hz broadcast],
  [Incident to dashboard], [≤ storage tick + poll ≈ 1 s], [Section 8.2],
  [Policy edit to rebuilt engine on every node], [≤ replication + storage tick ≈ 0.6 s on loopback], [SID 0005 path],
  [Interface module size], [≤ 300 KB], [`ReleaseSmall`, size gate],
  [Page render (statistics, 3,600-point timeline)], [≤ 5 ms in the module], [Bounded writer, per-panel versions],
  [WebSocket subscribers per console], [64], [Slot table; `503` beyond],
)

= Delivery Plan

#phase("Phase 1: Kernel, authentication, statistics")[
  `libs/serve` with HTTP, assets, and WebSocket; `libs/console` with auth, sessions, audit,
  the sampler, `traffic_minutes`, and the `stats` topic; the interface module with the shell,
  setup, login, and the statistics page; `console-assets` and the digest gate; the e2e test;
  the impact gate at its Phase 1 value. A single node is fully observable.
]
#phase("Phase 2: Events, policy, challenges, GeoIP")[
  The incident tap and `events` topic with the detail drawer and actions; the policy editor,
  tester, import and export, and IP groups over `policies` and `ip_reputation`; the challenge
  funnel with the one data-plane histogram addition; the GeoIP loader, lookup, map, and
  country actions; retention.
]
#phase("Phase 3: Cluster")[
  The `nodes` table and page, health probes, node-to-node live buckets, leader awareness,
  drain, per-node views on every page, and the cluster case of the impact gate on
  `benchmarks/cluster.py`.
]
#phase("Phase 4: Operations")[
  API tokens, notification webhooks, exports, the audit page, dark theme polish, keyboard
  navigation and screen-reader labels, and the operator guide in the book (a new chapter in
  Part IX with the wireframes replaced by screenshots of the built console).
]

= Verification

- *Unit.* Router matching, JSON writer bounds, Argon2id and token digests, CSRF, WebSocket
  framing against the standard library's own tests, ring and cursor semantics, sampler deltas
  across counter wrap, minute folding, GeoIP range parsing and lookup, retention windows.
- *Golden.* Every page and every event-driven patch of the interface module compiled
  natively, compared byte-for-byte with committed HTML; a change to markup is a reviewed diff.
- *End-to-end.* The `console-e2e` scenario above, plus: session expiry, role refusal, rate
  limit on login, a slow subscriber receiving `dropped`, a policy tester result agreeing with
  a live request's `X-Sibuna-Rule`, a country block appearing in the trie, and a cluster run
  in which a rule saved on node 1's console changes node 3's decision.
- *Impact.* The `console-impact` gate on every change to `libs/serve` or `libs/console`.
- *Browser.* A minimal Chromium script (the harness family of the benchmarks) loads the
  console, logs in, and checks that tiles update, kept outside `zig build test` because it
  needs a browser.

= Open Questions

- Whether the node-to-node live bucket exchange should reuse the Zaxonlite transport instead
  of a second WebSocket, which would remove one authenticated channel at the cost of coupling
  live statistics to the consensus library's connection lifecycle.
- Whether the challenge solve-time histogram belongs in the data plane at all, or whether the
  interstitial should post it to the console's own endpoint; the former costs one atomic add
  per accepted solution, the latter a second request from every browser.
- The retention default for `traffic_minutes` in a cluster: 90 days of one-minute rows for
  three nodes is about 390,000 rows, well within SQLite's comfort, but replication of every
  minute row is traffic each member pays.
- Whether to ship a pruned daisyUI sheet only (the `console-assets` output) or also the full
  sheet for operators who theme the console with their own components.

= References

- SID 0002 (foundation architecture), SID 0003 (declarative policy), SID 0004 (semantic
  inspection), SID 0005 (Zaxonlite storage), SID 0006 (mathematical foundations).
- Chaitin SafeLine, community edition documentation and README, September 2026: console
  pages "Statistics", "Attack Events", "Applications", "Protection", "Settings".
- zenfmt ZDS 0016, "The zenfmt server": the service kernel, the interface module and glue,
  the event hub, and the vendored stylesheet policy that this record adapts.
- Zig 0.16 standard library: `std.http.Server` (`receiveHead`, `respond`,
  `respondStreaming`, `upgradeRequested`, `respondWebSocket`, `WebSocket.readSmallMessage`,
  `WebSocket.writeMessage`), `std.crypto.pwhash.argon2`.
- daisyUI 5 and Tailwind CSS 4 documentation (component classes and the standalone build).
- DB-IP, "IP to Country Lite" (CC BY 4.0); MaxMind GeoLite2 Country (licence on account).
- RFC 6455 (WebSocket), RFC 9110 (HTTP semantics), OWASP Password Storage Cheat Sheet
  (Argon2id parameters), OWASP Cross-Site Request Forgery Prevention Cheat Sheet.
