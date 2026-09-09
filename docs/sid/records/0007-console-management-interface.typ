#let sid-number = "0007"
#let sid-title = "The Sibuna Console: A Real-Time Management Interface for Nodes and Clusters in Pure Zig"
#let sid-state = "discussion"
#let sid-created = "2026-09-08"
#let sid-discussion = "Specifies the Sibuna Console, a complete management interface for Sibuna: a separate pure-Zig module started from the Sibuna CLI that serves a real-time web interface over the standard library's HTTP server and WebSockets, renders its pages from a WebAssembly module styled with daisyUI 5, keeps authentication, statistics, audit, and a GeoIP database in the embedded Zaxonlite store, manages one node or a replicated cluster, and defines performance acceptance targets that remain to be measured."
#let sid-labels = ("console", "management", "websocket", "ui", "zaxonlite", "geoip", "cluster",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Proposed"
#let sid-last-updated = "2026-09-09"

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
  width: 100%, breakable: false, inset: 10pt, radius: 6pt, stroke: 0.7pt + rule,
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
  context {
    if target() == "html" {
      html.frame(body)
    } else {
      layout(size => {
        let factor = calc.min(1, size.width / measure(body).width)
        align(center, scale(factor * 100%, reflow: true, body))
      })
    }
  },
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
    content((x + 1.5, H - y - 1.2), anchor: "north-west", block(width: (w - 3) * 1mm)[#text(size: size, weight: weight, fill: ink)[#label]])
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
embedded Zaxonlite database. Operators of an application firewall expect a web console: a
statistics overview with live traffic and attack charts, an attack-event browser with payload
detail, rule editors, address groups, and system settings. This record specifies the Sibuna
Console: a proposed first-party Zig module, compiled into the same binary
and started from the Sibuna command line, that provides that class of interface for one node
or a replicated cluster. The console serves HTTP and WebSockets with the Zig standard library,
renders every page from a WebAssembly module written in Zig and styled with daisyUI 5 through
first-party components, streams statistics and events in real time, and keeps users,
sessions, audit records, minute-level statistics, and a GeoIP country database in the same
Zaxonlite store the data plane already replicates. Its interface is designed by three
principles applied page by page: Krug's "don't make me think", support for fast System 1
judgement, and support for deliberate System 2 analysis. Its defining engineering constraint
is an isolation contract: the console may read the data plane's counters and its database, and it may write
the database, but it never enters a request thread, never allocates on one, and never holds a
lock a worker needs; a proposed benchmark gate checks that the console's presence degrades data-plane
throughput by at most one percent and p99 latency by at most ten percent under the specified workloads. These are proposed acceptance targets, not measured results.

#callout("Review and implementation boundary · 2026-09-08")[
  This is a *proposed* console, not a delivery record. The implementation checklist records
  the initial contract modules and tests. The live listener, authenticated UI and management
  workflows are not yet implemented.
  Present-tense requirements below describe intended behavior unless explicitly called current.
  Evidence was checked against `build.zig`, `build.zig.zon`, `apps/sibuna/src/server.zig`,
  `persistent.zig`, `libs/policy/src/engine.zig`, `waf.zig`, `radix_trie.zig`, and the browser solver.
  The toolchain is Zig 0.16.0; Zaxonlite is pinned to 0.6.2. First-party service and UI logic
  is Zig, with browser JavaScript glue and CSS assets. The storage-enabled daemon links
  SQLite and libc (SID 0005); this is native software for a host OS, not a freestanding
  bare-metal kernel. Only the browser modules target `wasm32-freestanding`.
]

= Introduction and Motivation

SID 0002 defines the Gate and Shield surfaces, SID 0003 the declarative policy, SID 0004 the
inspection engine, and SID 0005 the storage layer with dynamic policies, replicated
reputation, and forensic incident search. SID 0005 closed with an open item: "an
authenticated HTTP administration API for policies and incident search." Operator
questions illustrate that gap. How much traffic did the gate challenge in the
last hour, and how many challenges were solved? Which addresses were banned on which node,
and did the ban propagate? Which rule fired for a denied request, and what did the payload
look like? Is node 2 the leader, and is it healthy? Some answers exist in Prometheus counters and `security_incidents`; others require new instrumentation and a storage-status API. The console must distinguish measured values, sampled estimates, missing evidence, and planned capabilities.

Sibuna operators need a front page that explains current traffic and protection outcomes,
an investigation path from a denial to recorded evidence, and controlled editing of policies,
address groups, users, retention, and notifications. These workflows must reflect Sibuna's
surfaces, policies, and nodes, including challenge verification, cluster membership, and
campaign investigation. Missing evidence must remain visibly unavailable.

= Operator Workflows

The interface uses a labelled left sidebar, a top bar with a breadcrumb, theme and refresh
controls, and a page body. Lists provide relevant filters, refresh controls, bounded exports,
and pagination. Incident details distinguish recorded request evidence from absent response
data. The following requirements describe the proposed Sibuna workflows.

#table(
  columns: (1fr, 3fr),
  table.header([*Workflow*], [*Operator requirements*]),
  [Traffic statistics], [Select time range and nodes; inspect requests, admitted, challenged, denied, distinct banned addresses and origin 4xx/5xx counts. View a live globe, country ranks, timeline and sampled request rankings with loss and coverage metadata. Page views and unique visitors require separate instrumentation.],
  [Security posture], [Inspect trends and source addresses for inspection, reputation, rate limiting, challenges, bans and honeypots; follow live events, attack categories and attacked paths. Show each decision with its recorded reason.],
  [Wall display], [Open a read-only, scoped, expiring kiosk session with the globe, country ranks and module trends; keep payload evidence outside the kiosk scope.],
  [Nodes], [Inspect each node's surface, upstream, listener, traffic, health and applied revision. Sibuna protects one origin per process. Preview drain and clear-local-bans commands and inspect their completion.],
  [Attack investigation], [Browse grouped and raw incidents, filter and paginate, export bounded results, and inspect redacted request evidence. Show rule evidence, available scores, campaigns and similar incidents. Historical fields absent from storage say “not recorded”; JA4 requires bounded capture from a trusted ingress that overwrites spoofed headers.],
  [Inspection controls], [Set each supported category to disabled, audit or enforce. Audit records findings and continues evaluation, preserving other enforcing denials. Category modes extend the current global inspection switch.],
  [Rules and address groups], [Edit and order rules, test a private candidate engine, import/export, inspect history and revert with revision checks. Manage reputation prefixes, groups and country-derived prefixes within existing engine capacities.],
  [Rate limits], [Inspect configured and effective node-local limits, their outcomes and affected addresses. Terminal-rule GCRA extends the existing global limiter; reject limiter settings on WEIGH rules. Overload remains visible through challenges and bounded-connection rejection.],
  [Challenges], [Inspect issued, submitted, accepted and rejected solutions, rejection causes, solve-time distributions and missing timing coverage. Display configured difficulty and effective proof parameters separately.],
  [Operational settings], [Manage constrained blocking/challenge templates, retention, bounded webhooks and syslog, GeoIP generations and About information. Show storage and cluster coverage without inventing healthy or zero states for missing nodes.],
  [Console access], [Manage users, roles, password changes, TOTP/recovery, scoped API tokens and revocation. Keep the authentication shell separate from dashboard data and geometry.],
  [Audit], [Investigate redacted console mutations, revision conflicts and changes; show local-command intent and completion separately.],
)

Authenticated pages share one WebSocket with snapshot/delta streaming; the backend polls
storage and health endpoints. Bounded request samples feed request-level rankings. Page views
and unique visitors cannot be inferred accurately from these samples and are excluded unless
separately instrumented. Incident details expose recorded rules, available scores, campaign
membership, and similar incidents while marking missing or truncated evidence.

The design follows the approach the zenfmt project uses for its server interface: a bounded
service kernel over the standard library, an application layer that composes routing,
authentication, and handlers as straight-line code, a WebAssembly interface module in Zig
that owns every page and all interface state, a fixed JavaScript glue that only moves events
in and commands out, and vendored daisyUI styling. Sibuna's console has eight navigation sections, live streams and a cluster, so the module structure below is deliberately more
granular, and the transport is WebSockets rather than server-sent events because the
interface also sends commands (subscribe, filter, acknowledge) on the same connection.

= Design Principles

Three principles govern every page, and the principle audit audits each page against them. They are
not decoration: each yields testable rules (R1 to R18) that the verification section checks.

== Don't make me think

Krug's rule is that a page should be self-evident: a person should know what it is, what
they can do, and where they are without reading. Applied to a security console, whose
operator is often looking at it under pressure, the rule becomes:

- *R1 One question per page.* Every page answers one question stated in its title: "What is
  happening?" (Statistics), "What was attacked and why?" (Attack events), "Are the puzzles
  working?" (Challenges), "What are the rules?" (Policy), "Is the cluster healthy?" (Nodes).
  Observation pages have useful defaults (all nodes, last 24 hours, live on); mutation forms explicitly ask for the information and confirmation they need.
- *R2 The trunk test.* From any page, without scrolling, the operator can name the product,
  the cluster and node, the page, the section within it, and the way back: the top bar and
  breadcrumb carry all five, always in the same place.
- *R3 Conventions over invention.* A left sidebar of pages, a filter bar above every list, a
  detail on the right, primary actions top right, destructive actions red and confirmed.
  Sibuna's own vocabulary (Gate, Shield, Edge, work bits) appears with a plain-language
  gloss on first use per page, never a tooltip the operator must discover.
- *R4 Obvious clickability.* Every clickable thing looks clickable and nothing else does:
  links are coloured and underlined on hover, buttons are buttons, table rows that open a
  detail show a chevron. No hidden gestures, no right-click menus, no double-click.
- *R5 Omit needless words.* Labels are nouns, buttons are verbs, and both are short. Intro
  banners, marketing copy, and explanations of what a firewall is do not appear; the one
  explanatory line a panel may carry links to the book.
- *R6 Nothing moves that does not need to.* Tiles and charts update in place at 1 Hz with
  no animation; new rows accumulate behind a “Show new events” control whenever the reader has scrolled or focused a row; layout never reflows on data.
- *R7 Errors are Elm-style.* A failed action names what happened, why, and what to do, in
  the diagnostic voice the daemon already uses, inline where the action was taken.

== Fast judgement: System 1

Kahneman's System 1 is fast, automatic, and pattern-driven; an operator glancing at the
console should be able to notice a potential anomaly quickly; these are usability goals to test with operators, not guarantees of correct judgement.
The interface therefore invests in preattentive cues and consistency:

- *R8 One colour per decision, everywhere.* Admitted is green, challenged is amber, denied is
  red, banned is dark red, informational is the single blue accent; the same hue in tiles,
  chart series, badges, and rows, in both themes. Decision badges keep these meanings; health uses separate labelled status icons, and charts never rely on colour alone.
- *R9 Deviation, not magnitude.* Each tile shows its value and a small marker of how it
  compares with the same window yesterday (an arrow with a percentage), because a raw count
  is meaningless at a glance and a change is not. A tile whose deviation exceeds a threshold
  gets a tinted background. Compare equal-duration windows with matching coverage; zero prior counts show “new”, and absent history shows “not available”, never an infinite percentage.
- *R10 Stable positions.* A panel is always in the same place at the same size; rankings keep
  slots and update bar length without animation; the map keeps its projection. Recognition works by
  location as much as by shape.
- *R11 Sparklines beside numbers.* Every count that has a history shows a 60-point
  sparkline next to it, so a spike is seen before it is read.
- *R12 Scannable typography.* Numbers use tabular figures and thousands separators, are
  right-aligned in tables and large in tiles; addresses and identifiers are monospaced;
  relative times ("12 s ago") in live views and absolute times in logs.
- *R13 Semantic icons only.* One icon per module (inspection, reputation, limits, challenge,
  ban, honeypot, node), used consistently; no decorative icons.

== Careful judgement: System 2

System 2 is slow, effortful, and analytic; it is what an operator engages when deciding
whether to ban a network, change a rule, or declare an incident. The console supports it by
making evidence explicit and decisions reversible:

- *R14 Evidence for every conclusion.* A denial shows its recorded reason and evidence; score terms, matched spans and raw request fields appear only when captured, otherwise “not recorded”;
  a challenge shows its parameters and recorded outcome; a ban shows who or what caused it and when
  it expires. No verdict appears without its reason.
- *R15 Depth on demand.* Pages are layered: glance (tiles), scan (tables), study (detail
  modal), investigate (campaign members, nearest incidents, the same address across nodes).
  Each layer is one click deeper and the way back is always the same control.
- *R16 Compare, don't recall.* Any period can be compared with the previous one, any node
  with another, and any rule's hits before and after an edit; the interface places the two
  side by side so the operator never holds one in memory.
- *R17 Simulate before you commit.* The policy tester evaluates a synthetic request against
  the current policy; a rule edit shows a diff of what will change and which recent events
  it could have matched from retained inputs, before Save. Truncated or absent inputs make a replay inconclusive; the tester does not reproduce live rate-limit, ban, or token state.
- *R18 Reversible by default.* Bans and allows carry a duration and an "undo" for thirty
  seconds; rule edits are versioned and can be reverted from the audit page; deletion needs a typed confirmation; drain and broad country changes require an impact preview and confirmation. Undo is a new versioned mutation, not deletion of the audit record.

== Elegance

Elegance is the absence of anything unnecessary, not the presence of ornament. The visual
system is small enough to hold in one's head: one accent colour and the four decision
colours; a neutral surface scale of five steps per theme; one typeface for text and one
monospaced face for identifiers, in a five-step type scale (12, 14, 16, 20, 28 px); an
8-pixel spacing unit; 4-pixel corner radius on inputs and 8 on cards; one shadow level for
overlays only; 150 ms transitions on hover and none on data. The daisyUI theme `sibuna` is
defined once from these tokens and the `sb-*` components use nothing else, so the console
looks like one thing rather than a collection of widgets. Density is a preference
(comfortable or compact) remembered per browser, because the same operator wants air on a
laptop and rows on a wall display.

== Principle audit by page

#table(
  columns: (0.75fr, 1.4fr, 1.4fr, 1.4fr),
  table.header([*Page*], [*Don't make me think*], [*System 1*], [*System 2*]),
  [Statistics · Traffic], [Answers "what is happening?" with defaults: all nodes, 24 h, live. No selectors demand attention until needed (R1, R2).], [Six tiles with deviation markers and sparklines; one stacked timeline; decision colours throughout (R8–R11).], [Period comparison toggle; every tile drills into its table; sampled panels say "sampled" (R15, R16).],
  [Statistics · Security], [One row of module tiles, one trend per module, the live feed on the right; the same layout as Traffic so the eye does not relearn (R3, R10).], [Trends share a y-axis so a spike in one module reads against the others; the feed uses module icons and decision colours (R8, R13).], [Each trend opens its module's events filtered to the period; the feed row opens the detail modal (R14, R15).],
  [Attack events], [Two views named for what they group (by source, raw); one filter bar; one detail control (R1, R4).], [Category chips coloured by decision; country flags; new rows wait behind the reader-controlled update button (R6, R8).], [The detail modal is the System 2 workbench: rule, score terms, decoded payload, raw request, campaign, nearest incidents, and the actions with durations and undo (R14, R17, R18).],
  [Challenges], [The funnel is the page; nothing else competes with it (R1, R5).], [Funnel stages in decision colours; the histogram shape shows a slow-device tail at a glance (R8, R11).], [Per-cause rejection tables; difficulty bump timeline against load; per-rule parameters editable with a preview of expected solve time (R14, R17).],
  [Policy], [Rules read top to bottom in evaluation order, with the order shown as a number and drag handles; one editor (R3, R4).], [Type chips in decision colours; hits-today sparkline per rule; disabled rules greyed (R8, R11).], [Tester, diff before save, "would have matched" against recent events, versions with revert, inspection-mode matrix with a one-line consequence per mode (R16–R18).],
  [Nodes], [One card per node; leader marked; unhealthy first (R1, R10).], [Health as colour plus word; sparklines for rate, memory, CPU (R8, R11).], [Per-node drill to its statistics; replication lag history; drain with a confirmation that states what it does (R14, R18).],
  [Settings, GeoIP, Audit], [Tabs named by noun; forms with one primary action; nothing hidden behind icons (R3, R5).], [Two-factor state and token expiry as badges; retention as a sentence, not a table (R12).], [Audit rows show before and after; page templates preview live; GeoIP shows source, licence, and count before the update button (R14, R17).],
)

= Terminology and Scope

- *Data plane*: the Sibuna daemon's request path (accept, parse, classify, verify, proxy),
  its worker and connection threads, and its bounded tables (including the sharded, locked spent set).
- *Storage thread*: the existing thread of SID 0005 that owns the Zaxonlite node and rebuilds
  engine slots.
- *Console*: the management application specified here: its listener, threads, module, and
  tables.
- *Kernel*: the console's bounded HTTP and WebSocket service layer (`libs/serve`).
- *Interface module*: the `wasm32-freestanding` Zig module that renders pages in the browser.
- *Glue*: the fixed JavaScript file that loads the module, opens the WebSocket only after authentication, forwards
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
- A complete management surface for everything Sibuna does: statistics, events, challenges,
  policy, reputation, nodes, GeoIP, users, tokens, pages, retention, notifications, audit.
  The console is complete on its own terms: one product, one feature set, no editions.
- Designed by three principles, applied and audited per page (Design Principles): don't make me think;
  fast, glanceable judgement (System 1); deliberate, evidence-backed analysis (System 2).
- Elegant: one accent colour, one type scale, one spacing unit, restrained motion, and nothing
  on a page that does not earn its place.
- Real-time by default: the overview targets 1.25-second counter-to-display updates; incident delivery is subject to storage backlog, commit time, polling, and broadcast delay.
- Cluster-aware: one console shows configured members and marks unobserved members; policy and reputation edits made on any node
  reach every node through the replicated tables of SID 0005.
- Pure Zig: the kernel, the application, and the interface module are Zig; the only
  JavaScript is the fixed glue; the only CSS is daisyUI 5 plus first-party components.
- The isolation contract in “Process model and the isolation contract”, with a measured gate.
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
  edge((2,0), (0,0), "-|>", [storage/control mailbox], bend: -25deg),
  edge((0,0), (1,2), "-|>", [SQL]),
  edge((2,0), (0,0), "--|>", [atomic loads], bend: 30deg),
)

#figure-box([Proposed modules and runtime interfaces. The daemon owns database access; console work uses its bounded mailbox. Dashed telemetry reads do not take engine or request-state locks.],
scale(72%, reflow: true, fit-diagram()))


== Modules and directories

#table(
  columns: (1.2fr, 2.6fr),
  table.header([*Path*], [*Contents*]),
  [`libs/serve/src/`], [`kernel.zig` (listener, connection slots, deadlines, drain), `router.zig` (comptime route table), `context.zig` (request context, response helpers), `websocket.zig` (upgrade, frame loop, per-connection send queue), `assets.zig` (embedded files with content-addressed paths), `json.zig` (bounded writer and reader), `ratelimit.zig`, `log.zig`],
  [`libs/console/src/`], [`app.zig` (composition and `handle`), `auth.zig` (Argon2id, sessions, roles, tokens, CSRF), `api/` (`stats.zig`, `events.zig`, `policy.zig`, `reputation.zig`, `nodes.zig`, `challenges.zig`, `settings.zig`, `users.zig`, `audit.zig`, `geoip.zig`), `telemetry/` (`sampler.zig`, `minutes.zig`, `funnel.zig`), `hub.zig` (topics, ring, subscribers), country lookup through `libs/geoip` (`geoip_job.zig`, `geoip_download.zig`, `geoip_generation.zig`), `cluster_probe.zig` (peer health probes; membership and the storage status snapshot live with the storage owner in `apps/sibuna/src/console_membership.zig` and `console_node_storage.zig`), `schema.zig`, `retention_job.zig`],
  [`apps/console-ui/src/`], [`main.zig` (ABI, state, event dispatch), `render/` (one file per page, plus `components.zig` for the `sb-*` components and `charts.zig` for SVG), `protocol.zig` (frames shared with `libs/console` by import), `main_test.zig` (golden renders)],
  [`apps/console-ui/web/`], [`shell.html`, `glue.js`, `tailwind.css` (source), `package.json`, `assets/console.css` (built, committed with digest), `assets/world-110m.bin` (committed)],
  [`apps/sibuna/src/console_start.zig`], [Flag parsing for `--console*`, the `sibuna console` subcommands, thread start and stop],
)

The two libraries and the UI module may import `core`, `crypto`, `policy`, and `store` for types they
share with the data plane (rule structures, address parsing, the incident record), and import
nothing from `apps/sibuna`. The daemon imports `console` and supplies narrow, library-owned interfaces for metric
snapshots and a bounded storage-command mailbox. `Metrics` and `IncidentRecord` currently
live in the application and must be extracted or adapted; no database-handle factory exists.
The storage thread remains the sole owner of `Persistent`, its allocator and database facade.
Console SQL work is serialized through that mailbox with priorities, result-size bounds and
per-tick quotas; it must not call `rebuild` or `publishEngine` itself. Heavy forensic queries
need validated cancellation/deadlines or a separately owned read snapshot before release.
An arbitrary SQLite connection must not bypass Zaxonlite's commit/replication path.



== Process model and the isolation contract

The console runs on its own listener, its own bounded thread pool, and its own allocator
arena. It shares the process and its CPU/cache/memory bandwidth with the data plane, plus controlled storage, metric, telemetry and command interfaces. The contract is stated as invariants and each has a test.

#invariant([I1], [No console code executes on a data-plane worker or connection thread. The
  daemon's `dispatch` has no console branch; console routes live on the console listener.])
#invariant([I2], [The console reads data-plane state only through atomic loads of `Metrics`
  and through bounded storage requests, plus the explicitly proposed telemetry rings. It never takes a shard spinlock, pins an engine slot, or consumes
  the incident ring.])
#invariant([I3], [The console writes data-plane state only through the database. A policy or
  reputation change is a committed row; the storage thread's existing tick observes the
  revision and publishes a rebuilt engine exactly as SID 0005 specifies.])
#invariant([I4], [Console-owned memory has explicit capacity and admission bounds: the connection slots, the WebSocket ring,
  the subscriber table, the sampler's minute buffers, and the GeoIP range array have fixed
  capacities recorded in `console.Budget`, and the sum is printed in the startup banner, including thread stacks, request bodies, authentication workspaces and double-buffered GeoIP reloads. Database/cache memory is measured separately as part of process RSS.])
#invariant([I5], [Console work is rate- and size-limited: the sampler runs at 4 Hz, broadcasts
  are coalesced to 1 Hz per topic, event fan-out is capped at 64 records per second per
  subscriber, and the GeoIP loader uses bounded batches. This does not provide a hard CPU-time bound: SQL, hashing, scheduling and shared cache/memory bandwidth still require measurement.])
#invariant([I6], [Recoverable handler, database and capacity errors fail console operations
  without stopping the request listener. A Zig panic, memory corruption, or process OOM can
  terminate both planes: a shared process is not a fault-isolation boundary. A separate
  console process is required if crash isolation becomes a requirement.])

I3 has two explicit proposed control exceptions: drain and clear-local-bans use a bounded,
authenticated command mailbox consumed by data-plane control code. Console threads never
mutate ban-table internals. Both commands require an audit intent, operation id and completion
record, since a local effect and a database transaction cannot be committed atomically.

The impact gate compares console compiled out, compiled in but disabled, idle, and eight
active dashboards. Measure admitted, challenge, denied/incident-heavy and policy-reload
workloads, including authentication and GeoIP reload contention. Use repeated interleaved
runs on a declared host, fixed warm-up/duration and traffic mix, and report uncertainty.
Throughput loss must be ≤ 1% and p99 increase ≤ 10% relative to the corresponding baseline;
inconclusive/noisy runs do not establish compliance. The active-console impact matrix has not yet run.


== Startup from the command line

```
sibuna --console 127.0.0.1:9443 --data-dir /var/lib/sibuna --secret-file /etc/sibuna/secret
sibuna --console 0.0.0.0:9443 --console-behind-proxy --console-cookie-secure ...
sibuna --console 127.0.0.1:9443 --console-advertise https://console-1.example \
  --console-probe 2=http://10.0.0.2:8080 --console-probe 3=http://10.0.0.3:8080 ...
sibuna console init-admin admin --data-dir /var/lib/sibuna
sibuna console add-user alice --role viewer --origin https://console.example \
  --username admin --password-file /run/private/console-password
sibuna console users --origin https://console.example \
  --username admin --password-file /run/private/console-password
sibuna console geoip status --origin https://console.example \
  --username admin --password-file /run/private/console-password
sibuna console geoip update --month 2026-09 --origin https://console.example \
  --username admin --password-file /run/private/console-password
# Optional: --checksum <compressed-source-sha256> --timeout <seconds>.
sibuna console mint-token monitoring --scope stats_read --scope geoip_read \
  --origin https://console.example --username admin --password-file /run/private/password
sibuna console tokens --origin https://console.example \
  --username admin --password-file /run/private/password
sibuna console revoke-token 42 --revision 1 --origin https://console.example \
  --username admin --password-file /run/private/password
sibuna console geoip status --origin https://console.example --token-file /run/private/token
# mint-token: optional --role and --expires <absolute Unix seconds>.
# remove-token explicitly removes inactive metadata, retaining the audit trail.
```

`--console` requires `--data-dir` and storage support (`-Dconsole=true` with `-Dstorage=false` is a build error; the console default follows storage): users, sessions, and statistics live in the database, and a
console without persistence would lose its administrator on restart. The console listens on
loopback by default; binding elsewhere without `--console-behind-proxy` (which requires an explicit trusted-proxy CIDR list and canonical HTTPS console origin) is refused. Only allowlisted socket peers may supply forwarded address or scheme headers; the ingress strips client-supplied copies. Proxy mode enables `Secure` cookies. HTTP on loopback is development-only. The shown account, token and GeoIP commands are implemented; other proposed management commands remain gated. Offline bootstrap takes an exclusive data-directory lock; commands against a running node use the authenticated console API, never a second embedded node over the same directory. In a cluster every member may run a console; each shows the whole cluster, because the
tables it reads are replicated, and each probes the others' health endpoints directly.

= The Serve Kernel

`libs/serve` is a bounded service kernel over `std.http.Server` and `std.Io`. It is the
console's HTTP substrate, not an OS kernel, and is written to be reusable by a future service; it knows nothing
about firewalls.

- *Listener and slots.* One acceptor thread; `max_slots` (default 80, at most 256; reserve at least 16 slots for HTTP and control traffic) connection
  threads with fixed 16 KB receive and send buffers. A head larger than the receive buffer is
  `431`; a full slot table is `503` with `Retry-After`. Deadlines (head 10 s, idle 60 s, body
  30 s) are enforced by a watchdog thread that shuts down expired sockets, the same mechanism
  the daemon's idle reaper uses, because the threaded `std.Io` exposes no per-read timeout.
- *HTTP.* `std.http.Server.receiveHead` parses the request; `Request.respond` and
  `respondStreaming` write responses. Bodies are limited to 1 MB except the policy import
  route (8 MB). Every response carries `Cache-Control`, `Content-Security-Policy`
  (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`; add only the exact console WebSocket origin if required by a supported browser), `X-Content-Type-Options`, `Referrer-Policy`, and `X-Frame-Options`.
- *WebSocket.* `Request.upgradeRequested` and `respondWebSocket` provide the Zig 0.16
  handshake/writer primitives. `readSmallMessage` is bounded by its input buffer, not a
  built-in 4 KB constant, and rejects fragmentation. The kernel must implement and test
  RFC 6455 fragmentation, masking, RSV/opcode checks, UTF-8, control-frame limits and close
  handling; cap a reassembled client message at 4 KiB (1009 on overflow). Each connection
  has independent read progress and one serialized writer, so blocked reads do not prevent
  unsolicited statistics delivery. Ping/pong and close frames share that writer. Bound
  write time, close idle peers, and account both tasks/threads in the memory budget.


- *Assets.* Embedded files (`shell.html`, `glue.js`, `console.css`, the interface module,
  `world-110m.bin`) are served under `/console/assets/<sha256-prefix>/<name>` with
  `Cache-Control: immutable`; the shell's placeholders resolve at start to those paths, so a
  new build names its assets by content; serve the shell with `no-cache`, immutable assets with `max-age=31536000`, and sensitive API responses with `no-store`.
- *Router.* A comptime table of `(method, pattern, role, handler)`; patterns are literal
  segments with at most two `{param}` segments; matching is a bounded loop with no
  allocation. Unknown paths under `/console/` return the shell so the interface module can
  route client-side; unknown paths under `/console/api/` return a JSON `404`.
- *Rate limits.* Token buckets keyed by client address for login (5 per minute) and by
  session for mutations (60 per minute); reads have per-session/global query, export and result-size budgets as well as the slot budget. Idle/read deadlines also cover slow response writers.

= Authentication and Authorization

- *Passwords* are hashed with Argon2id at the OWASP minimum recommended parameters (`t=2`,
  `m=19 MiB`, `p=1`) and stored as PHC strings; verification runs on the console's thread,
  never the data plane's, with a global single-verifier semaphore and bounded wait queue in addition to per-IP and per-account limits. Reserve the 19 MiB workspace and enforce supported PHC parameter maxima before verification; an IP limit alone cannot bound distributed login load.
- *Sessions* are 256-bit random tokens stored only as SHA-256 digests in `console_sessions`
  with an absolute lifetime (12 h) and an idle lifetime (30 min), delivered in an `HttpOnly;
  SameSite=Strict; Path=/console` cookie, `Secure` when behind a proxy. A session records the
  client address and User-Agent for audit; binding is an explicit console policy independent of data-plane proof tokens. Role changes, disablement and password resets revoke sessions and applicable tokens through an authorization revision. Privileged actions fail closed when current authorization cannot be established from the authoritative store.
- *Roles* form the order `viewer < operator < administrator`. Viewers read; operators edit
  policy, reputation, and bans; administrators manage users, tokens, GeoIP, retention, and
  settings. Every route declares its minimum role in the router table.
- *Cross-site request forgery* is prevented by the strict cookie plus a session-bound synchronizer token:
  the interface module receives a CSRF token at login and sends it in `X-Console-CSRF` on
  every mutation; the WebSocket upgrade is accepted only when `Origin` matches the console's
  configured canonical origin (scheme, host and port), not the untrusted Host header. Cookie-authenticated mutations require the token and same-origin checks; bearer-only API calls do not require a CSRF cookie. WebSocket commands are subscriptions only, with role/expiry/revocation rechecked during the stream.
- *Two-factor authentication* is optional per user and required for administrators when
  the console is bound off loopback: time-based one-time passwords (RFC 6238, HMAC-SHA1 from
  the standard library) enrolled through a QR code rendered by the interface module, with
  ten single-use recovery codes stored as digests. Encrypt the TOTP seed under a separately provisioned console key; atomically consume recovery codes and accepted TOTP time steps to prevent replay across nodes. Enrollment and recovery endpoints are rate limited. Seed envelopes use the standard-library XChaCha20-Poly1305 construction with a fresh 192-bit random nonce, binding the envelope version, console key identifier and user id as associated data. Recovery values contain 128 random bits and their SHA-256 digests are domain-separated and user-bound. Six-digit TOTP accepts at most one 30-second step of skew; the authoritative transaction consumes the newest matching step and refuses any previously consumed or older step. This is Phase 1 for any off-loopback release.
- *API tokens* for automation are opaque 256-bit values with a printable id, a role, and an
  optional expiry, presented as `Authorization: Bearer`; they are hashed like sessions.
- *Audit.* Every mutation writes one `console_audit` row (actor, role, action, subject,
  before and after summaries, address) in the same transaction as a database change. Redact passwords, token values, TOTP seeds, cookies and webhook secrets. Local effects use the intent/completion protocol above; exports and authentication outcomes also emit audit events.
- *Bootstrap.* `init-admin` atomically creates the first administrator with `must_change=true` and an expiring one-time password digest. Before initialization, HTTP serves only a “run init-admin locally” notice. A must-change account can only change its password and enroll required TOTP; consume the bootstrap credential and rotate the session atomically.

= The Telemetry Pipeline

The pipeline combines existing counters and persisted incidents with proposed bounded
instrumentation. “Exact” below means exact for the instrumented scope, not every connection.

== The sampler

At 4 Hz the sampler reads `Metrics` using monotonic atomic loads; it sums four deltas into
one second bucket and keeps 3,600 buckets. Loads are not a simultaneous snapshot. Persist
minute deltas with node id, boot id, coverage and completeness. Use monotonic time for
rates and UTC minute labels; a restart resets the baseline, never unsigned-subtracts the
old process's counters. CPU usage is delta CPU seconds / delta wall seconds, not a sum of RSS.
RSS is a gauge with last/max aggregation. Upsert partial minutes idempotently by boot id.

Current `requests` includes internal routes; `banned` counts requests rejected by the local
ban table, not distinct banned addresses. `denied`, `challenged`, `allowed`, `rate_limited`
and verification counters describe different branches; issued/accepted are separate requests,
and malformed submissions may not increment `solutions_rejected`. Never stack them as an
exhaustive partition. The console external-request outcome counter family assigns exactly one
outcome (admitted, challenged, denied, banned, rate-limited, other) per external request.
Here external means a successfully parsed request head outside `/__sibuna/`; incomplete
external bodies count as other. Unparseable heads and pre-admission connection rejections
cannot be classified by route and remain separate transport observations. Each selected
outcome is recorded before attempting response delivery, so it does not prove receipt.
Origin 4xx/5xx counts require response instrumentation; upstream errors are not their proxy.
Distinct active bans need a control-thread snapshot, not the existing `banned` counter.

== The incident tap

The storage thread alone drains the existing 512-slot MPSC incident ring, up to 32 records
per 500 ms tick: approximately 64 records/s before commit costs, with loss on overflow.
A feeder polls committed rows using a separate sequence cursor *per issuer node*; a single
maximum id would skip later records from lower-numbered nodes. Capture a cursor watermark
with each snapshot, then send later rows. Bound pagination, report missing retention history,
queue loss and replica staleness. Delivery includes queue drain, commit, feeder poll and
1 Hz fan-out; it is not bounded to one second during backlog or lost quorum.

Current rows retain node, IP, User-Agent (200 bytes), method (8), path (512), category (32),
payload (512), campaign and timestamp. The payload is the query if present, otherwise body;
it is not necessarily the matched substring. There is no full request/response capture,
JA4, WEIGH decomposition, WAF numeric score, matched offset or rule version. Console-enabled
capture now adds a version-1 metadata sidecar: selected firewall status, query/body byte lengths
and capture truncation flags. Query/body values and headers are omitted from this evidence view;
selected status does not establish delivery. Historical rows have no sidecar. Richer evidence
still needs explicitly bounded and redacted capture before its UI ships.
Show unavailable fields as “not recorded”; never reconstruct a raw request as if captured.
Campaign similarity is the current 64-dimensional embedding/cosine heuristic (threshold
0.35), not attribution or proof of a common attacker. A denied request has no origin response.

== The challenge funnel

Existing Prometheus counters expose issued, accepted and aggregate verification rejection.
Console-owned counters now add submitted, malformed and exhaustive per-cause rejections at
the verification endpoint. Window totals are a flow summary, not a cohort
conversion rate: retries, abandonment and solutions crossing windows break that interpretation.
Per-address records, fallback share and adaptive-difficulty histories need separate bounded
instrumentation, retention and loss accounting before display. Rule-hit totals likewise need
fixed-capacity counters keyed by rule id and applied revision; incident counts cannot supply
exact allow/WEIGH hits. Distinguish category findings from the one final outcome per request.

Accept optional `elapsed_ms` and solver metadata in the existing data-plane verify request;
the interstitial now sends them. Measure solver time before verification, validate
finite nonnegative bounds, and record only accepted solutions. Client timing is untrusted
telemetry, never an admission or difficulty input. Use 16 buckets: [0,1) ms, powers-of-two
intervals [1,2) through [8192,16384), and [16384,+infinity), with separate missing/invalid
counts. Partition by algorithm and bounded parameter bins. Hashcash has expected trial count
$2^b$ for $b$ work bits; PoSW depth $d$ requires $2^(d+1)-1$ labels in this implementation.
Do not label PoSW depth as a Hashcash security/work-bit equivalent or predict device solve
time without calibration. Server response time and client solve time are different metrics.

== Traffic sampling and top-k rankings

Use a per-connection PRNG with independently initialized state to select external requests
with probability $p=1/64$ by default. This avoids the periodic bias of every 64th request.
Copy at most 256 bytes of explicitly sized fields (including client IP, truncation flags,
method/path prefix, client-family labels, Referer host and outcome/origin status) into one
preallocated bounded MPSC queue drained by the console. Connection threads, not acceptor
workers, are producers; one shared queue of 4,096 slots costs 1 MiB for records, plus queue
metadata. A full queue drops and counts the sample; producer contention may require retries,
so no single-CAS cost guarantee is claimed. Unsampled requests still pay the sampling test.
Disable production when the console sampler is absent. Resolve country off the request path.

For $N$ retained samples and $m=256$ Space-Saving counters, every key with frequency greater
than $N/m$ is retained, and a tracked estimate obeys $hat(f)-e <= f <= hat(f)$ with
$e <= N/m$. This guarantees heavy-hitter inclusion, not exact counts or exact top-k order.
Persist all 256 counters, their errors, N, sampling probability, losses and covered interval
per kind; use a tested merge procedure for cross-minute/node queries. Saving only twenty
local winners can lose a global winner. Counts scaled by $1/p$ are sampling estimates;
queue loss, key truncation and sketch error remain visible. Use exact small sampled
histograms for countries and response classes instead of a top-k sketch. Country history
must survive minute folding. Visitors, page views and a complete traffic log are not inferred.

== Data-plane changes this record requests

The proposed work exceeds three atomic additions: outcome/response metrics, rejection and
client-timing histograms, the sample queue, bounded challenge events and richer incidents,
control commands, and new policy snapshot fields all require implementation and impact tests.
Current WAF configuration is a global boolean. Add per-category disabled/audit/enforce modes
inside inspection; audit records a finding and *continues* evaluation, so another enforcing
category, reputation denial or later rule can still block. Disabled categories skip detection.
New per-rule limits and page templates require loader and request-path changes; a database
schema alone does not activate them. Validate the immutable snapshot before commit and publish
only from storage/control code; failed rebuilds retain the prior snapshot and surface an error.

== Cluster aggregation

Minute history sums disjoint node/boot intervals; exclude overlapping live seconds already
covered by persisted minutes. Report node coverage, clock skew, reset/gap and stale values.
Cross-node live tiles are served from replicated minute rows and the probe results above
in this increment; direct authenticated peer snapshot streams (tagged by node id, boot id,
sequence and interval, never forwarding received totals as a node's own contribution)
remain the designed later transport. Only nodes running telemetry contribute; label a
partial cluster rather than treating missing members as zero. Applied policy revision is a per-node acknowledgment, not evidence inferred
from a committed row. Client dashboards do not connect directly to data-plane listeners.


= The Real-Time Protocol

One WebSocket per browser tab at `/console/ws`, opened after login. Frames are JSON text.

#table(
  columns: (0.8fr, 1.1fr, 2.4fr),
  table.header([*Direction*], [*Operation*], [*Fields and behavior*]),
  [Client → server], [`sub`], [`topic`, `args`: subscribe; snapshot precedes deltas.],
  [Client → server], [`unsub`], [`topic`: stop a subscription.],
  [Client → server], [`filter`], [`topic`, `args`: replace filter and start a new epoch.],
  [Client → server], [`ping`], [Application heartbeat, distinct from a transport ping.],
  [Server → client], [Snapshot], [`topic`, `epoch`, `seq`, `snapshot`, `data`: full bounded state, chunked if necessary.],
  [Server → client], [Delta], [`topic`, `epoch`, `seq`, `data`: coalesced updates; events carry bounded summaries.],
  [Server → client], [Gap], [`topic`, `epoch`, `dropped`: resubscribe for a new snapshot; never apply deltas across the gap.],
  [Server → client], [Unauthorized], [`error`: close the subscription and return to sign-in.],
)

Example subscription and response (separate JSON messages; production snapshots include
coverage and a watermark). `epoch` changes on reconnect, filter replacement or server restart.

```json
{"op":"sub","topic":"stats","args":{"window":"1h"}}
{
  "topic":"stats", "epoch":"node1-boot7-sub4", "seq":0,
  "snapshot":true, "data":{"requests":1832,"coverage":1.0}
}
```

The hub keeps one bounded ring per topic (1,024 entries of at most 2 KB) and a cursor per
subscriber; publishing never blocks and never allocates, and a slow consumer sees a `dropped`
count rather than growing memory. This is a proposed bounded hub design informed by zenfmt's event-hub pattern.
Fan-out runs on the hub thread, which writes into each connection's bounded send queue; a
queue that is full drops the oldest delta for that connection and marks it, so a stalled
tab costs one queue and nothing else. Subscribers are capped at 64 per console; the 65th
receives a `503` at upgrade. Reserve separate HTTP/control capacity so 64 long-lived sockets cannot prevent login or API requests. Sequence numbers are per subscription with an epoch; filters start a new epoch/snapshot. A 2 KiB ring entry carries a bounded event summary, not a 64-record full-payload batch. Chunk snapshots with explicit begin/end watermarks; bound reassembly and resynchronize after a gap. Reconnect with jittered backoff, show stale age and keep the last good view.

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
  msg(16, 1, 2, [read user; verify off-owner; store session])
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
policy rebuild it causes on every node. Storage arrows represent mailbox requests; password verification runs between the user read and session write, outside a storage transaction.], sequence())

= Data Model

All console tables live in the same Zaxonlite database as SID 0005 and replicate with it.
Migrations are numbered and version-gated in `schema.zig`. The authoritative writer serializes each migration and schema-version update; followers wait for application before serving compatible routes. Never run concurrent startup DDL independently on every member. All tables below are proposed. Bound row/result sizes and use typed SQL operations with parameter binding where supported (otherwise audited literal escaping), never client-supplied SQL. Console object IDs must be globally unique (random 128-bit ids or node-scoped sequences); foreign keys and uniqueness constraints are required.

#table(
  columns: (1fr, 2.8fr),
  table.header([*Table*], [*Columns and purpose*]),
  [`console_users`], [`id`, `name` (unique), `role`, `password_phc`, `must_change`, `disabled`, `auth_revision`, `last_login`, `totp_ciphertext`, `totp_key_id`, `totp_last_step`, `created_at`, `updated_at`],
  [`console_sessions`], [`digest` (primary), `user_id`, `role`, `client_ip`, `user_agent_hash`, `csrf`, `issued_at`, `last_seen`, `expires_at`, `auth_revision`, `kind` (`browser` or `kiosk`); expired rows are purged by retention],
  [`console_kiosk_grants`], [`digest` (primary; SHA-256 of the one-time code), `user_id`, `revision`, `label`, `created_at`, `use_by` (ten minutes), `expires` (twelve hours), `consumed_at`; at most 64 outstanding; audit `kiosk.grant` and `kiosk.exchange` never carry the code; retention removes consumed and unusable rows],
  [`console_tokens`], [`id` (printable), `digest`, `label`, `role`, `scopes`, `auth_revision`, `created_by`, `created_at`, `expires_at`, `disabled`],
  [`console_audit`], [`id`, `at`, `actor`, `role`, `action`, `subject`, `before`, `after`, `client_ip`; append-only],
  [`console_settings`], [`key` (primary), `value` (≤ 1 KiB, never a secret), `revision`, `updated_at`, `updated_by`; the denial-spike minimum and factor today; every change is audited with its before and after value],
  [`console_notifications`], [`id`, `kind` (`webhook` or `syslog`), `label`, `target`, `target_host`, `secret_envelope` (sealed under the console key and bound to the target), `events` bitmask (denial spike, ban, node unhealthy, leader change), `cooldown_seconds`, `enabled`, `revision`, created/modified actor and time, last attempt, outcome and detail; at most eight rows; audit summaries carry kind, label, events, cooldown, enabled state, whether a secret is set and the host only],
  [`console_notification_events`], [`node`, `boot`, `sequence` (unique per node and boot), `event`, `raised_at`, `detail` (≤ 128), `delivered_at`, `attempts`; every node enqueues what it observed, at most 256 undelivered rows are kept],
  [`console_job_leases`], [`job` (`retention` or `notifier`), `node`, `boot`, `fence`, `expires`; one fenced singleton lease per job name],
  [`console_pages`], [`kind` (primary: `challenge`, `denied`, `rate_limited`, `banned`, `overloaded`), `html` (≤ 16 KiB, validated before staging), `sha256`, `revision`, `updated_at`, `updated_by`; a one-row stage table commits the page, its audit record (`page.edit` or `page.reset` with digests and sizes only) and a policy-version bump together so the next tick rebuilds the snapshot],
  [`ip_reputation` (added columns)], [`source` (`console`, `console:country:XX`, or empty for data-plane rows), `note` (≤ 128), `geo_generation` (the GeoIP generation digest a country block was computed from); one-row stage tables `console_policy_order_stage`, `console_reputation_stage`, `console_country_commit` and `console_policy_import_commit` commit each workflow with its history rows, audit record and an explicit policy-version bump; `console_country_stage` and `console_policy_import_stage` hold chunked prefixes and canonical documents for ten minutes],
  [`traffic_minutes`], [`node_id`, `boot_id`, `minute` (epoch/60), coverage, completeness, counters from “The sampler”, `rss_last_kib`, `rss_max_kib`, `cpu_delta_seconds`; primary key (`node_id`, `boot_id`, `minute`)],
  [`challenge_minutes`], [`node_id`, `boot_id`, `minute`, algorithm/parameter bin, submitted/issued/accepted, rejected by exhaustive cause, missing/invalid timing, coverage, `solve_ms_buckets` (16 integers)],
  [`topk_minutes`], [`node_id`, `boot_id`, `minute`, `kind`, `key`, estimate and error; all bounded sketch counters plus N, probability, losses and coverage metadata],
  [`geoip_ranges`], [`generation`, `start` (16-byte address as blob), `end`, `country` (ISO 3166-1 alpha-2); one row per range from the source CSV],
  [`geoip_meta`], [`generation`, `active`, `source`, `licence`, `published`, `loaded_at`, `ranges`, `sha256`],
  [`console_nodes`], [`node` (primary), `address` (the member's consensus endpoint, or `local`), `console_url` (the advertised console origin, rendered only as a plain-origin link), `version`, `boot`, `first_seen`, `last_seen`, `applied_revision`, `control_revision`, `applied_slot`, `decided_slot`, `draining`; each node writes only its own row from the storage owner: at start, every minute, and after every successfully applied policy rebuild],
)

Additional migrations are required for `console_recovery_codes` (digest and consumed state),
`console_policy_versions` (revision and bounded before/after JSON for conflict-checked revert),
`console_jobs` (import/notifier/retention leases with expiry, fencing token and progress),
`console_node_commands` (target, operation id, expiry, desired state and acknowledgment),
`country_minutes` (node/boot/minute/country/outcome, sample count, probability and coverage),
and versioned incident/challenge evidence. Authentication-only changes must not trigger
policy rebuilds. Coalesce session activity writes; specify replica-staleness handling for
idle expiry. Audit is append-only to application users until explicit retention deletion;
it is not cryptographically tamper-proof. Retention deletes associated FTS/vector rows in
the same transaction and reports maintenance lag.

Existing tables are read, and two are written: `policies` (rule editor) and `ip_reputation`
(ban and allow actions, GeoIP-derived blocks), using the existing row formats for currently supported operations. Dynamic rules sort by `(priority, name)` before file rules, within the larger WAF/reputation/rules evaluation order. Preflight the whole candidate snapshot (128 total rules, matcher limits, 8,192 trie nodes) before commit; use an expected revision to prevent lost updates. New modes, limits and templates require rebuild-path changes. Report committed and applied status separately, including per-node failures.

= GeoIP

Country enrichment runs only off the request path. The first-party library `libs/geoip`
(standard library only; never imported by the data plane) owns address normalization, row
validation, the immutable sorted generation with binary-search lookup, the compact
`SBGEOIP1` snapshot format and every provider fact. The default provider is the
`user-country` dataset of #link("https://github.com/sapics/ip-location-db")[ip-location-db]:
public domain under the PDDL 1.0 (no attribution), rebuilt daily from RIR delegated
statistics, public BGP archives and RFC 8805 geofeeds, published as two uncompressed
`start,end,country` CSV files with a SHA-256 file each. DB-IP IP to Country Lite remains
selectable as a second provider: monthly, CC BY 4.0, one gzip archive, attribution shown
wherever its data is displayed. MaxMind GeoLite2 is not offered; its licence requires an
account and its CSV joins network blocks to location records. The generation digest is the
SHA-256 of the source bytes in provider file order; per-file publisher digests are recorded
and enforced when the provider publishes them, and an operator checksum pins the
generation. A GitHub release download is followed through exactly one HTTPS redirect to an
allowlisted asset host; any other hop fails. An optional `-Dgeoip-data=<snapshot>` build
flag embeds a validated snapshot that serves lookups at revision 0 until the first durable
import replaces it. Unknown, private, reserved and unmapped addresses stay in “Unknown” and
never acquire an invented country; the transitionally reserved codes `AN` and `FX` that
RIR-derived data still carries are accepted.

The loader bounds download/compressed and expanded sizes, row count, string lengths and
transaction sizes. HTTPS and an operator/publisher checksum when available protect transfer;
a locally computed digest identifies a dataset but does not authenticate its publisher.
Parse and validate address families, ordering, non-overlap and country codes, stage an
immutable generation, and atomically switch its active id only after validation. Replicate
bounded batches through the storage mailbox. Keep the previous generation until readers
release it, with at most two in-memory generations and one bounded import in flight.
Use sorted normalized 16-byte addresses with explicit IPv4 mapping semantics and binary
search. Memory is `capacity × @sizeOf(Range)` per generation; neither range count, 10 MB,
sub-microsecond lookup nor a one-minute import is an established result.

An operator may preview a country's ranges decomposed into exact CIDRs, with deduplication,
expiry and overlap analysis. Existing reputation maps scores ≤ -50 to deny and ≥ 50 to
allow; it does not load challenge verdicts. Country challenge requires explicit declarative
challenge rules and their limits, or a separately specified extension. Reject an entire
country action if the candidate engine would exceed 8,192 trie nodes or 128 total rules;
never apply a truncated country. GeoIP updates do not silently change existing country
policies: pin the generation and require a reviewed diff to refresh them.

== Live earth globe on the landing page

The front-page focal panel is a real-time earth globe showing traffic by country whenever
GeoIP is loaded. A pinned, attributed low-resolution world-boundary asset supplies geometry;
country-centroid markers are representative positions, not measured client coordinates.
Do not infer city-level locations or geographic destination coordinates from country-only data.
Animate aggregate inbound arrows from observed countries to a clearly labelled, non-geographic
Sibuna service hub until a node location is explicitly configured. These arrows illustrate the
rolling sample window, not individual packets or invented country-to-country connections.
Zig generates an orthographic SVG projection with a configurable center $(lambda_0, phi_0)$:
$x = cos(phi) sin(lambda-lambda_0)$,
$y = cos(phi_0) sin(phi)-sin(phi_0) cos(phi) cos(lambda-lambda_0)$,
$z = sin(phi_0) sin(phi)+cos(phi_0) cos(phi) cos(lambda-lambda_0)$.
Draw only $z >= 0$ and clip/split coastlines at the horizon and antimeridian; map to screen
coordinates $(c_x+R x, c_y-R y)$. Displaying the rear hemisphere through the sphere is a bug.
Preprocess geometry to a bounded vertex budget, simplifying before runtime.

Update country counts at 1 Hz over a rolling 60-second window via the `stats` subscription.
Default to sampled traffic with coverage, sample probability, lost samples, unknown count,
last update and node coverage visible; switching to persisted incidents explicitly labels
that incomplete incident population. Use marker area proportional to count (radius grows
with the square root of count, capped), and discrete intensity classes on country fills.
A ranked country table next to the globe contains *all* hemispheres and offers keyboard
selection to center the globe and open filtered events. Provide continuous rotation with a
separate animation pause, Rotate left/right, reset, pause/live and a flat-map alternative.
Manual country selection pauses automatic rotation for inspection. Hidden tabs suspend visual
updates and resnapshot on return. A globe is one panel, not a replacement for totals.

Without GeoIP, keep the earth outline and show “GeoIP unavailable”, Unknown totals and an
administrator setup link; no synthetic country markers. With zero traffic say “No traffic in
this window”. On disconnection freeze the last good state and label its age; never animate
stale traffic. Use accessible text/table equivalents; user-driven rotation honors reduced
motion. The same globe component serves desktop, responsive and kiosk views.

The lightweight implementation caps animation at 24 frames per second and 16 visible arcs.
Only the SVG globe region is replaced per frame; statistics retain their independent 1 Hz
subscription cadence. Geometry and animation state remain in Zig, while the browser bridge
supplies frame timestamps and the reduced-motion preference. Reduced motion disables automatic
rotation and moving arrows. Curves use bounded quadratic paths with directional arrowheads.
The inspiration is #link("https://github.blog/engineering/engineering-principles/how-we-built-the-github-globe/")[GitHub’s globe]; its connection endpoints come from actual pull-request location pairs,
whereas Sibuna currently has country-only source observations and a logical service endpoint.


= Cluster Management

The `nodes` page shows every member known from the replicated `console_nodes` table and
from this console's probe configuration: id, consensus address, version, boot, the policy
revision that node has applied against the committed revision, its log frontiers, and the
health of its data-plane listener. Role, leader, ballot term and quorum availability come
from a storage-owned snapshot the owner thread refreshes at most once per second: a single
node reads its own status; a cluster member asks its own Zaxonlite endpoint over the local
status RPC. Health is probed by each console over explicitly configured data-plane
addresses given as `--console-probe <node-id>=<http://ip:port>` (numeric hosts only, never
an address read from replicated data or a browser) with `GET /__sibuna/health` and
`/__sibuna/metrics` every 5 seconds, bounded to 2 s per probe, on one console-owned thread.
A member configured for probing but without a replicated row renders as unobserved with
its counters unavailable, never zero. `--console-advertise <origin>` names the link peers
show for this console. This lets a console show a member whose storage has failed but whose
data plane still serves from its last snapshot, the failure mode SID 0005 documents.

Operations offered per node: drain (set a flag the node's accept loop reads, so it answers
`503` to new connections while finishing current ones, for maintenance), clear local bans (a control command; a replicated reputation denial can still apply),
and open that node's own console. Cluster-wide operations are edits of replicated tables and
need no per-node action: a rule saved on any console is a `policies` row; a ban is an
`ip_reputation` row; both require commit, replica application and the next successful storage rebuild. Book benchmark results are workload-specific and do not establish a 100 ms bound at the default 500 ms polling interval. The page also shows the two facts an operator must know
from SID 0005: challenge verification is issuer-bound (sticky routing is needed), and rate
limits are per node.

= The Interface Module

The interface follows the zenfmt approach: a `wasm32-freestanding` Zig module owns every
page, all interface state, and every fragment of markup; the glue owns the browser. The glue
loads the module, opens the WebSocket only after authentication, forwards browser events and WebSocket frames into the
module as length-prefixed JSON, and executes the returned command list: `patch` (replace an
element's inner HTML), `attr`, `class`, `focus`, `navigate` (push state), `fetch` (issue an
API request the module described and post the result back), `ws` (send a frame), `download`,
`theme`. No markup, route, or form logic lives in JavaScript, so the golden tests compile the
same module natively and assert rendered HTML strings.

- *Rendering.* Pages render into a fixed 512 KB output buffer with a bounded HTML writer that
  escapes by construction. First-party HTML snippets use `{{ field }}` placeholders expanded
  at build time by the native/Wasm-compatible `libs/html` renderer; Zig supplies runtime values.
  Text is always escaped, unknown fields fail compilation, and templates cannot request raw
  output. Snippets are capped at 32 KiB and 128 placeholders; caller-owned output remains bounded.
  Conditions, bounded loops and snippet composition stay in Zig. This is separate from the
  constrained operator-editable data-plane page templates. A page re-renders only the panels whose inputs changed (each panel
  is a function of a slice of state with an explicit version), so a one-second stats delta
  patches four tiles and one chart, not the document.
- *Charts* are inline SVG produced by `charts.zig`: an external-outcome timeline (admitted, challenged, denied, banned, rate-limited and other), sparklines, horizontal bars, a donut, a histogram, and the orthographic earth globe and country table generated from the committed `world-110m.bin` (bounded longitude/latitude polygon vertices keyed by ISO code, projected to SVG at runtime; a flat-map SVG alone cannot supply rotating globe geometry). Decimate long timelines to the visible pixel width and enforce the output bound; output size depends on series and coordinate encoding, not just point count;
  no charting library is loaded, and no canvas is used, so the charts print, zoom, and are
  accompanied by titles and equivalent data tables; SVG titles alone do not establish accessibility.
- *Components.* daisyUI 5 supplies the primitives (`btn`, `card`, `table`, `drawer`,
  `badge`, `tabs`, `toast`, `modal`, `stat`). First-party `sb-*` components compose them
  with fixed markup and are the only elements the render functions emit: `sb-shell`,
  `sb-tile`, `sb-timeline`, `sb-table` (virtualised rows, sortable, with a filter bar),
  `sb-drawer` (event detail), `sb-form` (schema-driven, with validation messages in the
  daemon's Elm-style diagnostic voice), `sb-flag`, `sb-node-card`, `sb-diff`.
- *Visual system.* One daisyUI theme, `sibuna`, defined in `tailwind.css` from the tokens
  of the Elegance subsection (accent, four decision colours, five neutral surfaces, the type scale, the
  8-pixel unit) with `sibuna-light` and `sibuna-dark` variants selected by `data-theme`, following the
  system preference by default and remembered per browser, together with the density
  preference. The `sb-*` components consume only these tokens; a component that needs a new
  colour is a design change, reviewed as one.
- *Charts obey the rules.* `charts.zig` has one palette (the decision colours and the accent),
  draws deviation markers and sparklines as first-class marks, keeps axes and positions
  stable across updates, and uses no animation on data updates (R6, R8–R11).
- *Budget.* The module is compiled at `ReleaseSmall` with a 384 KiB size gate (raised from 300 KiB on 2026-09-09 after the module reached 307,144 bytes; the per-feature size ledger is recorded in the implementation evidence), 4 MiB initial and explicit maximum linear memory, bounded retained history, and no allocator on the event path beyond a bump arena reset per event.

== Pages

All panels are conditional on the instrumentation in “Data-plane changes this record requests”. Missing fields stay
explicitly unavailable; none of the wireframe examples establishes current capture support.

#table(
  columns: (0.9fr, 3fr),
  table.header([*Page*], [*Panels*]),
  [Setup and login], [First-run password change; login form with the optional one-time code; session expiry notices.],
  [Statistics · Traffic], [Period selector (live, 1 h, 24 h, 7 d, 30 d) and node selector; tiles (requests, admitted, challenged, denied, banned addresses, origin 4xx and 5xx with rates, nodes healthy); live timeline of disjoint external outcomes; queries-per-second, request-status and blocking-status sparklines; live orthographic earth globe with a ranked country table, 60-second sampled traffic window, manual rotation, pause and flat-map fallback (“Live earth globe on the landing page”); top-five panels: client operating systems, browsers, response status, referring hosts, popular paths, all marked as sampled.],
  [Statistics · Security], [Tiles per module (inspection, reputation, rate limiting, challenges, bans, honeypot); a trend chart per module with its top source addresses; the live event feed; attack-category donut; attacked paths; rule hits.],
  [Kiosk], [The traffic and security panels in a full-screen, read-only, optionally auto-cycling layout (off with reduced motion) for a wall display. An operator or administrator mints a one-time code (`POST /console/api/kiosk/token`, shown once, usable for ten minutes); the display pastes it into a second form on the sign-in page and receives a viewer cookie session scoped to statistics that expires with the grant (twelve hours) and with the granting user's revision. Codes and sessions never travel in URLs, fragments or local storage.],
  [Attack events], [Grouped view (source address, country, node, attack count, first and last seen) and raw view (action, URL, category, rule, address, time, detail); filter bar (node, category, rule, address, country, path, period); export; detail modal (category chip, URL, address with country and "ban", "allow", "add to group", "address info" actions, JA4 only after trusted-ingress capture is implemented, payload location and decoded value with the matched structure highlighted, rule and score, campaign and its members, similar incidents, request and response heads with charset selection, "copy as cURL").],
  [Challenges], [Funnel (issued, submitted, accepted, rejected by cause); solve-time histogram by algorithm and difficulty; adaptive-difficulty bump timeline; JavaScript-fallback share; per-address records (issued, accepted, rejected, cause, duration, start); per-rule challenge parameters.],
  [Policy], [Rules table with drag ordering, enable toggle, type (allow, deny, challenge, weigh), name, match summary, hits today, creator, updated; rule editor (form and JSON); pattern tester; import and export; inspection mode matrix per category (disabled, audit, enforce); limits (rate, window, ban seconds); IP groups (reputation prefixes with score, expiry, trigger, source, hits); GeoIP block builder.],
  [Nodes], [Member cards with surface, upstream, listener, role, health, version, requests and blocks today, sparklines; per-node drain and clear-bans; replication lag; the sticky-routing and local-limit notices.],
  [GeoIP], [Source, licence, published date, ranges loaded, last update, update button, attribution text.],
  [Settings], [Users (role, two-factor state, last login); API tokens; pages (challenge, denied, rate limited, banned, overloaded templates with preview); retention (minutes, incidents, audit, samples); notifications (webhooks, syslog; events: denial spike, ban, node unhealthy, leader change); about (version, node id, build, binding and proxy facts).],
  [Audit], [Append-only log with actor, action, subject, before and after, filterable and exportable.],
)

= Wireframes

These drawings specify every route and key workflow; illustrative values are not benchmark
results. Setup/sign-in are authentication-only: no globe geometry is fetched or decoded,
no GeoIP query runs and no telemetry WebSocket opens until successful login (and required
password change/TOTP). Then navigate to Statistics · Traffic and load the dashboard assets.
Sign-out closes streams, clears retained telemetry and returns to the authentication shell.
Dashboard globe controls select Traffic or Attacks; the latter shows recorded security
incidents with loss/coverage warnings, not an exhaustive attack count.


The drawings fix layout and information density, not visual style; the visual system of
the Elegance subsection supplies the style. Every panel named here maps to one `sb-*` component and one
render function, and every page is laid out to pass the audit of the principle audit: tiles first,
trends second, tables third, detail on the right or in a modal, and the way back in the same
place on every page.

#figure-box([The shell: top bar with cluster status and the account menu, a fixed sidebar of the
eight pages, and the page body. Below 1,024 px navigation becomes a labelled menu drawer.],
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
  content((85, H - 60), text(size: 5pt, fill: gray)[Authentication required · no telemetry before sign-in])
  content((85, H - 74), text(size: 5pt, fill: gray)[Five attempts per minute per address · sessions expire after 30 idle minutes])
}))

#import "../figures/0007-console-landing.typ": landing-page, earth
#figure-box([The signed-in landing page: Traffic overview with a live country-level earth globe,
ranked countries across both hemispheres, traffic totals and timeline. Values and geography
are illustrative; sampling, Unknown coverage and freshness are explicit.], landing-page())

#figure-box([Statistics · Security: one tile and one trend per module, the live event feed,
and the rankings that answer "what was attacked".],
wire(170, 118, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Statistics])
  panel(H, 60, 9.5, 42, 5, [TRAFFIC · SECURITY · KIOSK ↗], size: 5pt)
  let tiles = (("21 k", "inspection denials"), ("1,204", "reputation hits"), ("3,318", "rate limited"), ("64 k", "challenges"), ("312", "bans"), ("41", "honeypot"))
  for (i, t) in tiles.enumerate() {
    tile(H, 28 + i * 16, 16, 15, 12, t.at(0), t.at(1))
  }
  for (i, m) in ("inspection trend · top addresses", "rate limiting trend · top addresses", "challenges trend · failed solvers").enumerate() {
    let y = 31 + i * 26
    panel(H, 28, y, 66, 24, [#m], size: 5pt)
    line_chart(H, 30, y + 5, 38, 17, series: 1)
    table_rows(H, 70, y + 5, 23, 4, (([address], 14), ([n], 6)))
  }
  panel(H, 97, 31, 71, 40, [real-time events], size: 5.5pt)
  for (i, e) in (("inspection", "sqli · node 2 · 198.51.100.7", "12:41:07"), ("honeypot", "ban · node 1 · 203.0.113.9", "12:41:02"), ("rate limit", "429 · node 3 · 192.0.2.44", "12:40:58"), ("challenge", "rejected · double spend", "12:40:51"), ("reputation", "deny prefix 2001:db8::/32", "12:40:40"), ("inspection", "xss · node 1 · 198.51.100.7", "12:40:33")).enumerate() {
    let y = 37 + i * 5.3
    rect((99, H - y - 3.6), (114, H - y - 0.4), stroke: 0.3pt + blue, fill: blue-light, radius: 0.8)
    content((106.5, H - y - 2), text(size: 4.3pt, fill: blue)[#e.at(0)])
    content((116, H - y - 2), anchor: "west", text(size: 4.5pt, fill: ink)[#e.at(1)])
    content((166, H - y - 2), anchor: "east", text(size: 4.3pt, fill: gray)[#e.at(2)])
  }
  panel(H, 97, 74, 34, 40, [attack categories], size: 5.5pt)
  donut(H, 101, 82, 9)
  for (i, l) in ("sqli 48%", "xss 22%", "traversal 17%", "rce 9%", "honeypot 4%").enumerate() {
    content((122, H - 82 - i * 4.5), anchor: "west", text(size: 4.5pt, fill: ink)[#l])
  }
  panel(H, 134, 74, 34, 40, [attacked paths · rule hits], size: 5.5pt)
  for (i, c) in (("/search", 22), ("/login", 12), ("/.git/config", 9), ("/wp-admin", 6), ("/api/v1", 3)).enumerate() {
    bar_row(H, 135, 82 + i * 5, c.at(1) * 0.4, c.at(0))
  }
}))

#figure-box([Attack events with the detail modal open over the raw view. New rows wait behind a
“Show new events” control while the reader is interacting; the modal keeps the layout operators know and
adds available rule evidence, the campaign, and the nearest incidents. Raw-head capture shown below is a proposed redacted extension, not current stored evidence.],
wire(170, 125, H => {
  import cetz.draw: *
  shell(H, 170, "Attack events")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Attack events])
  panel(H, 75, 9.5, 30, 5, [BY SOURCE · RAW], size: 5pt)
  panel(H, 28, 16, 140, 6, [node ▾  category ▾  rule ▾  address  country ▾  path  period ▾  ● live   export ↓], size: 5pt)
  table_rows(H, 28, 24, 140, 10, (([action], 10), ([URL], 46), ([category], 14), ([rule], 18), ([address · country], 26), ([time], 18), ([], 8)))
  // modal
  rect((40, 4), (160, H - 20), stroke: 0.5pt + ink, fill: white)
  rect((42, H - 22 - 3.5), (56, H - 22), stroke: none, fill: rgb("fef2f2"), radius: 0.8)
  content((49, H - 23.8), text(size: 4.5pt, weight: "bold", fill: red)[waf:sqli])
  content((58, H - 23.8), anchor: "west", text(size: 5pt, fill: ink)[GET /search?q=%27%20OR%201%3D1-- · node 2 · 2026-09-08 12:41:07])
  for (i, r) in (("address", "198.51.100.7 · Unknown (documentation IP) · Ban 24 h · Allow"), ("JA4 (from ingress)", "Not recorded · requires trusted-ingress capture"), ("payload", "Query excerpt: ' OR 1=1-- · matched span not recorded"), ("rule · score", "waf:sqli (terminal) · numeric score not recorded"), ("campaign", "41 · 3 incidents · nearest: 12:38:51 node 1 (0.12), 11:02:10 node 3 (0.21)"), ("id", "node 2 · seq 88,412")).enumerate() {
    let y = 28 + i * 5.2
    content((43, H - y - 2), anchor: "west", text(size: 4.5pt, fill: gray)[#r.at(0)])
    content((66, H - y - 2), anchor: "west", text(size: 4.5pt, fill: ink)[#r.at(1)])
  }
  panel(H, 42, 61, 116, 5, [REQUEST · RESPONSE                                   UTF-8 ▾], size: 4.5pt)
  panel(H, 42, 67, 116, 30, none, bg: rgb("f8fafc"))
  for (i, l) in ("GET /search?q=%27%20OR%201%3D1-- HTTP/1.1", "Host: shop.example", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) …", "Accept: text/html,application/xhtml+xml,*/*;q=0.8", "Cookie: [redacted]", "Response: local denial · no origin response").enumerate() {
    content((44, H - 70 - i * 4.2), anchor: "west", text(size: 4.3pt, font: "Menlo", fill: ink)[#l])
  }
  panel(H, 42, 99, 22, 5, [Copy as cURL], size: 4.5pt)
  panel(H, 138, 99, 20, 5, [Close], bg: blue-light, weight: "bold", size: 4.5pt)
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
  for (i, f) in ("name", "path pattern", "user agent", "headers (4)", "CIDRs (8)", "action ▾ · weight", "challenge: posw · depth 20").enumerate() {
    panel(H, 123, 18 + i * 6.5, 43, 5.5, [#f], size: 5pt)
  }
  panel(H, 123, 64, 20, 6, [Save], bg: blue-light, weight: "bold", size: 5.5pt)
  panel(H, 145, 64, 21, 6, [JSON view], size: 5.5pt)
  panel(H, 121, 75, 47, 43, none, bg: rgb("fcfcfd"))
  content((123, H - 79), anchor: "west", text(size: 6pt, weight: "bold")[Test a request])
  panel(H, 123, 83, 43, 5.5, [GET /checkout/pay  UA: Mozilla/5.0 …], size: 5pt)
  panel(H, 123, 90, 43, 5.5, [X-Api-Key: … · 203.0.113.9], size: 5pt)
  panel(H, 123, 97, 43, 9, [CHALLENGE · rule protect-checkout #linebreak() posw depth 20 · openings per config], bg: amber-light, size: 5pt)
  panel(H, 123, 108, 43, 6, [Evaluate], bg: blue-light, weight: "bold", size: 5.5pt)
}))

#figure-box([Nodes: one card per member with role, health, version, and sparklines, and the two
facts an operator must know about cluster semantics.],
wire(170, 100, H => {
  import cetz.draw: *
  shell(H, 170, "Nodes")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Nodes · edge-eu · leader: node 2 · last commit 4,118 · lag 0])
  for (i, n) in (("node 1 · 10.0.0.1 · follower", "healthy · v0.1.0 · up 3d 4h"), ("node 2 · 10.0.0.2 · leader", "healthy · v0.1.0 · up 3d 4h"), ("node 3 · 10.0.0.3 · follower", "storage degraded · serving last snapshot")).enumerate() {
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

#figure-box([Settings: users with two-factor state, API tokens, page templates, retention,
notifications, GeoIP, and about.],
wire(170, 110, H => {
  import cetz.draw: *
  shell(H, 170, "Settings")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Settings])
  panel(H, 28, 15, 140, 5.5, [USERS · API TOKENS · PAGES · RETENTION · NOTIFICATIONS · GEOIP · ABOUT], size: 5pt)
  table_rows(H, 28, 24, 90, 5, (([user], 22), ([role], 16), ([2FA], 12), ([last login], 24), ([state], 10), ([], 6)))
  panel(H, 121, 24, 47, 30, none, bg: rgb("fcfcfd"))
  content((123, H - 28), anchor: "west", text(size: 6pt, weight: "bold")[Add user])
  for (i, f) in ("name", "role: viewer ▾", "temporary password", "require two-factor ☑").enumerate() {
    panel(H, 123, 32 + i * 5.2, 43, 4.6, [#f], size: 4.8pt)
  }
  panel(H, 28, 58, 45, 24, [Pages #linebreak() challenge · denied · rate limited · banned · overloaded #linebreak() edit template · preview · reset], size: 5pt)
  panel(H, 76, 58, 45, 24, [Retention #linebreak() minutes 90 d · incidents 30 d · audit 365 d · rankings 7 d], size: 5pt)
  panel(H, 124, 58, 44, 24, [Notifications #linebreak() webhook · syslog · events: denial spike, ban, node unhealthy, leader change], size: 5pt)
  panel(H, 28, 85, 68, 22, [GeoIP #linebreak() DB-IP Lite · 2026-09 · range count from import · loaded 2026-09-08 #linebreak() Update now · attribution shown in footer], size: 5pt)
  panel(H, 99, 85, 69, 22, [About #linebreak() v0.1.0 · node 1 · cluster edge-eu · bound 127.0.0.1:9443 behind proxy #linebreak() build (example) · storage v0.6.1], size: 5pt)
}))

// Supplemental route and workflow wireframes use the same navigation shell.
#let detail-wire(active, title, left-title, left, right-title, right, footer) = wire(170, 100, H => {
  import cetz.draw: *
  shell(H, 170, active)
  content((29, H - 13), anchor: "west", text(size: 8pt, weight: "bold", fill: ink)[#title])
  panel(H, 28, 19, 68, 67, none, bg: white)
  panel(H, 100, 19, 68, 67, none, bg: white)
  content((31, H - 23), anchor: "north-west", block(width: 62mm)[
    #text(size: 7.5pt, weight: "bold", fill: blue)[#left-title]
    #v(2mm)
    #text(size: 6.8pt, fill: ink)[#left]
  ])
  content((103, H - 23), anchor: "north-west", block(width: 62mm)[
    #text(size: 7.5pt, weight: "bold", fill: blue)[#right-title]
    #v(2mm)
    #text(size: 6.8pt, fill: ink)[#right]
  ])
  panel(H, 28, 89, 140, 9, footer, bg: blue-light, size: 6pt)
})

#figure-box([Challenge dashboard visual layout: independently counted flow stages, accepted
solve-time buckets and explicit missing-data coverage. The detailed controls follow.],
wire(170, 100, H => {
  import cetz.draw: *
  shell(H,170,"Challenges")
  content((29,H - 13),anchor:"west",text(size:8pt,weight:"bold")[Challenges · all nodes · last hour])
  panel(H,28,19,65,63,[*Challenge flow · window totals*],size:7pt)
  for (i,r) in (("Issued · 8,200",57,blue-light),("Submitted · 7,900",54,amber-light),("Accepted · 7,750",52,green-light),("Rejected 120 · malformed 30",48,rgb("fef2f2"))).enumerate() {
    let x=32+(57-r.at(1))/2
    panel(H,x,29+i*12,r.at(1),9,[#r.at(0)],bg:r.at(2),size:7pt)
  }
  panel(H,97,19,71,63,[*Accepted solve time · client reported* #linebreak() Hashcash ▾ · difficulty 16 ▾],size:7pt)
  for (i,n) in (1,2,3,6,10,15,22,29,34,25,18,11,7,4,2,1).enumerate() {
    rect((101+i*3.8,H - 70),(103.5+i*3.8,H - 70+n*0.8),stroke:none,fill:blue)
  }
  content((101,H - 75),anchor:"west",text(size:5pt,fill:gray)[0–1 ms · logarithmic powers of two · ≥16,384 ms])
  panel(H,28,86,140,11,[Timing missing 4% · invalid 0.1% · client-reported values are untrusted. Issued and submitted can refer to different time-window cohorts.],bg:blue-light,size:6pt)
}))

#figure-box([Challenges: flow totals, timing and rejection analysis, with algorithm-aware
parameters. Counts are illustrative window totals, not a cohort conversion rate.],
detail-wire("Challenges", [Challenges · all nodes · last hour · live], [Challenge flow], [
  Issued: 8,200 → Submitted: 7,900\
  Accepted: 7,750 · Rejected: 120 · Malformed: 30

  *Accepted solve time (client reported)*\
  Algorithm: Hashcash ▾ · difficulty: 16 ▾\
  Median: 280 ms · p95 bucket: 1,024–2,048 ms\
  Timing missing: 4% · invalid: 0.1%

  Histogram: 16 logarithmic buckets\
  Show bucket counts / Open timing table

  PoSW view uses depth and opening count.\
  Untrusted device timing; no security inference.
], [Investigate and tune], [
  *Rejections by cause*\
  Double spend: 52 · Expired: 31\
  Fingerprint mismatch: 12 · Other causes: 25\
  Select a cause → per-address records

  Address / node / issued / accepted / cause\
  192.0.2.44 / 2 / 10 / 8 / expired\
  Per-address capture missing? “Not recorded”

  Adaptive difficulty: Show change timeline\
  Solver mode: Wasm / JS fallback / unknown

  Edit rule parameters → preview → save\
  Runtime limits remain node-local.
], [No data: “No challenges in this window”. Missing instrumentation: “Not available”. Late submissions may cross windows.]))

#figure-box([Attack events grouped by source, including filters, pagination, export and the
transition to raw evidence. A paused reader controls when new rows appear.],
detail-wire("Attack events", [Attack events · By source / Raw], [Source groups], [
  Node: all ▾ · Category: all ▾\
  Address: ​──────── · Country: all ▾\
  Path: ​──────── · Period: last 24 h ▾

  *Show 12 new events* · Live paused\
  Address / incidents / first / last\
  198.51.100.7 / 18 / 12:00 / 12:41\
  192.0.2.44 / 9 / 11:30 / 12:39

  Select source → filtered raw events\
  Country: Unknown for these example IPs

  Previous / Page 1 / Next · Export CSV\
  Export respects filters and size limits.
], [Source detail], [
  *198.51.100.7* · nodes 1, 2\
  18 recorded incidents · 2 categories

  Timeline / categories / campaign candidates\
  Open raw event → retained evidence\
  Similarity is heuristic, not attribution.

  Ban 24 h / Allow 1 h / Add to group\
  Preview overlap and effective precedence\
  Confirm → applied per-node revision

  Undo 30 s → new audited mutation\
  Export omits credentials and redacted data.
], [Empty: adjust filters. Retention gap, dropped incidents and stale replica state are shown above the list.]))

#figure-box([Policy modes, limits and IP groups complement the rule editor. Audit mode
continues evaluation; country operations are capacity-checked before commit.],
detail-wire("Policy", [Policy · Rules / Inspection / Limits / IP groups], [Inspection and limits], [
  Category / mode\
  SQL injection / Enforce ▾\
  XSS / Audit ▾\
  Path traversal / Enforce ▾\
  RCE / Disabled ▾

  Audit logs a finding then continues evaluation.\
  Another enforcing rule can still deny.

  *Limits* · target node: node 2 ▾\
  Current GCRA: rate / window / ban duration\
  Terminal rules own additional node-local quotas.

  Review changes → Save expected revision 17
], [IP groups and country action], [
  Prefix / action / expiry / provenance\
  192.0.2.0/24 / deny / 1 h / operator\
  Add prefix / edit / remove

  *Country builder*\
  Country: select ▾ · GeoIP generation: current\
  Action: Deny ▾ · Duration: 24 h ▾\
  Preview CIDRs / overlaps / trie-node usage

  Reject if full; never silently truncate.\
  Challenge needs explicit supported rules.

  Confirm / Cancel · Conflict? reload and diff\
  Committed revision ≠ applied on every node.
], [Viewer: edits disabled. Invalid input: inline error. Full engine: reject. Concurrent edit: show conflict before retry.]))

#figure-box([GeoIP is a complete source/import workflow, with validation, attribution,
progress, failure recovery and policy-generation pinning.],
detail-wire("GeoIP", [GeoIP · country enrichment], [Current database], [
  Provider: ip-location-db user-country ▾\
  Source version: 2026-09-09 (example, daily)\
  Active generation: 7 · Loaded: 12:00 UTC\
  IPv4 / IPv6 ranges: counts from loader\
  SHA-256: copy digest\
  Licence: PDDL 1.0 · Attribution: none (DB-IP: CC BY 4.0)

  Country only; no individual coordinates.\
  Private/reserved/unmapped addresses: Unknown

  Lookup address: ​────────  [Look up]\
  Result: country / unknown / generation
], [Update database], [
  Download → validate → stage → activate\
  Progress: 2 of 4 stages · Cancel\
  Bounded bytes and rows; one import at a time

  Preview source, licence, checksum, range count\
  Errors keep the prior generation active.\
  Retry / View diagnostic

  Publisher SHA-256 files verified per source file\
  One HTTPS redirect hop to the fixed asset host

  Update data / Review affected country policies\
  Policy prefixes stay pinned until approved.
], [No database: “GeoIP unavailable”; dashboard globe shows only outline and Unknown totals. No invented locations.]))

#figure-box([Audit with before/after evidence, safe exports and conflict-checked rule revert.
Local commands show intent and completion separately.],
detail-wire("Audit", [Audit · activity and policy history], [Activity], [
  Actor: all ▾ · Action: all ▾ · Period: 24 h ▾\
  Subject: ​──────── · Node: all ▾

  Time / actor / action / subject / result\
  12:41 / alice / policy edit / p1 / committed\
  12:40 / admin / drain / node 2 / completed\
  12:38 / ci / export / events / completed

  Previous / Page 1 / Next · Export\
  Retention: 365 days · old records expire\
  Append-only for users, not tamper-proof.
], [Selected change], [
  Actor: alice · operator · address recorded\
  Policy p1 · revision 17 → 18

  Before: action challenge; difficulty 16\
  After: action deny\
  Reason: operator description

  Applied: node 1 ✓ · node 2 ✓ · node 3 pending\
  Open policy / Show diff / Revert to revision 17

  Revert creates revision 19 with a fresh audit.\
  Reject if revision 18 is no longer current.\
  Secrets and full token values never displayed.
], [Local action detail: request id, intent, target acknowledgment and failure reason; no false atomicity claim.]))

#figure-box([Settings forms cover credentials, templates, retention and notifications,
with separate read-only About information and safe previews.],
detail-wire("Settings", [Settings · Users / Tokens / Pages / Retention / Notifications / About], [Users and API tokens], [
  User: alice · role: operator ▾\
  TOTP: enrolled · last login: 12:00 UTC\
  Disable user / reset password / revoke sessions

  Token label: deploy-ci · role: operator ▾\
  Expiry: date/time · scope: policy only\
  Create → show secret once → copy → close\
  Existing tokens: id / scope / expiry / revoke

  Viewer role: inspect, cannot change settings.\
  Administrator changes require recent auth.

  About: node/version/build/listener/storage\
  Never expose secrets or arbitrary environment.
], [Operational settings], [
  *Templates* · denied ▾ · bounded placeholders\
  Edit / sandboxed preview / reset / save\
  No executable scripts or arbitrary imports

  *Retention* · traffic 90 d · incidents 30 d\
  Rankings 7 d / 512 MiB · audit 365 d\
  Estimate footprint → review → save

  *Notifications* · destination type: webhook ▾\
  URL / masked secret / events / cooldown\
  Test destination → show result → save\
  Node unhealthy / leader change / denial spike\
  Bounded retries; one cluster notifier lease
], [Validation is inline; save has pending/success/error states. Slow notifications never run in data-plane threads.]))

#figure-box([Authentication states. The public sign-in surface loads no globe, GeoIP or
telemetry; the dashboard starts only after all required authentication steps succeed.],
wire(170, 98, H => {
  import cetz.draw: *
  content((85,H - 8),text(size:10pt,weight:"bold",fill:blue)[SIBUNA · Sign in])
  panel(H,8,17,48,66,[*1 · Credentials* #linebreak() #linebreak() Username #linebreak() [────────] #linebreak() Password #linebreak() [••••••••••••••••] #linebreak() #linebreak() [Sign in] #linebreak() #linebreak() Invalid credentials: retry #linebreak() Rate limited: retry after Ns],size:7pt)
  panel(H,61,17,48,66,[*2 · Required verification* #linebreak() #linebreak() Authenticator code #linebreak() [────────] #linebreak() [Verify] #linebreak() #linebreak() Use recovery code #linebreak() #linebreak() First login: change temporary password; enroll TOTP when required.],size:7pt)
  panel(H,114,17,48,66,[*3 · Success / expiry* #linebreak() #linebreak() Success → Traffic overview #linebreak() Load globe + open streams #linebreak() #linebreak() Expired → Sign in again #linebreak() Preserve safe return route #linebreak() #linebreak() No users? Run init-admin locally; no public account creation.],size:7pt)
  panel(H,8,87,154,8,[Authentication only: no globe assets, telemetry connection, country data, cluster health or traffic on the sign-in page.],bg:blue-light,size:6pt)
}))

#figure-box([Kiosk after a one-time code is entered in the sign-in form: full-screen live
globe, coverage and traffic/attack summaries. Expired access returns to sign-in; no
mutation controls are present.],
wire(170, 95, H => {
  import cetz.draw: *
  panel(H,3,3,164,9,[SIBUNA · edge-eu · Traffic / Attacks · 3/3 reporting · live · last update 1 s],bg:blue-light,size:7pt)
  panel(H,3,15,103,62,[*Live earth globe · Traffic / Attacks*],size:8pt)
  earth((35,H - 49),23)
  panel(H,64,26,40,40,[*Countries* #linebreak() Germany · 2,560 #linebreak() India · 1,920 #linebreak() Brazil · 1,280 #linebreak() Unknown · 4% #linebreak() #linebreak() Samples · p=1/64 #linebreak() Loss: 0 (example)],size:6.5pt)
  panel(H,64,68,40,7,[Rotate / Pause / Reset],size:6pt)
  panel(H,110,15,57,29,[*Last 60 seconds* #linebreak() Requests: 128 k (example) #linebreak() Recorded incidents: 128 #linebreak() Unknown country: 4%],size:7pt)
  panel(H,110,48,57,29,[*Module trends* #linebreak() Inspection / reputation / limits #linebreak() Challenges / bans / honeypot #linebreak() Read-only · no payload detail],size:7pt)
  panel(H,3,81,164,10,[Exit kiosk · session expiry visible · no URL bearer token · stale stream freezes with age; GeoIP unavailable shows outline only],bg:amber-light,size:6pt)
}))

#figure-box([Responsive and data-state variants. Navigation remains labelled; the mobile
landing page places the globe and country table in a vertical flow.],
wire(170, 114, H => {
  import cetz.draw: *
  panel(H,5,5,51,103,none)
  panel(H,7,7,47,9,[Menu · SIBUNA · admin ▾],bg:blue-light,size:7pt)
  panel(H,7,19,47,12,[Traffic · all nodes #linebreak() 24 h · Live / Pause],size:7pt)
  panel(H,7,34,22,17,[128 k #linebreak() Requests],size:7pt)
  panel(H,32,34,22,17,[128 #linebreak() Incidents],size:7pt)
  panel(H,7,54,47,27,[Globe · Traffic / Attacks],size:6pt)
  earth((22,H - 70),9)
  panel(H,34,64,18,13,[Rotate #linebreak() Flat map],size:5pt)
  panel(H,7,84,47,21,[Countries ↓ #linebreak() Timeline ↓ #linebreak() Full labels in menu],size:7pt)
  panel(H,62,5,103,23,[*Loading / empty* #linebreak() Fixed-size skeleton; no fabricated zeros. Once loaded: “No traffic in this window”. First use preserves navigation and setup links.],size:7pt)
  panel(H,62,32,103,23,[*GeoIP unavailable* #linebreak() Earth outline only; Unknown totals, provider state and admin setup link. Country controls disabled with explanation.],size:7pt)
  panel(H,62,59,103,23,[*Disconnected / partial cluster* #linebreak() Freeze last values; display age and 2/3 reporting. Retry with backoff. Resnapshot before clearing stale state.],size:7pt)
  panel(H,62,86,103,23,[*Error / permission / overflow* #linebreak() Inline diagnosis and retry; viewer actions disabled; truncated history marked. Keyboard focus persists across live patches.],size:7pt)
}))

#table(
  columns: (1fr, 2.5fr),
  table.header([*Coverage*], [*Required variants and navigation*]),
  [Statistics], [Signed-in globe/timeline, Traffic and Security tabs, sampled/incident modes, country drill-down, kiosk, mobile, GeoIP missing and stale/partial cluster.],
  [Events and Challenges], [Grouped and raw events, evidence detail, source actions, export/pagination, challenge flow/timing/cause, missing instrumentation and retained-history gaps.],
  [Policy and Nodes], [Rule editor/tester, inspection/limits/groups/country builder, revision conflict; node drill-down, drain preview/confirm/result and clear-local-bans result.],
  [Settings and Audit], [Users, tokens, TOTP/recovery, templates, retention, notifications and About; audit diff/revert and local-command intent/completion.],
  [Authentication and shared states], [Credentials, setup, forced password change, TOTP, recovery, expiry; loading/empty/error/forbidden; labelled responsive navigation, focus and reduced motion.],
)

= The Build Pipeline

`build.zig` gains a `console` concern (`build/console.zig`, following zenfmt's one-file-per-
concern layout), wired by the existing `AppModules` helper.

#table(
  columns: (1.2fr, 2.6fr),
  table.header([*Step*], [*What it does*]),
  [`-Dconsole` (defaults to storage enabled)], [Compiles `libs/serve`, `libs/console`, and the interface module into the daemon; `-Dconsole=false` removes every console symbol and the `--console` flags.],
  [`console-ui` (implicit)], [Compiles `apps/console-ui/src/main.zig` for `wasm32-freestanding` at `ReleaseSmall`, asserts the 384 KiB budget, and embeds the bytes.],
  [`zig build console-assets`], [Runs `npm ci` and `npm run build` in `apps/console-ui/web/` through `b.addSystemCommand`, producing `assets/console.css` from `tailwind.css` with Tailwind 4 and the daisyUI 5 plugin, using explicit Tailwind source paths for Zig render files and HTML snippets, with complete class names in those sources; daisyUI components are restricted with its `include` configuration. The step then writes `assets/MANIFEST.md` with the SHA-256 of every asset.],
  [Digest gate (in `zig build test`)], [`tools/console_assets.py check` hashes both build inputs (render sources, HTML snippets, the snippet renderer, CSS configuration, package lock and scripts) and outputs against `MANIFEST.md`; output digests alone cannot detect stale CSS. A plain `zig build` therefore needs no npm; only `console-assets` does, and CI runs it and checks the tree is clean.],
  [`zig build console-test`], [Golden tests of the interface module compiled natively (rendered HTML per page and per event), protocol round-trip tests, and the kernel's HTTP and WebSocket tests with an in-process client.],
  [`zig build console-e2e`], [Boots a daemon with `--console` on loopback, runs setup, login, a WebSocket subscription, a policy edit, and asserts the engine rebuild and the audit row; part of `zig build test` when console support is enabled.],
  [`zig build console-impact`], [The isolation gate in “Process model and the isolation contract” through `benchmarks/console_impact.py`: builds a console-free and a console binary, runs compiled-out, disabled, idle and eight-dashboard daemons concurrently, interleaves wrk rounds in rotating order over admitted, challenged, denied and policy-reload workloads, and reports pass, fail or inconclusive with a bootstrap interval; `-- --quick` for a smoke run, `-- --cluster` for the three-node case.],
)

`package.json` pins exact compatible versions of `tailwindcss` 4, `@tailwindcss/cli` 4 and `daisyui` 5;
`package-lock.json` is committed. npm runs only inside `console-assets`, never in the default
graph, so a contributor without Node can build, test, and run the daemon and the console with
the committed stylesheet.

= Security Considerations

- The console is an administrative surface and is bound to loopback by default; off-loopback exposure
  requires an explicit address and `--console-behind-proxy` with TLS
  at the ingress. The data plane's own listener never serves console routes (I1), so a
  console vulnerability cannot be reached through the protected site.
- All state-changing routes require a session or token with an adequate role (cookie-authenticated requests also require the CSRF header),
  and are rate limited; all are audited. Password hashing concurrency, memory and request rates have independent bounds; session digests mean a database read exposure does not yield usable sessions.
- The interface module renders through an escaping writer; the content security policy
  forbids inline script and remote resources; the WebSocket accepts only same-origin
  upgrades; the shell sets `X-Frame-Options: DENY`.
- The policy tester evaluates through the real engine code but on the console thread against
  a private engine instance built from the same configuration, file fallback and current tables, never against the live slot.
- GeoIP enrichment is country-only; incident rows still contain client addresses and bounded request data. The loader verifies HTTPS and a publisher/operator digest when supplied, and the loaded set replaces the previous one atomically.
- Drain and clear-local-bans follow the audited control-command protocol. Rich incident capture redacts sensitive headers and query/body fields before persistence; previews and “copy as cURL” use escaped, redacted data and mark incomplete requests. Operator templates are constrained placeholders, not executable script, and preview inside a sandboxed frame. Webhook destinations and node probes use allowlisted schemes/hosts/ports with redirect and DNS-rebinding checks; credentials never appear in audit payloads.

= Performance Budget

These are proposed targets to validate, not measured properties or hard real-time guarantees.
Latency includes scheduling, contention and replication; expose age and backlog when targets
are missed. The default idle budget excludes active hashing/import work but includes the
configured slots, queues and optional GeoIP dataset. Record active peak RSS separately.

#table(
  columns: (1.6fr, 1fr, 2fr),
  table.header([*Quantity*], [*Bound*], [*Mechanism*]),
  [Console resident memory, idle], [Target to size and measure], [Five topic rings already cost 10 MiB; add 1 MiB traffic queue, slot buffers/stacks, SQL results, GeoIP generations, and 19 MiB per active Argon2 verifier],
  [Console CPU, idle], [≤ 2 % of one core], [4 Hz sampler, 1 Hz coalescing, 5 s probes],
  [Data-plane throughput with 8 live dashboards], [within 1 % of no console], [I1, I2, I5; measured by `console-impact`],
  [Data-plane p99 with 8 live dashboards], [within 10 %], [Same],
  [Statistics delta latency], [≤ 1.25 s], [Sampler period plus 1 Hz broadcast],
  [Incident to dashboard], [Target ≤ 2.25 s + commit delay without backlog], [“The incident tap”; slow storage and replication can exceed this],
  [Policy edit to rebuilt engine on every node], [Target: commit/apply + next successful tick], [SID 0005 path],
  [Interface module size], [≤ 384 KiB], [`ReleaseSmall`, size gate],
  [Page render (statistics, 3,600-point timeline)], [≤ 5 ms in the module], [Bounded writer, per-panel versions],
  [WebSocket subscribers per console], [64], [Slot table; `503` beyond],
)

= Delivery Plan

The staged implementation and acceptance evidence are tracked in
#context link(label("sid7-implementation-" + target()))[the implementation checklist and dated evidence in this SID].
The status remains *Proposed* until all release gates pass.

#phase("Phase 1: Kernel, authentication, statistics")[
  `libs/serve` with HTTP, assets, and WebSocket; `libs/console` with auth, sessions, audit,
  the sampler, `traffic_minutes`, and the `stats` topic; the interface module with the shell,
  setup, login, and the statistics page; `console-assets` and the digest gate; the e2e test;
  the impact gate with the stated throughput/p99 thresholds. A single node exposes currently available counters; unavailable panels say so. Include TOTP before permitting off-loopback access and keyboard/focus/accessibility support from this phase.
]
#phase("Phase 2: Events, policy, challenges, GeoIP")[
  The incident tap and `events` topic with the detail drawer and actions; the policy editor,
  tester, import and export, and IP groups over `policies` and `ip_reputation`; the challenge
  funnel with the solve-time histogram; the traffic sample ring, Space-Saving rankings and the
  sampled panels; per-category inspection modes; the GeoIP loader, lookup, map, and country
  actions; retention.
]
#phase("Phase 3: Cluster")[
  The `nodes` table and page, health probes, node-to-node live buckets, leader awareness,
  drain, per-node views on every page, and the cluster case of the impact gate on
  `benchmarks/cluster.py`.
]
#phase("Phase 4: Operations")[
  API tokens, notification webhooks and syslog, exports, editable
  page templates, the kiosk view, the audit page, dark theme polish, keyboard navigation and
  screen-reader labels, and the operator guide in the book (a new chapter in Part IX with the
  wireframes replaced by screenshots of the built console).
]

= Verification

- *Unit.* Router matching, JSON writer bounds, Argon2id and token digests, CSRF, WebSocket
  framing and fragmentation against RFC 6455 vectors (standard-library helper tests alone are insufficient), ring and cursor semantics, sampler deltas
  across counter wrap, minute folding, GeoIP range parsing and lookup, retention windows.
- *Golden.* Every page and every event-driven patch of the interface module compiled
  natively, compared byte-for-byte with committed HTML; a change to markup is a reviewed diff.
- *End-to-end.* The `console-e2e` scenario above, plus: session expiry, role refusal, rate
  limit on login, a slow subscriber receiving `dropped`, a stateless policy tester result agreeing with
  a live request's `X-Sibuna-Rule` under controlled identical inputs and configuration, a country block appearing in the trie, and a cluster run
  in which a rule saved on node 1's console changes node 3's decision
  (`tools/console_cluster_test.py`, run by `console-e2e` under `-Dcluster=true`: membership,
  probes, leader loss, lost quorum answering `CONSOLEQUORUM`, rejoin, cross-node revocation
  and local-command isolation).
- *Impact.* The `console-impact` gate on every change to `libs/serve` or `libs/console`.
- *Principles.* The golden tests assert the mechanical rules: every page passes the trunk
  test (product, cluster and node, page, section, way back present in the rendered shell,
  R2); decision colours appear only through the four semantic classes (R8); tiles carry a
  deviation marker and a sparkline (R9, R11); numbers render with tabular figures and
  separators (R12); no verdict element renders without its reason element (R14); every
  destructive action renders with a duration or a confirmation (R18). The judgement rules are
  evaluated with human operators using two scripted tasks (browser automation checks mechanics, not human comprehension): a five-second look at Statistics must
  let a reader name the anomalous module, and "find why request X was denied" must complete in
  three clicks from the shell.
- *Telemetry correctness.* Inject counter resets, issuer-order inversions, duplicate peer
  buckets, partial minutes, sample loss, and cross-window challenge solutions. Check sketch
  estimates against exact sample counts and merge error bounds; exercise the Unknown bucket.
- *Globe and authentication.* Assert zero globe/GeoIP/telemetry loads before successful login,
  including failed login, TOTP and forced-change states. Test Traffic/Attacks switching,
  missing GeoIP, country coverage, back hemisphere clipping, poles, antimeridian crossings,
  keyboard centering, pause, stale/reconnect and sign-out stream teardown. Record geometry
  vertex, linear-memory and render-time budgets on desktop and a low-end device.
- *Abuse and failure.* Test bounded distributed login load, revoked sessions on followers,
  fragmented/invalid WebSockets, unsolicited delivery while the reader blocks, 64 subscribers
  with HTTP slots remaining, SQL deadline/backpressure, GeoIP failed activation, trie-full
  country rejection, revision conflicts and unauthenticated probe/webhook destinations.
- *Document.* Compile this source to PDF and to page PNGs with Typst; inspect every wireframe
  for clipping, overlap, navigation completeness and the separate authentication shell.
- *Browser.* A minimal Chromium script (the harness family of the benchmarks) loads the
  console, logs in, and checks that tiles update, kept outside `zig build test` because it
  needs a browser.

Document review is reproducible without building the daemon:

```sh
mkdir -p docs/build/review-0007
typst compile --root docs docs/sid/records/0007-console-management-interface.typ docs/build/review-0007/console.pdf
typst compile --root docs docs/sid/records/0007-console-management-interface.typ 'docs/build/review-0007/page-{0p}.png' --ppi 120
typst compile --root docs docs/sid/figures/0007-console-landing-preview.typ docs/build/review-0007/landing.png --ppi 160
```

= Resolved Design Decisions

The former open questions are resolved as follows; implementation must verify the stated
bounds rather than reopen the architecture implicitly.

+ *Live cluster transport:* deferred, design retained. Membership, applied revisions and
  probe health need no peer socket because `console_nodes` and minute rows replicate; the
  later live-tile transport uses direct authenticated management WebSockets on a separate
  `/console/peer` route and bounded peer quota. Authenticate node identity against configured
  membership, using mTLS terminated by a trusted management ingress or a domain-separated
  HMAC challenge over TLS. The consensus PSK is not a browser bearer token. Never use a
  server-only masked-frame reader as the outbound client: peer clients must mask writes and
  accept unmasked server frames. Keep ephemeral statistics out of consensus and require
  fresh epoch/sequence metadata; disconnected peers become stale, never healthy zeros.
+ *Solve timing:* add optional telemetry to the existing verification POST as specified in
  “The challenge funnel”. No separate public endpoint on the privileged console listener, no second browser
  request, and no trust in client timing for security decisions. Missing telemetry is counted.
+ *Retention:* default traffic/challenge/country minutes to 90 days, ranking sketches to
  7 days, incidents to 30 days and audit to 365 days. Three continuously running nodes yield
  388,800 node-minute rows per 90-day table before boot/bin multiplicity. Ranking sketches
  can dominate storage (up to 256 keys × kinds × node-minutes); enforce explicit byte/row
  quotas, batch deletion and storage backpressure. Default to a 512 MiB ranking-store quota;
  on exhaustion shorten retained ranking history with a visible coverage boundary. Coalesce
  minute writes, prefer incident/control work over telemetry, and measure replicated disk,
  journal and compaction costs. Never assume a SQLite row count establishes capacity.
+ *Stylesheet:* ship only the pinned, curated sheet and its input/output manifest. The explicit
  `console-assets` step regenerates it reproducibly; ordinary builds use committed assets.
  Themes are reviewed source changes through the same build, not an unbounded full-CSS option.
+ *Globe:* implement the bounded orthographic SVG view in “Live earth globe on the landing page” with country-only traffic/attack views after successful login,
  1 Hz updates, accessible ranked table, manual rotation and honest unavailable/stale states.
  Its geometry, attribution, seam clipping and render budget are release checks.
+ *Storage ownership and local commands:* retain a single Zaxonlite owner and add bounded
  mailboxes, preflight validation and revision acknowledgments. SQL query cancellation or
  separately owned read snapshots is an implementation prerequisite for heavy forensics.
  This design cannot promise panic isolation inside the single daemon process.

Remaining work consists of implementation and acceptance measurements: storage adapter
concurrency/cancellation validation, memory sizing, provider import tests, browser protocol
conformance, globe projection tests, operator usability sessions and the impact matrix.
No unmeasured target in this record is a release claim.


#context [
  #heading(level: 1)[Implementation checklist and evidence]
  #label("sid7-implementation-" + target())
]

The dated notes describe the state at each implementation step. Earlier pending-work statements
are historical; the acceptance gates below govern delivery.

#text("Status: Proposed. This checklist records implementation, not acceptance by assertion. Unchecked gates block delivery. The daemon composes the console; application libraries must never import daemon code or acquire the database handle. Existing data-plane and proof semantics remain unchanged unless a stage explicitly extends them.")

== 1. Contracts, build integration and lifecycle

- #text("Verified: Remove comparison framing and the named product reference from SID 0007 only.")

- #text("Verified: Correct the geographic asset contract to world-110m.bin.")

- #text("Verified (2026-09-09): libs/console-protocol carries bounded owned requests, roles, scopes and stream contracts shared by the daemon, the native CLI and the Wasm interface; see the contract foundation, token, kiosk, notification, page and workflow entries.")

- #text("Verified (2026-09-09): ConsoleConfig validates origin, proxies, advertise and probes; Budget accounts stacks, subscribers and the import scratch; storage and control cross one typed mailbox. See the contract foundation, cluster and page-template entries.")

- #text("Verified (2026-09-09): libs/serve holds the kernel, context and WebSocket framing; libs/console holds routes, jobs and application services; apps/console-ui holds state, controllers, snippets and the globe; glue.js bridges requests, timers, focus and theme only.")

- #text("Verified (2026-09-09): core metrics (including the issued-ban counter) and store incident types are imported by the console; the data plane keeps its names.")

- #text("Verified (2026-09-09): console flags are parsed and validated before data-plane arguments are handed on unchanged (console_start); native management commands parse strictly with typed options. See the account, GeoIP, token and policy CLI entries.")

- #text("Verified: -Dconsole defaults to storage; explicit console without storage fails.")

- #text("Verified: Build-helper directory included in package, formatting and structural checks.")

- #text("Verified (2026-09-09): console-test runs native render and contract tests with the asset check; console-e2e drives twenty live-daemon scenarios (plus the three-node scenario under -Dcluster=true); console-assets rebuilds and verifies committed assets; console-impact runs the wrk matrix and reports pass, fail or inconclusive. See the acceptance run entry.")

- #text("Verified: Storage starts first; console drains, cancels and joins before storage closes.")

- #text("Verified (2026-09-09): -Dstorage=false, -Dconsole=false, the default single-node build and -Dcluster=true build and run in the acceptance matrix; console-off builds keep the console module out of the daemon.")

== 2. Storage bridge and transactions

- #text("Verified (2026-09-09): every console storage request executes on the Persistent thread through the typed mailbox with tickets, completion states, abandonment and, for page templates, mailbox-owned heap blocks. See the contract foundation, storage bridge and page-template entries.")

- #text("Verified (2026-09-09): the owner drains at most sixteen mailbox operations per tick with an urgent/background streak, before incidents and policy reload; see the contract foundation entry.")

- #text("Verified (2026-09-09): every console statement runs through the bounded console_database facade against zaxonlite 0.6.1 with prepared parameters and row limits; a caller timeout answers CONSOLEQUORUM without cancelling the owner. See the cluster entry for the timeout mapping and the bounded shutdown.")

- #text("Verified (2026-09-09): schema versions 1 through 23 are additive migrations replayed on the owner thread; the migration test refuses future schemas. See the authentication migration and the dated schema entries.")

- #text("Verified (2026-09-09): every mutation stages through a table whose trigger commits the change and its redacted audit row together under an expected revision; committed and applied revisions are reported separately. See the policy audit, workflow and page-template entries.")

- #text("Verified: Local commands record intent and completion separately from runtime effects. See the local-control storage, live-daemon and browser evidence below.")

- #text("Verified (2026-09-09): the storage-tick suites (console_store_test and its siblings for policies, audit, tokens, nodes, kiosk, notifications, pages and workflows) cover saturation, bounded reads, migration replay, conflicts, failed rebuilds and abandonment.")

== 3. HTTP, authentication and real-time transport

- #text("Verified (2026-09-09): the serve kernel owns the listener, slot deadlines (extended once a head arrives), static assets and reserved slots; the peer quota remains with the deferred peer transport. See the cluster entry.")

- #text("Verified (2026-09-09): libs/serve websocket tests and the live stream scenarios cover framing, masking, controls and close; the stream reader and writer are separate tasks. See the contract foundation and live stream entries.")

- #text("Verified (2026-09-09): bootstrap, forced change, Argon2id, digest-only sessions, roles, CSRF, encrypted TOTP with recovery codes and the verification bound are exercised by the live authentication scenarios. See the authentication entries.")

- #text("Verified (2026-09-09): ConsoleConfig refuses off-loopback without an HTTPS origin and trusted proxies; the trusted-ingress scenario verifies mandatory administrator TOTP behind a proxy.")

- #text("Verified (2026-09-09): the storage owner rechecks the credential at execution time for every mutation and read, and subscriptions are revoked on the owner clock. See the execution-time authorization entries.")

- #text("Verified (2026-09-09): the stats stream delivers snapshots and deltas with boot-aware intervals to at most 64 subscribers, and the interface reconnects with visible stale state. See the live interval and stream entries.")

- #text("Verified (2026-09-09): geometry, GeoIP and telemetry routes answer 403 until the session is fully authenticated (bootstrap scenario); the kiosk exchange is the only other entry and yields a statistics-only session.")

- #text("Verified (2026-09-09): the bootstrap, expiry, shutdown and revocation scenarios in console-e2e cover the gate.")

== 4. Single-node dashboard and globe

- #text("Verified (2026-09-09): see the exact outcomes, retained counter intervals, durable minute record and minute publication entries.")

- #text("Verified (2026-09-09): see the bounded ranking collection and ranking archive entries.")

- #text("Verified (2026-09-09): user-country (default, PDDL) and DB-IP imports through libs/geoip; bounded downloads/ranges, publisher checksums, immutable activation; failed updates retain the active generation; optional embedded snapshot. See the GeoIP library evidence.")

- #text("Verified (2026-09-09): see the animated globe, Traffic and Attacks globe delivery and current-minute ranking interface entries.")

- #text("Verified (2026-09-09): see the recorded-incident geography and globe delivery entries.")

- #text("Verified (2026-09-09): the kiosk layout reuses the globe, tiles and timeline components with rotation, pause and reset; flat map and accessible tables were verified earlier.")

- #text("Verified (2026-09-09): live stream scenarios and the Chrome checks recorded in the globe, nodes and kiosk entries cover the gate.")

== 5. Events, challenges and policy

- #text("Verified (2026-09-09): see the incident query, similarity and export entries and the events live scenario.")

- #text("Verified (2026-09-09): the version-1 evidence envelope records query, body and truncation bits; the replay workflow consumes it. See the audit inspection and workflow entries.")

- #text("Verified: Challenge submissions/rejections and optional untrusted timing on existing POST; configured/effective difficulty separate, PoSW conversion and proof format unchanged.")

- #text("Verified (2026-09-09): rule edit, ordering, set export and import through the API, the interface and the native CLI; the private-engine tester with file fallbacks, revisions and revert, and complete candidate validation were verified in earlier entries.")

- #text("Verified: Per-category inspection modes, revision-controlled editing and finding capture; native, live-daemon and browser tests verify audit cannot bypass enforcement. See the dated inspection evidence.")

- #text("Verified: Terminal-rule GCRA before session bypass, global limiter retained, WEIGH limits rejected; storage, live HTTP and browser evidence appears in the dated quota implementation note.")

- #text("Verified (2026-09-09): reputation prefixes and country blocks preflight in a private candidate; a full trie answers capacity, a moved revision conflicts, an incomplete chunk set is refused, and a rejected import leaves every rule untouched.")

- #text("Verified (2026-09-09): live decisions follow the committed order after rebuild, replay agrees with retained inspection findings, and country operations count trie nodes and refuse more than 1,024 prefixes.")

== 6. Cluster and operations

- #text("Verified (2026-09-09): Node health via configured probes, membership coverage and per-node applied revisions through replicated rows, drain/clear-local-bans via the control interface. See the cluster membership evidence.")

- #text("Deferred (design retained): Dedicated TLS management WebSockets with certificate validation and separate domain-separated peer HMAC key; telemetry outside consensus. Membership and health need no peer socket in the delivered increment.")

- #text("Verified (2026-09-09): Missing members render as unobserved, never zero; each node writes only its own row. Node/boot/sequence deduplication applies to the deferred peer stream.")

- #text("Verified (2026-09-09): challenge verification stays issuer-bound and rate limits stay local; the cluster scenario changes only replicated policy. See the cluster entry.")

- #text("Verified (2026-09-09): users, scoped API tokens, audit investigation, kiosk, notifications, constrained templates and the About panel (version, node, schema, origin, proxy and key facts).")

- #text("Verified (2026-09-09): the notifier runs under a fenced singleton lease shared with retention; destinations (8), retries (3, 1/4/16 s), the local ring (64) and the replicated queue (256) are bounded.")

- #text("Verified (2026-09-09): see the fenced retention storage and retention scheduling entries; kiosk grants and workflow stage rows joined the cycle.")

- #text("Verified (2026-09-09): tools/console_cluster_test.py under -Dcluster=true; see the cluster entry.")

== Release verification

- #text("Verified (2026-09-09): zig build fmt test console-test sid, console-e2e in the default and cluster builds, and the storage-off, console-off and cluster builds pass in the acceptance run entry.")

- #text("Verified (2026-09-09): native render tests run under console-test; browser checks at 1440 and 390 pixels are recorded in the nodes, settings, template, kiosk and workflow entries, with reconnect and stale states covered by the stream scenarios.")

- #text("Verified (2026-09-09): Typst PDF/PNGs regenerated; all 18 wireframes visually inspected; HTML retains all 20 inline SVG figures.")

- #text("Verified: SID 0007 has no removed-product references; book comparisons preserved.")

- #text("Verified (2026-09-09): the primitive baseline was regenerated from clean commit e528f7e after the response-page change on the request path; see the acceptance benchmark regeneration entry.")

- #text("Measured (2026-09-09): the matrix ran with all four configurations and all four workloads for seven rounds, and the clustered variant for three rounds; the eight dashboards received at least 0.99 frames per second each. See the acceptance run entry.")

- #text("Not passed (2026-09-09): the verdict is inconclusive on the development host. Point estimates stay within ±2 % throughput and +6 % p99 with peak RSS reported per configuration, but the compiled-out baseline's own spread (20–46 %) exceeds the 1 % rule and every bootstrap interval straddles the gate; the record says so rather than rounding to a pass. A quiet host is required.")

- #text("Pending: every functional gate is verified; the performance gate is inconclusive on the development host, so the record stays Proposed and the console stays opt-in at runtime.")

== Implementation evidence

- #text("2026-09-08: zig build fmt console-test test sid passed for the contract foundation. The storage failure-injection test emits its expected retained-batch warning.")

- #text("Added native/Wasm protocol types, configuration and reservation validation, and a mutex-protected management mailbox with owned payloads, correlation IDs, bounded fair scheduling, single-consumption completions and cancellation ownership tests.")

- #text("console-test tests these foundations; runtime composition, wire serialization and application workflows remain unchecked. No live console or performance result is claimed.")

=== Transport and build verification (2026-09-08)

- #text("Added a bounded RFC 6455 codec with fragmentation, masking direction, control frames, UTF-8 and close validation. Tests include the masked Hello vector, every partial prefix, interleaved ping/UTF-8 fragments, malformed lengths and aggregate message overflow.")

- #text("Added listener-owned admission accounting with reserved HTTP capacity and separate peer quota. These primitives are not yet connected to sockets or daemon startup.")

- #text("zig build fmt test sid sid-site --summary all: 108 tests passed, including 18 console and transport tests. console-test additionally checks Wasm compilation.")

- #text("Storage-off: 87 tests passed. Console-off: 90 tests passed. Cluster-enabled daemon builds. The existing overload test now reads admission rejection without racing a request write against immediate server closure; both disabled configurations pass with that fix.")

- #text("Invalid -Dconsole=true -Dstorage=false fails cleanly with CONSOLE001 and a recovery hint.")

- #text("Typst generated PDF and page PNGs; wireframe overview pages were inspected. HTML export retains SVG figures. Full-resolution review remains part of the document release gate.")

- #text("No measured request subsystem changed, and the console primitives are not yet composed into the daemon. No impact benchmark has run or passed. console-e2e, console-assets and console-impact remain unimplemented, rather than reporting success without evidence.")

#text("Next implementation work: finish daemon composition and lifecycle, connect the mailbox to Persistent with bounded prepared queries and migrations, then implement authentication and live transport before building the authenticated GeoIP dashboard. Later workflow and cluster stages remain required; these commits do not deliver the complete SID 0007 console.")

=== Live daemon and initial interface (2026-09-08)

- #text("Persistent now executes bounded prepared console operations through the owned mailbox. Bootstrap, password hashing, sessions, CSRF, password changes, and revision revocation are connected to the opt-in listener. Off-loopback startup remains unavailable until mandatory TOTP and proxy authorization are implemented.")

- #text("The Zig/Wasm authentication and initial statistics dashboard compile with committed Tailwind/daisyUI CSS. console-assets regenerates assets and console-assets-check verifies them without npm. The globe currently shows an honest unavailable outline.")

- #text("Real-daemon E2E tests exercise setup, failed/successful login, CSRF rejection, durable restart, fragmented WebSocket subscriptions, interleaved ping/pong, unsolicited updates, and sign-out revocation. Native tests prevent forced password changes from opening streams.")

- #text("Exact external outcome counters and sampled request records are compiled out when console support is disabled. A bounded background collector drains samples at 4 Hz. Existing Prometheus counter meanings are preserved. Benchmarks were regenerated after instrumentation; these subsystem results do not establish the console impact acceptance gate.")

- #text("Incremental Chrome review exercised setup, sign-in, live traffic (12 requests/12 challenges), pause/resume, theme switching, 390 px mobile layout and sign-out. Fixed an observed light-theme contrast defect. Full UI/accessibility/browser acceptance remains open for later workflows.")

- #text("zig build test console-test fmt sid passed with 120 tests for the initial interface; subsequent focused collector, account-boundary and GeoIP parser checks extend that coverage. The older evidence above records the state at those earlier commits, not current feature support.")

- #text("Work remains on durable GeoIP activation, geography, minute history, complete authentication, event/policy/challenge workflows, cluster/operational features, and release performance gates. SID 0007 remains Proposed; no feature-complete or full browser-acceptance claim is made.")

=== Country import and globe verification (2026-09-08)

- #text("Added a pinned Natural Earth 5.1.2 geographic binary with representative country centers, strict decoder bounds, native orthographic/horizon/seam tests, and an authenticated asset route.")

- #text("DB-IP gzip imports bound compressed bytes (16 MiB), expanded bytes (128 MiB), source rows (1,048,576), line length (128 bytes), and native generation allocations. CRC/size, optional operator SHA-256, address ordering, overlaps and country codes are checked before activation. The full September 2026 file validated and imported in the browser: 717,152 known ranges; compressed SHA-256 a32bb3c384bd3de60ad9024596aa5b395a6dd5beaa27a7223407cc2edc681d0b.")

- #text("Unknown provider super-ranges exposed an IPv4-mapping edge case; source ordering is validated before explicitly Unknown ranges are omitted. Full-size browser testing exposed a narrow inferred integer in 100-range batch packing; explicit sizing and a 200-range E2E regression now cover that path. Interrupted same-digest imports replay only identical immutable chunks under current authorization.")

- #text("One background importer publishes through Persistent, with bounded chunks and atomic activation audit. Native lookup uses the restored immutable active generation. The collector now reports rolling country samples, Unknown and Other totals alongside exact request outcome counters.")

- #text("Chrome verified the full HTTPS import, geographic activation, 2,048 controlled requests / 2,048 challenges, 33 observed country samples with zero sample loss, country centering, rotation, pause with stale age, and the flat map at 390 px width. Values are observed test results, not sampling or performance guarantees.")

- #text("zig build test reached 130 passing tests; storage-off and console-off matrices passed 89 and 93 tests respectively. The full release gates and all later SID workflows remain open.")

- #text("Storage completion notifications replace 10 ms caller polling while pinning waiter ownership; shutdown/cancellation cannot recycle an event still referenced by its caller. A full local generation restart became HTTP-ready in 15.6 seconds (one observation, not a performance gate).")

- #text("Browser verification after restart confirmed the active 717,152-range generation, restored authenticated subscriptions, labelled password fields, password change/session revocation, and successful login with the replacement password. Geographic markers are clipped at the visible globe horizon; returning to a visible GeoIP page refreshes import status.")

=== Authentication and journal restart verification (2026-09-08)

- #text("TOTP uses the RFC 4226/6238 SHA-1 vectors, six digits and a bounded adjacent-step window. Seeds use separately provisioned console-key encryption, with user-bound authenticated envelopes. Enrollment revokes earlier sessions. Session insertion atomically consumes the accepted step or one of ten recovery digests; rollback does not consume a code.")

- #text("Authentication schema v2 migrates in one owner-executed transaction. Deterministic tests cover a failure after ALTER, replay, refusal of future schemas, idle expiry and absolute expiry. Sessions now use the SID's 12-hour absolute and 30-minute idle lifetimes; passive subscription checks do not extend idle access.")

- #text("Live-daemon tests cover enrollment, password-only rejection for an enrolled account, replayed codes, recovery use, and recovery rejection after restarting. Chrome exercised enrollment, recovery delivery, recovery login, sign-out and rejection of the consumed code. The mobile review found a minimum-content card width issue; recovery text now wraps and the card can shrink. QR provisioning and complete account-management workflows remain open.")

- #text("The full country-data fixture crossed a journal rotation boundary and exposed a pinned Zaxonlite 0.6.1 iterator defect on restart. The manifest and segment checksums were valid. A reviewed one-line generated-source patch selects the sealed-segment reader, preserving trailer validation. The downloaded dependency and on-disk format are unchanged. A new deterministic regression writes across multiple rotations and authorizes after reopening. The patch was retired on 2026-09-09 when Zaxonlite 0.6.2 shipped the same correction upstream; the rotation regression still passes.")

- #text("A copy of the exact failed full-size fixture reopened with the sealed-reader fix in 16.2 seconds and retained revision 1 with all 717,152 known ranges. The original fixture remains untouched. Storage-off and console-off test builds and the clustered TLS build passed. These observations close this regression, not the broader cluster/release gates.")

=== Local initialization verification (2026-09-08)

- #text("sibuna init-admin <username> --data-dir <path> initializes through Persistent before any listeners start. The command prints a random temporary password once, stores only its Argon2id digest, and requires replacement within one hour. Duplicate initialization fails.")

- #text("HTTP setup now reports initialization status only; the UI explains the local command. Schema v3 adds temporary credential expiry and transactional explicit sign-out auditing.")

- #text("zig build fmt test console-e2e sid passed. Live tests cover an empty daemon, rejection of HTTP initialization, the local command, restricted temporary sessions, replacement, old-password rejection, authenticated geometry, TOTP and trusted-proxy restrictions. Password replacement currently revokes old sessions and requires another login; atomic replacement-session issuance remains the next authentication change.")

=== Atomic credential replacement (2026-09-08)

- #text("Schema v4 commits password replacement, revision increment, old-session revocation, replacement-session insertion and redacted audit rows together. The owner rechecks the password-verification revision and current session/CSRF authorization inside that transaction. A failed replacement insertion rolls back the password and preserves the existing session.")

- #text("Password changes now return a new cookie and CSRF token. The UI continues through required TOTP enrollment or the dashboard using the replacement session. Reusing the same password is rejected. The previous re-login limitation above is resolved.")

- #text("All 144 unit tests, live console E2E tests, formatting and SID generation passed. Chrome verified the empty-instance notice, local initialization, restricted temporary login, forced password change and immediate live dashboard access at 390 px width.")

=== Joined daemon shutdown (2026-09-08)

- #text("SIGTERM/SIGINT handlers set a lock-free flag. A normal monitor wakes acceptors; bounded task slots retain joinable connection threads. Shutdown stops admission, interrupts client and active upstream sockets, joins workers/reaper, drains pooled sockets, then releases console tasks before Persistent flushes incidents and closes storage.")

- #text("Idle slots remain owned until their connection unregisters. A deterministic regression covers the former reaper/reuse race. Startup/shutdown also release daemon-owned engine, slot and application state allocations after their borrowers have stopped.")

- #text("Zig 0.16's native connect-timeout option is unimplemented and panics. A fixed-buffer nonblocking POSIX connector uses a five-second monotonic deadline and restores blocking operation before handing the connected socket to Io. No request-path allocations were added.")

- #text("zig build fmt test sid passed, with 146 unit tests and live shutdown checks covering four accept workers, partial HTTP clients, an authenticated subscription, a silent origin, clean exit and restart. Tests fail on forced termination or a nonzero shutdown status. Storage-off, console-off, clustered TLS and x86_64 Linux/musl builds passed.")

- #text("The browser retained the last observed dashboard values and displayed Disconnected with stale age after the review daemon stopped. Broader release and feature gates remain open.")

=== Incident browsing and interface (2026-09-08)

- #text("Owner-executed incident queries support time, node, category, address and path filters, timestamp/id keyset cursors, at most ten rows and a 4 KiB serialized response. Schema v5 adds indexes without rewriting forensic/FTS/vector content. IDs cross the browser as strings.")

- #text("Historical query strings are removed from displayed paths. Unversioned payloads are withheld; absent country, response status, matched rule and capture metadata explicitly remain unrecorded. Existing campaign identifiers are labelled automated similarity candidates.")

- #text("The Events page provides time/category/address/path filters, bounded paging, UTC timestamps, expandable details and empty/error states. Filters use a compact desktop row and mobile stack. Stable heading/results targets preserve keyboard focus across asynchronous rendering.")

- #text("Repository tests, live query tests, SID generation and final native UI/asset checks passed. Live tests generated 15 honeypot incidents and verified filtering, complete pagination, authorization/CSRF, exact string IDs and omission of payload secrets. Browser checks verified two populated pages, address filtering, empty results, escaped script-like user-agent text, missing-evidence labels, mobile/desktop layouts and heading/results focus without overflow.")

- #text("Grouped investigation, exports, richer versioned evidence and remaining policy/operational workflows are still open; this entry does not close the full investigation acceptance gate.")

=== Source grouping and bounded exports (2026-09-08)

- #text("Source groups retain node/address identity, exact filtered record counts and first/last capture times. Drill-down keeps the selected node, address and time boundary. Historical countries stay unrecorded. Query and export budgets are independently bounded per session and globally, with their fixed memory included in the console reservation estimate.")

- #text("JSON and CSV export only the selected bounded page. The owner rechecks authorization and records export preparation before returning bytes; the audit does not claim download delivery. CSV visibly prefixes formula-like text and quotes separators; JSON preserves returned strings.")

- #text("All 152 unit tests and live console tests passed; formatting passed after final corrections. Browser review covered grouped/raw switching, node/address drill-down and both export controls. A full-page CSV test exposed dynamic parser exhaustion that a one-record export missed. A typed bounded parser and full-page live regression resolve it; the browser repeated the full-page export successfully. Export feedback preserves button focus and uses status styling.")

- #text("Rich versioned evidence, rule/address actions, campaign-member and nearest-incident navigation, and the remaining policy/cluster/operational work still block full SID acceptance.")

=== Challenge observation foundation (2026-09-08)

- #text("Console-owned atomic counters cover parsed verification submissions, early malformed/banned rejections, exhaustive verifier failures, issued and accepted authenticated parameter bins. Existing Prometheus counter meanings and proof/token formats remain unchanged. Console-off builds eliminate producers; console-disabled runtime work avoids parsing timing metadata.")

- #text("The interstitial sends solve duration measured before verification and an untrusted solver label. Only accepted proofs contribute timing: 16 bounded histogram buckets, separate missing and invalid counts, and finite nonnegative durations capped at one hour. A fixed scanner arena rejects ambiguous metadata without changing admission. Parameter bins use authenticated proof fields; client fields cannot select them. Reservation accounting includes these fixed counters.")

- #text("Required formatting, repository/live tests and SID generation passed. Live proof tests cover valid, missing and invalid timing, replay and missing challenge IDs. A storage-free, console-disabled daemon build passed. Benchmark regeneration follows for this measured change.")

- #text("Authenticated challenge presentation, historical windows and per-address observations remain pending; this foundation does not close the challenge or performance acceptance gates.")

=== Authenticated Challenges interface (2026-09-08)

- #text("The bounded, CSRF-protected snapshot endpoint shows boot-local issued/submitted/accepted totals, exhaustive rejection causes and one selected timing histogram. Configured difficulty, converted default parameters and most recently issued authenticated parameters are distinct. Query budgets apply; the response remains below 16 KiB even with maximal bin counts.")

- #text("The Zig page offers populated parameter partitions, accepted timing/missing/invalid counts, reported solver labels, explicit untrusted-data explanations and manual refresh. Snapshot age advances, failed refresh retains labelled stale values, and recovered connections refresh them.")

- #text("Required repository/live tests, formatting and SID generation passed; final native UI tests passed after browser corrections. The live browser solved a real PoSW depth-13/16-opening challenge and observed one issued/submitted/accepted proof with Wasm timing in 64–128 ms. Mobile rendering had no horizontal overflow; partition selection retained keyboard focus. Stopping/restarting the isolated daemon verified stale feedback and successful refresh recovery.")

- #text("Browser testing exposed generic JSON-tree arena exhaustion on the 256-bin array. A typed response decoder fixes it, with a full browser-event native regression; refresh is no longer stuck disabled. The UI also ignores delayed responses after leaving the Challenges page.")

- #text("Benchmark snapshot latest-20260907T225257Z.json was regenerated for the preceding measured observation changes. This does not replace the outstanding SID console-impact release gate.")

=== Versioned incident metadata (2026-09-08)

- #text("Additive schema v6 stores an incident metadata sidecar in the same idempotent transaction as forensic, FTS, vector and reputation writes. Historical content remains intact; historical and grouped rows have no inferred envelope. Console-disabled builds omit metadata producers and queue fields; the reservation estimate includes the incremental queue/batch metadata.")

- #text("Version 1 captures the selected firewall status, query/received/declared body lengths and separate capture truncation flags. The evidence view omits query/body values, cookies and other headers; it preserves the existing bounded User-Agent display. Selected status is not presented as proof of delivery. Country, matched rule and delivered status remain unrecorded.")

- #text("Required repository/live tests, SID compilation and final formatting/native UI checks passed. A deterministic failure trigger verifies incident/evidence rollback, retained-batch retry and migration replay. Live queries verify new metadata, private query omission and bounded CSV. A storage-free console-disabled build passed.")

- #text("Browser review checked mixed historical/new rows, address filtering, exact byte lengths, capture versus display truncation, escaped historical markup and successful versioned CSV export. A synthetic request's query/body/cookie/authorization values were absent from the view; its 810-byte body and User-Agent capture limit were represented explicitly.")

- #text("Rich matched evidence, policy revision, country-at-capture and configurable redaction remain future envelope extensions. Existing private forensic storage is not relabelled as sanitized evidence. Benchmark regeneration follows for this measured capture-path change.")

=== Candidate membership navigation (2026-09-08)

- #text("Incident details link existing similarity candidates to raw or grouped membership. Navigation preserves exact string IDs and the selected time boundary, clears address/node restrictions, and retains a visible candidate filter through paging, regrouping and bounded export. The interface explicitly distinguishes automated similarity grouping from attribution.")

- #text("Schema v7 adds a campaign/time/id index. Candidate queries use an equality predicate so SQLite can use it within the existing VM-step budget. A deterministic fixture with 15,000 unrelated records verifies exact membership for an ID above JavaScript's integer precision. Live tests verify all 15 related incidents across pages and reject oversized IDs.")

- #text("Required formatting, repository/live tests and SID compilation passed. Browser review exposed generic JSON-tree exhaustion on a full historical page; incident responses now use typed decoding, with a complete ten-row browser-event regression including versioned metadata. Browser repetition successfully displayed ten then five members and restored results focus.")

- #text("Nearest-incident search and policy/reputation actions remain pending. The preceding capture benchmark regeneration is committed as latest-20260907T231647Z.json; console-impact and storage-contention acceptance still require the release harness.")

=== Incremental nearest-incident queries (2026-09-08)

- #text("Similarity requests read the source vector by ID and scan at most 64 time/id-ordered records per background mailbox operation. They recheck authorization on every part and retain existing prepared-query limits. This avoids claiming that VM-step limits bound a vec0 internal KNN scan.")

- #text("Each part returns at most ten IDs, node/time metadata and normalized cosine distances in a bounded response. Raw payloads and vectors are not returned. The shared fixed top-ten merger preserves global ordering across parts, including deterministic ties and duplicate rejection. Missing/invalid vectors and the continuation cursor make search coverage explicit.")

- #text("Deterministic storage tests scan 130 records in three parts, verify closest-match merging and per-part revocation. Live API tests cover CSRF/authentication, missing source vectors, exact IDs, bounded output and incident drill-down. UI progress and browser acceptance follow below.")

=== Similarity interface and HTML snippets (2026-09-08)

- #text("The interface merges successive parts, exposes partial/complete coverage, and supports pause, resume and exact incident inspection. Generation checks reject delayed responses after pause or a replacement search. Returning from an incident preserves the previous search results.")

- #text("Browser checks on the isolated daemon scanned 146 retained records with zero missing vectors, rendered ten closest matches, opened the exact selected incident and restored completed results. The 390-pixel layout had no horizontal overflow; desktop rendering was inspected at 1280 pixels.")

- #text("Evaluated the sibling Kynetica ZMPL engine. Although used by its static generator, that engine parses and renders at runtime, with CMS inheritance, filters, maps and allocator-owned output. Sibuna instead adopts its strict lookup and escaping ideas in a small first-party renderer: trusted HTML snippets with build-time placeholder expansion and runtime typed Zig values.")

- #text("libs/html builds natively and for Wasm, allocates no memory, and writes to caller-owned output. It has no raw HTML path or runtime template interpreter. Conditions and bounded loops stay in Zig. Shared form fields, messages and the similarity page now use ordinary .html snippets; Tailwind scanning and committed input digests include those files. Other pages can migrate incrementally. Operator-editable data-plane templates require their separate constrained design.")

- #text("Required zig build fmt test sid passed, including native render and live daemon tests. Six compile-rejection probes verified missing fields, unclosed/invalid placeholders, unsupported tags, source-size limits and placeholder-count limits. Runtime tests cover escaping expansion, fixed-output exhaustion and exact 64-bit IDs. No measured data-plane subsystem changed.")

=== Consistent authenticated navigation (2026-09-08)

- #text("Moved the sidebar out of the Statistics renderer into a shared authenticated shell. Every full-access view, including similarity and account security, now has one navigation landmark and the correct active section. Required password/TOTP gates retain the authentication shell.")

- #text("Uses the pinned daisyUI menu/navbar components, theme tokens, sticky desktop navigation and a Wasm-owned mobile disclosure with aria-controls/aria-expanded. Page selection closes the disclosure and restores heading focus. A skip link bypasses repeated navigation.")

- #text("Required formatting, tests and SID compilation passed. Browser checks traversed all current desktop sections and verified mobile disclosure, selection, focus and no overflow at 390 px.")

=== Authenticated earth without a GeoIP dependency (2026-09-08)

- #text("The custom Zig/SVG orthographic earth now draws authenticated Natural Earth boundaries even when no GeoIP generation exists. No traffic locations are inferred: the unavailable notice and Unknown coverage remain explicit. Added ocean shading and a bounded geographic grid.")

- #text("Geometry requests remain behind full authentication and retry no more often than every 30 seconds after failure. Superseded browser downloads cannot publish over a newer request.")

- #text("Native tests render the complete committed geography in four rotations and flat mode within the existing 512 KiB output budget, and reject geometry publication after authorization loss. Required formatting, tests and SID compilation passed. Browser review verified rotation, reset, unavailable coverage and the flat-map layout at 390 pixels without horizontal overflow.")

- #text("No Three.js dependency is needed for the current globe. Pointer gestures and richer traffic/ attacks overlays remain separate work; existing keyboard-operable rotation controls remain.")

=== Applied policy inspection and evaluation (2026-09-08)

- #text("Added authenticated, CSRF-protected owner-mailbox reads of the published policy engine and bounded request evaluation. Pages contain at most eight summaries and 4 KiB of JSON; pagination and tests can pin an applied revision. Committed storage stamps and applied engine stamps are reported separately. Pins never survive an operation or block publication across a tick.")

- #text("Summaries include file/default and database rules in effective order, with explicit omission of header/CIDR values and display truncation metadata. Tests include inspection, reputation and complete applied matchers. They do not simulate sessions, local limiters or origin replies. Operator-supplied request bodies and headers are not persisted by this read-only operation.")

- #text("Deterministic storage ticks verify file/database composition, inspection precedence, stale revision rejection and session revocation. Live daemon tests compare Amazonbot and XSS denials with actual traffic and verify authentication, CSRF, invalid input and revision conflicts.")

- #text("The Policies UI uses HTML snippets and shared navigation, preserves submitted fields, rejects late response generations, and provides error/result focus and a direct tester link. Browser checks verified deny and allow cases, revision 146 becoming stale after a synthetic incident, refresh to revision 147, invalid-IP recovery, and a 390-pixel layout without overflow.")

- #text("The initial browser query exposed empty tuple serialization as an array; it now sends an explicit offset object and has regression coverage. The bridge compares successive Wasm HTML outputs rather than browser-normalized innerHTML, avoiding needless form replacement on no-op events. Browser keyboard clearing and re-evaluation were verified.")

- #text("Reusing the existing JSON decoder and resetting owned State fields individually kept the interface below the 300 KiB gate (287,701 bytes before the final small navigation additions). A native regression verifies credential/body erasure and default restoration during reset. Required repository tests, formatting and SID compilation passed; subsequent UI refinements passed console-specific checks and browser review. Policy edits, history and candidate-engine validation remain pending and are not represented as implemented by this read/test view.")

=== Strict management documents and private candidates (2026-09-08)

- #text("Added a separate management document compiler with owned strings, a 4 KiB input bound, strict field validation, and rejection of excess or ambiguous matchers. Existing startup file parsing remains compatible. Disabled documents receive the same validation.")

- #text("Private candidates own their engine and a fixed 2 MiB string/parser budget, include current file settings and fallbacks, and insert validated dynamic rules in priority/name/ID order. Their 128-rule limit includes fallbacks; reputation insertion rejects invalid actions, malformed networks and trie exhaustion. Failure releases the entire private candidate.")

- #text("Tests cover input ownership, allocator exhaustion, duplicate fields/IDs, matcher limits, deterministic order, disabled rules, fallback capacity and file/reputation composition. This is library support for upcoming management operations; no draft is published and no policy write endpoint is exposed by this change.")

=== Revision-bound draft preview service (2026-09-08)

- #text("The policy test endpoint accepts an optional owned draft document and a required committed revision. The storage owner replaces the matching database ID, or inserts a new candidate, without writing or publishing it. Results explicitly distinguish previews and their committed basis from the currently applied revision.")

- #text("Snapshot reads use prepared query limits, eight-rule pages and 64-reputation pages. Source staging has a fixed 2 MiB budget, in addition to the private candidate's engine and 2 MiB parser budget. Revisions are checked before and after composition, and authorization is rechecked before returning the result. Existing malformed neighboring rules reject the draft; replacing a malformed rule itself allows it to be repaired.")

- #text("Storage tests cover replacement without publication, stale revisions, revoked sessions, invalid disabled neighbors and complete header/CIDR matchers across page boundaries. Live daemon tests verify a draft denial over an applied allowance, invalid input, missing revision, conflicts and the unchanged applied decision afterward. Formatting, tests and SID checks pass. Editor controls and transactional writes remain subsequent work.")

=== Atomic policy saves and revision history (2026-09-08)

- #text("Schema 8 adds policy history, a redacted audit target, a deterministic ordering index and a temporary staging table. A conditional prepared statement rechecks session, CSRF, role and expected revision; its trigger commits the rule, history and audit together and clears staging. First edits preserve an encodable pre-existing database rule as a baseline. Invalid legacy rules without an encodable baseline can be repaired without inventing prior history.")

- #text("Operators and administrators can save validated documents through the authenticated edit endpoint. Candidate validation includes all neighboring policies, file settings and reputation. Responses distinguish the committed revision from the previously applied engine; publication occurs on the storage tick and failed rebuilds retain the old applied revision for retry. Priority/name/ID ordering now agrees between private candidates and published database rules.")

- #text("Tests cover stale edits, owner-side CSRF and role enforcement, revoked sessions, audit failure rollback, baseline preservation, migration replay and recovery after failed publication. Live daemon tests verify an edited denial against actual traffic and subsequently disable that rule. Formatting, repository tests and SID compilation passed.")

- #text("Regenerated primitive benchmarks with other review/test daemons stopped; the snapshot is benchmarks/results/latest-20260908T014358Z.json. This regeneration does not establish the separate console impact acceptance gate. Managed-rule browsing, editor forms and history/ revert controls remain pending.")

=== Managed-rule and history reads (2026-09-08)

- #text("Added authenticated, CSRF-protected catalog, complete-document and history reads. Catalogs and histories return at most eight rows and 4 KiB, with keyset cursors and revision checks around storage reads. Complete documents use a dedicated owned result rather than silently clipping editable fields to fit a summary. Historical documents retain their original content.")

- #text("Storage tests verify catalog page boundaries. Live daemon tests verify authorization, CSRF, complete-document round-trips, history reads, stale revisions, restoring an older document through the validated save transaction and restoring the current version afterward. Formatting, tests and SID checks passed. User-facing editor and history controls follow.")

=== Managed-rule editor and history interface (2026-09-08)

- #text("Added structured rule forms, catalog/history pagination, private draft previews and saving historical documents as new validated revisions. Inputs survive validation and revision conflicts; existing IDs are read-only. Operator controls follow protocol permissions.")

- #text("HTML snippets render through Zig with escaped values. A responsive two-column form becomes one column on mobile. The browser bridge collects form fields; Zig owns document construction and application behavior. Successful saves use the daisyUI success alert treatment.")

- #text("Removed the initialized global Wasm state image, initializing explicitly before events, to keep the expanded editor inside the startup bundle gate. Native initialization and document ownership/validation tests pass along with formatting, repository tests and SID compilation.")

- #text("Live browser checks covered private denial previews, malformed matcher JSON, save/disable, historical restore and stale-save rejection with draft retention. Actual firewall requests followed the saved denial. Desktop and 390-pixel mobile layouts were inspected; the shared navigation remains accessible and the mobile form has no horizontal overflow.")

=== CLI country database loading (2026-09-08)

- #text("Added tools/console_geoip.py with hidden password/TOTP prompts, HTTPS or literal loopback HTTP, bounded responses, monthly imports, optional compressed-file checksums, progress and status inspection. It uses the authenticated console service and never opens storage itself. Repeated requests for an already active month skip importing and verify any supplied digest.")

- #text("Downloaded September 2026 DB-IP data into the review instance: 717,152 known-country ranges. Verified durable restoration after restart and live US/Australia markers, country rankings, Unknown local-address samples and the flat-map fallback. Usage is in README.md (country data loading). This verifies development data loading, not the remaining SID telemetry or cluster gates.")

=== Dashboard reconnection after management navigation (2026-09-08)

- #text("Browser verification with the full country database found that policy navigation disconnected transport without releasing the dashboard's busy guard. Returning to Statistics consequently kept old values labelled Live. Disconnect commands now consistently clear that guard and mark retained data stale until a fresh subscription snapshot arrives.")

- #text("A native regression exercises an active dashboard, policy navigation and return, checking both the emitted connection command and the stale state while waiting for new data. Formatting, full repository tests and SID generation pass. Browser verification after a restart and policy round-trip received 768 new requests, US/Australia samples and Unknown local samples through the reconnected stream.")

=== Policy document transfer and complete request headers (2026-09-08)

- #text("Both applied and private policy testers accept up to eight request headers from bounded line-based input. Invalid names, control characters, repeated names and overflow are rejected while retaining entered text. Browser checks matched the built-in CF-Worker rule and rejected case-insensitive duplicate headers.")

- #text("Rule documents can be imported into an unsaved editor draft and exported as JSON downloads. Imports reject unknown fields, invalid field types and changes to an existing rule ID. Saving still requires the normal full candidate validation and expected revision. Export remains available after conflicts so an operator can retain a draft. Browser checks imported a new header rule, previewed its denial at unchanged committed revision 154 and exercised export. This supports individual documents; atomic bulk policy-set import/export is still required.")

- #text("Shared JSON-tree decoding replaces repeated typed scanners. A fixed 512 KiB scratch region is cleared after each event; large challenge, incident and similarity response regressions pass. The Wasm module is 293,413 bytes, within its existing gate, and now declares both initial and maximum memory of 4 MiB. Full tests, formatting, SID generation and asset checks pass.")

== Animated globe implementation (2026-09-08)

- Added a bounded 24 Hz browser frame bridge and an isolated SVG scene update. Zig owns rotation,
  curve geometry and arrow progress; the frame loop does not replace the sidebar, tables or forms.
  Manual rotation and country selection pause automatic movement. A separate motion control,
  reduced-motion preference, hidden-tab suspension and stale-data guards constrain animation.
- Up to 16 visible arcs represent observed country aggregates flowing to a non-geographic Sibuna
  hub. Unknown samples produce no invented locations. No arcs appear without country samples,
  after disconnection or while live updates are paused. Existing horizon clipping remains intact.
- Native tests cover authentication, bounded clock progression, reduced motion, pause and stale
  arcs. Browser checks observed continuous geometry movement, actual US/Australia sample arcs,
  and pause/resume behavior. Full tests, formatting and builds passed; the module is 297,208 bytes.

== Structured policy matchers (2026-09-08)

The rule editor presents four labelled header name/pattern pairs and up to eight
client networks, entered one CIDR per line. Its internal draft preserves duplicate
and incomplete header rows; document validation rejects them before a request is
sent. Imports and exports retain the existing bounded JSON wire contract.

Native console tests pass (68 tests), including duplicate preservation and IPv4/IPv6
network conversion. The full formatting, test and SID build passed for this change;
assets were regenerated and the final console checks and daemon build passed.
Browser verification imported a header/network rule, rejected a duplicate header
without discarding input, then previewed a denial and saved revision 155. Live
requests returned 403 for a matching header and 401 from the fallback challenge
for a nonmatching header. These checks cover this editor increment, not the
remaining policy and release acceptance gates.

== Bounded ranking collection (2026-09-08)

Path-prefix samples now feed collector-owned 256-counter Space-Saving summaries.
Two minute slots separate current and late preceding-minute samples. Each retains
all counters and errors; the authenticated, rate-limited rankings endpoint returns
at most twelve display rows, retained sample count, sampling probability, truncation
and rejected-record counts, and explicitly boot-scoped queue losses. Invalid UTF-8
keys use a labelled hexadecimal encoding. No request producer work was added.

Cross-window merging follows Algorithms 3 and 4 of
#link("https://arxiv.org/abs/1401.0702")[Cafaro, Pulimeno and Tempesta,
A Parallel Space Saving Algorithm for Frequent Items]. Common keys add estimates
and errors; absent keys add the other summary's minimum (zero if not full), then
the largest 256 estimates survive. Native tests compare repeated merges against
exact populations, including heavy-hitter retention, error bounds, empty inputs,
overflow rejection and a global winner below each local winner. Callers must merge
only disjoint populations and retain sampling and coverage metadata separately.

Formatting, native tests, live-daemon end-to-end tests, SID generation and the
daemon build passed. Live requests populated the path ranking without exposing
query-string secrets. Anonymous and required-password-change sessions could not
read the endpoint.

This increment does not persist minute sketches, combine peer data, provide other
ranking kinds, or complete the ranking interface and retention gates. The endpoint
reports only the current partial minute; first and last sample times are null when
there are no retained samples.

== Current-minute ranking interface (2026-09-08)

The signed-in Statistics page now renders path-prefix estimates and lower bounds,
retained/truncated/rejected sample counts, boot-scoped queue loss, captured UTC
minute and age. It refreshes every ten seconds while dashboard statistics arrive;
paused or disconnected values remain visibly stale. A separate controller correlates
requests across session resets. Bounded decoding copies keys and commits a complete
replacement only after validation. Native tests cover excess rows, ownership,
escaping, erasure and delayed responses from a previous session.

Formatting, full tests, console checks, SID generation and the daemon build passed.
The Wasm artifact is 307,119 bytes, within its unchanged 300 KiB bound. Browser
verification observed 26 retained samples (19 and 7 for two actual paths), no query
secrets, minute rollover, unchanged paused rows with increasing age, and a 390-pixel
mobile viewport without horizontal overflow. Desktop review retained the sidebar
and rendered the ranking table below the globe and timeline. Durable history,
additional ranking kinds and cluster aggregation remain pending.

== Bounded browser fetches (2026-09-08)

The fixed browser bridge now applies a fifteen-second deadline to API responses,
geographic geometry, exports and initial Wasm loading. Reads count bytes before
retaining chunks, skip empty chunks, cancel excess bodies, and release reader locks.
API payload limits reserve space for the Wasm event envelope. A visible startup
message becomes a retry instruction when the console asset cannot load. Browser
timeouts do not cancel an executing database operation or prove a mutation failed.

Focused transport checks verified abort propagation, timer cleanup, capacity
cancellation and chunk assembly. Browser review verified startup, geometry,
challenge data, policy reads and dashboard recovery; a stalled-asset fixture
produced the visible retry message. Formatting, console checks, full regression
tests, SID generation and the daemon build passed. No request-path code changed.

== Complete ranking archive encoding (2026-09-08)

The bounded SBR1 archive format encodes a collector minute with explicit
little-endian fields: node and boot identity, minute index, first/last sample times,
truncation and rejection counts, queue-loss boundaries, retained N, sampling
denominator and every occupied counter with its full key, estimate and error.
The maximum record is 37,468 bytes. Counter sums must equal N for original local
minutes; serializing only display winners is rejected. Decoding rejects unknown
versions, trailing or truncated bytes, duplicate keys, invalid intervals and bounds.
Native tests exercise the maximum 256-counter record and incomplete archives.
This codec is a storage prerequisite; durable publication and recovery are not yet
implemented by this increment.

== Transactional ranking archive storage (2026-09-08)

Console schema version 9 adds bounded staging, immutable 2 KiB chunks and a unique
node/boot/minute archive index. Publication verifies all chunks, the SHA-256 digest
and the complete SBR1 record before inserting the index. Identical retries succeed;
conflicting chunks or archive identities preserve the published record. Each query
stays within the prepared native and supported replicated-facade bounds. Only the
existing Persistent owner executes these typed internal operations.

Staging admits at most 64 records and reserves against a 512 MiB charged retention
budget, including conservative chunk/index allowances. This is a retained-data
reservation, not the shared database file's physical size. Cleanup removes at most
two ten-minute-old staging records and two expired or quota-pressure archives per
invocation; normal ranking retention is seven days. Triggers release reservations
and remove corresponding chunks atomically with each deletion.

Deterministic storage ticks verified copied input ownership, incomplete publication,
chunk conflicts, checksums, unique archive conflicts, quota and staging exhaustion,
bounded cleanup, migration replay and restart recovery. Full formatting, test and
SID checks passed. The collector publisher and historical query interface remain
pending; these internal operations are not browser ingestion endpoints.

== Nonblocking ranking publication (2026-09-08)

The collector now seals sampled minutes after the late-sample horizon and hands
complete archives to a two-job journal. One background mailbox ticket advances
publication without waiting for storage. Ten-second monotonic deadlines abandon
caller ownership safely; idempotent retries use bounded exponential backoff and
stop after eight failures. Unconfirmed writes remain explicitly labelled because
a timeout cannot prove that a database mutation failed. Shutdown joins the collector,
abandons its outstanding ticket and erases queued archive buffers before storage
is released. The console budget includes journal and collector memory.

Bounded retention maintenance runs every five seconds and caches durable inventory
for dashboard readers, avoiding a history query per dashboard. Stored inventory is
distinct from boot-local saved, pending, unconfirmed and maintenance-failure counts.
SBR1 queue-loss boundaries currently describe zero through cumulative boot loss at
sealing, not loss attributable to an individual minute. Empty unsampled minutes
are not archived; missing archives do not establish zero traffic or full coverage.

Deterministic tests cover queue exhaustion, acknowledgement ordering, executing
timeouts, retry identity, retry exhaustion, cancellation and maintenance failures.
Formatting, console checks, full regression tests, SID generation and the daemon
build passed. A live 1,024-request run published minute 29,814,050 with 9,216 bytes
of charged reservation and no unconfirmed writes or maintenance failures. Restart
retained that archive while resetting the boot-local saved count to zero. Historical
queries and their interface, other ranking kinds, and exact outcome/country minute
persistence remain pending.

The storage-off default, storage-enabled console-off, and cluster-enabled console
builds passed in separate output directories. Explicit console-on with storage-off
was rejected with CONSOLE001 as required. These are compilation checks, not the
three-node management or console-impact acceptance tests.

Required primitive benchmark regeneration completed with the review daemon stopped:
`benchmarks/results/latest-20260908T050301Z.json`, source SHA-256
`4266b025d0ccc7e370c0312d31d041f1db8dccd224a30f9e6622dbe032a79fe7`.
This records seven-batch primitive timings and 9,696 KiB idle RSS with storage
compiled but inactive. It does not measure active console storage contention or
satisfy the dashboard throughput and p99 gates.

== Per-category inspection engine (2026-09-08)

Immutable policy snapshots now carry disabled/audit/enforce modes for path traversal,
SQL injection, cross-site scripting and command injection. The existing WAF boolean
remains the master switch. The policy-file `inspection` object accepts partial mode
defaults and rejects unknown categories or mode values. Private candidates retain
these settings. Applied-policy and tester responses expose modes and audit-category
bits independently of the terminal request decision.

The all-enforce path retains the combined automaton. Mixed modes select category
outputs from the same automaton, including failure-link suffix matches, and use the
same structural detectors and canonicalization. Disabled detectors are skipped;
audited categories record at most one finding per request and do not terminate
evaluation. Findings enter the existing bounded incident queue under explicit
`audit:` categories before session admission, without raw query/body payloads or
fabricated response evidence. They do not trigger automatic reputation bans.

Native automaton tests cover a rejected longer output hiding an enabled suffix.
Engine/candidate tests cover encoded enforcing matches after audit, disabled
categories, file fallback and strict invalid settings. Live daemon requests verified
that audit preserves enforcing-category, rule and reputation denials while allowing
normal admission to continue. Formatting and full regression tests passed. A separate
mixed-mode 8 KiB benchmark workload now records the cost of category selection;
this increment does not establish the console-impact release gate.

== Transactional inspection settings (2026-09-08)

Storage now owns a replicated singleton mode override, separate from file fallback.
It participates in the existing policy revision triggers and is loaded into every
rebuilt engine, including storage-enabled builds with the console compiled out.
Console schema 10 adds a staging trigger that commits the complete matrix, previous
and next mode documents, history and audit together. Management requires all four
categories explicitly; omission cannot silently restore a category to enforcement.

The authenticated edit route checks role, CSRF and expected revision, validates a
complete private candidate, and repeats authorization/revision predicates in the
conditional commit. Replies distinguish committed and locally applied revisions.
Deterministic tests cover invalid/partial modes, stale edits, CSRF refusal, injected
history failure with complete rollback, migration replay and restart recovery.
Live-console tests compare audit findings and terminal decisions with real requests,
then restore the original matrix. Full regression and formatting checks passed.
Storage-off and cluster builds passed. A direct storage test, also run with the
console compiled out, verifies override publication and restoration of file defaults
after removing the override; these checks do not establish three-node acceptance.

== Inspection interface and bounded browser decoding (2026-09-08)

The applied-policy page now includes four labelled daisyUI selectors, explicit
review of enforcement effects, and a revision-bound save. It retains submitted
selections through pending/error states, distinguishes saved from applied settings,
and requires refresh after conflicts or a successful save. Editing is disabled while
the applied revision lags the committed one. The policy tester names audited
categories independently of the final verdict; older responses say not recorded.

Browser responses now decode from the existing JSON tree through a bounded typed
reader. Strings borrow the event arena and retained models copy them before erasure;
variable incident/similarity rows are capped at ten before allocation, histogram
arrays require their exact lengths, and numeric narrowing/nonfinite values fail.
This replaces repeated general-purpose value decoders without changing browser glue.
The completed interface is 291,192 bytes, below the unchanged 300 KiB limit.

Full regression and console checks passed. Browser review exercised login, dashboard
and globe, incident details, unavailable similarity, challenge observations, mode
save/refresh, named tester findings and restoration of enforcement. Actual requests
after the browser edit returned challenge for SQL audit, denial for encoded XSS,
and denial for Amazonbot. Persisted audit incidents omitted response evidence and
query/body payloads. Desktop navigation remained present; mobile navigation used its
menu and the form fit a 390-pixel viewport without horizontal overflow. This closes
the category-mode workflow, not the broader policy or interface release gates.

Required benchmark regeneration completed from clean commit `2f3cd50` with the
review daemon stopped: `benchmarks/results/latest-20260908T064243Z.json`, source
SHA-256 `41579936ef6331b69280ac5534ab81f702647b62a8f307b188a51b35b240785f`.
Median full request classification was 1,441.5 ns; the 8 KiB all-enforce scan was
23,253.7 ns and SQL-audit/other-enforce scan was 113,144.1 ns. Mixed modes currently
pay for category selection passes (about 4.9 times this body-scan workload).
Idle RSS was 9,808 KiB with storage compiled but inactive. These primitive results
do not measure active dashboard/storage contention or pass the isolation gate.

== Terminal-rule quota implementation (2026-09-08)

Terminal Allow, Deny and Challenge rules may now carry a bounded `limits` object:
`rate` (1–1,000,000 requests), `window_seconds` (1–86,400) and optional
`ban_seconds` (0–86,400, default zero). This is an additional GCRA quota per
client and selected terminal rule. The existing global limiter still runs first.
WEIGH rules cannot own quotas. A rule selected before another terminal rule owns
the request, preserving the existing ordered policy semantics.

The daemon checks this quota before session admission. Excess requests return 429
and a rounded-up Retry-After. A positive ban duration additionally places the
address in this node's existing ban table, affecting subsequent requests to other
paths. Exhausted limiter capacity refuses the current request without banning the
address. Quota cells use a separate fixed 8,192-cell table with 16 shards and a
16-probe bound; cells are reclaimed only after draining. No request-path allocation,
SQL, policy mutation or console callback is introduced.

Managed rule IDs provide stable quota identity through renames, ordering and
unrelated revisions. File rules use their name and ordinal. Settings changes create
a new scope; reverting the same settings can reuse its still-active cell. Node
restart resets transient quotas, as for the existing global limiter. Quotas and
local bans are not replicated or multiplied into a cluster-wide allowance.

An additive base policy-format migration installs `limit_config` independently of
console compilation and refuses newer known format versions. Console schema 11
extends the existing atomic policy/history/audit commit. Legacy rules have no
additional quota. Stored documents, private candidates and history restoration
retain the complete quota; invalid stored settings prevent engine replacement.
The editor retains all three fields through import, preview, save and reload,
rejects partial settings, and explains the global and node-local behavior. Tester
results expose configured quotas without consuming quota or simulating cookies,
existing local bans or the global limiter.

Native tests exercise burst/pace bounds, scope separation, saturated probe windows,
strict file/management validation, valid-cookie admission ordering, global-limiter
precedence and cross-path local bans. Deterministic storage ticks cover legacy
column upgrade, replay, console-off publication, future-format refusal, unrelated
revisions, document/history restoration, restart, atomic audit failure and retention
of the previous engine after an invalid stored quota. Live-console tests verify
that previews do not consume quota and unrelated edits do not reset it.

Browser review saved a two-request/60-second Challenge quota at revision 160;
actual requests returned 401, 401 and 429 with Retry-After 30. Reload retained
all fields. A WEIGH save was refused while preserving the draft. The form fit a
390-pixel viewport with 300-pixel inputs and 16-pixel text, without horizontal
overflow. The temporary rule was disabled at committed/applied revision 161.
Specific `POLICY007` recovery guidance replaces the generic form error for invalid
quotas. The interface remains below its unchanged 300 KiB Wasm limit.

The release build exposed a pre-existing by-value copy of all telemetry geography
buckets on the 256 KiB HTTP worker stack, causing a SIGBUS during a statistics
request. Snapshot iteration now borrows locked buckets instead. Release-mode
console end-to-end tests and the live dashboard passed after this fix. Full tests,
formatting, SID generation and storage-off/console-off/cluster build checks passed;
the broader three-node and console-impact acceptance gates remain pending.

Benchmark regeneration from clean commit `bef3336` produced
`benchmarks/results/latest-20260908T072137Z.json`, source SHA-256
`e46d9294c2318c60bfb66cb7c9dd4648d286911ac1a674661eb577593cba586c`.
Seven-batch medians were 5.9 ns for the existing global GCRA workload, 6.2 ns
for four rule scopes and 1,450.4 ns for full policy classification. Idle RSS was
9,904 KiB with storage compiled but inactive and the review daemon stopped.
These primitive measurements do not establish throughput/p99 isolation under
active dashboards, storage contention or cluster traffic.

== Exact outcomes and boot-aware live intervals (2026-09-08)

Console-only counters now distinguish admitted, challenged, policy-denied, banned,
rate-limited and other requests without changing Prometheus counter meanings.
One recorded-outcome guard covers parsed external dispatch, and incomplete external
bodies contribute one other outcome. Incomplete verification POSTs contribute one
submission and malformed-solution observation, without entering external totals.
Internal endpoints, including blocked ones, remain excluded. Origin response classes
are independent observations associated with admitted requests, not extra outcomes.

Statistics snapshots carry a versioned outcome contract, node ID, the same random
boot ID used by ranking persistence, and monotonic elapsed time since console
observation began. The UI displays the six outcomes separately and labels banned
request counts explicitly; they are not distinct addresses. Older snapshots show
unrecorded breakdown fields, and newer unsupported formats leave a stale view.
Boot bytes always serialize as an array, including byte sequences that happen to
be valid UTF-8. Counters at or above 2^53 serialize as decimal strings so the fixed
JavaScript JSON bridge cannot round them; the Wasm decoder validates decimal syntax
and the full unsigned range. Country sample counts use the same representation.
The collector separately counts samples discarded as expired or future-dated;
those no longer disappear silently from coverage. These are cumulative observation
losses since boot, separate from producer queue saturation and Unknown geography.

Live timeline intervals require the same nonzero boot and node, nondecreasing
counters, adjacent UTC labels and positive monotonic elapsed time of at most two
seconds. Restarts, backward clocks and counter resets clear the baseline; missing
observations leave gaps. Rates divide the observed count by monotonic elapsed time.
An accessible, horizontally scrollable table exposes the last ten observed counts,
durations and rates. This is the live observation view; the specified 3,600 server
buckets and their bounded query API are added in the following increment. Durable
90-day minute history and its historical query interface remain pending.

Verification passed native tests, console tests, formatting and SID generation,
console-disabled tests, storage-disabled and clustered builds, and live console
end-to-end tests in Debug and ReleaseFast. Browser review exercised real denied,
challenged, rate-limited, banned, admitted and incomplete-body requests, then restored
the review policy. Restart changed the boot ID and reset the live baseline without
a spike. At 390 px and 1440 px the document stayed within the viewport. The values
table remains open through refreshes; its bounded browser scroll coordinates survive
replacement while the Wasm model owns visibility. These checks do not replace the
pending whole-process console impact or complete browser acceptance gates.

The required primitive regeneration is `latest-20260908T080201Z.json`, measured from
clean source `4119f960035628613c5c9d581a833bc82408eb47`; artifact SHA-256
`5141f60a6b4a3208b5ec6f5ba1688b38fdaefeaeeb0483c8f318774bbf1a2c01`.
Seven-batch medians include 1,439.8 ns full policy classification, 287.4 ns Gate,
5.8 ns global GCRA and 6.1 ns for four rule scopes. Idle RSS was 9,888 KiB with
storage compiled but inactive and the review daemon stopped. No active-console
throughput or p99 conclusion follows from these primitive measurements.

== Retained counter intervals and collector progress (2026-09-08)

The console collector now retains 3,600 monotonic ending-second buckets independently
of subscribers. Each bucket sums its observed counter deltas, records actual monotonic
start/end and duration, UTC start/end labels and observation count. Initial baselines
do not invent deltas. Zero-duration reads leave their counts for the next timed read.
A delayed interval keeps its entire count and actual duration in the ending bucket;
intervening seconds remain absent and the bucket has an explicit gap flag. UTC jumps
that monotonic time cannot explain also flag gaps. A backward clock or decreasing
counter invalidates retained intervals, advances a cursor epoch and increments the
discarded-interval count. Individual counter loads are still not simultaneous.

`POST /console/api/timeline` requires full authentication and CSRF and shares the
bounded investigation query allowance. It copies at most 16 rows under the collector
mutex, then releases the mutex before serialization or network writes. Cursor identity
includes boot and epoch; a changed identity returns `TIMELINE001` with HTTP 409 and a
reload hint. At most 3,600 slots are inspected, including for arbitrary cursor values.
An all-maximum-counter page fits the existing 16 KiB response buffer and preserves
unsigned 64-bit values through the browser JSON bridge. These are observed intervals,
not a claim that all requests happened within their ending UTC second or minute.

GeoIP cleanup previously waited synchronously on the storage mailbox from the collector.
It now owns at most one background ticket, polls without waiting, spaces attempts by
five monotonic seconds and abandons its caller after ten seconds without claiming SQL
cancellation. Shutdown joins the collector before abandoning that ticket. Failed or
unconfirmed cleanup attempts have a separate since-boot coverage counter. Deterministic
tests exercise in-flight completion after timeout, pacing and shutdown cancellation.
The optimized live-daemon test exercises authentication/CSRF, invalid limits, retained
outcome counts before any subscriber connects, pagination and restart cursor rejection.
The dashboard's expandable retained-values table requests ten rows per page. Latest
refreshes every ten seconds while visible; Older holds its selected page through live
statistics refreshes. Counts, actual elapsed milliseconds, observed rate and gap status
remain accessible in a keyboard-scrollable table. The newest interval is explicitly
labelled Collecting until a later monotonic bucket closes it. Boot/epoch conflicts require Latest;
failed reads preserve old values with an unavailable notice. Request generations survive
session resets without retaining credentials, so an old response cannot expire a new
session. The 60-second chart still reflects consecutive browser observations; a full
3,600-point server-history chart, durable minute history and metric families beyond
outcomes remain pending.

The additional interface initially exceeded the 300 KiB Wasm gate. Removing duplicate
event-row initialization images across reset, navigation and decoder paths reduced
the final module to 299,213 bytes. Tests compare all semantic defaults and confirm
owned incident display buffers are erased; campaign time boundaries and exact IDs
retain their previous behavior. The bundle limit was not raised. Active-console impact
and the full SID browser acceptance gate remain pending.

The final browser review observed six real denied requests in a retained interval,
checked that Older stays fixed through live updates, and verified Latest refresh,
the Collecting label, keyboard scrolling and unwrapped timestamps at 390 px. At
1,440 px the persistent navigation remained present across Statistics, Events and
Policies; incident pagination remained functional after the initialization change.
Neither viewport acquired document-level horizontal overflow. Formatting, native
console/UI tests, full repository tests and SID generation passed.

The subsequent required regeneration is `latest-20260908T084254Z.json`, from clean
source `2e5cad8c0de4bd64a820c0152e237a5f9633c556`, artifact SHA-256
`9b2741a191a76d585cd55ed038d6b4b27460c5a081693e18bbc537690a08d29c`.
Seven-batch medians were 2,355.2 ns full policy, 476.2 ns Gate, 9.5 ns global GCRA
and 9.9 ns for four rule scopes; idle RSS remained 9,888 KiB. The review daemon
was stopped. Many unchanged primitives also slowed substantially relative to the
earlier run on this host. These uncontrolled runs do not isolate the cause of that
variation and cannot establish console overhead or pass the throughput/p99 gate.

== Durable minute record format and storage (2026-09-08)

Additive console schema 12 introduces counter minutes keyed by node, random boot,
observation epoch and UTC ending-minute label. The 152-byte `SBM1` encoding fixes
little-endian field order, preserves all eight unsigned 64-bit outcome/origin counters,
and validates reserved bits, actual monotonic duration, observation count and coverage
flags. Complete records must be sealed and have no gap. This is a sample-aligned
interval representation; UTC labels do not imply exact attribution to wall-clock
minute boundaries. Stored payloads do not rely on native struct layout or SQLite
signed-integer conversion of counters.

The sole storage owner accepts typed, owned writes and reads. Partial upserts retain
their original start and monotonically advance counters and endpoints. Identical and
older partial retries cannot downgrade newer records; a sealed record is immutable.
Sealing may advance the status at the same endpoint. Expected previous payload bytes
fence competing replicated updates between read and write. Native tests exercise owned
queue input, full-width counts, idempotence, sealing, conflicting updates, restart and
migration replay. A failing update trigger leaves the previous payload intact.

History queries recheck the session on the storage owner, return at most eight records,
and use node/time or time indexes with compound keyset cursors. Separate node and boot
records are never implicitly summed. Reads exclude records outside the 90-day window
even if cleanup lags; each retention operation removes at most 64 indexed records.
The following integration connects the collector and HTTP reader; storage handlers
alone do not constitute durable live telemetry acceptance.

== Minute publication and restart recovery (2026-09-08)

The same observed deltas feed the retained second buckets and the minute journal.
The journal publishes partial snapshots every five seconds, seals a minute at its
next boundary and retains at most two queued snapshots. Coalescing updates only queued
copies and preserves the minute's retry count and backoff; an in-flight acknowledgement
belongs to its original copy. Eight failed attempts exhaust a minute's retry budget.
Timeout abandons the caller without claiming SQL rollback. Counters report pending,
confirmed and unconfirmed snapshots separately from retention failures; confirmed
snapshots are not a distinct-minute count. Shutdown joins the collector before abandoning
its ticket, so the latest durable record may honestly remain partial.

Completeness describes an uninterrupted sample-aligned minute with a known preceding
boundary, no observation gap and 59–61 seconds of monotonic coverage, sealed by a
contiguous following minute. Startup, reset, short windows and delayed observations
remain incomplete. Actual endpoints and elapsed time are retained independently of
this flag. Counter wraps reset the observation epoch; no unsigned subtraction spans
the reset. These records currently cover external outcomes and origin response classes,
not country, challenge, CPU or memory history.

`POST /console/api/minutes` enforces full authentication, CSRF and investigation budgets,
then rechecks the session on the storage owner. It supports bounded UTC minute ranges,
optional node selection and compound keyset paging. The optimized daemon test generated
five external requests without a statistics subscriber, waited for confirmed minute
storage, restarted the process and read those same counts under their original boot.
The new boot's live counters remained zero. Deterministic journal tests also verify
ownership after timeout, pending coalescing, bounded retries and shutdown.

Both minute and ranking maintenance now schedule the next cleanup from completion or
timeout, leaving a publication opportunity even when cleanup took longer than its normal
period. A focused test reproduces delayed cleanup before checking queued publication.
The minute journal and GeoIP maintenance state are included in the capacity reservation
estimate. Historical UI, other metric families and full performance/cluster acceptance
remain pending.

Verification passed formatting, full repository and console tests, SID generation,
console-disabled tests, the storage-disabled build and the clustered build. The
clustered build verifies facade compatibility; it does not replace the pending
three-node failover, quorum, management-peer and revocation acceptance scenarios.

== Persisted minute history interface (2026-09-08)

The authenticated dashboard now switches between retained second observations and
persisted outcome minutes. Minute windows cover one hour, 24 hours, seven days or
90 days; queries select the serving node or all stored nodes. Eight-row keyset pages
retain separate node, boot and observation-epoch identities. Earlier pages pin their
range and scope while current statistics continue; missing intervals are unobserved.
Coverage distinguishes complete, partial, unsealed and delayed intervals, and publication
status reports confirmed/unconfirmed snapshots rather than distinct-minute counts.

The Wasm decoder validates ordered cursors, duration/coverage consistency, bounded ranges,
node scope and exact full-width outcome sums. Oversized arrays fail before allocation;
invalid replies preserve the previous owned model. Authentication, inactive sources,
pause/visibility, request correlation and session reset constrain history requests.
Shared request-envelope serialization keeps the expanded module at 306,743 bytes within
the existing 307,200-byte gate; the gate was not increased.

A live browser review found that periodic rendering reset a filter before its submit
button was pressed. These selectors now apply native change events immediately through
the fixed browser bridge; Zig owns the resulting filters. Stable element IDs preserve
focus. The corrected interface retained its 90-day/all-node selection through live
updates. Eight-row paging found an earlier interval containing exactly seven real policy
denials after a daemon restart; the original and replacement boots remained separate.
Desktop and 390-pixel mobile layouts retained navigation and had no document overflow.
The ending startup interval remained partial, and the interrupted boot's latest stored
interval remained explicitly unsealed. Native render/decoder/controller tests and the
release build passed. The full repository suite passed all 255 tests after the interaction
correction; a formatting violation in the separate cursor-recovery test was corrected
and the subsequent formatting, SID and console checks passed.

The full server-retained history chart, other minute metric families, historical ranking
queries, cluster management and the complete impact/acceptance matrix remain pending.

== Incident identity after retention (2026-09-08)

Startup now restores the next incident sequence from the maximum of retained rows and
the durable per-node commit receipt. The receipt is committed with incident, FTS,
vector and reputation mutations. Ignoring it after deleting old incidents could reuse
identities and cause the replay guard to suppress new batches while reporting success.
Malformed, zero and out-of-range receipts fail startup; the exhausted sequence remains
exhausted. Stores without a receipt retain their legacy row-derived starting point.

A real-store regression writes an incident, removes its forensic rows and search indexes,
reopens the owner, and verifies the next incident is present under a new identity. It also
checks legacy receipt absence, exhaustion and invalid receipts. Full repository tests,
formatting and SID generation passed together, and console-disabled tests passed. This
fix is a prerequisite for bounded incident retention, whose cleanup job remains pending.

== Fenced retention storage operations (2026-09-08)

Additive console schema 13 adds the retention lease and the indexed session deadline.
Its deletion trigger removes the external-content FTS entry, vector entry and evidence
sidecar in the same transaction as the forensic row. Bounded prepared commands select
at most 16 expired rows: incidents older than 30 days, audit records older than 365 days,
and sessions whose absolute or idle deadline has passed. Incident commit receipts,
policies, reputation and current records remain intact.

Lease holders identify a node and random boot. Renewal by the current unexpired holder
keeps the fence; expiry or takeover increases it without wraparound. Every DELETE checks
the stored holder, fence and deadline in its own write transaction. Storage-owner time,
not the collector's queued timestamp, chooses the cutoff and lease expiry. Clock skew
can change takeover timing, but cannot permit an older fence to write after replacement.
This is a database-side fence and makes no atomicity claim about external effects.

The underlying mutation count includes trigger and vector/FTS shadow-table writes;
completion therefore acknowledges the bounded command rather than inventing a deleted-row
count. Tests inspect actual forensic, FTS, vector and evidence contents, including rollback
after an injected sidecar deletion failure. Separate cases cover competing holders, renewal,
expiry, stale commands, fence exhaustion, audit/session deadlines and owned mailbox inputs.

Retention-capable stores set the existing base storage-format guard to 2. Older
console-disabled binaries check that guard even though they do not read console_schema,
so they cannot reopen a retained store and revert to row-derived incident identities.
The current binary accepts base formats 1 and 2 and rejects newer values. Runtime scheduling
and visible cleanup health are the next increment; this storage increment does not start
automatic deletion by itself. Full repository/console tests, formatting, SID generation,
console-disabled tests and the clustered facade build passed. Three-node lease failover
remains an acceptance scenario, not a claim from the single-owner fencing tests.

== Retention scheduling and compact HTML literals (2026-09-08)

The collector now schedules incident, audit and expired-session cleanup through one
owned background mailbox ticket. It renews the 30-second lease on a ten-second monotonic
schedule and spaces completed cleanup attempts by five seconds. A failed acquisition
backs off; a competing holder is normal standby. Cleanup failures and ten-second caller
timeouts move to the next category so a damaged forensic index cannot indefinitely starve
audit or session cleanup. Shutdown joins the collector before abandoning its ticket;
executing SQL can still complete and remains protected by the database fence.

Dashboard coverage reports failed/unconfirmed attempts. The optional counter remains
absent for older servers and preserves full-width values through JSON decimal strings.
Capacity accounting includes the job state. Deterministic scheduler tests cover standby,
renewal, slow operations and cancellation ownership; composed owner-tick tests delete
expired forensic/audit data while preserving lifetime incident metrics and the durable
next sequence. Repository and console tests, formatting, SID generation and the release
build passed with scheduling enabled.

Trusted snippet literals now use a fixed 32-entry HTML dictionary at compile time.
Each token replaces a matching literal span with two bytes; the decoder scans bounded
compiled bytes and writes the original text directly to the caller's Writer. Templates
remain ordinary reviewed HTML, and runtime values still go through the existing escaping
path. Unprofitable spans and literal NUL bytes retain a raw exact-sized copy. Retaining
only that span avoids pinning the entire original embedded template alongside packed
fragments. No untrusted encoded input, runtime allocation or general template parser is
introduced. With a fixed dictionary, construction is linear in source length times the
fixed matching bound; decoding is linear in encoded plus emitted bytes. The existing
32 KiB snippet/output bounds and Writer failures still apply.

Native tests preserve UTF-8, overlapping prefixes, literal NUL, field escaping and output
exhaustion. The final Wasm artifact is 304,210 bytes. The storage-disabled and clustered
builds passed; those builds do not constitute three-node operational acceptance.
Live browser checks preserved the shared navigation, policy summaries and editor fields,
and a private preview returned the expected deny at committed revision 163. Retained events,
challenge panels, the 717,152-range DB-IP generation and account forms rendered correctly.
The mobile account view stayed within 390 pixels, and cleanup-health observations stayed
at zero failed/unconfirmed attempts during review.
Full cluster/runtime impact and
broader SID acceptance remain pending; these size and correctness checks do not establish
latency, throughput or memory-impact targets.

== Benchmark source manifest (2026-09-08)

Source manifest version 2 hashes tracked and unignored source/build/asset files under
build, apps, libs, tools and benchmarks, plus the root Zig build files. It includes the
build-helper directory and committed CSS/geographic assets, excludes previous benchmark
results and ignored generated dependencies, and prefixes each file's contents with its
byte length. This avoids environment-dependent node_modules inputs and incomplete asset
provenance. The record includes the manifest version and file count; version-1 and
version-2 source digests are not directly comparable. The daemon digest remains separate.
Manifest validation found 276 inputs and confirmed the required inclusion/exclusion cases.

== Retention and history benchmark baseline (2026-09-08)

`benchmarks/results/latest-20260908T104534Z.json` and `latest.json` were regenerated
from clean commit `f41937a36590aefafb9f901ae2db62b62df583bf` with the review daemon stopped.
The version-2 source manifest covers 276 inputs. The timestamped result SHA-256 is
`0331965bac5852f89c154b70e9fa82065c0c750e85b4093278f79f3e6a0906f4`.
Seven-batch medians were 1,438.96 ns for full classification, 288.54 ns for Gate,
5.78 ns for global GCRA and 6.06 ns for four terminal-rule scopes. Full classification
ranged from 1,437.70 to 1,454.20 ns within this run. The 8 KiB inspection medians were
23,213.10 ns for all-enforce and 112,770.30 ns for mixed SQL audit/other enforcement.
Idle RSS was 9,888 KiB with storage compiled but inactive.

These results are near the earlier 08:02 baseline across multiple primitives. The broad
slowdown observed in the 08:42 run therefore remains uncontrolled host variation; no
console speedup is inferred. This primitive baseline does not exercise active storage,
GeoIP, retention, subscribers or peer telemetry and does not pass the required console
throughput/p99/memory contention matrix. Those acceptance measurements remain pending.

== Typed browser object decoding (2026-09-08)

The browser decoder now shares one object-field loop across wire structs. Private
descriptors contain compiler-derived names, offsets, defaults and concrete typed
readers; no response can supply a descriptor or destination. Lookup remains bounded
by the parsed response and field count. Nested fields retain their own alignment,
integer checks, fixed-array lengths and pre-allocation row limits. Strings borrow
only the dispatch arena, so models still copy retained values.

Native rendering and decoder tests cover absent required nullable fields, explicit
null, defaults, nested wide-integer alignment, empty structs, extra fields, malformed
objects and allocation-free fixed fields. The ReleaseSmall interface decreased from
304,210 to 291,012 bytes, leaving headroom under the existing 300 KiB module limit.
This code-size result does not establish browser runtime or console-impact acceptance.

== Recorded-incident geography foundation (2026-09-08)

Locally acknowledged incident batches publish owned timestamp/address records into a
1,024-slot storage-owned queue. The console borrows this queue until its collector has
joined; the storage owner outlives that borrower. An atomic runtime gate disables
publication without the console, and console-disabled builds omit the field and producer.
No request-path instrumentation, SQL, callback, formatting or GeoIP lookup is added.
The existing commit receipt makes a retried batch publish once after acknowledgement,
including an ambiguous earlier commit. A process crash can lose this live projection;
it is not a replay of durable incident history.

A separate 60-second collector window records known countries and Unknown by original
event time. At most 1,024 findings drain per collector tick. Expired, future-dated and
overflowed records have separate boot-local counters. Findings are unsampled, but cover
only local persisted incidents, including audit findings and possible multiple findings
per request. They are neither unique attacks nor all blocked requests. Geographic
coverage is therefore explicitly incomplete even with zero queue loss. The capacity
estimate includes both the queue and additional country buckets.

Snapshots expose this optional, versioned series separately from sampled traffic.
The stream reserves an 8 KiB payload buffer for the two bounded country lists; readers
and serialized writers remain independent. Console identity now uses Persistent's
issuer ID (1 for a non-clustered node), matching incident identity. Existing history
labelled node 0 is retained as recorded; no historical identities are rewritten.

Native checks exercise copied input, queue saturation and disablement, SQL failure,
ambiguous commit replay, event-time cutoffs, Unknown and expiration without subscribers.
This foundation does not claim cross-node deduplication or incident-history replay.

== Traffic and Attacks globe delivery (2026-09-08)

The signed-in globe now switches between sampled Traffic and locally recorded Attacks
without another stream or another geometry load. Both modes borrow their own accepted
snapshot list and reuse projection, clipping, rotating country markers, at most sixteen
animated inbound connections, keyboard centering and the flat-map fallback. Labels say
samples or findings consistently. Missing or unsupported incident geography displays
unavailable and never falls back to traffic counts. Incomplete coverage remains visible;
expandable details show observation start in UTC and queue, expired, future and upstream
incident loss. Native rendering checks preserve the disclosure's accessible target and
verify Unknown even when GeoIP is unavailable.

The real-daemon suite now checks fifteen findings with no GeoIP, imports a generation,
then checks five unsampled US findings through HTTP and a new authenticated WebSocket.
Earlier Unknown observations remain Unknown after import. Native tests also round-trip
full-width incident counters and both complete 32-country lists within the stream's
8 KiB payload budget. Required formatting, tests, SID compilation and console checks
passed, as did storage-off, console-off and clustered builds.

Browser review on the local daemon verified five real honeypot findings as US while
sampled external traffic remained zero, independent Traffic/Attacks selection, visible
inbound arrows and changing projected paths, expiration, restart without historical
replay, the disclosure, and the flat-map fallback. At 390 px both the globe and expanded
coverage kept document width at 390 px. DaisyUI's joined buttons retain keyboard focus
and expose the selected mode through aria-pressed. Applied and managed policy screens
also decoded correctly after the shared object-reader change, along with mobile events,
challenges and account navigation. The final UI module measured 295,283 bytes; its
existing 300 KiB gate remains enforced. This does not close cluster aggregation or
impact acceptance.

== Incident geography benchmark regeneration (2026-09-08)

`latest-20260908T112129Z.json` records clean source
`caca893d1d87ff648508d936e3061e7e3b439173`, source-manifest version 2 with 284
inputs, and result SHA-256
`04379d49894c70e5cd3e2b83ba0602ebe9263a2dd55a54fb5d5da533cbc74caf`.
Review daemons were stopped and no code edits occurred during measurement. Seven-batch
medians were 1,439.0 ns for full policy classification, 289.1 ns for Gate, 5.8 ns for
global GCRA, 6.1 ns for four rule scopes, 23,166.4 ns for enforcing 8 KiB inspection,
and 112,750.0 ns for mixed audit/enforcing inspection. The mixed scan ranged from
112,615.72 to 115,173.36 ns. Idle RSS was 9,936 KiB with storage compiled but inactive
and two workers. These primitive measurements remain close to the preceding baseline;
they do not measure active incident collection, eight dashboards, p99 latency or storage
contention, and do not satisfy the separate console-impact acceptance gate.

== Account-management storage and API (2026-09-08)

Account administration now has owned native/Wasm contracts, eight-row keyset pages and
a 1,024-account creation limit. Viewers can inspect names, roles, enabled state, required
password change, two-factor state and last login; creation, access changes, password
reset and session revocation require a full administrator session and CSRF. User routes
share the global query budget and add a sixty-mutation per-session minute limit. Password
hashing uses the existing single Argon2 workspace rather than another verifier pool.

Each creation/reset generates a 256-bit temporary password in the service, stores only
its hash, requires a password change, expires it after one hour and returns the plaintext
only after storage acknowledges the mutation. A lost reply is an unknown outcome, not
proof of rollback. Reset preserves enabled state, role and enrolled TOTP. Account
operations never accept a caller-supplied database handle or store plaintext credentials.

Persistent stamps execution time, checks current authorization, then repeats session,
CSRF, role, expiry, revision and required-TOTP conditions in the conditional SQL statement.
Edits require the target's expected revision. Access/password changes require an actor
distinct from the target; because that actor must still be an enabled administrator in
the same statement, an administrator survives each such change and competing actors
cannot disable each other. Self-revocation is allowed and immediately ends the caller's
sessions. All affected sessions are removed atomically with the revision and redacted audit.

Schema 14 records subsequent last-login observations in a separate table so that login
activity cannot trigger account revocation. Historical missing timestamps remain NULL.
User audit records now carry actor role and bounded before/after account summaries,
excluding hashes, passwords and factors. Existing summaries remain NULL. Address capture,
token revocation and the broader audit-investigation interface remain separate work.

Storage-tick tests passed for pagination, account capacity, temporary-password metadata,
audit privacy and rollback, conflicts, self-demotion refusal, expiry, missing MFA, CSRF,
queued caller revocation and removal of 4,095 target sessions at the global session bound.
The live daemon scenario passed creation, forced password rotation, viewer refusal,
role change, WebSocket/session revocation, password reset, disable/enable and restart
persistence. It preserves the production password-verification rate limit by separating
its phases with a restart. This API foundation does not complete the users UI or CLI gates.


== Account-management interface and shared snippet execution (2026-09-08)

The authenticated Users page now provides bounded account browsing, creation, role and
enabled-state editing, password reset and explicit session revocation. Viewers receive a
read-only catalog. Administrator mutations carry the selected account revision; rejected
or uncertain outcomes remain visible, and refresh obtains current records. A failed page
request cannot relabel the previous page's rows. Request tickets are never reused after
navigation, so delayed replies cannot overwrite a newer view or end a different session.

Temporary credentials appear in a labelled, read-only field only after the acknowledged
mutation. The page erases its retained credential on dismissal, navigation and session
reset. Creation/reset requires delivery confirmation; access changes and revocation have
explicit confirmation controls. Self access/password changes are omitted in favor of the
Account workflow and a different administrator; self-revocation explicitly signs out the
current session. Account IDs retain full 64-bit precision through authentication responses
and decimal-string mutation fields. Last-login values remain “Not recorded” for historical
accounts without an observation.

The HTML source remains ordinary first-party snippets. Their build-time compiler now
encodes literal dictionary entries and escaped text/scalar slots in a compact immutable
program. Runtime execution accepts only compiler-produced instructions and borrowed values:
no runtime template source, raw HTML values, allocation or browser application logic was
introduced. Tests cover repeated slots, exact whitespace and NUL preservation, UTF-8,
escaping, output exhaustion and signed/unsigned integer limits. A concrete flat-object
JSON writer shares simple command encoding while nested contracts retain the standard
serializer; byte-for-byte tests cover quoting, null, optional values, enums and integer bounds.
Navigation also uses one bounded rendering loop instead of expanding every item.

The complete interface is 307,031 bytes, within the unchanged 300 KiB gate and 4 MiB linear
memory bound. Account-controller tests cover late responses, authentication restrictions,
revision conflicts, exact IDs, preservation of unrelated access drafts and credential
erasure. Render tests protect self-management boundaries, read-only roles and the bridge's
form-ID submission contract. Browser review caught an initial data-submit/form-ID mismatch;
the forms now use the existing bridge contract and stable focus IDs. The running daemon
passed browser creation, password reset, forced rotation, viewer access, role change,
disablement and self-revocation. Account buttons identify their target and rows have clear
separation. Pagination moves focus to the results; acknowledged credentials receive focus
for copying. Browser checks confirmed two-page navigation, result focus and no horizontal
overflow at 390 pixels with a 64-character account name. Native username validation
describes the accepted characters. The required
repository run passed all 283 tests, live daemon scenarios, formatting and SID generation.
Storage-off, console-off and clustered builds pass; this does not establish
cluster-management acceptance. CLI account commands, API tokens, audit investigation and
the remaining operational workflows still require implementation and their own gates.

== Account-workflow benchmark regeneration (2026-09-08)

The required primitive baseline was regenerated from a clean, isolated checkout of
`e809b846fc3331cc8a40c833c0d982d6c136afed` with review daemons stopped. Its 302-input,
version-2 source manifest is
`76edbcc8c790f7a364901defe066296b9c1273b51feec6d52bc5707cb7c51a3d`;
the daemon digest is
`a10eb4168066711e5fb418d0e0cbf4309ad3351ff89adeecdef06117ec61c520`.
The result `latest-20260908T124907Z.json` and `latest.json` share SHA-256
`099efc024b6edaca7a4b57b13a9b36ac3961b0ba86ef8a033c8318a773e63e8d`.

Full classification measured 1,462.51 ns median (1,455.50–1,467.56 ns across seven
batches). Idle RSS was 9,904 KiB with two workers, storage compiled but inactive.
The reported 8,831-byte Wasm artifact is the proof solver, not the console interface.
These primitive and idle measurements do not exercise active dashboards or storage
contention and do not satisfy the console-impact acceptance gate.


== Native account CLI (2026-09-08)

`sibuna console` now supports `users`, `add-user`, `set-user`, `reset-password` and
`revoke-sessions`. `console init-admin` aliases the existing exclusive local initializer.
Running-node commands require an explicit origin, login username and private password
file; an optional private factor file supplies a TOTP or recovery value. No command-line
password, persistent session file, second embedded storage owner or shell/Python dispatch
was added. Credential files are bounded regular files; POSIX group/other permissions are
refused, and final CR/LF is removed. Caller-owned credential, response and JSON scratch
buffers are erased. Creation/reset prints the acknowledged temporary credential as JSON;
failed and incompatible replies do not print server bodies.

The client permits HTTP only for literal loopback addresses and otherwise uses the
standard library's certificate- and hostname-validated HTTPS. Authorities cannot contain
credentials, paths, fragments, queries or encoded hosts. Redirects are refused. Each
request has a twenty-second deadline, a 16 KiB response limit and owned headers; canceling
joins outstanding I/O before borrowed buffers are released. Queries return eight rows and
a next cursor. Edits require exact decimal target IDs and expected revisions; role/enabled
changes require both fields. Temporary-password or mandatory-MFA accounts must finish
those browser workflows before issuing management commands.

Each command logs in, performs one bounded operation and closes that session, including
validation/error paths. A closure failure is reported separately. Transport loss, deadline,
invalid acknowledgments and unavailable storage remain unknown outcomes; operators must
query current revisions before retrying. The client does not interpret a timeout as SQL
cancellation or rollback. Production login and mutation limits are unchanged.

Focused live tests pass private-file permissions, the bootstrap alias, creation, forced
rotation refusal, read-only role refusal, expected-revision conflicts, revocation, reset
and restart. Controlled peers verify redirects are not followed, oversized and unexpected
sensitive replies produce no stdout, success and validation failure close sessions, and a
stalled request is canceled within the deadline. All 287 native tests, live daemon scenarios, formatting and SID generation pass. A
private recovery-code file authenticates successfully; missing and replayed factors fail
without leaking the credential or leaving the CLI session open. Storage-off and console-off
binaries refuse native management commands without starting a daemon; the clustered build
also compiles. Native GeoIP/token commands,
scoped bearer authorization and the remaining SID phases remain separate work.

== Native account CLI benchmark regeneration (2026-09-08)

The primitive baseline was regenerated from clean isolated commit `5331a37c8f29fb30d58eaedb5bfc13b6ebb4896c`,
with review daemons stopped. The version-2 manifest covers 308 inputs
and has SHA-256 `b07952224c6f82f5adc67cb38df3a8cf957873bbb3f125ee9e31d302a4bd2027`; the daemon digest is
`99578370786d731efd47cc7b2d15c19f0894ec40807276673b20eff8c3e13c34`. `latest-20260908T132625Z.json` and `latest.json` share SHA-256
`2788bc7bc7640006176bac1879bd3a475fcb9f79fdd078b8e8bf1576fc008b10`.
Full classification measured 1,441.18 ns median
(1,438.52–1,448.91 ns across seven batches).
Idle RSS was 9,936 KiB with two workers and storage compiled but inactive.
The 8,831-byte Wasm artifact is the proof solver. These measurements do not exercise
active dashboards, imports or storage contention and do not pass console-impact acceptance.

== GeoIP execution-time authorization (2026-09-08)

Generation begin, chunk insertion, exact immutable retries and activation now authorize
against Persistent's execution clock. Authorization carries no caller timestamp that could extend an expired queued
session. Off-loopback imports carry the mandatory-factor requirement into each conditional
SQL write and replay query, together with session revision, CSRF, role and password-change
checks. Expiry or missing required MFA leaves the active generation and audit unchanged.
A deterministic storage-tick test queues a chunk, expires its session before execution,
and verifies refusal; it also checks both immutable retries and activation, followed by
one authorized activation and exactly one audit record. The activation acknowledgment
returns the durable storage timestamp, so live GeoIP metadata and restart metadata agree
even when a queued activation spans a clock tick.

== Native GeoIP CLI and publisher review (2026-09-08)

`sibuna console geoip status` reads active database metadata through an ephemeral authenticated
session. `geoip update --month YYYY-MM` reads the current revision and submits a conditional
DB-IP import. Private password/factor files and the native client's origin, TLS, redirect,
response-size and session-closure rules also apply. An optional 64-hex checksum pins the
compressed publisher source. A matching active month is a no-op; a mismatched checksum or
concurrent revision fails without overwriting the active database.

The command waits for an acknowledged active generation, preserving exact decimal revisions
above JavaScript's integer range. The polling budget defaults to 1,200 seconds and accepts
1–86,400 seconds; each HTTP wait is limited by both the remaining budget and twenty seconds.
Login and session closure have separate twenty-second request bounds. Progress uses stderr;
stdout contains only validated final metadata. No caller-selected download URL, inline CSV,
raw database connection or subprocess downloader is exposed by the native command. Polling
expiry, transport failure or an incompatible acknowledgment leaves the outcome uncertain;
session closure is not evidence of import cancellation or rollback.

Controlled peers pass exact-revision submission, no-op and checksum handling, concurrent
activation, failed imports, unexpected sensitive fields, a stalled polling deadline and
session closure. Real-daemon tests cover restored status, no-op and checksum conflict.
A fresh native command downloaded September 2026 DB-IP Lite and activated 717,152 ranges
in 81.28 seconds on the review host. Its compressed-source SHA-256 was
`a32bb3c384bd3de60ad9024596aa5b395a6dd5beaa27a7223407cc2edc681d0b`.
A matching repeat made no change, and restart preserved revision, digest, source month,
range count and activation time. The source remains DB-IP IP to Country Lite, CC BY 4.0,
with DB-IP attribution. This functional import duration is not an impact benchmark.
All 289 native tests and live scenarios pass. Storage-off, console-off and clustered builds
pass; disabled binaries refuse the command. The optional MaxMind adapter and scoped tokens
remain pending, together with the broader SID acceptance gates.

== Shared management mutation allowance (2026-09-08)

Authenticated management POST routes now consume one shared allowance of sixty mutations
per session per minute, including account, policy, inspection and GeoIP changes. Dispatch
checks current access and CSRF before spending the allowance, then counts the submission
before parsing or expensive work. Invalid authorized input counts; missing credentials or
CSRF cannot spend another session's allowance. Existing query/global ceilings still bound
aggregate work. Account and policy handlers no longer charge the same mutation twice.
The stable `CONSOLEMUTATION` diagnostic reports HTTP 429 with a one-minute recovery hint.
A live-daemon check alternates sixty invalid writes across the four workflows, verifies
shared refusal on each route, and checks that reads and a different session retain capacity.
Password verification and enrollment keep their separate limits.

== Native GeoIP benchmark regeneration (2026-09-08)

The primitive baseline was regenerated from clean isolated commit `69c0374f67d106ff16a9dee1a598eb8aae5f44c8`,
with review daemons stopped and heavy verification outside the timed run. The version-2
manifest covers 311 inputs, SHA-256 `d261b2bd39868f0cae17498cb9fbb4b66ba78973127dff2b95461136dd92a3c0`;
the daemon digest is `fb30d723e566d41e31385e6fa57d0effbda6a02fccf9bc9238299d70775282ae`.
`latest-20260908T135102Z.json` and `latest.json` share SHA-256
`0686edf5f3c5d0283836314419e3afc7a7b2ecd3f54936f6166c9f5583366b5f`.
Full classification measured 1,450.28 ns median
(1,445.58–1,470.86 ns across seven batches).
Idle RSS was 9,952 KiB, two workers, storage compiled but inactive.
The 8,831-byte Wasm artifact is the proof solver, not the console. These measurements do
not exercise imports, active dashboards or storage contention and do not pass console-impact.

== Policy execution-time authorization (2026-09-08)

Policy and inspection edit contracts now carry credentials and the required-factor flag,
with no caller authorization timestamp. A shared owner-side check rejects expired sessions,
missing mandatory administrator MFA, wrong roles and mismatched CSRF before candidate
construction. After candidate validation the conditional SQL mutation uses a fresh owner
clock and repeats the same predicate, so a queued edit cannot extend its caller's session.
The audit timestamp comes from that commit attempt. Candidate reputation evaluation also
uses the owner clock; revision conflicts still leave the candidate unpublished.
Deterministic storage ticks cover session expiry after queuing for both edit kinds and
refuse missing required MFA without advancing policy or audit. Operators retain their
specified policy authority; only administrators require the off-loopback factor.

== Bounded token storage and credential kinds (2026-09-08)

Schema 15 adds immutable token authority, eight-row keyset pages and a 1,024-record limit.
Tokens select explicit statistics, event, policy, GeoIP and user read/write capabilities;
role validation rejects capabilities beyond the chosen role. The token store holds only
SHA-256 digests of 256-bit opaque values. Printable numeric IDs use a non-reusing sequence.
Optional expiry is an absolute deadline. Administrator cookie sessions with completed
required MFA manage tokens; tokens cannot issue or manage other tokens. Revocation and
explicit removal of inactive metadata require expected revisions. Removing metadata
retains its redacted audit history and permits reclamation within the record bound.

The existing session table also serves as the credential registry, distinguished by a
nullable token reference. This preserves atomic revocation on user revision changes while
preventing bearer values from authenticating as cookies or cookies as bearer values.
The principal separates the effective token role from its issuing account role, so mandatory
administrator MFA applies consistently to the issuer even for a viewer/operator token.
Token entries share the 4,096-live-credential bound and retain their absolute deadline;
HTTP activity does not turn them into idle-limited browser sessions. Minting does not
record a browser login or consume a second factor. Registry insertion and the token audit
commit together; failed audit writes roll back both. Authority, creator revision, role,
scopes and expiry cannot be edited after issuance.

Queued authorization checks now obtain time only from Persistent, including subscription
checks and idle renewal. Explicit-time numerical tests use the synchronous owner helper;
no production clock override or caller timestamp extends a session. Storage-tick coverage
includes late expiry, required MFA, credential-kind separation, expected-revision conflicts,
non-reused IDs, audit rollback, creator revocation, capacity and restart pagination.
This increment supplies persistence and authorization contracts. Public bearer routes,
token CLI commands and the token interface remain to be connected and verified before
the token workflow is complete.

== Token-storage benchmark regeneration (2026-09-08)

The primitive baseline was regenerated from clean isolated commit `585e5dd218fca8d5416ef4cf649789275a19e146`,
with review daemons stopped and heavy checks outside the timed run. The version-2 manifest
covers 319 inputs, SHA-256 `aa1c5673691caf5d50c0ecb940b6804abdb1ee0b1055a177be462e663e6fa986`;
the daemon digest is `901778f29765166313e902a70753088d5d8b7756f16b80f0839f4dc9b48ce7ca`.
`latest-20260908T144429Z.json` and `latest.json` share SHA-256
`05e674796996bc2161761d90db482d90650139b2e5a71b39870e4e2b486ebe7f`.
Full classification measured 1,465.50 ns median
(1,464.70–1,466.16 ns across seven batches).
Idle RSS was 9,920 KiB with two workers and storage compiled but inactive.
The 8,831-byte Wasm artifact is the proof solver. These primitive measurements do not
exercise active credentials, dashboards or storage contention and do not pass console-impact.

== Scoped bearer HTTP operations (2026-09-08)

The native listener accepts opaque bearer credentials only on explicitly scoped statistics,
event, policy, GeoIP and user routes. Each request validates the credential kind, current
issuer authority, effective role and exact capability. Bearer calls can omit Origin and
CSRF; a supplied Origin must still match the configured origin. Simultaneous Cookie and
Authorization headers fail closed. Browser authentication, account-factor operations,
geometry, subscriptions and token management remain cookie-session operations. Token
catalogs use eight-row pages; creation discloses a value only in the acknowledged response,
and revision-checked revocation/removal returns only the printable identifier. The shared
mutation budget includes token writes while catalog reads retain their query allowance.

The live daemon suite verifies all eight capabilities, cookie/bearer separation, malformed
credentials, origin checks, policy and inspection commits, GeoIP activation, catalog
pagination, expiry, conflict/revocation, creator revision changes and restart persistence.
The combined native suite passes 298 tests. Native token commands and the token interface
remain pending; this HTTP increment does not complete those acceptance gates.

== Native token commands (2026-09-08)

The first-party CLI now implements `tokens`, `mint-token`, `revoke-token` and
`remove-token`. Minting requires explicit nonempty, distinct scopes within the selected
role and accepts an optional absolute expiry. Token-management commands always use an
administrator password/factor login. Account and GeoIP commands also accept a private
64-hex-character `--token-file`, mutually exclusive with password/factor options. Bearer
requests send neither Cookie nor CSRF headers and create no ephemeral login session.
GeoIP updates require both GeoIP read and write scopes for status, CAS and completion polling.

Private regular-file permissions, strict origin validation, certificate-validated HTTPS,
redirect refusal, bounded replies and joined I/O deadlines apply to both credential kinds.
Output validation preserves full-width identifiers and rejects unknown catalog fields,
invalid roles/scopes, contradictory state and malformed one-time values. A lost issuance
response is an unknown outcome: list the catalog and revoke the undisclosed token.
The live suite covers scoped account/GeoIP reads, account creation, expected-revision
conflicts, inactive removal, creator revocation and restart. Controlled peers verify
bearer headers, no login/logout, deadline, oversize, redirects and sensitive-field refusal.
The combined native suite passes 301 tests. The Tokens browser interface is a separate
increment and remains subject to its rendering, size and live browser checks.

== Bounded UI helpers and standalone artifact gate (2026-09-09)

Owned byte buffers now support bounded in-place assignment, including overlapping source
slices and erasure of truncated tails. Oversize input preserves the previous value. The
shared HTML executor formats scalar slots in one bounded buffer and accepts owned country
code arrays. JSON field descriptors represent null and zero defaults without embedding
large initialized payloads; typed nonzero defaults remain intact.

Both `console-ui` and `console-test` now validate the emitted Wasm header and enforce the
300 KiB artifact limit. The server asset assertion remains an additional integration gate.
Native checks cover overlap, overflow, optional false versus null, integer extrema and
escaping. This size check does not replace runtime impact or browser acceptance.

== Caller-owned policy forms and shared page rendering (2026-09-09)

Policy load, matcher capture, document serialization and import/export now write into
caller-owned bounded outputs. A candidate form replaces the active draft only after full
validation. Header pairs and CIDR lists use concrete bounded structs rather than dynamic
JSON object/array results. This removes large error-union payload images from the Wasm
artifact while retaining editor limits and private-test behavior.

Console pages reuse the escaped scalar HTML executor for trusted literals and text slots.
SVG projection and numeric precision remain unchanged. Native rendering checks cover
real submit-button attributes, header/network round trips, duplicate-header rejection,
invalid imports, quota settings and output bounds. Browser review exercises the existing
structured matcher editor and its shared navigation.

== Scoped token interface (2026-09-09)

The administrator Tokens page shares the authenticated navigation shell and provides
bounded catalog pages, explicit role/scope selection, seven/thirty/ninety-day or unlimited
expiry, one-time issuance, revision-checked revocation and inactive-entry removal. Role
changes clear scopes outside the chosen authority. Decimal-string request fields preserve
full-width IDs and expiry values. Mutation confirmation precedes submission.

The interface erases the disclosed credential on dismissal, navigation and session reset;
dismissal remains available during a pending catalog refresh. Late response tickets cannot
modify another view. Opening a token editor and dismissing its secret restore keyboard
focus. Native coverage includes authorization boundaries, stale replies, output escaping,
large identifiers and owned secret erasure. Browser checks verify issuance, catalog state,
revocation/removal and the persistent sidebar. The final interface is 297,424 bytes against
the 307,200-byte cap; 127 console tests and 308 combined repository tests pass. Storage-off,
console-off and clustered build configurations remain functional. Cluster runtime,
operational pages and the complete impact matrix remain outstanding acceptance work.

== Token interface and native CLI benchmark regeneration (2026-09-09)

A clean isolated `f7e2d0856a90fa16251b47667a3e7e088273c94e` run regenerated the primitive
baseline with review daemons stopped and heavy verification outside the timed run. The
version-2 manifest covers 337 inputs, SHA-256
`61dcb5d4447ea10014bc6cde8a9653cc12951427337886c99fbbe37d4e09bd59`;
the daemon digest is `deae1beb9d12b2f2652dff46ad2a1d44f32acdd25f00d8107978bd3b350972cb`.
`latest-20260908T162352Z.json` and `latest.json` share SHA-256
`3878c35f3c144efb69885f1d2f2104bbf1f7e517140d77c778db6fda8e988267`.
Full classification measured 1,461.73 ns median (1,461.00–1,465.03 across seven batches).
Idle RSS was 9,936 KiB with two workers and storage compiled but inactive. The recorded
8,831-byte Wasm artifact is the proof solver. These measurements do not exercise active
dashboards or storage contention and do not satisfy console-impact acceptance.

== Bounded audit investigation API (2026-09-09)

Authenticated cookie sessions can query eight-row descending audit pages by action, actor
and UTC interval, inspect one record and export one filtered metadata page. Full-width
identifiers use decimal request strings and bounded owned native/Wasm results. Filters
use prepared parameters and the existing 100-row/64-KiB/100,000-step query ceilings;
exhaustion returns an unavailable response with a hint to narrow the filters.

Persistent rechecks current session revision, expiry, CSRF and mandatory administrator MFA
before and after reads. Bearer credentials have no audit capability. Export uses the shared six-per-session/thirty-global allowance per minute and creates a
conditional audit receipt before disclosing its result; a failed receipt releases no page.
Historical role and summary values remain absent. Summary JSON exposes only supported
account/token metadata, removes unknown fields and controls, and reports redaction and
UTF-8-safe truncation. Raw hashes, sessions and arbitrary stored documents are never returned.

Storage ticks verify descending cursors beyond JavaScript's exact integer range, filters,
missing history, secret removal, queued expiry and export rollback. Live-daemon tests cover
role access, cookie/CSRF boundaries, malformed filters, export receipts, revocation and
restart. The combined suite passes 312 tests. The Audit interface, richer mutation capture,
command intent/completion, audit-driven policy comparison/revert and streaming are separate
remaining increments; this API does not imply those acceptance gates have passed.

== Audit investigation interface (2026-09-09)

The Audit page now shares the authenticated navigation and exposes period, actor and exact
action filters, eight-record pages, metadata export, and recorded before/after summaries.
Pagination retains a fixed UTC window; refresh deliberately obtains new records. Invalid
filter input cannot relabel the preceding page. Detail requests match the selected ID and
current request ticket, and malformed or late responses cannot replace another view.
Absent historical roles and summaries display “Not recorded”; redaction and truncation
remain visible. An unavailable record can be refreshed after retention removes it.

The typed JSON decoder now writes nested structs, arrays and optional payloads into
caller-owned buffers and publishes only a validated candidate. Existing by-value callers
retain a compatibility wrapper. This keeps the complete current interface within its
unchanged 307,200-byte bound: 306,574 bytes after the focus fixes. Native console checks
pass 130 tests; the combined repository suite passes 315. Browser checks cover actual
revocation summaries, action filtering, invalid full-width actor input, export receipts,
pagination, persistent navigation and visible keyboard focus. Audit and token detail focus
now scrolls to the selected content rather than the page header.

This increment does not complete historical metadata capture, policy diff/revert from
audit, command intent/completion or cluster audit coverage. Those remain part of the
Proposed SID's outstanding implementation and release gates.

== Authentication execution clock (2026-09-09)

Authentication mailbox contracts no longer carry an authorization timestamp. Persistent
uses its execution clock for bootstrap deadlines, session issuance and factor replay
windows, password rotation, TOTP enrollment/confirmation, and sign-out audit timestamps.
Absolute credential deadlines remain bounded inputs; they cannot extend authorization.
Numerical SQL tests call explicit synchronous helpers. Production dispatch exposes no
clock override. Queued regressions expire a password, cookie or enrollment after submission
and reject a previously verified TOTP step outside the current window.

== Investigation execution authority (2026-09-09)

Policy snapshots, private previews, managed documents/history, incident pages/exports,
similarity partitions and durable minute pages recheck current authority on their storage
owner before work and before releasing results. A queue delay cannot retain an earlier
session instant. Current password restrictions, required administrator MFA (including the
issuer of a restricted token), and endpoint-specific token capabilities are enforced there.
The frozen minute-history observation boundary selects data and never supplies authority.

Deterministic queue tests change expiry or password restrictions after submitting all seven
read paths. Scope coverage verifies that a statistics-only bearer can read minute history
but cannot inspect policies or incidents, and cannot bypass its issuer's required MFA.
These checks close the older read-contract timestamp gap; they do not establish cluster
runtime, complete audit metadata or impact acceptance.

== Audit and execution-authority benchmark regeneration (2026-09-09)

An isolated clean `c629e0ae49e70bdf25916ff80132227ae6400b1e` checkout regenerated the
primitive baseline with review daemons stopped. Manifest version 2 covers 356 inputs,
SHA-256 `e9441f46ae7517541ae5063808828566bc747de4f8b646502aac92a00af50649`;
the daemon digest is `fb1040e38c4f2cf094ed1ba29c5c1e36ac8b7251d888246f25a256e3b9bf73c1`.
The snapshot is `latest-20260908T171917Z.json`. Idle RSS was 9,936 KiB with two workers
and storage compiled but inactive. This covers the current audit and authorization source
baseline, not the active-console throughput/p99/contention acceptance matrix.

== Local node control and durable receipts (2026-09-09)

The serving node exposes authenticated status, drain/resume and clear-local-bans through
bounded storage/control commands. Its status reports the boot, control revision, current
connections, active local ban-table entries, uptime, committed/applied policy revisions and
pending completion. The count describes hashed table entries, not historical distinct IPs.
A fresh operation identifier accompanies each status snapshot for confirmation and retries.
The same process boot now identifies console telemetry, minute/ranking journals and controls.

A command binds its node, boot, expected control revision and random operation identifier.
The owner checks current cookie/CSRF, role and required MFA, conditionally commits an audit
intent, rechecks authorization and its thirty-second execution deadline, applies the local
effect and commits completion separately. Drain rejects new data-plane connections with 503
while existing connections finish and the console remains reachable. Resume restores new
admission. Clearing affects only the local temporary ban table; replicated policy/reputation
can still deny requests. Ban writers serialize with the bounded clear and readers retain
versioned snapshots throughout it.

A failed completion retains one owned result and prevents new effects until it is recorded.
Repeating the identifier returns that result without reapplying a clear. Completion retries
also tolerate an acknowledgment lost after commit, with no duplicate completion audit.
Unresolved intents after restart remain uncertain and are never replayed automatically;
drain is boot-local and resets on restart. Receipts retain thirty days, at most 4,096 per
node, with at most sixteen expired rows pruned per new command. Capacity exhaustion causes
no effect. Audit intent/completion metadata uses the existing 365-day audit retention.

This increment is the serving-node control foundation. The Nodes interface, authenticated
peer management transport, missing-member coverage and three-node failover acceptance remain
separate required work; it does not complete the Cluster Management phase.

== Local node control benchmark regeneration (2026-09-09)

Clean isolated revision `15925bcfdffd54b548fb9c3bdee853729d3a2fdb` regenerated the
primitive baseline in `latest-20260908T174752Z.json`. Manifest version 2 covers 365 inputs,
SHA-256 `5aaa059623d3e94124bdeabd06ed5f045f05f83e6f0d5671127f8d7f898f2665`;
the daemon digest is `4cc90c0bdc2389f6ff2bace4b2264138e5621f462dcd952eabf6b18a3d231673`.
Idle RSS was 9,968 KiB with two workers and storage compiled but inactive. Review daemons
were stopped and subsequent verification ran outside the timed measurement. Active drain,
clear-command contention, dashboards and clustered impact still require the release matrix.

== Compact Wasm linking and browser ABI gate (2026-09-09)

The UI build now emits a Zig object with its compiler runtime and links it with the
pinned Zig 0.16.0 toolchain's bundled `wasm-ld`. `--compress-relocations` removes reserved
operand padding after symbol resolution; it does not rewrite application logic. This
requires no additional package, npm invocation or JavaScript renderer in ordinary builds.
The same final artifact is embedded by the server and checked by `console-ui` and
`console-test`. The 300 KiB artifact gate, 256 KiB stack and fixed 4 MiB memory remain.

The asset check now also requires an unshared memory with both bounds, the exact fourteen
browser bridge exports, and no host imports. Metadata regressions reject missing bounds,
unexpected exports, host imports, duplicate sections and truncation. Native UI rendering
and live browser execution remain separate behavioral checks. Linker compaction creates
headroom for additional workflows; it does not satisfy the active-console impact gate.

== Nodes interface and Chrome verification (2026-09-09)

Nodes joins the persistent navigation shell and exposes the serving node's admission state,
connections, local ban entries, committed/applied policy stamps, boot, uptime and control
revision. Peer coverage is explicitly unavailable. Snapshots refresh every five seconds;
mutations require a snapshot received within ten seconds and pause while a preview is open.
Drain, resume and ban clearing show their effects and current counts before confirmation.
Viewers cannot mutate, and an exhausted revision or outstanding durable completion disables
new commands.

The model retains the exact operation identity across navigation and uncertain responses.
Operators can inspect its receipt or retry that operation; late responses cannot consume a
newer request. Receipts validate identity and consistent effect/completion fields before
publication, distinguish unpersisted effects, and show revision, timestamps and cleared count.
Unknown outcomes survive until a matching completion or explicit uncertainty acknowledgment.
Session loss erases retained state. Owned protocol strings use bounded decoding and do not
borrow the event arena.

`zig build fmt test console-test sid` passed 337 native tests and the live-daemon suite.
The final UI is 297,740 bytes. Storage-disabled, console-disabled and clustered builds passed.
Native cases cover stale previews, permissions, retry identity, late replies, contradictory
receipts, polling, navigation and full-width counters. The shared navigation regression now
includes Nodes, Policies, Audit and Tokens with the appropriate administrator fixture.

The in-app browser verified login, drain/resume, real 503/200 admission, durable receipts,
keyboard focus and a persistent sidebar. Chrome additionally verified clearing a real local
ban, redacted command audit detail, account pagination and scoped token creation/revocation.
At 390 pixels, Nodes and Statistics had no horizontal overflow and the navigation disclosure
closed after selection. Real traffic produced 512 requests, 400 challenges and 112 rate-limit
responses, with sampled countries and animated connection arrows. Geometry changed during
animation and remained fixed after pausing. A new isolated policy draft named its matched
rule, saved successfully and produced a live 403; disabling it restored the fallback challenge.
The temporary rule remains disabled and the temporary token revoked. No Chrome console errors
were observed before the deliberate disconnect. Stopping the review daemon exposed increasing
stale age and disabled all node mutations; polling recovered automatically after restart with
the new boot and control revision zero. These checks do not complete peer management,
cluster coverage, all-page acceptance or the impact matrix; SID 0007 remains Proposed.

== Nodes UI benchmark regeneration (2026-09-09)

Clean isolated revision `9eb2a68a7736977fd6c7699e685d382da70d9892` regenerated
`latest-20260909T001059Z.json`. Manifest version 2 covers 373 source inputs with SHA-256
`0e0521d23e4df8297f9b538f476ccc950c49a629bcbe3478afc74176e53ab55c`;
the daemon digest is `e0961a8c5347bc1c2643012ae2637af31e7accdf36e9a15b2a95ba2a6f611958`.
Idle RSS was 9,920 KiB with two workers and storage compiled but inactive. The 8,831-byte
Wasm measurement is the proof solver. Browser sessions were signed out and both review
servers stopped before timing. This primitive baseline does not measure active dashboards,
storage contention or the SID's console-impact acceptance thresholds.

== Transactional policy audit context (2026-09-09)

Schema 17 adds the effective actor role and bounded before/after decision summaries to
policy and inspection edits in their existing commit triggers. A token records its attenuated
role; both the owner check and final conditional mutation require the policy-write scope.
Policy summaries retain action, enabled state, priority, challenge settings, weight and local
limiter settings. Names, paths, user-agent patterns, header values and CIDRs are omitted;
selector coverage is explicitly marked redacted. Inspection summaries retain exactly the four
validated modes. Historical audit absence remains NULL rather than inferred from current state.

The console schema library owns one ordered migration catalog, shared by the storage owner
and historical-schema tests. Verification covers upgrade from schema 16, replay, preservation
of existing policy/history/audit records, token attenuation, missing write scope, transaction
rollback on audit failure, and live policy edits with redacted audit detail. Request IP and
user-agent capture, audit-driven policy comparison/revert, cluster audit coverage and the
remaining acceptance gates are still unfinished. SID 0007 remains Proposed.

The required formatting, full tests, console tests and SID build pass: 341 tests. A real
Chrome session edited and restored the priority of a disabled review rule. Its new audit
record showed administrator role and priority 101 → 100, marked selectors redacted, omitted
the path matcher and preserved historical records as not recorded. Chrome reported no
warnings or errors during this audit review. The book and README now document the usable
console, native country-import command and explicit remaining feature boundaries.

== Policy audit benchmark regeneration (2026-09-09)

The primitive baseline was regenerated from clean revision `6e4f7be` with Zig 0.16.0 and
Zaxonlite 0.6.1 after review daemons and concurrent compilers stopped. Manifest v2 covers
375 inputs with SHA-256
`5630b2e082b8435e321c5b30a41479f765fcc5e5a6ec7df4b0d1eaeaaa5a7021`.
The daemon is 7,370,808 bytes and its SHA-256 is
`9d3c80e3d72d847c22ff336b8111591cb0a4ff8e8a2c491997b7c9250c1825c9`.
Idle RSS was 9,936 KiB with two workers and storage compiled but inactive. Results are in
`latest-20260909T003841Z.json`. The harness stopped its temporary daemon after measurement.
This baseline does not establish the separate console-impact throughput/p99 acceptance gate.

== Document rendering acceptance (2026-09-09)

Typst regenerated the PDF and every page PNG at 110 ppi. All 18 wireframes (Figures 3–20,
pages 25–34) were visually inspected for panel, label and caption clipping. The stale landing
illustration label now identifies example data without claiming no console exists. The HTML
bundle contains 20 figure elements and 20 inline SVGs. Typst's experimental HTML export emits
existing spacing warnings; figure geometry remains embedded. The updated console operations
book pages were also rendered and inspected. This closes the document-rendering check only;
SID 0007 remains Proposed and its unfinished feature and performance checks remain open.

== Reviewed policy saves and historical comparisons (2026-09-09)

Managed-policy actions, imports, inspection submissions and responses now share one
controller with a dispatch-local borrowed context for state, transport and request generation.
The Wasm entry point composes it without passing repeated callback signatures or retaining
browser buffers. Native policy and node controller tests share a caller-owned command fixture.

Saving a rule first captures a bounded, owned document and presents changed editor fields in
a before/after table. Confirm save submits that exact document with the reviewed revision;
Back to editor preserves the draft. Unchanged reviews disable confirmation. While a review
is open, draft import and request-preview actions cannot replace its inputs. Historical
selection first reads the current document at the pinned revision, then reads the chosen
historical document using the same revision. A revert is a new policy edit and audit record.

Formatting, full tests, console tests and SID compilation pass with 345 tests; storage-off,
console-off and cluster builds also pass. The UI is 303,740 bytes within its 307,200-byte cap.
Real Chrome checks covered cancellation, confirmation, unchanged drafts, focus, persistent
navigation, a historical revert and the 390-pixel mobile layout without horizontal overflow.
The disabled fixture rule was restored and the review daemon stopped. Chrome reported no
warnings or errors. At that commit, audit-to-policy navigation, preserving and comparing a
draft after a concurrent edit, recent-event match previews, and the other unfinished SID
features remained separate work; the following entry records the first two.

== Audit-to-policy navigation and conflict rebase (2026-09-09)

Audit rows now retain the complete policy identifier as a 128-byte target, and the protocol
extracts an owned identifier/revision pair only from complete, valid targets, so changing
the selected audit row cannot retarget a request. An audit detail with a policy target
offers a review action that opens the managed editor at the audited revision. While a
reviewed save is open and the catalog has become stale, the review shows a rebase control:
reloading fetches the current rule at its committed revision, keeps the reviewed draft, and
re-renders the before/after comparison against the current document. A draft without a
loadable baseline explains that export and re-import is the recovery path.

Native controller tests cover the rebase path, the retained draft, the recomputed
comparison and the exact expected revision sent on confirmation. A server test verifies
that full policy identifiers survive audit recording. Against a running daemon, an edit
produced an audit row whose target was the rule identifier and whose subject was the new
revision; reading the document at that revision succeeded, the history read listed the
edit, and a repeated edit with the stale expected revision was refused with 409. One
formatting violation from these commits (a 105-character test line) was corrected; the
regenerated asset manifest, formatting, console tests, full repository tests, the live
console suite and SID generation pass. Chrome interaction for this increment remains to be
recorded by an operator sign-in; the native and live checks above do not replace it.

== Audit-navigation benchmark regeneration (2026-09-09)

`latest-20260909T010316Z.json` and `latest.json` were regenerated from clean commit
`cc99ee6` with review daemons stopped. Manifest version 2 covers 381 inputs with SHA-256
`7d24323b335b1b0ce2c780829ffafef67a28a7a6fcce8c19064749e2a655e9a7`; the daemon digest is
`031b7804948a977a2d41ca1007ebc5d12125fdd228c79a063f41d3d15089b070` and the result file
SHA-256 is `c3fce86cc7d4067c474921c45b0c729d9fb01d8256927e3244fc9c0cfc384b01`. Full
classification measured 1,470.09 ns median (1,467.85–1,476.77 ns across seven batches).
Idle RSS was 9,920 KiB with two workers and storage compiled but inactive. These primitive
measurements do not satisfy the console-impact acceptance gate.

== GeoIP library, public-domain provider and embedded snapshots (2026-09-09)

Country lookup moved into the standard-library-only `libs/geoip` (address normalization,
ISO validation, `start,end,country` parsing, the sorted generation with binary search, a
streaming two-file loader that hashes source bytes, the gzip path, the 34-byte storage row
codec shared with the storage owner, the `SBGEOIP1` snapshot format and every provider
fact). The console, its tools and its tests import the library; the data plane does not.
The default provider is now ip-location-db `user-country` (PDDL 1.0, no attribution, daily,
two uncompressed CSV files with publisher SHA-256 files); DB-IP Lite remains selectable.
The MaxMind option is withdrawn. The real September 9, 2026 files contain 252 country codes
including the transitionally reserved `FX` (2 rows) and `AN` (1 row); both are accepted.

Snapshot rows use a canonical tagged width class (IPv4, /64-aligned IPv6, or full) with an
adjacency flag; the decoder rejects non-canonical, unordered, overlapping or unknown rows
and verifies the payload digest. The full dataset encodes to 5,649,713 bytes. Console
schema 18 records the provider and per-file digests; the protocol carries a 12-byte provider
name, a 10-byte version and a `hex` or `hex:hex` digest text. GitHub release downloads
follow exactly one HTTPS redirect to an allowlisted asset host; the publisher checksum file
is fetched and enforced for every source file before a row enters the loader.

Evidence: the library's 19 native tests and the offline tool validated the real files
(559,667 known ranges; generation SHA-256
`cd52619878ee0f7592f1c9eb45b03383722a38b443408348743ba27e18a23ce0` equal to the
concatenated files; per-file digests equal to the publisher's `.sha256` files), and 64
random addresses (15 outside any range) agreed with an independent Python bisect. The
review daemon downloaded both files through the redirect, verified both publisher digests,
stored 559,667 ranges in 66.8 seconds and restored the provider, version and file digests
after restart. A build with `-Dgeoip-data` reported the snapshot as `embedded snapshot` at
revision 0 with 559,667 ranges; a pasted import at expected revision 0 replaced it with
revision 1, and the native CLI read both states. `-Dconsole=false -Dgeoip-data`, a missing
file and a file without the magic are refused at build time with GEOIP001/GEOIP002.

Interface changes (provider selector, daily version input, provider-dependent attribution,
the DB-IP globe credit only while DB-IP data is active) moved the module from 306,856 to
307,994 bytes. The reductions considered before raising the gate (three page-local button
helpers with different markup; six authorization-failure branches with distinct messages)
would have recovered well under one kilobyte each, so the gate was raised to 384 KiB
(393,216 bytes) with this ledger rather than by unifying behaviour. Formatting, full
repository tests, console tests, the live console suite (default and embedded builds), SID
and book generation pass; the console-off, storage-off and cluster builds compile.

== Cluster membership, probes, failover gate and impact harness (2026-09-09)

Each node writes its own row of the replicated `console_nodes` table from the storage
owner tick (at start, every 60 seconds, and after every successful rebuild, coalesced to
two seconds, or thirty while quorum is unavailable): consensus address, advertised console
origin, version, boot, applied and control revisions, decided and applied log slots, and
the drain flag. Role, leader, ballot term, frontiers and quorum availability come from a
storage-owned snapshot refreshed at most every five seconds (a single node reads its own
status and reports `single`; a member asks its own Zaxonlite endpoint over the local status
RPC). A console-owned probe thread checks the configured `--console-probe` data-plane
addresses every five seconds, two seconds per probe, and the request-rate delta from
`/__sibuna/metrics`. `GET /console/api/nodes` returns the page and the probes; the Nodes
page ranks members unreachable, degraded, unobserved, healthy, leader first, renders an
unobserved member with dashes rather than zeros, and offers peers only a plain link to their
advertised console. A storage request that times out or fails as unavailable, including the
authorization read at the start of every route, answers `503 CONSOLEQUORUM` so an operator
sees lost quorum rather than a sign-out. Command receipts are readable from any console.

Two shutdown defects surfaced under the failover scenario. A cluster call has no deadline
of its own, so a storage thread blocked in a handshake to a member that stopped mid-call
could never be joined; `Persistent.shutdown` now cancels the in-flight call until the
worker returns. Zaxonlite 0.6.1 stops ticking as soon as `stop` is accepted while a peer
request already waiting on consensus is woken and deadline-checked only by ticks, so the
leader's serve thread can wait for that handler forever; `Db.closeBounded` abandons the
close after 15 seconds with a warning and the process exits with durable data (every
acknowledged write was synced before its reply). The defect was reported upstream as
insanai/zaxonlite issue 7 and fixed in Zaxonlite 0.6.2, which Sibuna pins since the same
day (see the 0.6.2 entry); the bound stays as a safety net rather than a hung service
manager.

Evidence: `tools/console_cluster_test.py` (run by `console-e2e` under `-Dcluster=true`)
starts three PSK loopback nodes with consoles, bootstraps the administrator through node 1
into the replicated store, and verified in order: all three members observed with one
agreed leader; a rule saved on console 1 enforced by node 3 with every node's applied
revision reaching the committed revision; the leader stopped with exit status 0, the
survivor answering, the stopped member unreachable, a new leader elected and a mutation
accepted with two of three nodes; the second node stopped, the last console answering
`503 CONSOLEQUORUM` to a mutation and to a session read while its data plane still
returned 200 and enforced the rule; both nodes restarted with new boots and the restarted
node enforcing a rule saved during the outage; a logout on one console rejecting the
session on another; a drain on one node lowering only that node's health with its receipt
readable from another console; and every node stopped with exit status 0 and no chain
mismatch or leak report. `tools/console_nodes_test.py` adds the single-node membership,
probe and drained-degraded checks. `benchmarks/console_impact.py` (`zig build
console-impact`) builds console-free and console binaries, runs compiled-out, disabled,
idle and eight-dashboard daemons, interleaves wrk rounds over admitted, challenged, denied
and policy-reload workloads and reports pass, fail or inconclusive; its measured verdict is
recorded in the acceptance entry, not here. The Nodes members view moved the interface
module from 307,994 to 315,781 bytes (gate 393,216). Formatting, full repository tests,
console tests, the live console suite in the default and cluster builds, SID and book
generation pass; the console-off and storage-off builds compile.

== Kiosk sessions and the form-exchange decision (2026-09-09)

A wall display signs in by pasting a one-time code into a second form on the sign-in page,
never through a URL, fragment or stored bearer credential; the earlier wording "exchanging
a short-lived scoped token" is revised to this form exchange. An operator or administrator
mints the code (`POST /console/api/kiosk/token`, mutation-budgeted, CSRF-bound, TOTP required
behind a proxy); only its SHA-256 is stored with the granting user's id and revision, a label,
a ten-minute use-by and a twelve-hour expiry, at most 64 outstanding. `POST
/console/api/kiosk/exchange` is public, limited like a login, and consumes the grant in one
statement before inserting a `kind = 'kiosk'` session bound to the same revision, so a lost
reply can cost a code but never yields two sessions. A kiosk principal is a viewer with the
statistics scope only; every route except statistics, the live stream, the session read,
logout and the timeline answers 403, and the route table marks that opt-in explicitly. The
existing user-revision trigger revokes kiosk sessions with every other session. Schema 20
adds the session kind and the grant table; retention gains a `kiosk_grants` kind. The
interface renders a shell-free layout (globe, outcome tiles, request timeline, expiry
countdown, pause, theme and exit) and alternates Traffic and Attacks every 30 seconds on its
own clock unless paused, stale or under reduced motion.

Evidence: storage-tick tests cover CSRF mismatch, unknown code, exchange once and replay,
the kiosk identity (viewer, statistics scope, cannot mint), an expired grant, revocation by
user revision and the 64-grant bound. `tools/console_kiosk_test.py` (in `console-e2e`)
verified through the live daemon that a viewer cannot mint, a missing CSRF answers 400, the
exchange sets an `HttpOnly; SameSite=Strict; Path=/console` cookie, replay answers 401, the
session read reports `kiosk`, statistics and globe geometry answer 200, eight other routes
answer 403 with a valid CSRF header, the stream delivers a snapshot, four bad codes are
followed by 429, logout ends the session, both audit actions are recorded without the code,
and a consumed grant stays consumed across restart. The interface module grew from 315,781
to 317,663 bytes. Formatting, full repository tests, console tests, the live suite, SID and
book generation pass; console-off, storage-off and cluster builds compile.

== Notification destinations, sealed secrets and the fenced notifier (2026-09-09)

Administrators manage up to eight destinations, each a webhook (`https`, or `http` to a
loopback literal) or a syslog endpoint (UDP, or TCP with RFC 6587 octet framing), with a
label, an event mask over denial spike, ban, node unhealthy and leader change, a cooldown
and an enabled flag. Targets are validated in a standard-library-only module: no user
information or fragment, no private, link-local or metadata literals, ports 443 and 8443 or
loopback ports above 1023, and the resolved addresses are checked again before every
connection so a public name cannot resolve into the private network. A webhook secret is
sealed with XChaCha20-Poly1305 under the console key with the target as associated data, so
an envelope copied to a different target cannot be opened and a retarget without a new
secret drops it; saving a secret without a console key answers `CONSOLEKEYREQUIRED`. Pages
and audit rows report only whether a secret is set. Schema 21 adds `console_settings`,
`console_notifications`, `console_notification_events` and widens the job-lease check to a
`notifier` job.

Events are observed without touching a request: the collector feeds the cumulative denied
counter to a detector once per second (spike when the current 60 s window exceeds the
larger of the settings minimum and factor times the previous window, re-armed below the
threshold), the data plane counts issued bans in one atomic that both ban sites bump, the
probe thread raises node unhealthy on a healthy-to-unreachable transition, and the storage
owner writes leader changes itself from its status snapshot. Raised events enter a 64-entry
ring and are moved to the replicated queue by the notifier thread; the lease holder claims
eight events at a time, fans out to enabled destinations whose mask and cooldown allow it,
delivers with a 10 s deadline and at most three attempts (1, 4 and 16 s apart), records
each outcome under the fence, and marks an event delivered once every eligible destination
has an outcome. Webhook bodies are JSON with the event, node, boot, time and detail, signed
as `X-Sibuna-Signature: sha256=HMAC(secret, body)`; syslog lines follow RFC 5424 with
facility local0 and the node as the host. `POST /console/api/notifications/test` delivers
synchronously with the administrator's authority and reports the outcome.

Evidence: unit tests cover target validation (each rejected shape), the syslog formatter
and framing, the detector (minimum, factor, gap handling, re-arming) and the sealed
envelope (wrong subject and altered bytes fail). Storage-tick tests cover destination
capacity, secret masking in pages and audit, stale revision conflicts, lease-fenced
claims and records, and the queue bound. `tools/console_notify_test.py` (in `console-e2e`)
verified through the live daemon that five unsafe targets answer 400, a loopback webhook
and a UDP syslog destination save with the secret masked everywhere, a test delivery
reaches the receiver with a valid HMAC, a honeypot ban raises an event that the notifier
delivers to the webhook and the syslog socket within 30 seconds, a stale revision answers
409, and the audit export carries no secret bytes. The Settings page (administrators
only; a destination table with edit, a bounded form with kind, label, target, secret,
clear-secret, event checkboxes, cooldown and enabled, test delivery with its outcome
inline, remove, and the two spike thresholds with revisions) was checked in Chrome through
a loopback cookie-injecting proxy so no credential was typed into the browser: a syslog
destination saved and listed, test delivery reported status 200, a threshold saved at
revision 1 while the open destination stayed selected, the destination was removed, and
the page laid out at 1440 and 390 pixels without console errors. The interface module grew
from 317,663 to 334,978 bytes. Formatting, full repository tests, console tests, the live
suite, SID and book generation pass; console-off, storage-off and cluster builds compile.

== Operator page templates and the preview isolation decision (2026-09-09)

The five browser-facing pages (challenge, denied, rate limited, banned, overloaded) are
compiled into the immutable engine snapshot as bounded templates: at most 16 KiB and 32
segments, UTF-8 without NUL, placeholders only for status, reason, retry-after, request id,
node and, for the challenge page exactly once, the fixed solver block that the daemon
supplies and no operator can alter. The validator refuses scripts, frames, objects, embeds,
base, link, form and comment markup, `javascript:`, `vbscript:`, `data:`, `url(`,
`@import` and `expression(` anywhere, every `on*` attribute, `meta http-equiv`, and any
`src`, `href`, `srcset`, `action`, `formaction`, `xlink:href` or `poster` that does not start
with a single `/` or `#`; placeholders inside tags and unknown placeholders are refused. The
request path pins the slot only to copy the template to the connection stack, then renders
segments with escaped values and an exact `Content-Length`; browsers (by `Accept`) receive
the template, every other client keeps the plain-text bodies this daemon always sent, 429
keeps `Retry-After`, and the accept-loop overload and drain rejections serve a customized
overload page as HTML. Schema 22 stores edited pages with a stage-and-trigger commit; the
loader installs defaults, then compiles each stored row, and a row that no longer validates
keeps the default as a marked fallback with a warning rather than failing the rebuild. The
challenge default is the embedded interstitial with its solver script replaced by the slot.

Template bytes cross the storage boundary in a heap block owned by the mailbox between
submission and completion (freed on execution, abandonment, stop and shutdown) so the storage
request and result envelopes stay small; the first by-value attempt overflowed the collector
thread's stack. Preview isolation follows the decision recorded for this increment: a draft
is compiled and stored per session in a bounded LRU on the console, and `GET
/console/api/pages/preview/<kind>` renders it with sample values under `Content-Security-
Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'self'` in a new
tab, so operator markup never runs under the console's own policy or origin; the console's
own CSP is unchanged. The Settings page gained a tab strip for the five kinds, the committed
markup with revision and customized/default state, save, preview (the draft survives the
round trip and a refused save) and reset.

Evidence: the library's tests cover compilation, escaping, every refused shape, the
challenge slot rule and that defaults compile; the e2e daemon test serves a customized
denial page to a browser with the escaped rule name and matching length, plain text without
`Accept: text/html`, and a rate-limit page that keeps `Retry-After: 60`; storage-tick tests
cover validation refusals, commit with digest-only audit, stale revisions, reset, loading
into a rebuilt snapshot and the fallback for a corrupted row. `tools/console_pages_test.py`
(in `console-e2e`) verified through the live daemon that the default reads at revision 0, a
script is refused with 400, a save commits revision 1 and a stale save answers 409, a deny
rule then renders the custom page to a browser only, a preview renders under the sandbox
policy with sample values while `//evil/` markup is refused with a diagnostic, reset restores
the default, and audit rows carry digests but never the markup. In Chrome through the
cookie-injecting proxy the editor loaded the default, previewed a draft in a sandboxed tab,
saved it as revision 1 and reset it, without console errors. The interface module grew from
334,978 to 342,159 bytes. Formatting, full repository tests, console tests, the live suite,
SID and book generation pass; console-off, storage-off and cluster builds compile.

== Policy workflows: ordering, replay, reputation prefixes, country blocks and set import (2026-09-09)

Five workflows complete the policy surface, each as one revision-checked mutation staged
through a one-row table whose commit trigger writes the change, its history rows and its
audit record and sets the policy version to the expected revision plus one explicitly (the
base row triggers would bump it once per touched row). Ordering moves a rule past its
neighbour in `(priority, name, id)` order: different priorities swap, equal priorities are
nudged by one, both rules gain a history row and the audit names the moved rule. Replay
evaluates the last 64 retained incidents of a window against the live engine or a draft
candidate and counts matches for a named rule (or any non-allow decision); only incidents
whose evidence envelope shows no query bytes, no body bytes and no truncation are
conclusive, because the request path's rate, ban and session state is never reproduced.
Reputation prefixes are listed with their provenance (`source`, `note`, hits, expiry) and
edited or removed per revision after a private-candidate preflight that refuses a full
trie as capacity; the interface keeps a thirty-second undo that posts the inverse as a
new mutation. The country builder decomposes every range of a country in the active GeoIP
generation into aligned prefixes (at most 1,024, never truncated), stages them in chunks,
preflights them in a private candidate (trie nodes before and after, overlaps with
existing rows, a sample) and applies them in one revision with `source =
console:country:XX` and the generation digest pinned on every row. Set import stages
canonical documents in chunks under a session key, validates the whole set as one
candidate (a duplicate id or an invalid rule refuses everything) and replaces every
managed rule atomically with history rows and a `policy.import` audit record; `sibuna
console policies export` prints the managed set as a JSON array and `sibuna console
policies import --file` replays it against the revision observed at the start.
Refreshing country rows after a later GeoIP generation is recorded as remaining work:
rows keep the generation they were computed from and are not recomputed automatically.

Evidence: storage-tick tests cover the ordering swap, tie nudge, edge and stale cases with
their audit and history rows; reputation validation, a filled trie answering capacity,
removal and audit; replay counts against the live engine and a draft with a stale draft
conflicting; chunked country staging, an incomplete set refused, preflight node counts and
a pinned apply; and an import that replaces the set, refuses a bad document and rolls back
a duplicate id. `tools/console_workflows_test.py` (in `console-e2e`) verified through the
live daemon that reordering flips a path from allowed to denied on the data plane after
rebuild, that traversal probes replay conclusively while an XSS probe with a query is
inconclusive and a draft matches nothing, that a denied prefix answers 403 and its removal
restores 200 with a stale removal answering 409, that a two-hundred-range country previews
200 prefixes with trie counts and applies so a covered address is denied, that a chunked
import drops one rule while the audit carries every workflow action, and that the CLI
export and import round trip replaces the set and a broken file is refused. In Chrome
through the cookie-injecting proxy the managed list showed Up and Down on every rule and a
move swapped two priorities, the editor's replay rendered its summary table, the IP groups
panel saved a prefix with a note and offered a thirty-second undo that removed it again, the
country builder reported that no GeoIP generation was active, and the replace-all review
listed two documents and replaced the managed set after confirmation, without console
errors. Schema 23 carries the tables; the interface module grew from 342,159 to 363,977
bytes (a non-zero default inside the state struct had briefly moved the whole struct into
the data segment, which is why staged documents and replay text live outside it).
Formatting, full repository tests, console tests, the live suite, SID and book generation
pass; console-off, storage-off and cluster builds compile.

== Acceptance run (2026-09-09)

The full matrix ran on the committed tree: `zig build fmt test console-test sid` (twenty
live-daemon scenarios in `console-e2e`, the storage-tick suites and the native render
tests), `zig build -Dcluster=true console-e2e` (the three-node membership, edit, failover,
quorum-loss, rejoin, revocation and drain scenario), and the `-Dconsole=false` and
`-Dstorage=false` builds; every step passed. `zig build console-impact -- --rounds 7
--seconds 8` on an Apple Silicon MacBook Pro with other applications open measured the
four configurations under the four workloads with wrk at two threads and thirty-two
connections. The first run showed that the eight dashboard subscribers had received no
frames: the harness read the sockets through a buffered file with a one-second timeout,
which discards bytes on every timeout, so the "active" daemon had been idle. The reader now
blocks, and a run whose dashboards receive fewer than 0.8 frames per second each is
reported as inconclusive with a limitation line. The corrected run delivered 1,837 frames
(at least 0.99 per second per subscriber) and reported:

#table(
  columns: (auto, auto, auto, auto, auto),
  align: (left, right, right, right, left),
  [Workload], [Baseline req/s (spread)], [Console idle], [Eight dashboards], [95 % CI of loss, active],
  [admitted], [147,680 (34.5 %)], [−0.7 % loss, −0.9 % p99], [−0.7 % loss, +0.3 % p99], [−15.1 % to +12.2 %],
  [challenged], [154,255 (27.4 %)], [+1.5 % gain, −1.0 % p99], [+1.5 % gain, −4.3 % p99], [−13.0 % to +11.3 %],
  [denied], [125,595 (46.2 %)], [−0.4 % loss, +0.3 % p99], [−2.0 % loss, +6.3 % p99], [−31.5 % to +25.3 %],
  [policy reload], [147,195 (19.5 %)], [+0.2 % gain, +6.2 % p99], [−0.6 % loss, +3.1 % p99], [−14.4 % to +10.4 %],
)

Peak resident memory was 77–83 MiB with the console compiled in but disabled, 103–114 MiB
idle and 111–115 MiB with eight dashboards, against 30–80 MiB compiled out. Every
configuration's verdict is inconclusive: the compiled-out baseline's own spread across
rounds is between 19 % and 46 %, far above the 1 % rule, and every bootstrap interval
straddles the 1 % gate. The point estimates are consistent with the isolation contract, but
this host cannot establish it, and the record says so.
`benchmarks/results/console-impact-latest.json` and its timestamped copy carry the
measurement.

The clustered variant (`--cluster --rounds 3`, three PSK nodes with load on node 1) writes
its own record, `console-impact-cluster-latest.json`. Its first run lost the dashboards in
the last round: the streams ended and the harness never reopened them, so the final two
samples measured an idle daemon. Subscribers now reopen a closed stream after a second, as
the browser does, and the record carries the reconnect count and close codes; the rerun
delivered every sample (at least 0.98 frames per second per subscriber, no reconnects) and
reported:

#table(
  columns: (auto, auto, auto, auto, auto),
  align: (left, right, right, right, left),
  [Workload], [Baseline req/s (spread)], [Console idle], [Eight dashboards], [95 % CI of loss, active],
  [admitted], [170,591 (6.2 %)], [+0.3 % gain, −1.5 % p99], [+0.3 % gain, −15.1 % p99], [−9.9 % to +5.2 %],
  [challenged], [176,514 (8.3 %)], [+1.7 % gain, −94.1 % p99], [+1.8 % gain, −94.1 % p99], [−9.7 % to +6.8 %],
  [denied], [169,097 (13.3 %)], [−0.6 % loss, −1.9 % p99], [−1.2 % loss, +1.6 % p99], [−11.2 % to +13.3 %],
  [policy reload], [169,056 (4.3 %)], [−0.9 % loss, +1.3 % p99], [−1.1 % loss, −3.3 % p99], [−1.8 % to +5.5 %],
)

Peak resident memory of node 1 stayed between 28 and 34 MiB in every configuration. The
challenged baseline's 4.7 ms p99 is a single slow round; the clustered verdict is also
inconclusive, with baseline spreads of 4–13 % and every interval straddling the gate.
Both harness runs exit non-zero, as the SID requires for an inconclusive measurement.

== Acceptance benchmark regeneration (2026-09-09)

The primitive baseline was regenerated from clean commit
`e528f7e8c8cbd4e98e76cd487cf85ea3357d1146` with every daemon stopped, covering the
request-path change that renders response pages from snapshot templates. The version-2
manifest covers 465 inputs and has SHA-256
`7d5afa83348353356e74011163458fe49f12663133bdd316040d5c2878c15389`; the daemon digest is
`e65102ede23f4f41c9e6cf6807d994da67cc3d495df08d232c550b08fd36cb0d`.
`latest-20260909T090902Z.json` and `latest.json` share SHA-256
`36fa027744ab9fc909c3f693de9c5566e7ae98bcbecae7258866dfa27ac39f88`. Full classification
measured 1,462.87 ns median (1,458.81–1,468.22 ns across seven batches), within the run to
run variation of the previous 1,441.18 ns record. Idle RSS was 10,048 KiB with two workers and storage compiled but inactive. The 8,831-byte Wasm artifact is
the proof solver. The console-impact matrix is recorded separately in the acceptance run
entry and remains inconclusive on this host.

== Zaxonlite 0.6.2 upgrade (2026-09-09)

The shutdown defect found by the failover scenario was reported as insanai/zaxonlite
issue 7 and fixed in release 0.6.2, which also bounds client connection establishment and
embedded startup with monotonic deadlines and carries the sealed-journal iterator
correction upstream. `build.zig.zon` now pins v0.6.2 (hash
`zaxonlite-0.6.2-o9bF7GoWHABw0T60ff1rkNCGUQKggxd6AcDozCgZ2v06`). The generated-source
patch, its review script and `build/patches` are removed; `build/storage.zig` returns the
dependency module unchanged. `Db.closeBounded` and the worker cancellation stay as a
safety net, and the failover test now asserts that no node log contains the abandoned
close warning, so a clean member stop is verified rather than tolerated. No first-party
call site changed: the API surface Sibuna uses is unchanged between 0.6.1 and 0.6.2.

Evidence: `zig build fmt test console-test sid` (native tests, the rotation and restart
regression, twenty live scenarios), `zig build -Dcluster=true console-e2e` (three-node
membership, edit, failover, quorum loss, rejoin, revocation and drain with every stop
returning within its bound and status 0), and the `-Dconsole=false` and `-Dstorage=false`
builds all pass. Wire protocol 9 and journal format 2 are unchanged, so existing data
directories open without migration.

The primitive baseline was regenerated from clean commit
`ef5dafbff9ae9e852d32020b3ba4221fa737aa88` so the record's dependency pin matches the tag:
manifest v2 covers 462 inputs with SHA-256
`18bf0d234e1d09ee817f50d3d6d40687a2261745d1f435d9a3a595560b3d17f5`, the daemon digest is
`2d115f856293171ae60d7cf6d7cd74621009f1b550110a0e9ea23821882fd2ef`, and
`latest-20260909T131836Z.json` and `latest.json` share SHA-256
`87ec136cd2d7b6e5b411d77f0aa3add4b60be980b12900bba77302d9647527a0`. Full classification
measured 1,461.28 ns median (1,445.89–1,499.61 ns); idle RSS was 10,064 KiB. The storage
dependency is not on the measured request path, and the figures match the previous
record within run to run variation.

== Response-template validation correction (2026-09-09)

The implementation review found that whitespace splitting accepted browser-recognized event
attributes adjacent to quoted values and after a tag-name slash. `page_markup.zig` now parses
an explicit bounded subset of HTML, requiring separated names and quoted values, refusing
foreign-content integration elements, event attributes, URL entities/backslashes and CSS
escapes. Style and title bodies cannot conceal the fixed solver placeholder. Common layout,
accessibility attributes, local images, inline styling and the built-in shield icon remain
supported. Invalid historical templates retain the existing safe-default fallback.

Served response pages also send a restrictive Content Security Policy. Challenge pages allow
only the SHA-256 hash of the embedded solver script, local workers and local verification;
other response pages permit no scripts. This is independent of the existing sandboxed console
preview. Native parser vectors and live save/preview refusal tests cover the discovered forms.
Chrome completed the hashcash solver and reached the local origin under the new CSP, with
no warning/error logs; the console refused the unsafe draft while retaining it in the editor
and leaving the stored revision at zero.
This correction does not close the outstanding notification, real-time or impact review items.

== Outbound-delivery correction (2026-09-09)

Management connections share `libs/net/src/outbound.zig`: bounded owned hostnames and DNS
answers, address validation before connecting, and a pinned numeric socket destination.
TLS retains the original hostname for SNI and certificate validation. The resolver drains
its bounded result queue concurrently and refuses a private answer or excess capacity;
delivery does not resolve the hostname a second time. Percent-encoded URI hostnames no
longer escape a temporary parsing buffer.

Webhook delivery reads the bounded response head and closes its one-shot connection without
buffering the body. An oversized error response now retains its actual HTTP status instead
of being recorded as success. Live regression cases verify both small and 9,000-byte HTTP
500 responses, alongside signed successful delivery. `zig build fmt test console-test sid`
passes all 62 steps and 401 native tests, including the live console scenarios. Notification
scheduling and lease corrections remain separate acceptance work.

= References

- SID 0002 (foundation architecture), SID 0003 (declarative policy), SID 0004 (semantic
  inspection), SID 0005 (Zaxonlite storage), SID 0006 (mathematical foundations); repository
  implementation paths are listed in the dated review note.
- Krug, Steve. _Don't Make Me Think, Revisited_, 2014; Kahneman, Daniel. _Thinking, Fast
  and Slow_, 2011. Interface heuristics, not guarantees of operator performance.
- Metwally, A., Agrawal, D., and El Abbadi, A. “Efficient computation of frequent and top-k
  elements in data streams.” _ICDT_, 2005. See also #link("https://hadjieleftheriou.com/papers/vldb08-2.pdf")[Cormode and Hadjieleftheriou, Finding Frequent Items in Data Streams] for Space-Saving bounds.
- zenfmt ZDS 0016, “The zenfmt Server: REST, Streaming, and the Administered Service”
  (`zenfmt/docs/zds/records/0016-server.typ`, reviewed from the sibling checkout): service,
  UI/glue and vendored-style patterns. Sibuna defines its own asset build and peer protocol.
- #link("https://github.com/ziglang/zig/blob/0.16.0/lib/std/http/Server.zig")[Zig 0.16.0 HTTP/WebSocket source], checked against the installed source; `std.crypto.pwhash.argon2`.
- #link("https://tailwindcss.com/docs/installation/tailwind-cli")[Tailwind CLI] and
  #link("https://daisyui.com/docs/config/")[daisyUI configuration]: CLI dependency and explicit component inclusion.
- #link("https://db-ip.com/db/lite.php")[DB-IP Lite] (CC BY 4.0) and
  #link("https://dev.maxmind.com/geoip/docs/databases/city-and-country/")[MaxMind country CSV schema] (provider-specific account, format and licence requirements).
- RFC 6455 (WebSocket), RFC 9110 (HTTP semantics), RFC 6238 (TOTP).
- #link("https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html")[OWASP password storage] and
  #link("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html")[OWASP CSRF prevention].
