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
Zaxonlite store the data plane already replicates. Its interface is designed by three
principles applied page by page: Krug's "don't make me think", support for fast System 1
judgement, and support for deliberate System 2 analysis; SafeLine's console is studied as
inspiration, not as a parity target. Its defining engineering constraint is an isolation
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
a traffic timeline, attack-type and source breakdowns, and a globe; "Attacks" lists blocked
requests with a request-level detail; "Applications" configures protected sites; "Allow &
Deny", "HTTP Flood", "Anti-Bot" and "Auth" hold rules, rate limits, the challenge, and
authentication; "Settings" holds IP groups, users, notifications, and system options. Section
3 records each page as observed. This record adopts that information architecture where
Sibuna has the same concept, replaces it where Sibuna's model differs (there are no per-site
upstreams; there are surfaces, policies, and nodes), and adds what SafeLine does not have: a
challenge funnel, cluster membership, campaign clustering, and a live transport.

#callout([Inspiration, not a target], [
  SafeLine's console was studied on its hosted demonstration (`demo.waf.chaitin.com`,
  version 9.4.1, 8 September 2026) page by page through a browser session, and cross-checked
  against its documentation. The next section records what was seen, because an operator's
  expectations are shaped by tools like it. Nothing in it is a requirement: each panel is
  kept, changed, or dropped by the principles of section 4 and by what Sibuna actually does.
  No SafeLine markup, stylesheet, or code is reproduced or referenced.
], fill: amber-light, stroke: amber)

= Inspiration: The SafeLine Console, as Observed

The demonstration console has a fixed left sidebar (Statistics, Applications, Attacks,
Allow & Deny, HTTP Flood with Rate Limiting and Waiting Room, Anti-Bot, Auth, Settings; the
version and support links at the bottom), a top bar with a breadcrumb, the licence badge, a
community link, a theme toggle and a refresh button, and a page body. Every list page shares
one grammar: a filter bar (address, application, port, date range), an auto-refresh selector
that defaults to off, a refresh button, an export button where a log is involved, and a
paginated table. Attack payloads are shown in a modal with a request and a response tab. The
pages, in the order of the sidebar:

#table(
  columns: (0.9fr, 2.2fr, 1.9fr),
  table.header([*SafeLine page*], [*What it shows*], [*Sibuna console equivalent*]),
  [Statistics · Traffic Analysis], [Period and application selectors; tiles for requests, page views, unique visitors, unique addresses, blocked, blocking addresses, 4xx and 5xx counts with rates; a 3D or 2D globe of requests or blocks by country with a ranked country list; queries per second, request-status and blocking-status sparklines; top-five bars for client operating systems and browsers, response status codes, referring applications and pages, popular applications and pages], [*Statistics · Traffic*: the same tiles in Sibuna's vocabulary (requests, admitted, challenged, denied, banned addresses, origin 4xx and 5xx from relayed response heads), the choropleth, the live timeline, and the top-five panels fed by the traffic sample ring (section 8.4)],
  [Statistics · Security Posture], [Tiles per protection module (attacks, allow and deny, rate limiting, waiting room, anti-bot, auth); a trend chart per module with its top source addresses; a real-time event feed with a module chip, name, and time; a web-attack donut; rule-hit, attacked-page, and attacked-application rankings], [*Statistics · Security*: tiles per Sibuna module (inspection, reputation, rate limiting, challenges, bans, honeypot); trend plus top addresses per module; the live event feed from the `events` topic; the attack-category donut; attacked paths],
  [Statistics · Data Dashboard], [A full-screen "big screen" export with its own theme, title, and validity, for a wall display], [*Kiosk view*: a read-only full-screen statistics page reachable with a scoped viewer token],
  [Applications], [One card per protected site (defense mode, host match, port and scheme, requests and blocks today, module chips) and a detail page with basic settings, upstream, forwarding rules, routings, per-site module toggles, per-site statistics, and access and error logs], [*Nodes*: Sibuna protects one origin per process, so the unit is the node, not the site; the card carries surface, upstream, listener, and the same request and block counts],
  [Attacks · Events and Logs], [Events grouped by source address and application with attack count, duration, and start; raw logs with action, URL, attack type, address and country, time; detail modal with the type chip, URL, address with "add to IP group" and "IP info", the JA4 fingerprint, the payload location and value, module, time, id, a "deny" stamp, request and response tabs with charset selection, and "copy as cURL"], [*Attack events*: the same two views (grouped by source, raw) and the same detail modal; Sibuna adds the rule and score, the campaign, and similar incidents by vector search; JA4 is shown only when the ingress forwards it, because Sibuna does not terminate TLS],
  [Attacks · Semantic Analysis], [A per-module mode matrix, each of fourteen detection modules set to disabled, audit, balance, or strict, with batch edit], [*Policy · Inspection*: per-category mode for Sibuna's categories (disabled, audit, enforce); balance and strict do not apply, since Sibuna's detectors have one calibrated threshold each],
  [Allow & Deny], [Events and logs of rule hits; custom rules in whitelist and blacklist tabs with order, id, status, type, name, detail, hits today, creator, and update time], [*Policy · Rules* and *IP groups*: the ordered rules table with the same columns, and reputation prefixes as groups],
  [HTTP Flood · Rate Limiting], [Per-address records with the triggering reason ("n requests within m seconds"), the action taken (an anti-bot challenge for a period), blocked count, start, and an unblock-all button; settings], [*Statistics · Security* rate-limit panel and *Policy · Limits*: GCRA is per node and configured by flags today; the console shows hits and offers the rate settings per rule in Phase 2],
  [HTTP Flood · Waiting Room], [Per-application queue statistics: active users allowed, waiting, peak, average wait, bounce rate], [Not adopted: Sibuna's answer to overload is the proof-of-work challenge and the `503` connection bound, both already visible],
  [Anti-Bot], [Per-address challenge records with hits and verified counts, duration, start; settings], [*Challenges*: the funnel and solve-time histogram, plus per-address records of issued, accepted, and rejected solutions with the rejection cause],
  [Auth], [Login records per account, application, method, result, address, time; single sign-on centre; settings], [Not adopted as a data-plane feature; the console's own user and audit pages cover console access],
  [Settings · Protections], [IP groups including a vendor-maintained malicious-address group and a search-engine group; a JA4 fingerprint database; TLS certificates; custom blocking pages per status code; performance mode; retention for logs and statistics; configuration synchronisation between a master and slave nodes with machine codes and sync status; notifications to Telegram, Discord, webhooks, and syslog; information-sharing programmes], [*Settings*: IP groups map to reputation prefixes; blocking and challenge pages become editable templates; retention as specified; synchronisation is replaced by the symmetric cluster of SID 0005 on the *Nodes* page; webhooks and syslog are adopted; no vendor feeds],
  [Settings · Management], [Manager users with role, two-factor state, and last login; the API token; the console's own certificate; a proxy for outbound calls; system information and machine id], [*Settings · Users*, *API tokens*, and *About*; two-factor authentication by TOTP is adopted],
  [Settings · System Log], [Console activity log], [*Audit*],
)

Three observations shaped the design more than any single page. First, every SafeLine list
is polled (auto-refresh off by default) whereas the security-posture page has a "real-time
events" feed; Sibuna makes every page live over one WebSocket and drops polling entirely.
Second, SafeLine's statistics are dominated by traffic analytics (page views, visitors,
referrers, popular pages) that a firewall can only compute by sampling the request stream;
Sibuna adopts them through a bounded sample ring rather than by logging every request.
Third, the detail modal is the page operators spend the most time in; Sibuna's version
keeps its layout and adds what the engine knows and SafeLine cannot show: the rule, the
score, the campaign, and the nearest incidents.


The design follows the approach the zenfmt project uses for its server interface: a bounded
service kernel over the standard library, an application layer that composes routing,
authentication, and handlers as straight-line code, a WebAssembly interface module in Zig
that owns every page and all interface state, a fixed JavaScript glue that only moves events
in and commands out, and vendored daisyUI styling. Sibuna's console is larger than zenfmt's
(eight pages, live streams, a cluster) so the module structure below is deliberately more
granular, and the transport is WebSockets rather than server-sent events because the
interface also sends commands (subscribe, filter, acknowledge) on the same connection.

= Design Principles

Three principles govern every page, and section 4.5 audits each page against them. They are
not decoration: each yields testable rules (R1 to R18) that the verification section checks.

== Don't make me think

Krug's rule is that a page should be self-evident: a person should know what it is, what
they can do, and where they are without reading. Applied to a security console, whose
operator is often looking at it under pressure, the rule becomes:

- *R1 One question per page.* Every page answers one question stated in its title: "What is
  happening?" (Statistics), "What was attacked and why?" (Attack events), "Are the puzzles
  working?" (Challenges), "What are the rules?" (Policy), "Is the cluster healthy?" (Nodes).
  A page never asks the operator a question of its own; defaults answer them (all nodes,
  last 24 hours, live on).
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
  no animation; new event rows fade in at the top and never push a row the operator is
  reading; layout never reflows on data.
- *R7 Errors are Elm-style.* A failed action names what happened, why, and what to do, in
  the diagnostic voice the daemon already uses, inline where the action was taken.

== Fast judgement: System 1

Kahneman's System 1 is fast, automatic, and pattern-driven; an operator glancing at the
console should be able to tell "normal" from "not normal" in under a second and be right.
The interface therefore invests in preattentive cues and consistency:

- *R8 One colour per decision, everywhere.* Admitted is green, challenged is amber, denied is
  red, banned is dark red, informational is the single blue accent; the same hue in tiles,
  chart series, badges, and rows, in both themes. No other meaning is ever given to these
  colours.
- *R9 Deviation, not magnitude.* Each tile shows its value and a small marker of how it
  compares with the same window yesterday (an arrow with a percentage), because a raw count
  is meaningless at a glance and a change is not. A tile whose deviation exceeds a threshold
  gets a tinted background, and the page keeps a quiet look otherwise.
- *R10 Stable positions.* A panel is always in the same place at the same size; rankings keep
  slots and animate bar length only; the map keeps its projection. Recognition works by
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

- *R14 Evidence for every conclusion.* A denial always shows the rule, the score and its
  terms, the decoded payload with the matched structure highlighted, and the raw request;
  a challenge shows its parameters and outcome; a ban shows who or what caused it and when
  it expires. No verdict appears without its reason.
- *R15 Depth on demand.* Pages are layered: glance (tiles), scan (tables), study (detail
  modal), investigate (campaign members, nearest incidents, the same address across nodes).
  Each layer is one click deeper and the way back is always the same control.
- *R16 Compare, don't recall.* Any period can be compared with the previous one, any node
  with another, and any rule's hits before and after an edit; the interface places the two
  side by side so the operator never holds one in memory.
- *R17 Simulate before you commit.* The policy tester evaluates a synthetic request against
  the current policy; a rule edit shows a diff of what will change and which recent events
  it would have matched, before Save.
- *R18 Reversible by default.* Bans and allows carry a duration and an "undo" for thirty
  seconds; rule edits are versioned and can be reverted from the audit page; deletion needs
  a typed confirmation and is the only action with one.

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
  [Attack events], [Two views named for what they group (by source, raw); one filter bar; one detail control (R1, R4).], [Category chips coloured by decision; country flags; new rows fade in at the top (R6, R8).], [The detail modal is the System 2 workbench: rule, score terms, decoded payload, raw request, campaign, nearest incidents, and the actions with durations and undo (R14, R17, R18).],
  [Challenges], [The funnel is the page; nothing else competes with it (R1, R5).], [Funnel stages in decision colours; the histogram shape shows a slow-device tail at a glance (R8, R11).], [Per-cause rejection tables; difficulty bump timeline against load; per-rule parameters editable with a preview of expected solve time (R14, R17).],
  [Policy], [Rules read top to bottom in evaluation order, with the order shown as a number and drag handles; one editor (R3, R4).], [Type chips in decision colours; hits-today sparkline per rule; disabled rules greyed (R8, R11).], [Tester, diff before save, "would have matched" against recent events, versions with revert, inspection-mode matrix with a one-line consequence per mode (R16–R18).],
  [Nodes], [One card per node; leader marked; unhealthy first (R1, R10).], [Health as colour plus word; sparklines for rate, memory, CPU (R8, R11).], [Per-node drill to its statistics; replication lag history; drain with a confirmation that states what it does (R14, R18).],
  [Settings, GeoIP, Audit], [Tabs named by noun; forms with one primary action; nothing hidden behind icons (R3, R5).], [Two-factor state and token expiry as badges; retention as a sentence, not a table (R12).], [Audit rows show before and after; page templates preview live; GeoIP shows source, licence, and count before the update button (R14, R17).],
)

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
- A complete management surface for everything Sibuna does: statistics, events, challenges,
  policy, reputation, nodes, GeoIP, users, tokens, pages, retention, notifications, audit.
  SafeLine's console is inspiration for what operators expect; Sibuna's console is complete
  on its own terms and makes no distinction between editions.
- Designed by three principles, applied and audited per page (section 4): don't make me think;
  fast, glanceable judgement (System 1); deliberate, evidence-backed analysis (System 2).
- Elegant: one accent colour, one type scale, one spacing unit, restrained motion, and nothing
  on a page that does not earn its place.
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
- *Two-factor authentication* is optional per user and required for administrators when
  the console is bound off loopback: time-based one-time passwords (RFC 6238, HMAC-SHA1 from
  the standard library) enrolled through a QR code rendered by the interface module, with
  ten single-use recovery codes stored as digests.
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
accepted solution.

== Traffic sampling and top-k rankings

SafeLine's traffic analytics (client families, response status codes, referring pages,
popular pages) need a view of ordinary requests, not only denied ones. Logging every request
is out of the question on a data plane that serves 180,000 requests per second per node.
Sibuna samples: the request path increments one atomic counter per request and, when the
counter is a multiple of the sample interval (64 by default, configurable), copies a fixed
256-byte record (timestamp, node, decision, method, path prefix, User-Agent family, Referer
host, origin status when relayed, client country resolved later) into a lock-free
single-producer-per-worker ring of 4,096 slots. The push is one compare-and-swap and one
memcpy on the sampled request only and nothing on the other 63; the ring is drained by the
console's sampler thread. Rankings are computed with the Space-Saving algorithm (Metwally,
Agrawal, and El Abbadi, ICDT 2005) with 256 counters per kind, which bounds memory and gives
the exact top-k for any key whose frequency exceeds $1/256$ of the samples; the top twenty per
kind per minute are persisted in `topk_minutes`. Counts are shown scaled by the sample
interval and labelled as sampled.

== Data-plane changes this record requests

The isolation contract forbids console code on the request path; the three additions below
are data-plane code, reviewed as such, each one atomic operation per request or less:

+ the 16-bucket solve-time histogram above, one atomic add per accepted solution;
+ the traffic sample ring above, one atomic increment per request and one ring push per
  sampled request;
+ per-category inspection modes (`disabled`, `audit`, `enforce`) carried by the policy
  snapshot and applied by the storage thread at rebuild, so that the request path tests one
  bitmask; `audit` records the incident and admits the request, which is how SafeLine's
  observe mode behaves and what an operator needs to tune a rule without risk.

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
  [`topk_minutes`], [`node_id`, `minute`, `kind` (path, user_agent, referer, origin_status, client_os, client_browser), `key`, `sampled_count`; top twenty per kind per minute],
  [`console_pages`], [`kind` (challenge, denied, rate_limited, banned, overloaded), `html`, `updated_at`, `updated_by`; operator-edited templates the data plane loads at engine rebuild],
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
- *Visual system.* One daisyUI theme, `sibuna`, defined in `tailwind.css` from the tokens
  of section 4.4 (accent, four decision colours, five neutral surfaces, the type scale, the
  8-pixel unit) with a light and a dark variant selected by `data-theme`, following the
  system preference by default and remembered per browser, together with the density
  preference. The `sb-*` components consume only these tokens; a component that needs a new
  colour is a design change, reviewed as one.
- *Charts obey the rules.* `charts.zig` has one palette (the decision colours and the accent),
  draws deviation markers and sparklines as first-class marks, keeps axes and positions
  stable across updates, and animates nothing but bar length (R6, R8–R11).
- *Budget.* The module is compiled at `ReleaseSmall` with a 300 KB size gate, 4 MB initial
  memory, and no allocator on the event path beyond a bump arena reset per event.

== Pages

#table(
  columns: (0.9fr, 3fr),
  table.header([*Page*], [*Panels*]),
  [Setup and login], [First-run password change; login form with the optional one-time code; session expiry notices.],
  [Statistics · Traffic], [Period selector (live, 1 h, 24 h, 7 d, 30 d) and node selector; tiles (requests, admitted, challenged, denied, banned addresses, origin 4xx and 5xx with rates, nodes healthy); live timeline (allowed, challenged, denied); queries-per-second, request-status and blocking-status sparklines; choropleth with ranked countries (requests or denials); top-five panels: client operating systems, browsers, response status, referring hosts, popular paths, all marked as sampled.],
  [Statistics · Security], [Tiles per module (inspection, reputation, rate limiting, challenges, bans, honeypot); a trend chart per module with its top source addresses; the live event feed; attack-category donut; attacked paths; rule hits.],
  [Kiosk], [The traffic and security panels in a full-screen, read-only, auto-cycling layout for a wall display, reached with a scoped viewer token and no session.],
  [Attack events], [Grouped view (source address, country, node, attack count, first and last seen) and raw view (action, URL, category, rule, address, time, detail); filter bar (node, category, rule, address, country, path, period); export; detail modal (category chip, URL, address with country and "ban", "allow", "add to group", "address info" actions, JA4 when forwarded by the ingress, payload location and decoded value with the matched structure highlighted, rule and score, campaign and its members, similar incidents, request and response heads with charset selection, "copy as cURL").],
  [Challenges], [Funnel (issued, submitted, accepted, rejected by cause); solve-time histogram by algorithm and difficulty; adaptive-difficulty bump timeline; JavaScript-fallback share; per-address records (issued, accepted, rejected, cause, duration, start); per-rule challenge parameters.],
  [Policy], [Rules table with drag ordering, enable toggle, type (allow, deny, challenge, weigh), name, match summary, hits today, creator, updated; rule editor (form and JSON); pattern tester; import and export; inspection mode matrix per category (disabled, audit, enforce); limits (rate, window, ban seconds); IP groups (reputation prefixes with score, expiry, trigger, source, hits); GeoIP block builder.],
  [Nodes], [Member cards with surface, upstream, listener, role, health, version, requests and blocks today, sparklines; per-node drain and clear-bans; replication lag; the sticky-routing and local-limit notices.],
  [GeoIP], [Source, licence, published date, ranges loaded, last update, update button, attribution text.],
  [Settings], [Users (role, two-factor state, last login); API tokens; pages (challenge, denied, rate limited, banned, overloaded templates with preview); retention (minutes, incidents, audit, samples); notifications (webhooks, syslog; events: denial spike, ban, node unhealthy, leader change); about (version, node id, build, binding and proxy facts).],
  [Audit], [Append-only log with actor, action, subject, before and after, filterable and exportable.],
)

= Wireframes

The drawings fix layout and information density, not visual style; the visual system of
section 4.4 supplies the style. Every panel named here maps to one `sb-*` component and one
render function, and every page is laid out to pass the audit of section 4.5: tiles first,
trends second, tables third, detail on the right or in a modal, and the way back in the same
place on every page.

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

#figure-box([Statistics · Traffic, the landing page. Tiles update every second; the timeline
shows the selected period with the live second at the right edge; the choropleth colours
countries by denied requests; the bottom panels are fed by the sample ring and say so.],
wire(170, 150, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Statistics])
  panel(H, 60, 9.5, 42, 5, [TRAFFIC · SECURITY · KIOSK ↗], size: 5pt)
  panel(H, 106, 9.5, 30, 5, [all nodes ▾], size: 5pt)
  panel(H, 138, 9.5, 30, 5, [live · 1h · 24h · 7d · 30d], size: 5pt)
  let tiles = (("1.28 M", "requests 24 h"), ("1.19 M", "admitted"), ("64 k", "challenged"), ("21 k", "denied"), ("312", "banned addresses"), ("2.1 % · 0.3 %", "origin 4xx · 5xx"))
  for (i, t) in tiles.enumerate() {
    tile(H, 28 + i * 23.5, 16, 22, 13, t.at(0), t.at(1))
  }
  panel(H, 28, 32, 92, 36, [requests per second · allowed / challenged / denied (stacked)], size: 5.5pt)
  line_chart(H, 30, 38, 88, 28, series: 3)
  panel(H, 123, 32, 45, 11, [queries per second · 2,140], size: 5pt)
  line_chart(H, 124, 36, 43, 6, series: 1)
  panel(H, 123, 44.5, 45, 11, [request status · max 264], size: 5pt)
  line_chart(H, 124, 48.5, 43, 6, series: 1)
  panel(H, 123, 57, 45, 11, [blocking status · max 18], size: 5pt)
  line_chart(H, 124, 61, 43, 6, series: 1)
  panel(H, 28, 71, 60, 40, [geo location · requests ○ denied ●], size: 5.5pt)
  panel(H, 30, 77, 34, 32, none, bg: rgb("f8fafc"))
  content((47, H - 93), text(size: 5pt, fill: gray)[choropleth])
  for (i, c) in (("CN", 18), ("US", 14), ("RU", 10), ("BR", 7), ("DE", 4)).enumerate() {
    bar_row(H, 66, 79 + i * 5, c.at(1), c.at(0))
  }
  panel(H, 91, 71, 37, 40, [attack types], size: 5.5pt)
  donut(H, 95, 78, 9)
  for (i, l) in ("sqli 48%", "xss 22%", "traversal 17%", "rce 9%", "honeypot 4%").enumerate() {
    content((116, H - 79 - i * 4.5), anchor: "west", text(size: 4.5pt, fill: ink)[#l])
  }
  panel(H, 131, 71, 37, 40, [top source addresses], size: 5.5pt)
  table_rows(H, 132, 76, 35, 7, (([address], 16), ([denied], 9), ([action], 9)))
  panel(H, 28, 114, 34, 33, [response status (sampled)], size: 5pt)
  for (i, c) in (("200", 30), ("404", 8), ("403", 6), ("429", 2), ("502", 1)).enumerate() {
    bar_row(H, 30, 121 + i * 4.8, c.at(1) * 0.3, c.at(0))
  }
  panel(H, 64, 114, 34, 33, [clients (sampled)], size: 5pt)
  for (i, c) in (("Chrome", 26), ("Firefox", 9), ("Safari", 7), ("curl", 3), ("Python", 2)).enumerate() {
    bar_row(H, 66, 121 + i * 4.8, c.at(1) * 0.3, c.at(0))
  }
  panel(H, 100, 114, 34, 33, [popular paths (sampled)], size: 5pt)
  for (i, c) in (("/", 24), ("/blog", 11), ("/api/v1", 8), ("/search", 5), ("/login", 3)).enumerate() {
    bar_row(H, 102, 121 + i * 4.8, c.at(1) * 0.3, c.at(0))
  }
  panel(H, 136, 114, 32, 33, [referring hosts (sampled)], size: 5pt)
  for (i, c) in (("direct", 22), ("news.ycombinator", 6), ("google", 5), ("t.co", 2), ("mastodon", 1)).enumerate() {
    bar_row(H, 138, 121 + i * 4.8, c.at(1) * 0.35, c.at(0))
  }
}))

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
    bar_row(H, 136, 82 + i * 5, c.at(1) * 0.5, c.at(0))
  }
}))

#figure-box([Attack events with the detail modal open over the raw view. The list streams new
rows at the top while a filter is active; the modal keeps the layout operators know from
SafeLine and adds the rule, the score, the campaign, and the nearest incidents.],
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
  for (i, r) in (("address", "198.51.100.7 · CN   Ban 24 h · Allow · Add to group · Address info"), ("JA4 (from ingress)", "t13d1517h2_8daaf6152771_a323378790d4"), ("payload", "QUERY q · decoded: ' OR 1=1--   quote · keyword OR · tautology 1=1"), ("rule · score", "waf:sqli (terminal) · score 4 of 4"), ("campaign", "41 · 3 incidents · nearest: 12:38:51 node 1 (0.12), 11:02:10 node 3 (0.21)"), ("id", "node 2 · seq 88,412")).enumerate() {
    let y = 28 + i * 5.2
    content((43, H - y - 2), anchor: "west", text(size: 4.5pt, fill: gray)[#r.at(0)])
    content((66, H - y - 2), anchor: "west", text(size: 4.5pt, fill: ink)[#r.at(1)])
  }
  panel(H, 42, 61, 116, 5, [REQUEST · RESPONSE                                   UTF-8 ▾], size: 4.5pt)
  panel(H, 42, 67, 116, 30, none, bg: rgb("f8fafc"))
  for (i, l) in ("GET /search?q=%27%20OR%201%3D1-- HTTP/1.1", "Host: shop.example", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) …", "Accept: text/html,application/xhtml+xml,*/*;q=0.8", "Cookie: __sibuna_token=…", "X-Sibuna-Status: DENY · X-Sibuna-Rule: waf:sqli").enumerate() {
    content((44, H - 70 - i * 4.2), anchor: "west", text(size: 4.3pt, font: "DejaVu Sans Mono", fill: ink)[#l])
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
  panel(H, 76, 58, 45, 24, [Retention #linebreak() minutes 90 d · incidents 30 d · audit 365 d · samples 7 d], size: 5pt)
  panel(H, 124, 58, 44, 24, [Notifications #linebreak() webhook · syslog · events: denial spike, ban, node unhealthy, leader change], size: 5pt)
  panel(H, 28, 85, 68, 22, [GeoIP #linebreak() DB-IP Lite · 2026-09 · 318,402 ranges · loaded 2026-09-08 #linebreak() Update now · attribution shown in footer], size: 5pt)
  panel(H, 99, 85, 69, 22, [About #linebreak() v0.3.0 · node 1 · cluster edge-eu · bound 127.0.0.1:9443 behind proxy #linebreak() build 2c9e258 · storage v0.6.1], size: 5pt)
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
  API tokens, two-factor authentication, notification webhooks and syslog, exports, editable
  page templates, the kiosk view, the audit page, dark theme polish, keyboard navigation and
  screen-reader labels, and the operator guide in the book (a new chapter in Part IX with the
  wireframes replaced by screenshots of the built console).
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
- *Principles.* The golden tests assert the mechanical rules: every page passes the trunk
  test (product, cluster and node, page, section, way back present in the rendered shell,
  R2); decision colours appear only through the four semantic classes (R8); tiles carry a
  deviation marker and a sparkline (R9, R11); numbers render with tabular figures and
  separators (R12); no verdict element renders without its reason element (R14); every
  destructive action renders with a duration or a confirmation (R18). The judgement rules are
  checked by two scripted tasks in the browser suite: a five-second look at Statistics must
  let a reader name the anomalous module, and "find why request X was denied" must complete in
  three clicks from the shell.
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
- Chaitin SafeLine 9.4.1, hosted demonstration console observed on 8 September 2026
  (Statistics with Traffic Analysis, Security Posture and Data Dashboard; Applications;
  Attacks with Events, Logs, Semantic Analysis and Enhanced Rules; Allow & Deny; HTTP Flood;
  Anti-Bot; Auth; Settings), and its documentation.
- Krug, S. _Don't Make Me Think, Revisited: A Common Sense Approach to Web Usability_, 3rd
  edition, New Riders, 2014.
- Kahneman, D. _Thinking, Fast and Slow_, Farrar, Straus and Giroux, 2011.
- Ware, C. _Information Visualization: Perception for Design_, 4th edition, Morgan Kaufmann,
  2020 (preattentive attributes behind R8–R11).
- Metwally, A., Agrawal, D., and El Abbadi, A. "Efficient computation of frequent and top-k
  elements in data streams." _ICDT_, 2005 (the Space-Saving algorithm).
- M'Raihi, D., Machani, S., Pei, M., and Rydell, J. _TOTP: Time-Based One-Time Password
  Algorithm_, RFC 6238. IETF, 2011.
- zenfmt ZDS 0016, "The zenfmt server": the service kernel, the interface module and glue,
  the event hub, and the vendored stylesheet policy that this record adapts.
- Zig 0.16 standard library: `std.http.Server` (`receiveHead`, `respond`,
  `respondStreaming`, `upgradeRequested`, `respondWebSocket`, `WebSocket.readSmallMessage`,
  `WebSocket.writeMessage`), `std.crypto.pwhash.argon2`.
- daisyUI 5 and Tailwind CSS 4 documentation (component classes and the standalone build).
- DB-IP, "IP to Country Lite" (CC BY 4.0); MaxMind GeoLite2 Country (licence on account).
- RFC 6455 (WebSocket), RFC 9110 (HTTP semantics), OWASP Password Storage Cheat Sheet
  (Argon2id parameters), OWASP Cross-Site Request Forgery Prevention Cheat Sheet.
