#let sid-number = "0008"
#let sid-title = "AI Bot Traffic Identification, Multi-Tier Verification, and Operator Console Analytics"
#let sid-state = "discussion"
#let sid-created = "2026-09-15"
#let sid-discussion = "Specifies the architecture for identifying, verifying, and monitoring AI crawler and automated bot traffic in Sibuna: zero-allocation single-pass signature matching, sub-microsecond Radix CIDR verification for major providers (OpenAI, Anthropic, Google Gemini, Perplexity, Meta, Apple, ByteDance), multi-tier confidence classification, bounded telemetry extensions, and a real-time console dashboard delivering visual composition, time-series analysis, and granular tabular analytics contrasting bot traffic against actual human traffic."
#let sid-labels = ("analytics", "bot-detection", "console", "dashboard", "waf", "ai-crawlers",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Open for Discussion"
#let sid-last-updated = "2026-09-15"

#import "../../shared/sid.typ": sid-document
#import "@preview/cetz:0.5.2" as cetz

#let blue = rgb("0284c7")
#let blue-light = rgb("f0f9ff")
#let green = rgb("16a34a")
#let green-light = rgb("f0fdf4")
#let amber = rgb("d97706")
#let amber-light = rgb("fffbeb")
#let red = rgb("b91c1c")
#let red-light = rgb("fef2f2")
#let purple = rgb("7c3aed")
#let purple-light = rgb("f5f3ff")
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

#let invariant(id, body) = block(width: 100%, inset: (left: 8pt, y: 3pt), stroke: (left: 2pt + green))[
  #text(weight: "bold", fill: green)[#id]#h(6pt)#body
]

#let figure-box(caption, body) = figure(
  context {
    if target() == "html" {
      html.frame(body)
    } else {
      layout(size => {
        let bw = measure(body).width
        let factor = if bw == 0pt { 1 } else { calc.min(1, size.width / bw) }
        align(center, scale(factor * 100%, reflow: true, body))
      })
    }
  },
  caption: text(size: 9pt, fill: gray)[#caption],
)

#let cyan = rgb("0891b2")
#let cyan-light = rgb("ecfeff")
#let slate-light = rgb("f8fafc")
#let border-gray = rgb("e2e8f0")
#let dark-slate = rgb("0f172a")

// ---------------------------------------------------------------- wireframe primitives
// A wireframe is a canvas in millimetres with y measured from the top edge.
#let wire(width, height, draw) = cetz.canvas(length: 1mm, {
  import cetz.draw: *
  rect((0, 0), (width, height), stroke: 0.6pt + rule, fill: white, radius: 1.5)
  draw(height)
})

#let panel(H, x, y, w, h, label, bg: none, size: 6.5pt, weight: "regular", radius: 0.8) = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.35pt + border-gray, fill: bg, radius: radius)
  if label != none {
    content((x + 1.5, H - y - 1.2), anchor: "north-west", block(width: (w - 3) * 1mm)[#text(size: size, weight: weight, fill: ink)[#label]])
  }
}

#let card_panel(H, x, y, w, h, title: none, action: none, bg: white, radius: 1.2) = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.35pt + border-gray, fill: bg, radius: radius)
  if title != none {
    content((x + 2.5, H - y - 3.2), anchor: "west", text(size: 5.2pt, weight: "bold", fill: ink)[#title])
  }
  if action != none {
    content((x + w - 2.5, H - y - 3.2), anchor: "east", text(size: 4.2pt, fill: gray)[#action])
  }
}

#let sparkline_draw(H, x, y, w, h, pts, stroke-color: blue) = {
  import cetz.draw: *
  if pts.len() >= 2 {
    let min-v = calc.min(..pts)
    let max-v = calc.max(..pts)
    let range-v = if max-v == min-v { 1.0 } else { max-v - min-v }
    let coords = ()
    for (i, v) in pts.enumerate() {
      let px = x + (i / (pts.len() - 1)) * w
      let py = H - y - h + ((v - min-v) / range-v) * h
      coords.push((px, py))
    }
    line(..coords, stroke: 0.6pt + stroke-color)
  }
}

#let kpi_tile(H, x, y, w, h, number, label, delta: none, delta-color: green, delta-bg: green-light, spark: (), num-color: blue, bg: white) = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.35pt + border-gray, fill: bg, radius: 1.2)
  // Top row: Value and delta pill
  content((x + 2, H - y - 3.8), anchor: "west", text(size: 7.2pt, weight: "bold", fill: num-color)[#number])
  if delta != none {
    rect((x + w - 13.5, H - y - 4.8), (x + w - 1.5, H - y - 1.8), stroke: none, fill: delta-bg, radius: 0.7)
    content((x + w - 7.5, H - y - 3.3), text(size: 3.4pt, weight: "bold", fill: delta-color)[#delta])
  }
  // Middle row: Label
  content((x + 2, H - y - 6.8), anchor: "west", text(size: 4pt, fill: gray)[#label])
  // Bottom row: Sparkline running across the lower edge of the card
  if spark.len() >= 2 {
    sparkline_draw(H, x + 2, y + h - 1.8, w - 4, 2.8, spark, stroke-color: num-color)
  }
}

#let tile(H, x, y, w, h, number, label, bg: blue-light, num-color: blue) = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.35pt + border-gray, fill: bg, radius: 1.2)
  content((x + 1.5, H - y - 4), anchor: "west", text(size: 8.5pt, weight: "bold", fill: num-color)[#number])
  content((x + 1.5, H - y - h + 2.2), anchor: "west", text(size: 4.8pt, fill: gray)[#label])
}

#let line_chart(H, x, y, w, h, series: 1) = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  for s in range(series) {
    let pts = ()
    for k in range(25) {
      let t = k / 24
      let v = 0.35 + 0.25 * calc.sin(t * 720deg + s * 90deg) + 0.15 * calc.sin(t * 2200deg + s * 40deg) - s * 0.12
      pts.push((x + 2 + t * (w - 4), H - y - h + 2 + v * (h - 4)))
    }
    line(..pts, stroke: 0.7pt + (green, blue, red).at(s))
  }
}

#let donut(H, x, y, r) = {
  import cetz.draw: *
  let cx = x + r
  let cy = H - y - r
  arc((cx, cy), start: 0deg, stop: 173.5deg, radius: r, anchor: "origin", stroke: 2.8pt + blue)
  arc((cx, cy), start: 173.5deg, stop: 267.5deg, radius: r, anchor: "origin", stroke: 2.8pt + purple)
  arc((cx, cy), start: 267.5deg, stop: 319.7deg, radius: r, anchor: "origin", stroke: 2.8pt + amber)
  arc((cx, cy), start: 319.7deg, stop: 360deg, radius: r, anchor: "origin", stroke: 2.8pt + gray)
}

#let segmented_donut(H, cx, cy, r, slices) = {
  import cetz.draw: *
  let cur = 0deg
  for sl in slices {
    let span = sl.at(0)
    let col = sl.at(1)
    arc((cx, H - cy), start: cur, stop: cur + span, radius: r, anchor: "origin", stroke: 2.8pt + col)
    cur += span
  }
}

#let bar_row(H, x, y, w, label, bar-color: blue) = {
  import cetz.draw: *
  content((x, H - y), anchor: "west", text(size: 5pt, fill: ink)[#label])
  rect((x + 24, H - y - 1.2), (x + 24 + w, H - y + 1.2), stroke: none, fill: bar-color, radius: 0.6)
}

#let shell(H, W, active) = {
  import cetz.draw: *
  // top bar
  rect((0, H - 8), (W, H), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"))
  content((3, H - 4), anchor: "west", text(size: 7pt, weight: "bold", fill: blue)[SIBUNA])
  content((W - 3, H - 4), anchor: "east", text(size: 5.2pt, fill: gray)[cluster: edge-eu · 3/3 healthy  ·  admin ▾  ·  ◐])
  // sidebar
  rect((0, 0), (26, H - 8), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"))
  let items = ("Statistics", "Attack events", "Challenges", "Policy", "Nodes", "GeoIP", "Settings", "Audit")
  for (i, item) in items.enumerate() {
    let yy = H - 8 - 7 - i * 6.5
    if item == active {
      rect((1.5, yy - 2.8), (24.5, yy + 2.8), stroke: none, fill: blue-light, radius: 1)
    }
    content((4, yy), anchor: "west", text(size: 5.8pt, weight: if item == active { "bold" } else { "regular" }, fill: if item == active { blue } else { ink })[#item])
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

Autonomous artificial intelligence crawlers, multi-modal data extraction agents, and real-time retrieval-augmented generation (RAG) fetchers have transformed edge web traffic. In modern web infrastructure, automated scrapers and AI agents frequently represent between 30% and 75% of total ingress requests, consuming valuable origin compute, cache capacity, and network bandwidth while skewing site metrics. As a high-performance Web Application Firewall (WAF) and anti-crawler daemon, `sibuna` must provide website operators with clear, actionable visibility into incoming automated traffic, specifically separating bot traffic—with granular breakdowns for major AI service providers including OpenAI, Anthropic, Google (Gemini), Perplexity, Meta, Apple, ByteDance, and others—from genuine human visitors.

Achieving 100% classification accuracy is fundamentally impossible in adversarial web environments due to User-Agent spoofing, headless browser evasion, distributed residential proxy rotations, and the strict zero-allocation, sub-microsecond latency budget of the Sibuna hot path, which prohibits synchronous reverse DNS queries during request evaluation. 

This specification establishes an explicit *multi-tier confidence model* combining zero-allocation Aho-Corasick signature classification, zero-allocation Radix-trie IP CIDR verification against published provider ranges, and structural behavioral heuristics. It extends Sibuna's telemetry and storage architecture to record bot identity, provider family, crawl intent (offline model training vs. real-time user-directed fetch vs. search indexing), and verification confidence without dynamic allocations. Finally, it specifies a dedicated real-time operator console dashboard delivering visual composition ratios, time-series trends, and detailed tabular inspection to give operators an honest, mathematically bounded understanding of their incoming traffic and enable targeted declarative policy enforcement.

= Introduction and Motivation

Sibuna's foundational architecture (SID 0002), declarative policy engine (SID 0003), semantic shield (SID 0004), and management console (SID 0007) establish a pure-Zig, zero-allocation WAF daemon capable of processing requests in sub-microsecond time. While `libs/policy/src/bot_signatures.zig` currently maintains a flat list of bot User-Agent strings, and `libs/console-protocol/src/client_family.zig` lumps all automated clients into a single coarse `.bot` ("Automated") display label, operators currently lack deep visibility into their incoming bot landscape.

Website operators are routinely confronted with urgent operational questions that the current telemetry cannot answer:
1. *Volume and Proportion:* What fraction of total incoming requests and egress bandwidth is consumed by automated bots versus genuine human traffic?
2. *Provider Breakdown:* Which major AI service providers (e.g., OpenAI, Anthropic, Google, Perplexity, ByteDance) are currently crawling the application, and at what rate?
3. *Intent and Purpose:* Is an AI request part of an aggressive bulk training corpus scrape (e.g., `GPTBot`, `ClaudeBot`, `Google-Extended`, `Bytespider`), or is it a live, single-page retrieval initiated by a human prompt inside an interactive AI assistant (e.g., `ChatGPT-User`, `Claude-Web`, `Perplexity-User`)?
4. *Authenticity and Spoofing:* Is an incoming request claiming to be `GPTBot` genuinely originating from OpenAI's infrastructure, or is it an unverified third-party scraper spoofing the User-Agent header to evade naive bot blocks?
5. *Targeted Assets:* What specific application endpoints, documentation paths, or proprietary data archives are AI bots targeting most intensely?

To resolve these questions, Sibuna must elevate bot classification from a binary filter into a first-class analytical and observability subsystem within the console management interface.

#callout("The Accuracy Reality Principle", [
  No perimeter security system can guarantee 100% identification accuracy based solely on HTTP request headers or external IP addresses. Malicious bots can forge standard browser User-Agents, while unscrupulous actors can forge known AI bot User-Agents. Conversely, genuine AI providers periodically expand their IP allocations before updating public documentation. Sibuna explicitly rejects illusory precision: the system computes and presents transparent, multi-tier confidence levels, distinguishing *Verified Bots* (cryptographically or CIDR-proven) from *Declared Bots* (self-reported via User-Agent) and *Suspected Bots* (behaviorally detected).
])

= Terminology and Scope

#table(
  columns: (1fr, 3fr),
  table.header([*Term*], [*Definition and System Scope*]),
  [Major AI Provider], [Hyperscale organizations operating foundation models, autonomous agents, and commercial web scraping fleets. Specifically: OpenAI, Anthropic, Google (Gemini/Vertex), Perplexity AI, Meta, Apple (Apple Intelligence), ByteDance, Amazon, Cohere, Mistral, and Common Crawl.],
  [AI Training Crawler], [A high-throughput, recursive automated crawler collecting broad web corpora for training or fine-tuning foundation models (e.g., `GPTBot`, `ClaudeBot`, `Google-Extended`, `Applebot-Extended`, `Bytespider`, `CCBot`).],
  [AI Live Fetcher / RAG], [A low-latency, episodic fetcher retrieving specific web pages in direct response to an active human prompt or query in an AI interface (e.g., `ChatGPT-User`, `Claude-Web`, `Perplexity-User`, `OAI-SearchBot`).],
  [Search Engine Indexer], [Traditional search engine crawlers indexing the web for general public search results (e.g., `Googlebot`, `bingbot`, `Baiduspider`, `YandexBot`, `DuckDuckBot`).],
  [Scraper Library / Tool], [Developer tools, HTTP script libraries, and headless browser automation frameworks (e.g., `curl`, `python-requests`, `aiohttp`, `Scrapy`, `Puppeteer`, `Selenium`).],
  [Actual (Human) Traffic], [Legitimate human end-users accessing web applications via standard graphical desktop or mobile web browsers, exhibiting interactive navigation, DOM asset fetching, and valid cryptographic session tokens.],
  [Radix CIDR Verification], [Zero-allocation lookup of a client IPv4/IPv6 address against an in-memory prefix trie containing published IP ranges of known AI and search service providers.],
  [Confidence Tier], [Categorization of classification certainty: Tier 1 (Verified via CIDR), Tier 2 (Declared via UA, Unverified IP), Tier 3 (Suspected via Heuristics), Tier 4 (Actual Human Traffic).],
)

*In Scope:*
- Single-pass, zero-allocation matching of known AI bot User-Agents and automated tools.
- Sub-50ns Radix trie lookup against pre-loaded CIDR blocks of major AI providers.
- Bounded telemetry collection recording exact aggregate bot/human ratios and sampled detailed bot records.
- Minute-level aggregation and historical archival (`SBR3` record format) in the console subsystem.
- High-fidelity visual and tabular dashboard interfaces in the pure-Zig WebAssembly console UI.
- Actionable operator controls enabling one-click declarative policy generation from bot analytics.

*Out of Scope:*
- Synchronous reverse DNS lookups (FCrDNS) during the hot-path request evaluation.
- Heavy JavaScript-rendered CAPTCHAs or third-party challenge widgets.
- Deep semantic analysis of dynamic response bodies emitted by origins.

= Problem Statement and Architectural Challenges

== The Gap in the Current Codebase

Sibuna's existing architecture handles bot traffic through two isolated mechanisms, neither of which fulfills the needs of modern site operators:

1. *Engine Policy Evaluation (`libs/policy/src/engine.zig`):* The policy engine runs an Aho-Corasick matcher (`BotMatcher`) over `req.user_agent`. If a match is found in `AI_SCRAPERS` or `SCRAPER_LIBRARIES`, it returns a rule decision (e.g., `matched_bot`), which applies a default action (typically `.challenge` or `.deny`). However, this classification is ephemeral: it is not structured by provider, does not verify the originating IP, does not distinguish training bots from live search bots, and is not recorded in analytics unless a security incident is triggered.
2. *Console Protocol Client Family (`libs/console-protocol/src/client_family.zig`):* Telemetry samples classify requests into `Os` and `Browser` enums. Automated agents matching basic tokens (`"bot"`, `"crawl"`, `"curl/"`, etc.) are unconditionally collapsed to `Os.bot` and `Browser.bot`. The identity of the bot (e.g., whether it is ClaudeBot or a malicious script) is permanently discarded.
3. *Console UI Statistics (`apps/console-ui/src/traffic_tiles.zig` and `render.zig`):* The traffic overview presents tiles for admitted, challenged, and denied requests, and histograms for generic operating systems and browsers. Website operators have no mechanism to observe the ratio of bot traffic to actual traffic, no provider-level breakdown, and no visual indication of AI crawling activity.

== The Asymmetric Challenges of AI Bot Identification

Building an effective WAF analytics dashboard for AI bots introduces three severe engineering constraints:

1. *The Spoofing Dilemma:* Any client can send `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0` to pretend to be human, or send `User-Agent: GPTBot/1.2 (+https://openai.com/gptbot)` to pretend to be OpenAI. If an operator configures an allow rule for AI search fetchers, an attacker can spoof that User-Agent to bypass protection. Conversely, if analytics rely solely on User-Agent strings, spoofed scrapers distort business metrics.
2. *The Zero-Allocation Latency Contract:* Standard anti-bot systems perform Forward-Confirmed Reverse DNS (FCrDNS) lookups to verify Googlebot or Bingbot. Performing synchronous DNS queries in Sibuna's hot path would introduce 15ms–200ms of latency, require dynamic memory allocation, and create external network dependencies that violate Sibuna's sub-microsecond latency guarantee.
3. *Provider IP Churn and Asymmetry:* Major AI providers publish their CIDR blocks in machine-readable JSON feeds (e.g., OpenAI, Google, Meta, Amazon), but updates occur out-of-band. The verification mechanism must handle out-of-band CIDR synchronization without locks or latency penalties on request threads.

= System Invariants and Design Principles

The design strictly upholds the TigerStyle engineering principles defined in SID 0001:

#invariant("INV-BOT-1: Zero Allocations on Hot Path", [
  The classification of incoming requests by bot identity, provider family, and CIDR verification must never perform dynamic heap allocation. All trie lookups, string comparisons, and counter increments operate entirely within pre-allocated static tables or thread-local stack frames.
])

#invariant("INV-BOT-2: Bounded Telemetry Memory", [
  The telemetry record must not exceed 256 bytes. Bot classification metadata (provider ID, bot ID, intent category, confidence tier) must fit within a 4-byte packed field in `store.telemetry.Record`.
])

#invariant("INV-BOT-3: Asynchronous Offline Verification", [
  Request threads must never perform network I/O, DNS queries, or synchronous database transactions to verify a bot's IP address. All IP verification must resolve via in-memory Radix tries updated out-of-band.
])

#invariant("INV-BOT-4: Honest Uncertainty Bounds", [
  The console dashboard must never present unverified User-Agent declarations as verified provider traffic. The interface must visibly distinguish between Verified Bot Traffic, Declared Bot Traffic, and Suspected Bot Traffic.
])

#invariant("INV-BOT-5: Strict Structural Code Limits", [
  All newly introduced Zig functions must not exceed 70 lines of code, all code lines must not exceed 99 characters, and all modules must integrate Elm-style diagnostic explanations for operator errors.
])

= Detailed Design

== 1. The Multi-Tier Bot Classification Engine

The bot classification engine operates in `libs/policy` and `libs/console-protocol`. It evaluates incoming requests across three orthogonal dimensions:
1. *Bot Identity & Provider Family:* Identifying the specific bot and owning organization.
2. *Operational Intent (Purpose):* Distinguishing offline corpus scrapers from live user queries.
3. *Verification Confidence:* Determining whether the source IP matches the provider's published infrastructure.

=== 1.1 Provider and Bot Taxonomy

We establish bounded, strongly-typed enums for major AI service providers, bot agents, and operational intents:

```zig
pub const Provider = enum(u8) {
    none = 0,
    openai,
    anthropic,
    google_gemini,
    perplexity,
    meta,
    apple,
    bytedance,
    amazon,
    cohere,
    mistral,
    common_crawl,
    generic_search,
    scraper_library,
    other_bot,
};

pub const BotIntent = enum(u8) {
    human = 0,
    ai_training,       // Bulk corpus crawler (e.g. GPTBot, ClaudeBot, Google-Extended)
    ai_live_fetch,     // Real-time user RAG fetch (e.g. ChatGPT-User, Perplexity-User)
    search_index,      // Traditional web search indexer (e.g. Googlebot, bingbot)
    developer_tool,    // Script libraries and CLI tools (e.g. curl, python-requests)
    generic_crawler,   // Unclassified spiders and bots
    suspected_stealth, // Evasive automated client masquerading as human
};

pub const Confidence = enum(u8) {
    human = 0,
    verified,          // User-Agent matched AND source IP matched verified CIDR trie
    declared,          // User-Agent matched, but source IP was outside published CIDRs
    heuristic,         // User-Agent appeared human/unknown, but behavioral heuristics fired
};
```

=== 1.2 Comprehensive AI Bot Signatures Database

We expand `libs/policy/src/bot_signatures.zig` to associate each signature pattern with its exact provider, bot identifier, and primary intent:

#table(
  columns: (1.2fr, 1.2fr, 1.2fr, 2.4fr),
  table.header([*Provider*], [*Bot Identifier*], [*Primary Intent*], [*Pattern Tokens / User-Agent Substrings*]),
  [OpenAI], [`GPTBot`], [AI Training], [`GPTBot/`, `+https://openai.com/gptbot`],
  [OpenAI], [`ChatGPT-User`], [AI Live Fetch], [`ChatGPT-User/`, `+https://openai.com/bot`],
  [OpenAI], [`OAI-SearchBot`], [AI Live Fetch], [`OAI-SearchBot/`, `+https://openai.com/searchbot`],
  [Anthropic], [`ClaudeBot`], [AI Training], [`ClaudeBot/`, `+claudebot@anthropic.com`],
  [Anthropic], [`Claude-Web`], [AI Live Fetch], [`Claude-Web/`, `+https://www.anthropic.com/`],
  [Anthropic], [`anthropic-ai`], [AI Training], [`anthropic-ai/`],
  [Google], [`Google-Extended`], [AI Training], [`Google-Extended`, `+https://developers.google.com`],
  [Google], [`GoogleOther`], [AI R&D / Multi-modal], [`GoogleOther/`, `GoogleOther-Image`],
  [Google], [`Googlebot`], [Search Index], [`Googlebot/`, `Googlebot-Image`],
  [Perplexity], [`PerplexityBot`], [AI Training / Index], [`PerplexityBot/`, `+https://perplexity.ai`],
  [Perplexity], [`Perplexity-User`], [AI Live Fetch], [`Perplexity-User/`],
  [Meta], [`Meta-ExternalAgent`], [AI Training], [`Meta-ExternalAgent/`, `meta-externalagent`],
  [Meta], [`Meta-ExternalFetcher`],[AI Live Fetch], [`Meta-ExternalFetcher/`],
  [Meta], [`FacebookBot`], [Search / Social], [`FacebookBot/`],
  [Apple], [`Applebot-Extended`], [AI Training], [`Applebot-Extended/`],
  [Apple], [`Applebot`], [Search Index], [`Applebot/`],
  [ByteDance], [`Bytespider`], [AI Training / Scrape], [`Bytespider/`],
  [Amazon], [`Amazonbot`], [AI / Alexa Index], [`Amazonbot/`],
  [Cohere], [`cohere-ai`], [AI Training], [`cohere-ai`, `cohere-training-data-crawler`],
  [Mistral], [`MistralAI`], [AI Training], [`MistralAI/`, `MistralBot`],
  [Common Crawl], [`CCBot`], [AI Training Corpus], [`CCBot/`, `+http://www.commoncrawl.org`],
  [Search Engines], [`bingbot`, `Baidu`], [Search Index], [`bingbot/`, `Baiduspider/`, `YandexBot/`],
  [Tools / Libs], [`curl`, `requests`], [Developer Tool], [`curl/`, `python-requests`, `aiohttp`, `Go-http`],
)

=== 1.3 Sub-Microsecond Radix CIDR Verification

To eliminate DNS lookup latency on the hot path, Sibuna pre-loads the public CIDR blocks published by major AI providers into an immutable 128-bit Radix Prefix Trie (`ProviderCidrTrie`) residing in read-copy-update (RCU) engine memory:

1. *Provider IP Ingestion:* The daemon periodically fetches and parses the published JSON IP lists for OpenAI (`gptbot.json`), Google (`special-crawlers.json`), Meta (published IP endpoints), and Applebot ranges via a background management job in `libs/console/src/provider_cidr_job.zig`.
2. *Zero-Allocation Trie Lookup:* During request evaluation, if a request declares an AI provider User-Agent (e.g., `GPTBot`), `engine.zig` queries the client's IPv4 or IPv6 address against the Radix trie:
   - If the trie associates the IP address with `Provider.openai`, the classification is stamped as `Confidence.verified`.
   - If the trie does not contain the IP, the classification is stamped as `Confidence.declared`.
   - Time complexity: exactly $\le 32$ bit tests for IPv4 and $\le 128$ bit tests for IPv6, executing in under $45$ nanoseconds on modern x86_64 and aarch64 processors.

```zig
pub const Classification = struct {
    provider: Provider = .none,
    intent: BotIntent = .human,
    confidence: Confidence = .human,
    bot_id: u8 = 0,
};

pub fn classifyRequest(
    agent: []const u8,
    client_ip: []const u8,
    cidr_trie: *const ProviderCidrTrie,
) Classification {
    if (agent.len == 0) return .{ .intent = .developer_tool, .confidence = .declared };
    const match = bot_matcher.findFirst(agent) orelse {
        return evaluateHeuristics(agent);
    };
    const verified = cidr_trie.lookup(client_ip) == match.provider;
    return .{
        .provider = match.provider,
        .intent = match.intent,
        .confidence = if (verified) .verified else .declared,
        .bot_id = match.bot_id,
    };
}
```

=== 1.4 Behavioral and Structural Heuristics

For requests claiming to be standard browsers, a fast heuristic pre-scan identifies stealth bots:
- *Absence of Typical Browser Headers:* Modern browsers consistently supply `Accept-Language`, `Sec-Fetch-Mode`, and `Sec-CH-UA`. A request with a Chrome User-Agent lacking these headers is tagged as `BotIntent.suspected_stealth` with `Confidence.heuristic`.
- *Missing Asset Cascade:* Real human navigation requests HTML, followed immediately by CSS, JavaScript, fonts, and images. Sustained traversal of pure HTML document paths without static asset requests flags an automated crawler.
- *Proof-of-Work Verification:* If the firewall issues a cryptographic challenge (SID 0002), automated scrapers lacking JavaScript runtimes or compute capabilities fail or timeout, providing definitive evidence of automation.

== 2. Telemetry and Bounded Storage Pipeline

To deliver accurate statistical dashboards without degrading proxy throughput, Sibuna employs a two-tier telemetry design:

#figure-box("Two-Tier Bot Telemetry Pipeline: 100% Exact Aggregate Striped Counters and 1/64 Bounded Sample Queue", [
  #cetz.canvas(length: 1mm, {
    import cetz.draw: *
    
    // Ingress box
    rect((0, 30), (35, 50), stroke: 0.8pt + ink, fill: blue-light)
    content((17.5, 43), text(size: 8pt, weight: "bold", fill: blue)[Ingress Connection Thread])
    content((17.5, 36), text(size: 6.5pt, fill: ink)[Single-pass UA & CIDR Scan])

    // Arrow to exact counters
    line((35, 45), (55, 55), stroke: 0.8pt + green, mark: (end: ">"))
    content((45, 53), text(size: 6pt, fill: green)[100% requests])

    // Exact counters box
    rect((55, 45), (100, 65), stroke: 0.8pt + green, fill: green-light)
    content((77.5, 58), text(size: 8pt, weight: "bold", fill: green)[Striped Exact Counters])
    content((77.5, 51), text(size: 6.5pt, fill: ink)[Human vs AI vs Search vs Tool])

    // Arrow to sample queue
    line((35, 35), (55, 25), stroke: 0.8pt + purple, mark: (end: ">"))
    content((45, 27), text(size: 6pt, fill: purple)[1/64 selected])

    // Sample queue box
    rect((55, 15), (100, 35), stroke: 0.8pt + purple, fill: purple-light)
    content((77.5, 28), text(size: 8pt, weight: "bold", fill: purple)[Bounded Sample Queue])
    content((77.5, 21), text(size: 6.5pt, fill: ink)[Packed Record (<=256 bytes)])

    // Arrow to Stats collector
    line((100, 40), (120, 40), stroke: 0.8pt + ink, mark: (end: ">"))
    
    // Stats Engine Box
    rect((120, 25), (165, 55), stroke: 0.8pt + ink, fill: white)
    content((142.5, 48), text(size: 8pt, weight: "bold", fill: ink)[Console Stats Engine])
    content((142.5, 41), text(size: 6.5pt, fill: gray)[Minute Rollup & Space-Saving])
    content((142.5, 34), text(size: 6.5pt, fill: gray)[Historical SBR3 Archive])

    // Arrow to UI
    line((165, 40), (180, 40), stroke: 0.8pt + blue, mark: (end: ">"))
    content((195, 40), text(size: 7.5pt, weight: "bold", fill: blue)[Console UI Dashboard])
  })
])

=== 2.1 Exact Striped Counters (100% Population)

To guarantee that the top-level "Bot vs. Actual Traffic" ratio is perfectly accurate and free of statistical sampling error, the connection worker threads maintain 64-byte aligned, atomic counters in `ConsoleTelemetry`:

```zig
pub const Stripe = struct {
    admitted: std.atomic.Value(u64) = .init(0),
    challenged: std.atomic.Value(u64) = .init(0),
    denied: std.atomic.Value(u64) = .init(0),
    banned: std.atomic.Value(u64) = .init(0),
    rate_limited: std.atomic.Value(u64) = .init(0),
    other: std.atomic.Value(u64) = .init(0),
    origin_4xx: std.atomic.Value(u64) = .init(0),
    origin_5xx: std.atomic.Value(u64) = .init(0),
    // Exact traffic composition counters
    traffic_human: std.atomic.Value(u64) = .init(0),
    traffic_ai_bot: std.atomic.Value(u64) = .init(0),
    traffic_search_bot: std.atomic.Value(u64) = .init(0),
    traffic_tool_bot: std.atomic.Value(u64) = .init(0),
    traffic_stealth_bot: std.atomic.Value(u64) = .init(0),
};
```

Every incoming request increments its corresponding intent counter in the thread's assigned stripe using atomic monotonic operations. The total request count and exact bot-to-human ratio are computed by summing all stripes with zero lock contention.

=== 2.2 Bounded Sample Queue (1/64 Sampling)

For deep inspection (provider breakdown, specific bot identifiers, targeted URL paths, and status distribution), 1 in every 64 requests is pseudorandomly sampled into the bounded ring buffer `Queue(Record, 4096)`. 

We extend `store.telemetry.Record` with four packed bytes, keeping the structure within its 256-byte static invariant:

```zig
pub const Record = struct {
    second: u64,
    outcome: Outcome,
    ip_len: u8,
    path_len: u8,
    truncated: bool,
    status: u16,
    referer_len: u8,
    os: u8,
    browser: u8,
    // Bot classification extensions:
    bot_provider: u8,    // @intFromEnum(Provider)
    bot_intent: u8,      // @intFromEnum(BotIntent)
    bot_confidence: u8,  // @intFromEnum(Confidence)
    bot_id: u8,          // Specific bot identifier index
    ip: [48]u8,
    path: [128]u8,
    referer: [24]u8,
};
comptime {
    std.debug.assert(@sizeOf(Record) <= 256);
}
```

=== 2.3 Minute Rollup and Historical SBR3 Archive

In `libs/console/src/rankings.zig`, the collector drains the sample queue each second and folds the records into the active `Minute` structure:
- `bot_providers: [16]u64`: Exact counts of sampled requests per provider.
- `bot_intents: [8]u64`: Counts per operational intent category.
- `bot_confidence: [4]u64`: Counts of verified vs. declared vs. heuristic classifications.
- `provider_outcomes: [16][6]u64`: Outcomes (admitted, challenged, denied, etc.) partitioned by provider.
- `ai_paths: Summary`: Space-Saving heavy-hitters sketch ($k=256$) tracking the specific path prefixes most frequently targeted by AI bots.

The archive module (`libs/console-protocol/src/rankings_archive.zig`) introduces the `SBR3` magic format to persist these bot histograms to Zaxonlite storage, enabling day-over-day and week-over-week comparative analytics.

== 3. Operator Console Dashboard Interface

The Sibuna Console UI (`apps/console-ui`) provides website operators with an intuitive, real-time monitoring dashboard rendered in pure Zig via WebAssembly. 

=== 3.1 Operator Screen Wireframes

The interface follows the visual architecture and information density established in SID 0007. Every panel maps to an `sb-*` component and native WebAssembly render function. Rather than static ASCII art, all screens are rendered via vector primitives maintaining exact spatial proportion:

#figure-box([Statistics · AI & Bot Traffic Overview: Top-level proportional composition bar, metric tiles for human vs. automated traffic with inline sparklines and deviation pills, live request composition trend with axes and anomaly callout, AI provider market share segmented donut with top scraped paths, and real-time crawl event feed with verification badges.],
wire(170, 122, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  
  // Header bar & navigation tabs
  content((29, H - 11.2), anchor: "west", text(size: 6.8pt, weight: "bold", fill: ink)[Statistics · AI & Bot Traffic Overview])
  content((29, H - 14.5), anchor: "west", text(size: 4.2pt, fill: gray)[Live ingress population telemetry & 24h comparative baseline])
  
  // Segmented Pill Controls
  rect((98, H - 14.5), (166, H - 9.5), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 1)
  rect((98.5, H - 14), (115, H - 10), stroke: none, fill: dark-slate, radius: 0.8)
  content((106.7, H - 12), text(size: 4.2pt, weight: "bold", fill: white)[Overview])
  content((124.5, H - 12), text(size: 4.2pt, fill: gray)[AI Providers])
  content((142.5, H - 12), text(size: 4.2pt, fill: gray)[Event Log])
  content((158.5, H - 12), text(size: 4.2pt, fill: gray)[Policy])
  content((164, H - 12), text(size: 4.2pt, fill: blue)[↗])

  // Top Proportional Ratio Card (Hero Glanceable Widget)
  rect((28, H - 26), (166, H - 16.5), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  content((30, H - 18.6), anchor: "west", text(size: 4.6pt, weight: "bold", fill: ink)[Ingress Population Ratio (100% Monotonic Striped Counters)])
  content((164, H - 18.6), anchor: "east", text(size: 4pt, fill: gray)[2,441,000 total requests · Zero sampling error])
  
  // Stacked horizontal bar
  let bx = 30
  let bw = 134
  let by = H - 22.8
  let bh = 3.8
  rect((bx, by), (bx + bw * 0.582, by + bh), stroke: none, fill: green, radius: 0.6)
  content((bx + bw * 0.29, by + bh / 2), text(size: 4.4pt, weight: "bold", fill: white)[Actual Human: 58.2%])
  rect((bx + bw * 0.582, by), (bx + bw * 0.742, by + bh), stroke: none, fill: blue)
  content((bx + bw * 0.662, by + bh / 2), text(size: 4.2pt, weight: "bold", fill: white)[OpenAI 16%])
  rect((bx + bw * 0.742, by), (bx + bw * 0.832, by + bh), stroke: none, fill: purple)
  content((bx + bw * 0.787, by + bh / 2), text(size: 4.2pt, weight: "bold", fill: white)[Claude 9%])
  rect((bx + bw * 0.832, by), (bx + bw * 0.892, by + bh), stroke: none, fill: amber)
  content((bx + bw * 0.862, by + bh / 2), text(size: 4pt, weight: "bold", fill: white)[Google 6%])
  rect((bx + bw * 0.892, by), (bx + bw * 0.963, by + bh), stroke: none, fill: gray)
  content((bx + bw * 0.927, by + bh / 2), text(size: 4pt, weight: "bold", fill: white)[Search 7%])
  rect((bx + bw * 0.963, by), (bx + bw, by + bh), stroke: none, fill: red, radius: 0.6)
  content((bx + bw * 0.981, by + bh / 2), text(size: 3.8pt, weight: "bold", fill: white)[3.7%])

  // Metric tiles with deviation pills and inline sparklines
  let tiles_data = (
    ("1.42 M", "Actual Human", "+12.4%", green, green-light, (22, 25, 24, 28, 31, 30, 35, 38, 42), green),
    ("1.02 M", "Total Automated", "+18.7%", red, red-light, (18, 19, 21, 20, 24, 28, 26, 30, 33), red),
    ("766 k", "AI LLM Crawlers", "+24.1%", purple, purple-light, (10, 11, 12, 15, 18, 22, 20, 25, 28), blue),
    ("173 k", "Search Indexers", "-1.2%", gray, rgb("f1f5f9"), (15, 15, 16, 14, 15, 15, 14, 15, 15), gray),
    ("96.4%", "Verified CIDR", "48 subnets", green, green-light, (94, 95, 96, 95, 96, 96, 97, 96, 96), purple),
    ("142 k", "Challenged / Denied", "32% drop", amber, amber-light, (8, 9, 12, 15, 22, 18, 14, 16, 19), amber),
  )
  for (i, t) in tiles_data.enumerate() {
    kpi_tile(H, 28 + i * 23.3, 27.5, 21.8, 12.5, t.at(0), t.at(1), delta: t.at(2), delta-color: t.at(3), delta-bg: t.at(4), spark: t.at(5), num-color: t.at(6))
  }

  // Middle Row Left: Time-Series Composition Trend (with axes and burst callout)
  let cx = 28
  let cy = 41.5
  let cw = 68
  let ch = 36.5
  rect((cx, H - cy - ch), (cx + cw, H - cy), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  content((cx + 2.5, H - cy - 3.2), anchor: "west", text(size: 5.2pt, weight: "bold", fill: ink)[Traffic Composition Trend (Live & 24h)])
  // Time controls
  rect((cx + cw - 28, H - cy - 5), (cx + cw - 2, H - cy - 1.8), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  rect((cx + cw - 28, H - cy - 5), (cx + cw - 19, H - cy - 1.8), stroke: none, fill: blue, radius: 0.8)
  content((cx + cw - 23.5, H - cy - 3.4), text(size: 3.6pt, weight: "bold", fill: white)[60s Live])
  content((cx + cw - 14, H - cy - 3.4), text(size: 3.6pt, fill: gray)[24h])
  content((cx + cw - 6, H - cy - 3.4), text(size: 3.6pt, fill: gray)[7d])

  // Plot Area
  let px = cx + 8
  let py = cy + 7.5
  let pw = cw - 10
  let ph = ch - 13.5
  for k in (0, 1, 2) {
    let gy = H - py - (k / 2) * ph
    line((px, gy), (px + pw, gy), stroke: (dash: "densely-dashed", paint: rgb("e2e8f0"), thickness: 0.3pt))
    let lbl = if k == 0 { "50k" } else if k == 1 { "25k" } else { "0" }
    content((px - 1.5, gy), anchor: "east", text(size: 3.4pt, fill: gray)[#lbl])
  }
  // Human diurnal curve
  let pts_h = ()
  for i in range(25) {
    let t = i / 24
    let v = 0.45 + 0.30 * calc.sin((t - 0.25) * 360deg) + 0.05 * calc.sin(t * 1440deg)
    pts_h.push((px + t * pw, H - py - ph + v * ph))
  }
  line(..pts_h, stroke: 0.8pt + green)
  // AI crawler curve with burst
  let pts_a = ()
  for i in range(25) {
    let t = i / 24
    let burst = 0.44 * calc.exp(-1.0 * calc.pow((t - 0.35) * 20, 2))
    let v = 0.20 + 0.06 * calc.sin(t * 720deg) + burst
    pts_a.push((px + t * pw, H - py - ph + v * ph))
  }
  line(..pts_a, stroke: 0.8pt + blue)
  // Burst callout
  let spk_x = px + 0.35 * pw
  let spk_y = H - py - ph + 0.64 * ph
  line((spk_x, spk_y), (spk_x, spk_y + 3.8), stroke: 0.3pt + blue)
  rect((spk_x - 13, spk_y + 3.8), (spk_x + 13, spk_y + 7.2), stroke: 0.3pt + blue, fill: blue-light, radius: 0.8)
  content((spk_x, spk_y + 5.5), text(size: 3.4pt, weight: "bold", fill: blue)[▲ 03:15 AM ClaudeBot (+320 rps)])
  // X-ticks
  let times = ("00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "Now")
  for (i, tm) in times.enumerate() {
    let tx = px + (i / 6) * pw
    content((tx, H - py - ph - 2.2), text(size: 3.4pt, fill: gray)[#tm])
  }
  // Legend
  rect((px, H - py - ph - 4.5), (px + 2.5, H - py - ph - 3.8), stroke: none, fill: green)
  content((px + 3.5, H - py - ph - 4.1), anchor: "west", text(size: 3.6pt, fill: ink)[Human Traffic])
  rect((px + 22, H - py - ph - 4.5), (px + 24.5, H - py - ph - 3.8), stroke: none, fill: blue)
  content((px + 25.5, H - py - ph - 4.1), anchor: "west", text(size: 3.6pt, fill: ink)[AI Crawl])

  // Middle Row Right: AI Provider Market Share & Scraped Paths
  let dx = 98
  rect((dx, H - cy - ch), (dx + cw, H - cy), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  content((dx + 2.5, H - cy - 3.2), anchor: "west", text(size: 5.2pt, weight: "bold", fill: ink)[AI Provider Distribution & Scraped Paths])
  
  // Segmented Donut Chart on Left Side
  let dcx = dx + 14
  let dcy = cy + 12
  segmented_donut(H, dcx, dcy, 5.2, (
    (173.5deg, blue),
    (94.0deg, purple),
    (52.2deg, amber),
    (40.3deg, gray),
  ))
  circle((dcx, H - dcy), radius: 3.4, stroke: none, fill: white)
  content((dcx, H - dcy + 0.6), text(size: 3.6pt, weight: "bold", fill: ink)[766 k])
  content((dcx, H - dcy - 1.0), text(size: 2.6pt, fill: gray)[AI Reqs])

  // Donut legend stacked below
  let dly = cy + 20.5
  content((dx + 2.5, H - dly), anchor: "west", text(size: 3.4pt, fill: blue)[• OpenAI 48% (391k)])
  content((dx + 2.5, H - dly - 3.4), anchor: "west", text(size: 3.4pt, fill: purple)[• Anthropic 26% (220k)])
  content((dx + 2.5, H - dly - 6.8), anchor: "west", text(size: 3.4pt, fill: amber)[• Google 15% (147k)])
  content((dx + 2.5, H - dly - 10.2), anchor: "west", text(size: 3.4pt, fill: gray)[• Others 11% (89k)])

  // Top Scraped Paths (Horizontal Bars on Right Side)
  content((dx + 30, H - cy - 5.5), anchor: "west", text(size: 4.2pt, weight: "bold", fill: ink)[Top Targeted URIs])
  bar_row(H, dx + 30, cy + 10.5, 17, "/blog (62%)", bar-color: blue)
  bar_row(H, dx + 30, cy + 16.5, 10, "/docs (24%)", bar-color: purple)
  bar_row(H, dx + 30, cy + 22.5, 6, "/api (9%)", bar-color: amber)
  bar_row(H, dx + 30, cy + 28.5, 4, "/pricing (5%)", bar-color: gray)

  // Lower Section: Real-Time AI Crawl Event Feed
  let fx = 28
  let fy = 79.5
  let fw = 138
  let fh = 40
  rect((fx, H - fy - fh), (fx + fw, H - fy), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  content((fx + 2.5, H - fy - 3), anchor: "west", text(size: 5.2pt, weight: "bold", fill: ink)[Real-Time AI Ingress Feed (1/64 Bounded Sample Queue)])
  content((fx + fw - 2.5, H - fy - 3), anchor: "east", text(size: 4pt, fill: green)[● Ingestion: 64 samples/s · buffer: 14%])

  // Table header
  rect((fx, H - fy - 8), (fx + fw, H - fy - 4.5), stroke: none, fill: rgb("f8fafc"))
  line((fx, H - fy - 8), (fx + fw, H - fy - 8), stroke: 0.3pt + border-gray)
  content((fx + 2, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[TIME])
  content((fx + 16, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[PROVIDER])
  content((fx + 34, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[USER-AGENT])
  content((fx + 64, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[TARGET URI])
  content((fx + 104, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[STATUS])
  content((fx + 118, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[CIDR VERIFICATION])

  let events = (
    ("15:32:01", "OpenAI", blue, blue-light, "GPTBot/1.2", "/blog/deep-learning-foundations", "200 OK", green, "✔ Azure CIDR", green, green-light),
    ("15:31:58", "Anthropic", purple, purple-light, "ClaudeBot/1.0", "/docs/architecture/spec-v2", "429 Chlg", amber, "✔ AWS CIDR", green, green-light),
    ("15:31:54", "ByteDance", red, red-light, "Bytespider", "/internal/catalog-dump", "403 Deny", red, "✖ Spoofed IP", red, red-light),
    ("15:31:49", "Perplexity", cyan, cyan-light, "Perplexity-User", "/news/product-announcement", "200 OK", green, "✔ Azure CIDR", green, green-light),
    ("15:31:42", "Google", amber, amber-light, "Google-Extended", "/archive/quarterly-report", "200 OK", green, "✔ GCP CIDR", green, green-light),
    ("15:31:38", "Unknown", gray, rgb("f1f5f9"), "python-requests/2.31", "/api/v1/pricing", "429 Limit", amber, "⚡ Heuristic", amber, amber-light),
  )
  for (i, e) in events.enumerate() {
    let yy = fy + 12.5 + i * 4.8
    if calc.rem(i, 2) == 1 {
      rect((fx, H - yy - 2), (fx + fw, H - yy + 2.5), stroke: none, fill: rgb("fafafa"))
    }
    line((fx, H - yy - 2), (fx + fw, H - yy - 2), stroke: 0.2pt + border-gray)
    content((fx + 2, H - yy + 0.4), anchor: "west", text(size: 4pt, fill: gray)[#e.at(0)])
    rect((fx + 15.5, H - yy - 1.2), (fx + 31.5, H - yy + 1.8), stroke: 0.3pt + e.at(2), fill: e.at(3), radius: 0.6)
    content((fx + 23.5, H - yy + 0.3), text(size: 3.8pt, weight: "bold", fill: e.at(2))[#e.at(1)])
    content((fx + 34, H - yy + 0.3), anchor: "west", text(size: 4.1pt, weight: "bold", fill: ink)[#e.at(4)])
    content((fx + 64, H - yy + 0.3), anchor: "west", text(size: 4pt, font: "Menlo", fill: ink)[#e.at(5)])
    content((fx + 104, H - yy + 0.3), anchor: "west", text(size: 4pt, weight: "bold", fill: e.at(7))[#e.at(6)])
    rect((fx + 118, H - yy - 1.2), (fx + 136, H - yy + 1.8), stroke: 0.3pt + e.at(9), fill: e.at(10), radius: 0.6)
    content((fx + 127, H - yy + 0.3), text(size: 3.6pt, weight: "bold", fill: e.at(9))[#e.at(8)])
  }
}))

#figure-box([Major AI Service Providers & Crawlers: Granular table inspection showing active agents, operational intent (training vs. live search RAG), sampled volumes with relative share bars, CIDR verification rate, active WAF policy actions, and configuration triggers.],
wire(170, 108, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  
  // Header and subtitle
  content((29, H - 11.2), anchor: "west", text(size: 6.8pt, weight: "bold", fill: ink)[Statistics · Major AI Service Providers & Crawlers])
  content((29, H - 14.5), anchor: "west", text(size: 4.2pt, fill: gray)[1/64 Space-Saving bounded sketch (k=256) · In-memory Radix CIDR verification (sub-50ns)])

  // Filter toolbar
  rect((28, H - 22.5), (84, H - 17), stroke: 0.35pt + border-gray, fill: white, radius: 0.8)
  content((31, H - 19.7), anchor: "west", text(size: 4.4pt, fill: gray)[🔍 Search provider, agent, or subnet...])

  rect((87, H - 22.5), (111, H - 17), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((99, H - 19.7), text(size: 4.2pt, fill: ink)[Intent: All ▾])

  rect((114, H - 22.5), (136, H - 17), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((125, H - 19.7), text(size: 4.2pt, fill: ink)[CIDR: All ▾])

  rect((139, H - 22.5), (155, H - 17), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((147, H - 19.7), text(size: 4.2pt, fill: ink)[Status: All ▾])

  rect((158, H - 22.5), (166, H - 17), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((162, H - 19.7), text(size: 4.2pt, fill: ink)[CSV ▾])

  // Table header
  rect((28, H - 29), (166, H - 24.5), stroke: none, fill: rgb("f8fafc"))
  line((28, H - 29), (166, H - 29), stroke: 0.35pt + border-gray)
  content((30, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[PROVIDER])
  content((48, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[ACTIVE AGENTS])
  content((76, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[OPERATIONAL INTENT])
  content((102, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[VOLUME & SHARE])
  content((127, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[CIDR VERIFIED])
  content((145, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[POLICY ACTION])
  content((161, H - 26.8), text(size: 4.2pt, weight: "bold", fill: gray)[CONFIG])

  let rows = (
    ("OpenAI", "GPTBot, ChatGPT-User", "Training + Live RAG", purple, purple-light, "391,200 (16.0%)", 16.0, blue, "✔ 98.2%", green, "Challenge Scraper", amber, amber-light),
    ("Anthropic", "ClaudeBot, Claude-Web", "Training + Live RAG", purple, purple-light, "220,100 ( 9.0%)", 9.0, purple, "✔ 96.4%", green, "Challenge Scraper", amber, amber-light),
    ("Google", "Google-Extended, Other", "AI Training / R&D", blue, blue-light, "146,800 ( 6.0%)", 6.0, amber, "✔ 99.5%", green, "Admitted (Allow)", green, green-light),
    ("Perplexity", "PerplexityBot, -User", "Live Search Fetch", cyan, cyan-light, " 51,300 ( 2.1%)", 2.1, cyan, "✔ 94.0%", green, "Admitted (Allow)", green, green-light),
    ("ByteDance", "Bytespider", "High-Freq Scraper", red, red-light, " 48,200 ( 2.0%)", 2.0, red, "⚠ 81.2%", red, "Denied (Block 403)", red, red-light),
    ("Meta", "Meta-ExternalAgent", "Model Training", blue, blue-light, " 22,400 ( 0.9%)", 0.9, blue, "✔ 97.1%", green, "Challenge", amber, amber-light),
    ("Apple", "Applebot-Extended", "Foundation Models", gray, rgb("f1f5f9"), " 14,800 ( 0.6%)", 0.6, gray, "✔ 98.4%", green, "Admitted (Allow)", green, green-light),
    ("Tools/Libs", "curl, python-requests", "Developer Script", gray, rgb("f1f5f9"), " 86,500 ( 3.5%)", 3.5, gray, "— 0.0%", gray, "Rate Limited", gray, rgb("f1f5f9")),
  )
  for (i, r) in rows.enumerate() {
    let yy = 34 + i * 7.6
    if calc.rem(i, 2) == 1 {
      rect((28, H - yy - 3.8), (166, H - yy + 3.8), stroke: none, fill: rgb("fafafa"))
    }
    line((28, H - yy - 3.8), (166, H - yy - 3.8), stroke: 0.2pt + border-gray)
    content((30, H - yy + 0.3), anchor: "west", text(size: 4.5pt, weight: "bold", fill: ink)[#r.at(0)])
    content((48, H - yy + 0.3), anchor: "west", text(size: 4.1pt, fill: ink)[#r.at(1)])
    
    // Intent pill
    rect((75, H - yy - 1.2), (99, H - yy + 1.8), stroke: 0.3pt + r.at(3), fill: r.at(4), radius: 0.6)
    content((87, H - yy + 0.3), text(size: 3.6pt, weight: "bold", fill: r.at(3))[#r.at(2)])
    
    // Volume text & micro progress bar
    content((102, H - yy + 0.9), anchor: "west", text(size: 4.1pt, fill: ink)[#r.at(5)])
    rect((102, H - yy - 2.8), (102 + (r.at(6) / 16.0) * 18, H - yy - 1.8), stroke: none, fill: r.at(7), radius: 0.4)
    
    // CIDR Verified
    content((127, H - yy + 0.3), anchor: "west", text(size: 4.3pt, weight: "bold", fill: r.at(9))[#r.at(8)])
    
    // Policy badge
    rect((144, H - yy - 1.4), (157, H - yy + 1.8), stroke: 0.3pt + r.at(11), fill: r.at(12), radius: 0.6)
    content((150.5, H - yy + 0.2), text(size: 3.5pt, weight: "bold", fill: r.at(11))[#r.at(10)])
    
    // Config button
    rect((159, H - yy - 1.8), (164, H - yy + 1.8), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
    content((161.5, H - yy), text(size: 4pt, fill: ink)[⚙])
  }

  // Table pagination and summary footer
  rect((28, H - 104), (166, H - 97), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((31, H - 100.5), anchor: "west", text(size: 4pt, fill: gray)[Showing 1–8 of 14 detected AI crawler organizations · Bound error under 0.2% · Memory: 42 KB])
  content((163, H - 100.5), anchor: "east", text(size: 4pt, fill: ink)[◀ Prev  #text(weight: "bold", fill: blue)[1]  2  Next ▶])
}))

#figure-box([AI Provider Policy & CIDR Verification Modal: Granular policy configuration drawer for OpenAI, enabling operators to differentiate live search queries (ChatGPT-User) from training scrapers (GPTBot) with automated Radix CIDR enforcement.],
wire(170, 114, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  // Dim background
  rect((26, 0), (170, H - 8), stroke: none, fill: rgb("00000033"))

  // Modal container
  rect((32, 7), (164, H - 11), stroke: 0.6pt + ink, fill: white, radius: 1.8)
  
  // Modal Header
  rect((32, H - 18), (164, H - 7), stroke: none, fill: rgb("f8fafc"), radius: 1.8)
  line((32, H - 18), (164, H - 18), stroke: 0.35pt + border-gray)
  rect((35, H - 15.5), (49, H - 10.5), stroke: 0.35pt + blue, fill: blue-light, radius: 0.7)
  content((42, H - 13), text(size: 4.6pt, weight: "bold", fill: blue)[OpenAI])
  content((52, H - 13), anchor: "west", text(size: 6.2pt, weight: "bold", fill: ink)[Provider Policy & Radix CIDR Enforcement])
  content((160, H - 13), text(size: 6pt, fill: gray)[✕])

  // Modal Nav Tabs
  rect((35, H - 23.5), (71, H - 19.5), stroke: none, fill: blue, radius: 0.7)
  content((53, H - 21.5), text(size: 4.2pt, weight: "bold", fill: white)[Rules & CIDR Enforcement])
  content((88, H - 21.5), text(size: 4.2pt, fill: gray)[Verified Subnets (48)])
  content((122, H - 21.5), text(size: 4.2pt, fill: gray)[Sampled Ingress Audit])

  // Left Column: Telemetry Evidence & CIDR Audit
  rect((35, H - 91), (95, H - 26), stroke: 0.35pt + border-gray, fill: rgb("fafafa"), radius: 1)
  content((38, H - 29.5), anchor: "west", text(size: 5.2pt, weight: "bold", fill: blue)[Observed Ingress Telemetry])
  content((38, H - 34.5), anchor: "west", text(size: 4.3pt, fill: ink)[• Total Volume: 391,200 reqs (16.0% site ingress)])
  content((38, H - 38.5), anchor: "west", text(size: 4.3pt, fill: ink)[• Training (GPTBot): 342,100 reqs (87.4%)])
  content((38, H - 42.5), anchor: "west", text(size: 4.3pt, fill: ink)[• Live Search (ChatGPT-User): 49,100 reqs (12.6%)])

  content((38, H - 48.5), anchor: "west", text(size: 5pt, weight: "bold", fill: ink)[Radix CIDR Verification Audit])
  // Dual-color split bar
  rect((38, H - 54), (38 + 52 * 0.982, H - 51), stroke: none, fill: green, radius: 0.5)
  rect((38 + 52 * 0.982, H - 54), (38 + 52, H - 51), stroke: none, fill: red, radius: 0.5)
  content((38, H - 57.5), anchor: "west", text(size: 4pt, fill: green)[✔ 98.2% (384,158 reqs) verified in Azure ASN 8075])
  content((38, H - 61.5), anchor: "west", text(size: 4pt, fill: red)[⚠ 1.8% (7,042 reqs) from alien residential IPs])

  content((38, H - 67.5), anchor: "west", text(size: 5pt, weight: "bold", fill: ink)[Top Target Endpoints])
  content((38, H - 72), anchor: "west", text(size: 4pt, fill: gray)[/blog (62%) · /docs (28%) · /api (10%)])
  content((38, H - 77), anchor: "west", text(size: 4pt, fill: gray)[Verified subnets: 20.15.0.0/16, 20.28.0.0/16, ...])

  // Right Column: Policy Configuration & Enforcement
  rect((99, H - 91), (161, H - 26), stroke: 0.35pt + border-gray, fill: white, radius: 1)
  content((102, H - 29.5), anchor: "west", text(size: 5.2pt, weight: "bold", fill: blue)[Policy Configuration & Enforcement])
  
  // Master toggle
  rect((102, H - 36), (106, H - 32), stroke: 0.4pt + blue, fill: blue-light, radius: 0.5)
  content((104, H - 34), text(size: 3.8pt, fill: blue)[✔])
  content((108, H - 34), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Enforce Radix CIDR Match (sub-50ns)])

  content((102, H - 41.5), anchor: "west", text(size: 4.2pt, fill: ink)[Training Scraper (GPTBot):])
  rect((102, H - 48.5), (157, H - 43.5), stroke: 0.35pt + amber, fill: amber-light, radius: 0.7)
  content((105, H - 46), anchor: "west", text(size: 4.2pt, weight: "bold", fill: amber)[⚡ Proof-of-Work Challenge (PoW) ▾])

  content((102, H - 53.5), anchor: "west", text(size: 4.2pt, fill: ink)[Live User Search (ChatGPT-User):])
  rect((102, H - 60.5), (157, H - 55.5), stroke: 0.35pt + green, fill: green-light, radius: 0.7)
  content((105, H - 58), anchor: "west", text(size: 4.2pt, weight: "bold", fill: green)[✔ Admitted (Bypass WAF) ▾])

  content((102, H - 65.5), anchor: "west", text(size: 4.2pt, fill: ink)[Unverified / Spoofed Agents:])
  rect((102, H - 72.5), (157, H - 67.5), stroke: 0.35pt + red, fill: red-light, radius: 0.7)
  content((105, H - 70), anchor: "west", text(size: 4.2pt, weight: "bold", fill: red)[✖ Deny Immediately (Block 403) ▾])

  content((102, H - 77.5), anchor: "west", text(size: 4.2pt, fill: ink)[GCRA Rate Limiter:])
  rect((102, H - 84.5), (157, H - 79.5), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.7)
  content((105, H - 82), anchor: "west", text(size: 4.2pt, fill: ink)[25 req/s · Burst capacity: 100 reqs ▾])
  content((102, H - 88), anchor: "west", text(size: 3.6pt, fill: gray)[Immutable trie updates execute via zero-downtime RCU.])

  // Modal Footer
  line((32, H - 94), (164, H - 94), stroke: 0.35pt + border-gray)
  rect((35, H - 102.5), (72, H - 97.5), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((53.5, H - 100), text(size: 4.2pt, fill: ink)[🧪 Dry Run Simulation])

  rect((112, H - 102.5), (133, H - 97.5), stroke: 0.35pt + border-gray, fill: white, radius: 0.8)
  content((122.5, H - 100), text(size: 4.2pt, fill: gray)[Cancel])

  rect((136, H - 102.5), (161, H - 97.5), stroke: none, fill: blue, radius: 0.8)
  content((148.5, H - 100), text(size: 4.2pt, weight: "bold", fill: white)[Save & Apply Policy])
}))

#figure-box([Comparative Posture Matrix: Side-by-side behavioral contrast between legitimate human visitors and automated bot traffic across response status distributions, resource cascades, latency, and origin ISP classification.],
wire(170, 108, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  
  // Header and subtitle
  content((29, H - 11.2), anchor: "west", text(size: 6.8pt, weight: "bold", fill: ink)[Statistics · Human vs. Bot Comparative Analysis])
  content((29, H - 14.5), anchor: "west", text(size: 4.2pt, fill: gray)[Side-by-side behavioral, protocol, and network telemetry analysis (100% Exact + 1/64 Samples)])

  // Left panel: Human traffic
  rect((28, H - 94), (95, H - 16), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  rect((28, H - 23), (95, H - 16), stroke: none, fill: green, radius: 1.2)
  content((31, H - 19.5), anchor: "west", text(size: 5.6pt, weight: "bold", fill: white)[🛡 Legitimate Human Traffic Profile (58.2%)])

  // Mini KPI row
  rect((30, H - 31), (49, H - 25), stroke: 0.3pt + border-gray, fill: green-light, radius: 0.6)
  content((39.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: green)[420 rps])
  content((39.5, H - 29.8), text(size: 3.4pt, fill: gray)[peak rate])

  rect((51, H - 31), (70, H - 25), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
  content((60.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: ink)[4.8 min])
  content((60.5, H - 29.8), text(size: 3.4pt, fill: gray)[avg session])

  rect((72, H - 31), (93, H - 25), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
  content((82.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: ink)[78.4%])
  content((82.5, H - 29.8), text(size: 3.4pt, fill: gray)[cache hit])

  content((30, H - 34.5), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[HTTP Status Code Distribution])
  bar_row(H, 30, 38.5, 28, "200 OK (89.2%)", bar-color: green)
  bar_row(H, 30, 42.5, 10, "304 Cache (8.0%)", bar-color: blue)
  bar_row(H, 30, 46.5, 5, "4xx Error (2.6%)", bar-color: amber)
  bar_row(H, 30, 50.5, 2, "5xx Error (0.2%)", bar-color: red)

  content((30, H - 55), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Resource Cascade & Client Engine])
  content((30, H - 59.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ 12% Document HTML / 88% Static Assets])
  content((30, H - 63.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ Full V8/WebKit/Gecko asset rendering cascade])
  content((30, H - 67.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ Median TTFB: 24 ms · Interactive clicks & scrolls])

  content((30, H - 73), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Network & Origin Fingerprint])
  content((30, H - 77.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ 84% Consumer Broadband (Comcast, DT, Orange)])
  content((30, H - 81.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ Valid Session Cookies & Cryptographic PoW tokens])
  content((30, H - 85.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ Standard Browser TLS JA4 & HTTP/2 headers])

  // Right panel: Bot traffic
  rect((99, H - 94), (166, H - 16), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  rect((99, H - 23), (166, H - 16), stroke: none, fill: red, radius: 1.2)
  content((102, H - 19.5), anchor: "west", text(size: 5.6pt, weight: "bold", fill: white)[🤖 Automated Bot & Crawler Profile (41.8%)])

  // Mini KPI row
  rect((101, H - 31), (120, H - 25), stroke: 0.3pt + border-gray, fill: red-light, radius: 0.6)
  content((110.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: red)[310 rps])
  content((110.5, H - 29.8), text(size: 3.4pt, fill: gray)[burst rate])

  rect((122, H - 31), (141, H - 25), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
  content((131.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: ink)[Stateless])
  content((131.5, H - 29.8), text(size: 3.4pt, fill: gray)[leaf crawl])

  rect((143, H - 31), (164, H - 25), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
  content((153.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: ink)[11.8%])
  content((153.5, H - 29.8), text(size: 3.4pt, fill: gray)[cache hit])

  content((101, H - 34.5), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[HTTP Status Code Distribution])
  bar_row(H, 101, 38.5, 20, "200 OK (52.1%)", bar-color: green)
  bar_row(H, 101, 42.5, 18, "403 Denied (26.3%)", bar-color: red)
  bar_row(H, 101, 46.5, 14, "429 Chlg (17.8%)", bar-color: amber)
  bar_row(H, 101, 50.5, 6, "404 Missing (3.8%)", bar-color: gray)

  content((101, H - 55), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Resource Cascade & Client Engine])
  content((101, H - 59.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ 96% Document HTML / 4% Static Assets])
  content((101, H - 63.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ Zero asset cascade (headless script leaf scraper)])
  content((101, H - 67.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ Median TTFB: 18 ms · Rapid recursive crawling])

  content((101, H - 73), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Network & Origin Fingerprint])
  content((101, H - 77.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ 98% Cloud Datacenter ASNs (Azure, AWS, GCP)])
  content((101, H - 81.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ Headless HTTP runtimes (Python, Go, cURL)])
  content((101, H - 85.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ Missing Sec-Fetch headers & anomalous ciphers])

  // Footer note
  rect((28, H - 104), (166, H - 97), stroke: 0.35pt + blue, fill: blue-light, radius: 0.8)
  content((31, H - 100.5), anchor: "west", text(size: 4pt, fill: blue)[Comparative telemetry derived from 100% exact atomic striped counters combined with 1/64 Space-Saving sample sketches. Zero-allocation hot path executes in sub-50 nanoseconds.])
}))

=== 3.2 Visual Components

1. *Proportional Composition Bar:* A prominent stacked horizontal gauge displaying the exact ratio of Actual Human Traffic to Bot Traffic. Each major category is rendered in distinct theme colors: Actual Human (calm green), OpenAI (vibrant blue), Anthropic (purple), Google (amber), Perplexity (cyan), Traditional Search (slate), and Generic Scrapers (orange/red).
2. *Top-Level Metric Cards (KPIs):*
   - *Actual Human Visitors:* Total requests and percentage, along with day-over-day trends.
   - *Total Bot Ingress:* Combined automated traffic footprint.
   - *AI Training Crawlers:* Volume dedicated to offline model scraping.
   - *AI Live Search Fetchers:* Volume triggered by interactive end-user prompts.
   - *Verification Confidence Ratio:* Percentage of AI bot requests verified via source CIDR trie.
3. *Time-Series Composition Chart:* A responsive dual-layer area/line chart comparing live requests-per-second across 60-second real-time windows and 24-hour historical horizons. Sudden scraping spikes (e.g. an aggressive ClaudeBot or Bytespider recursive crawl) are immediately visually distinct from the smooth diurnal curve of human users.
4. *Provider Distribution Donut Chart:* A circular SVG widget illustrating the relative market share of crawling activity among AI providers.

=== 3.3 Granular Tabular Components

1. *Major AI Service Providers Table:*
   Operators can inspect each provider's footprint across key operational metrics:
   - *Provider & Active Agents:* Identifies the organization and specific active bot User-Agents.
   - *Operational Intent:* Flags whether traffic is offline training data ingestion, real-time user-directed RAG, or traditional indexing.
   - *Sampled Volume & Percentage:* Bounded Space-Saving estimate of request count and percentage of total site ingress.
   - *CIDR Verification Health:* Percentage of requests originating from cryptographically or CIDR-verified IP ranges, alerting operators to potential User-Agent spoofing campaigns.
   - *WAF Enforcement Action:* Current policy disposition (Admitted / Challenged / Denied).
   - *Top Target Endpoints:* The top 3 URL path prefixes requested by this provider.
2. *Comparative Posture Matrix (Human vs. Bot):*
   A side-by-side comparative table evaluating human traffic against automated traffic:
   - *Response Status Distribution:* Ratio of 2xx success vs. 3xx redirects vs. 4xx client errors vs. 5xx origin failures. (Scrapers frequently generate elevated 404/403 rates through speculative path enumeration).
   - *Bandwidth Utilization:* Total egress bytes transferred to AI bots versus human visitors.
   - *Average Request Rate:* Peak and sustained requests per minute.
   - *Geographic Concentration:* Contrast between human user locations and AI crawler datacenter egress regions.

=== 3.4 Actionable Policy Integration

To close the loop between visibility and enforcement, each provider row in the table provides a context menu allowing the operator to generate or modify declarative firewall rules with one click:
- *Allow Verified Real-Time Search:* Permit genuine live search queries (`ChatGPT-User`, `Perplexity-User`) while challenging or blocking offline training crawlers (`GPTBot`, `ClaudeBot`).
- *Challenge Unverified Scrapers:* Enforce Proof-of-Work challenges on any request claiming to be an AI bot that fails CIDR trie verification.
- *Rate Limit AI Crawlers:* Apply GCRA token-bucket limits to specific provider identities to prevent origin resource exhaustion.

== 4. Elm-Style Operator Error and Diagnostic Reporting

In conformance with SID 0001, when bot policies challenge or deny traffic, or when anomalous spoofing is detected, the daemon and CLI emit structured, human-friendly Elm-style diagnostics:

```text
-- SPOOFED BOT DETECTED --------------------------------------------------------

A client claiming to be 'GPTBot/1.2' connected from 198.51.100.42, which does
not belong to OpenAI's published CIDR blocks.

Rule:         ai-crawler-strict-verify
Action:       CHALLENGE (Proof of Work)
Provider:     OpenAI (Claimed, Unverified)

Hint: To allow unverified crawlers, set 'verify_cidr: false' in your declarative
policy file, or check for recent OpenAI IP range announcements at /console/#nodes.
--------------------------------------------------------------------------------
```

= Verification and Testing Matrix

Implementation acceptance requires passing the following verification gates:

#table(
  columns: (1.2fr, 1fr, 2fr),
  table.header([*Test Suite*], [*Target*], [*Acceptance Criteria*]),
  [Bot Signature Unit Tests], [`bot_matcher_test.zig`], [100% correct classification of all major AI bots, scraper libraries, and search crawlers; zero false positives on standard desktop and mobile browser strings.],
  [Radix CIDR Trie Verification], [`provider_cidr_test.zig`], [Correctly verifies IPs matching published ranges; rejects alien IPs; executes in $< 50$ ns without heap allocations.],
  [Striped Exact Telemetry], [`telemetry_test.zig`], [Concurrent worker threads accurately increment exact bot intent counters without data races or cache line contention.],
  [Archive Compatibility], [`rankings_archive_test.zig`], [Correct serialization and deserialization of `SBR3` archives; seamless backward-compatibility when decoding legacy `SBR1` and `SBR2` records.],
  [Console UI Wasm Tests], [`console-ui-test`], [Native and WebAssembly render tests for the AI & Bot dashboard panel; verification of goldens with `zig build console-golden-check`.],
  [Data-Plane Impact Gate], [`console-impact`], [Under an eight-dashboard load with active AI crawling streams, data-plane throughput remains within 1% and p99 latency within 10% of console-free builds.],
)

= Security Considerations

1. *Adversarial User-Agent Spoofing:* Malicious scrapers regularly forge common browser headers to bypass naive crawler bans. Sibuna mitigates this by combining signature matching with behavioral heuristics and PoW verification.
2. *Spoofed AI Credentials for Policy Bypass:* If an operator configures an allow rule for AI search fetchers, attackers may forge `ChatGPT-User` or `Perplexity-User`. Sibuna's Radix CIDR trie ensures that privileged allow rules apply only to cryptographically or network-verified provider IP addresses.
3. *Privacy and Data Leakage:* Sampled bot telemetry contains only path prefixes (up to 128 bytes) and stripped referring hosts (up to 24 bytes). Query parameters, credentials, authentication cookies, and request bodies are strictly excluded from telemetry buffers.
4. *Memory Exhaustion Protection:* Space-Saving sketches and Radix tries are allocated with fixed upper bounds at daemon startup. No incoming traffic surge can cause telemetry memory usage to grow unbounded.

= Rollout and Operational Plan

The implementation follows a four-phase rollout:

1. *Phase 1 (Core Classification Engine):* Expand `bot_signatures.zig`, implement `ProviderCidrTrie` in `libs/policy`, and verify sub-microsecond classification performance.
2. *Phase 2 (Telemetry and Storage Pipeline):* Extend `ConsoleTelemetry` striped counters and sample `Record` structure; update `rankings.zig` and implement `SBR3` format in `rankings_archive.zig`.
3. *Phase 3 (Console Management UI):* Build the "AI & Bots" tab in `apps/console-ui`, including the proportional composition bar, time-series graphs, and interactive provider inspection table.
4. *Phase 4 (Automated Ingestion and Testing):* Deploy background CIDR update jobs in `libs/console`, run `console-impact` benchmarks, and verify UI golden tests.

= References

- SID 0001: The Shibuna Discussion Process and Engineering Standards
- SID 0002: Sibuna: Foundation Architecture, Delivery Plan, and Performance Contract
- SID 0003: Declarative Rule Policy Engine
- SID 0004: Semantic Attack Inspection and GCRA Rate Limiting
- SID 0007: The Sibuna Console: A Real-Time Management Interface for Nodes and Clusters
- OpenAI: *Overview of OpenAI Crawlers and IP Ranges* (`https://platform.openai.com/docs/bots`)
- Anthropic: *Claude Web Crawler Documentation* (`https://support.anthropic.com/en/articles/8896518-claude-web-crawler`)
- Google Search Central: *Google Crawler (User Agent) Overview* (`https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers`)
- Apple Inc.: *About Applebot* (`https://support.apple.com/en-us/HT207507`)
