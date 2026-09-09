#import "theme.typ": *

#part_page("XI", [Quick Reference Card], [
  Keep beside a terminal: build, run, configure, route, observe, and diagnose.
  Part X holds the full tables; this card holds what an operator types.
])

#let card(title, body) = block(
  width: 100%, inset: 7pt, radius: 3pt, fill: blue_light, stroke: 0.5pt + rule, breakable: false,
)[
  #text(size: 8.5pt, weight: "bold", fill: blue)[#title]
  #v(2pt)
  #set text(size: 7.6pt)
  #set par(leading: 0.42em, spacing: 0.4em, justify: false)
  #show raw.where(block: true): set text(size: 7pt)
  #show raw.where(block: false): set text(size: 6.9pt)
  #body
]

#card([Build], [
  ```sh
  zig build -Doptimize=ReleaseFast          # daemon + storage
  zig build -Doptimize=ReleaseFast -Dstorage=false   # static, no libc
  zig build -Dcluster=true                  # Multi-Paxos, needs OpenSSL 3
  zig build test        # native, UI and live daemon tests
  zig build console-test # console workflows through a live daemon
  zig build fmt         # zig fmt + 70-line / 99-column gate
  zig build book sid    # this book, the SID records
  zig build benchmark   # primitives -> results/latest.json
  python3 benchmarks/tools.py --anubis <binary>   # whole products under wrk
  ```
])
#v(4pt)
#card([Run], [
  ```sh
  # Shield (default): PoW + WAF, proxy to :3000
  sibuna -p 8080 -u 3000 -s /etc/sibuna/secret
  # Gate: PoW only
  sibuna --gate -p 8080 -u 3000 -s /etc/sibuna/secret
  # Forward auth behind Nginx/Caddy (trusts X-Forwarded-For)
  sibuna -m forward_auth --host 127.0.0.1 -p 8080 -s /etc/sibuna/secret
  # Edge: persistent policies, reputation, forensics
  sibuna -D /var/lib/sibuna -s /etc/sibuna/secret
  head -c 32 /dev/urandom | xxd -p -c 64 > /etc/sibuna/secret
  ```
])
#v(4pt)
#card([Console (opt-in preview)], [
  ```sh
  # Initialize while the daemon is stopped, then start the console
  sibuna init-admin admin --data-dir ./data
  sibuna --data-dir ./data --console 127.0.0.1:19446
  ```
  Open `http://127.0.0.1:19446/console/` and replace the temporary password.
  Add `--console-location 1.3521,103.8198` to place the node on the globe.
  Remote access requires an HTTPS proxy, an explicit origin and trusted-proxy CIDRs;
  follow Part IX. SID 0007 remains Proposed; the interface is not full acceptance evidence.
])
#v(4pt)
#grid(columns: (1fr, 1fr), gutter: 5pt,
  card([Flags that matter first], [
    #table(columns: (1.5fr, 0.45fr, 1.4fr), inset: 3pt, stroke: 0.3pt + rule,
      [`-d, --difficulty`], [16], [work bits (PoSW depth = bits − 3)],
      [`-a, --algorithm`], [posw], [`posw` or `hashcash`],
      [`--posw-challenges`], [16], [openings per proof],
      [`--token-ttl`], [86400], [session seconds],
      [`--challenge-ttl`], [300], [challenge seconds],
      [`--token-scheme`], [mac], [`mac` or `ed25519`],
      [`--rate-limit / --rate-window`], [100 / 10], [GCRA burst per window],
      [`--ban-seconds`], [3600], [honeypot ban],
      [`-w, --workers`], [CPUs], [accept threads],
      [`--max-connections`], [1024], [then `503`],
      [`--idle-timeout`], [15], [reaper seconds],
      [`-P, --policy-file`], [—], [JSON policy],
      [`--trust-forwarded`], [off], [on in forward auth],
      [`--secure-cookie`], [off], [add `Secure`],
    )
  ]),
  card([Endpoints under `/__sibuna/`], [
    #table(columns: (1.2fr, 1.8fr), inset: 3pt, stroke: 0.3pt + rule,
      [`challenge`], [interstitial HTML],
      [`challenge.json?path=`], [`{id, algorithm, difficulty, challenges, expires_at}`],
      [`verify` (POST)], [`{challenge_id, nonce | proof}` → `200` + `Set-Cookie`, else `400`],
      [`wasm/sibuna-pow.wasm`], [8,831-byte solver],
      [`worker.js`], [worker with WASM and JS provers],
      [`honeypot`], [bans caller, `403`],
      [`health`], [`{"status":"ok",…}`],
      [`metrics`], [Prometheus text],
    )
    Route all of them to the daemon, never to the origin.
  ]),
)
#v(4pt)
#grid(columns: (1fr, 1fr), gutter: 5pt,
  card([Status codes], [
    #table(columns: (0.35fr, 2fr), inset: 3pt, stroke: 0.3pt + rule,
      [200], [admitted (forward auth), interstitial, internal routes],
      [400], [malformed request or rejected solution (diagnostic body)],
      [401], [challenge required: non-HTML client or forward auth],
      [403], [policy or WAF denial, ban, honeypot],
      [413], [solution body over the 64 KB buffer],
      [417], [unsupported request expectation],
      [429], [GCRA limit, `Retry-After` seconds],
      [431], [head over 16 KB],
      [502], [origin unreachable or malformed],
      [503], [`--max-connections` reached],
    )
  ]),
  card([Headers], [
    *Upstream (proxy)*: `X-Forwarded-For`, `X-Real-IP`, `X-Sibuna-Status: PASS`,
    `X-Sibuna-Rule: <rule>`; hop-by-hop and incoming forwarded-for dropped. #linebreak()
    *Forward-auth reply*: `X-Sibuna-Status`, `X-Sibuna-Rule`, `X-Sibuna-Rule-Hash`. #linebreak()
    *Challenge reply*: `X-Sibuna-Status: CHALLENGE`. #linebreak()
    *Cookie*: `__sibuna_token=<64 chars>; Path=/; Max-Age=<ttl>; HttpOnly; SameSite=Lax[; Secure]`
  ]),
)
#v(4pt)
#card([Policy file skeleton], [
  ```json
  { "default_action": "CHALLENGE", "waf": true,
    "thresholds": {"challenge_at": 10, "deny_at": 40, "bits_step": 5},
    "ip_rules": {"10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY"},
    "rules": [
      {"name": "api", "path": "/api/*", "headers": {"X-Api-Key": ".*"}, "action": "ALLOW"},
      {"name": "checkout", "path": "/checkout/*", "action": "CHALLENGE",
       "challenge": {"difficulty": 20, "algorithm": "posw"}},
      {"name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30} ] }
  ```
  Patterns: `*`/`.*` any · `^…$` exact · trailing `*` prefix · leading `/` exact path ·
  else case-insensitive substring. Order: WAF → trie deny/allow → rules → score → bypass →
  trie challenge → bots → default.
])
#v(4pt)
#card([Storage (Edge) in SQL], [
  ```sql
  INSERT INTO policies (id, name, priority, path_pattern, action, difficulty, algorithm,
    header_matchers, cidr_matchers, weight, enabled, created_at, updated_at)
    VALUES ('p1', 'protect', 10, '/checkout/*', 'CHALLENGE', 20, 'posw', '{}', '[]', 0, 1,
    unixepoch(), unixepoch());
  INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, trigger_rule, hits, last_seen)
    VALUES ('198.51.100.7', -100, unixepoch() + 86400, 'analyst', 1, unixepoch());
  SELECT s.client_ip, s.violation_category, s.path, s.campaign_id
    FROM incidents_fts f JOIN security_incidents s ON s.id = f.rowid
    WHERE incidents_fts MATCH 'union' ORDER BY rank LIMIT 20;
  ```
  Score ≤ −50 → deny prefix; ≥ 50 → allow. Cluster: same member list and secret on every
  node; `-Dcluster=true`, `--cluster-node N --cluster-listen host:port --cluster-peer id@host:port`,
  certificates `zaxon-node-<id>` or `--cluster-secret-file` for loopback.
])
#v(4pt)
#grid(columns: (1fr, 1fr), gutter: 5pt,
  card([Diagnostics], [
    #table(columns: (1.1fr, 1.9fr), inset: 3pt, stroke: 0.3pt + rule,
      [`MALFORMED CHALLENGE`], [id edited or truncated; fetch a new one],
      [`INVALID CHALLENGE TAG`], [not minted by this seed or node],
      [`CHALLENGE EXPIRED`], [older than TTL or clock skew > 60 s],
      [`FINGERPRINT MISMATCH`], [address or User-Agent changed],
      [`DIFFICULTY NOT MET`], [nonce lacks zero bits],
      [`INVALID PROOF`], [openings do not reach the root],
      [`WRONG SOLUTION TYPE`], [nonce for PoSW or proof for Hashcash],
      [`DOUBLE SPEND`], [challenge already used],
      [`STORE FULL`], [spent shard saturated; lower TTL],
      [`TOKEN … MISMATCH`], [cookie copied to another client],
    )
    Metrics to alert on: `denied`, `rate_limited`, `overloaded`, `upstream_errors`,
    `incidents_dropped`, `incident_write_failures` (all `sibuna_*_total`).
  ]),
  card([Numbers to remember], [
    Challenge id 70 chars (36-byte payload + 16-byte tag) · token 64 chars (32 + 16) ·
    proof bytes $32(1 + t(n+1))$ · PoSW depth $= "bits" - 3$, range 4–24 · request buffer
    64 KB · head limit 16 KB · body inspected 8 KB · spent set 16 × 4,096 · rate cells
    16 × 512 · bans 4,096 · incident ring 512 · batch 32 · campaign distance 0.35 ·
    keep-alive 4,096 requests per connection · origin pool 256 sockets.
  ]),
)
#v(4pt)
#card([Ingress routing], [
  Use the complete, live-tested Nginx or Caddy recipe in Part IX, Forward Auth Behind an
  Ingress. Route `/__sibuna/*` directly; authorize application requests with the original
  URI, method and trusted client address. Replace incoming Sibuna audit headers with the
  authorization result. Nginx needs explicit challenge, 429 and unavailable-auth handling.

  `reverse_proxy` carries admitted HTTP/1.1 bodies and WebSockets; `forward_auth` grants
  admission and the ingress carries them. Omitted auth bodies and origin responses cannot
  be inspected or counted by Sibuna. TLS terminates at the ingress; native HTTP/2 is deferred.
  Uploads use Content-Length; inspection sees at most an 8 KiB prefix, with file bytes opaque.
])
